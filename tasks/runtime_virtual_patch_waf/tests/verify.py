#!/usr/bin/env python3
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import signal
import time
import unicodedata
import urllib.parse
from contextlib import contextmanager
from email import policy as email_policy
from email.parser import BytesParser
from pathlib import Path

from diagnostic_metrics import replay_metrics

from policy_runtime import (
    BACKEND_CONTEXT_PIPELINES,
    backend_pipeline,
    canonical_route,
    evaluate_policy,
    extract_values,
    legacy_assess,
    load_policy,
    locator_outside,
    parse_request,
    transform_value,
)

ARTIFACT = Path(os.environ.get(
    "POLICY_PATH", str(Path(os.environ.get("APP_ROOT", "/app")) / "edge-policy.json"),
))
LOG = Path(os.environ.get("LOG_DIR", "/logs/verifier"))
REQUIRED_AUDIT = {"request_id", "rule_id", "method", "route", "source", "field", "reason"}

# Deterministic work is the primary cost boundary. These wall-clock thresholds are
# intentionally far above ordinary policy evaluation on the full corpus and guard against
# unexpected runtime stalls independently of the submitted configuration.
PER_REQUEST_DEADLINE_SECONDS = 0.75
PRIMARY_CORPUS_DEADLINE_SECONDS = 30.0
MALFORMED_CORPUS_DEADLINE_SECONDS = 5.0
FULL_BENIGN_REPLAY_DEADLINE_SECONDS = 30.0

# The solver-visible representative capture is a grading contract, not merely a hint.
# Harbor normally exposes it at /app/traffic.  Because /app is solver-writable, only the
# byte-identical published corpus is accepted there; otherwise the verifier falls back to
# its synchronized private copy.  The digest plus the ordered ID/decision manifest makes
# capture drift or truncation a verifier-consistency error rather than a grading change.
PUBLISHED_CAPTURE_SHA256 = "c80e50fe944135c178044172275d0fac8bd56d9f3b12f6f0c576b5f06893d6c3"
PUBLISHED_CAPTURE_EXPECTATIONS = (
    ("m-json-parent", "block"),
    ("m-query-double", "block"),
    ("m-json-backslash", "block"),
    ("m-json-unicode", "block"),
    ("m-integration-scheme", "block"),
    ("m-batch-member", "block"),
    ("m-validate-form", "block"),
    ("m-route-canonical", "block"),
    ("m-duplicate-json", "block"),
    ("b-within-root", "allow"),
    ("b-asset", "allow"),
    ("b-dotted-name", "allow"),
    ("b-batch-complex", "allow"),
    ("b-integration", "allow"),
    ("b-import-lookalike", "allow"),
    ("b-search-lookalike", "allow"),
    ("b-events-opaque", "allow"),
    ("b-ignored-legacy-header", "allow"),
    ("x-malformed-json", "reject"),
    ("d-adapter-url-generation", "block"),
    ("d-adapter-document-generation", "allow"),
)
PUBLISHED_CAPTURE_PRIVATE_COPY = Path(__file__).resolve().with_name(
    "public_representative.jsonl",
)


def load_published_capture():
    """Load exactly the immutable 21-row public corpus without trusting mutable /app."""
    candidates = []
    app_root = Path(os.environ.get("APP_ROOT", "/app"))
    for path in (
        app_root / "traffic" / "representative.jsonl",
        Path("/app/traffic/representative.jsonl"),
        PUBLISHED_CAPTURE_PRIVATE_COPY,
    ):
        if path not in candidates:
            candidates.append(path)

    rejected = []
    for path in candidates:
        try:
            raw = path.read_bytes()
        except OSError as exc:
            rejected.append({"path": str(path), "reason": f"unreadable: {exc}"})
            continue
        digest = hashlib.sha256(raw).hexdigest()
        if digest != PUBLISHED_CAPTURE_SHA256:
            rejected.append({
                "path": str(path),
                "reason": f"digest mismatch: {digest}",
            })
            continue
        try:
            text = raw.decode("utf-8", "strict")
            encoded_lines = text.splitlines()
            rows = [json.loads(line) for line in encoded_lines]
        except Exception as exc:
            rejected.append({"path": str(path), "reason": f"invalid JSONL: {exc}"})
            continue
        observed = tuple(
            (row.get("id"), row.get("decision")) if isinstance(row, dict) else (None, None)
            for row in rows
        )
        if observed != PUBLISHED_CAPTURE_EXPECTATIONS:
            rejected.append({
                "path": str(path),
                "reason": "ordered ID/decision manifest mismatch",
            })
            continue
        if any(
            not isinstance(row.get("request"), dict)
            or set(row.get("request", {})) != {"method", "target", "headers", "body"}
            for row in rows
        ):
            rejected.append({
                "path": str(path),
                "reason": "a capture row lacks the exact request-envelope shape",
            })
            continue
        return rows, str(path), rejected
    rendered = "; ".join(
        f"{item['path']}: {item['reason']}" for item in rejected
    ) or "no candidate paths"
    raise ValueError(f"no byte-identical published representative capture is available: {rendered}")


class EvaluationDeadlineExceeded(TimeoutError):
    def __init__(self, scope, label, seconds):
        super().__init__(f"{scope} deadline exceeded for {label}")
        self.scope = scope
        self.label = label
        self.seconds = seconds


@contextmanager
def interrupting_deadline(seconds, scope, label):
    """Interrupt a bounded verifier operation and restore process alarm state safely."""
    started = time.monotonic()
    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_timer = signal.getitimer(signal.ITIMER_REAL)

    def alarm_handler(_signum, _frame):
        raise EvaluationDeadlineExceeded(scope, label, seconds)

    signal.signal(signal.SIGALRM, alarm_handler)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0.0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0] > 0.0:
            elapsed = time.monotonic() - started
            # If an inherited timer would have expired while ours was active, arrange for
            # it to fire immediately after restoration instead of silently discarding it.
            restored_delay = max(0.000001, previous_timer[0] - elapsed)
            signal.setitimer(signal.ITIMER_REAL, restored_delay, previous_timer[1])


class ReplayCorpus:
    def __init__(self, label, seconds):
        self.label = label
        self.seconds = seconds
        self.started = time.monotonic()

    def elapsed(self):
        return time.monotonic() - self.started

    def remaining(self):
        return self.seconds - self.elapsed()


def request(method, target, body="", content_type=None, headers=None, rid="hidden"):
    pairs = [["Authorization", "Bearer verifier-client"], ["X-Request-ID", rid]]
    if content_type:
        pairs.append(["Content-Type", content_type])
    if headers:
        pairs.extend(headers)
    return {"method": method, "target": target, "headers": pairs, "body": body}


def multipart(fields, boundary="verify-boundary"):
    chunks = []
    for name, value in fields:
        chunks.append(
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n"
            f"{value}\r\n"
        )
    chunks.append(f"--{boundary}--\r\n")
    return "".join(chunks), f"multipart/form-data; boundary={boundary}"


def exact_size_multipart(total_bytes, boundary="capacity-import-1m"):
    """Build one legal text field whose complete ASCII MIME body is exactly total_bytes."""
    prefix = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="template"\r\n'
        "Content-Type: text/plain; charset=utf-8\r\n\r\n"
    )
    suffix = f"\r\n--{boundary}--\r\n"
    payload_bytes = total_bytes - len(prefix.encode("ascii")) - len(suffix.encode("ascii"))
    if payload_bytes < 1:
        raise ValueError("multipart total is too small for its framing")
    body = prefix + ("A" * payload_bytes) + suffix
    if len(body.encode("ascii")) != total_bytes:
        raise AssertionError("exact-size multipart construction drifted")
    return body, f"multipart/form-data; boundary={boundary}"


def derived_token(policy_digest, index, alphabet, length):
    """Map submitted-policy bytes to an unpredictable but reproducible MIME token."""
    material = hashlib.shake_256(
        b"northstar-safe-import-metamorphic-v1\0"
        + policy_digest
        + index.to_bytes(2, "big")
    ).digest(length)
    return "".join(alphabet[byte % len(alphabet)] for byte in material)


def policy_dependent_import_controls(raw_policy):
    """Generate ordinary legal imports which cannot be fixture-whitelisted statically.

    Boundary values and correlation IDs depend on the submitted serialization.  Editing a
    policy to name the resulting values changes the values.  A deployable policy therefore
    has to preserve the documented multipart grammar rather than enumerate this corpus.
    """
    digest = hashlib.sha256(raw_policy).digest()
    alnum_lower = "abcdefghijklmnopqrstuvwxyz0123456789"
    alnum_mixed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    word_token = alnum_mixed + "-_"
    dotted_token = alnum_mixed + ".+-_"
    quoted_punctuation = alnum_mixed + "'()+_,-./:=?"

    # Disjoint digest-selected length bands span the ordinary 5..70-character range.
    # Source-level enumeration must consequently accept broad length ranges, not eight
    # constants which happen to be present in this verifier version.
    length_bands = [
        (5, 11), (12, 18), (19, 26), (27, 34),
        (35, 43), (44, 52), (53, 61), (61, 69),
    ]
    lengths = [
        low + digest[index] % (high - low + 1)
        for index, (low, high) in enumerate(length_bands)
    ]
    tokens = [
        derived_token(digest, 0, alnum_lower, lengths[0]),
        derived_token(digest, 1, alnum_mixed, lengths[1]),
        derived_token(digest, 2, word_token, lengths[2]),
        derived_token(digest, 3, dotted_token, lengths[3]),
        derived_token(digest, 4, alnum_mixed, lengths[4]),
        derived_token(digest, 5, quoted_punctuation, lengths[5]),
        derived_token(digest, 6, word_token, lengths[6]),
        derived_token(digest, 7, alnum_mixed, lengths[7]),
    ]
    # Force each expanding alphabet to be observable rather than merely possible.
    for index, alphabet in ((2, "-_"), (3, ".+"), (5, "'()+_,-./:=?"), (6, "-_")):
        position = 1 + digest[8 + index] % (len(tokens[index]) - 2)
        tokens[index] = (
            tokens[index][:position]
            + alphabet[digest[16 + index] % len(alphabet)]
            + tokens[index][position + 1:]
        )
    # RFC 2046 permits interior spaces in a quoted boundary, but not as the final
    # character.  Its digest-derived neighbors keep even this case serialization-bound;
    # after insertion its complete token remains within the 70-character maximum.
    position = 1 + digest[31] % (len(tokens[7]) - 1)
    tokens[7] = tokens[7][:position] + " " + tokens[7][position:]
    content_types = [
        f"multipart/form-data; boundary={tokens[0]}",
        f"Multipart/Form-Data; BOUNDARY={tokens[1]}",
        f"multipart/form-data; charset=UTF-8; boundary={tokens[2]}",
        f'multipart/form-data; boundary={tokens[3]}; charset="utf-8"',
        f'multipart/form-data; boundary="{tokens[4]}"',
        f'Multipart/Form-Data; profile="ordinary"; boundary="{tokens[5]}"',
        f'MULTIPART/FORM-DATA; boundary="{tokens[6]}"; charset=utf-8',
        f'multipart/form-data; charset="UTF-8"; boundary="{tokens[7]}"',
    ]
    header_names = [
        "content-type", "CONTENT-TYPE", "CoNtEnT-TyPe", "Content-Type",
        "cOnTeNt-TyPe", "Content-type", "CONTENT-type", "content-TYPE",
    ]
    field_shapes = [
        [("filename", "../../quarter.tpl"), ("template", "Hello {{ ../../customer.name }}")],
        [("note", "routine"), ("template", "Literal ../ content"), ("filename", "team.tpl")],
        [("template", "{{ customer.name }}"), ("filename", "daily.tpl")],
        [("filename", "reports/../quarter.tpl"), ("template", "ordinary text")],
        [("template", "Hello from import")],
        [("filename", "q2.tpl"), ("metadata", "../ is literal here"), ("template", "safe")],
        [("template", "Hello {{ ../../customer.name }}"), ("filename", "deep/report.tpl")],
        [("filename", "spaced-boundary.tpl"), ("template", "ordinary")],
    ]

    rows = []
    for index, (boundary, content_type, header_name, fields) in enumerate(zip(
        tokens, content_types, header_names, field_shapes,
    )):
        body, _ = multipart(fields, boundary)
        rid = "imp-" + hashlib.sha256(digest + bytes([index])).hexdigest()[:18]
        req = request(
            "POST", "/v1/templates/import", body,
            headers=[[header_name, content_type]], rid=rid,
        )
        # Vary ordinary header order as well as spelling.  Parsing and policy selection
        # are explicitly case-insensitive and must not depend on pair-array position.
        if index % 3 == 1:
            req["headers"] = [req["headers"][2], req["headers"][0], req["headers"][1]]
        elif index % 3 == 2:
            req["headers"] = [req["headers"][1], req["headers"][2], req["headers"][0]]
        rows.append((
            f"safe-import-metamorphic-{index:02d}", req,
            "route_scope_import_multipart_grammar", "unrelated",
        ))
    return rows


def generated_segment(label):
    return "g" + hashlib.sha256(("northstar-context-v3:" + label).encode()).hexdigest()[:13]


def percent_all(value):
    return "".join(f"%{byte:02X}" for byte in value.encode("utf-8"))


def encoded(value, layers):
    for _ in range(layers):
        value = percent_all(value)
    return value


def outside_value(label):
    return f"../../{generated_segment(label)}/leaf"


def inside_value(label):
    return f"dept/{generated_segment(label)}/../shared/{generated_segment(label + '-tail')}"


def generated_scheme(label, style):
    digest = hashlib.sha256(("northstar-scheme-v1:" + label).encode()).digest()
    letters = "".join(chr(ord("a") + byte % 26) for byte in digest[:10])
    if style == 0:
        value = letters
    elif style == 1:
        value = letters[:4] + "+" + letters[4:]
    else:
        value = letters[:3] + "." + letters[3:8] + "-7"
    return "".join(ch.upper() if digest[i % len(digest)] & 1 else ch
                   for i, ch in enumerate(value))


def integration_case_variants():
    variants = {
        "".join(ch.upper() if mask & (1 << index) else ch
                for index, ch in enumerate("legacy"))
        for mask in range(1 << len("legacy"))
    }
    ordered = sorted(
        variants,
        key=lambda value: hashlib.sha256(("northstar-mode-case-v1:" + value).encode()).digest(),
    )
    required = ["legacy", "LeGaCy", "LEGACY"]
    return required + [value for value in ordered if value not in required][:21]


def suffix_media_types(label):
    digest = hashlib.sha256(("northstar-json-media-v1:" + label).encode()).hexdigest()
    return [
        "application/problem+json",
        "Application/Problem+Json; Charset=UTF-8",
        "application/merge-patch+json; charset=utf-8",
        'APPLICATION/MERGE-PATCH+JSON; CHARSET="UTF-8"',
        f"Application/Vnd.northstar-{digest[:10]}+Json; Charset=UTF-8",
        f'APPLICATION/vnd.{digest[10:20]}.policy+JSON; charset="utf-8"',
    ]


# The 13 public business carriers are described independently from policy rules.  The
# profile labels below are verifier-private behavioral-model labels, not required IDs.
CARRIERS = [
    {"name": "query-template", "profile": "interactive_url_form", "method": "POST", "route": "/v1/render", "source": "query", "field": "template"},
    {"name": "query-view", "profile": "interactive_url_form", "method": "POST", "route": "/v1/render", "source": "query", "field": "view"},
    {"name": "json-template", "profile": "interactive_document", "method": "POST", "route": "/v1/render", "source": "json", "field": "/template"},
    {"name": "json-options", "profile": "interactive_document", "method": "POST", "route": "/v1/render", "source": "json", "field": "/options/template"},
    {"name": "form-template", "profile": "interactive_url_form", "method": "POST", "route": "/v1/render", "source": "form", "field": "template"},
    {"name": "form-options", "profile": "interactive_url_form", "method": "POST", "route": "/v1/render", "source": "form", "field": "options.template"},
    {"name": "multipart", "profile": "interactive_document", "method": "POST", "route": "/v1/render", "source": "multipart", "field": "template_locator"},
    {"name": "integration-header", "profile": "legacy_integration", "method": "POST", "route": "/v1/render", "source": "header", "field": "x-legacy-template"},
    {"name": "batch-template", "profile": "batch_dispatch", "method": "POST", "route": "/v1/render/batch", "source": "json", "field": "/jobs/*/template"},
    {"name": "batch-options", "profile": "batch_dispatch", "method": "POST", "route": "/v1/render/batch", "source": "json", "field": "/jobs/*/options/template"},
    {"name": "validation-query", "profile": "validation_gateway", "method": "PUT", "route": "/v1/templates/validate", "source": "query", "field": "locator"},
    {"name": "validation-json", "profile": "validation_gateway", "method": "PUT", "route": "/v1/templates/validate", "source": "json", "field": "/locator"},
    {"name": "validation-form", "profile": "validation_gateway", "method": "PUT", "route": "/v1/templates/validate", "source": "form", "field": "locator"},
]
assert len(CARRIERS) == 13 and len({item["name"] for item in CARRIERS}) == 13


# These are the exact neighboring operations and concrete carrier shapes published in the
# protocol or exercised by a legal replay below.  Structural overlap is useful maintainer
# diagnostics, but it is not a semantic violation: the predicate can be unsatisfiable,
# header conditions can be contradictory, or the selected legal values can simply fail to
# match.  Reward-fatal non-interference is established only by a guarded evaluation of an
# actual legal request later in the verifier.
SUPPORTED_NEIGHBOR_OPERATIONS = [
    {
        "name": "template-import",
        "method": "POST",
        "route": "/v1/templates/import",
        "selector_shapes": {
            "multipart": {"filename", "template", "note", "metadata"},
            "header": {"authorization", "x-request-id", "content-type"},
        },
        "contract": "published multipart import fields, metadata, and request headers",
    },
    {
        "name": "published-search",
        "method": "GET",
        "route": "/v1/search",
        "selector_shapes": {
            "query": {"template", "q"},
            "header": {"authorization", "x-request-id"},
        },
        "contract": "published literal search terms and request headers",
    },
    {
        "name": "opaque-events",
        "method": "POST",
        "route": "/v1/events",
        "selector_shapes": {
            "json": {"/event", "/template", "/payload/path"},
            "header": {"authorization", "x-request-id", "content-type"},
        },
        "contract": "published opaque event JSON and request headers",
    },
]
assert all(
    operation["method"] == operation["method"].upper()
    and canonical_route(operation["route"]) == operation["route"]
    for operation in SUPPORTED_NEIGHBOR_OPERATIONS
)


def selector_description(selector):
    location = selector.get("location")
    key = "pointers" if location == "json" else "names"
    fields = selector.get(key, [])
    return f"{location}:" + ",".join(fields)


def selector_shape_overlap(selector, operation):
    location = selector.get("location")
    documented = operation["selector_shapes"].get(location, set())
    key = "pointers" if location == "json" else "names"
    submitted = selector.get(key, [])
    if location == "header":
        submitted = [field.lower() for field in submitted]
    return sorted(set(submitted) & documented)


def selector_legal_active_fields(selector, operation):
    """Return published leaves a selector may consume; actual extraction is authoritative."""
    location = selector.get("location")
    documented = operation["selector_shapes"].get(location, set())
    if not documented:
        return []
    if location == "json":
        # Wildcard and escaped submitted pointers are tested against each concrete legal
        # document leaf later; exact-string structural overlap is not required.
        return sorted(documented)
    submitted = selector.get("names", [])
    if location == "header":
        lowered = {name.lower() for name in submitted}
        return sorted(field for field in documented if field.lower() in lowered)
    return sorted(set(submitted) & documented)


def neighbor_non_interference_advisories(candidate_policy):
    """Report structural rule/contract overlap without treating it as a violation."""
    advisories = []
    for rule_index, rule in enumerate(candidate_policy.get("rules", [])):
        action = rule.get("action", {})
        if action.get("type") != "block":
            continue
        match = rule.get("match", {})
        methods = {method.upper() for method in match.get("methods", [])}
        routes = {canonical_route(route) for route in match.get("routes", [])}
        for operation in SUPPORTED_NEIGHBOR_OPERATIONS:
            if operation["method"] not in methods or operation["route"] not in routes:
                continue
            overlapping = []
            for selector_index, selector in enumerate(rule.get("selectors", [])):
                fields = selector_shape_overlap(selector, operation)
                if fields:
                    overlapping.append({
                        "selector_index": selector_index,
                        "location": selector.get("location"),
                        "selector": selector_description(selector),
                        "overlapping_fields": fields,
                    })
            if not overlapping:
                continue
            advisories.append({
                "classification": "advisory_structural_overlap_only",
                "reward_fatal": False,
                "rule_index": rule_index,
                "rule_id": rule.get("id"),
                "action": action.get("type"),
                "method": operation["method"],
                "route": operation["route"],
                "operation": operation["name"],
                "contract": operation["contract"],
                "overlapping_selectors": overlapping,
                "diagnostic": (
                    f"rule {rule.get('id')!r} is scoped to published "
                    f"{operation['method']} {operation['route']} and names a concrete legal "
                    "carrier shape; this is advisory until a guarded legal replay is "
                    "actually denied"
                ),
            })
    return advisories


def supported_neighbor_operation(req):
    operation_key = (req.get("method", "").upper(), canonical_route(req.get("target", "")))
    return next(
        (operation for operation in SUPPORTED_NEIGHBOR_OPERATIONS
         if (operation["method"], operation["route"]) == operation_key),
        None,
    )


def witnessed_neighbor_denial(case_id, req, result, witness_provenance=None):
    """Describe a causal denial of one concrete legal neighboring request."""
    operation = supported_neighbor_operation(req)
    if operation is None or result.get("decision") == "allow":
        return None
    audit = result.get("audit") if isinstance(result.get("audit"), dict) else {}
    source = result.get("source", audit.get("source"))
    field = result.get("field", audit.get("field"))
    record = {
        "classification": "causal_legal_request_denial",
        "reward_fatal": True,
        "case_id": case_id,
        "operation": operation["name"],
        "contract": operation["contract"],
        "method": operation["method"],
        "route": operation["route"],
        "decision": result.get("decision"),
        "status": result.get("status"),
        "rule_id": result.get("rule_id", audit.get("rule_id")),
        "predicate_or_rejection_reason": result.get("reason"),
        "extracted_source": source,
        "extracted_field": field,
        "cause": (
            f"guarded legal replay {case_id!r} for {operation['method']} "
            f"{operation['route']} was actually {result.get('decision')!r}"
            + (f" after extracting {source}:{field}" if source and field else "")
            + f" under documented {result.get('reason')!r} semantics"
        ),
    }
    if witness_provenance is not None:
        record["witness_provenance"] = witness_provenance
        record["cause"] += (
            f"; candidate provenance={witness_provenance.get('origin')} "
            f"embedding={witness_provenance.get('request_embedding')} and independent "
            f"parse={witness_provenance.get('independent_parse', {}).get('success')}"
        )
    return record



# Rule-directed neighboring witnesses are bounded independently of policy size.  Structural
# overlap remains advisory; only a successfully parsed request which the interrupting
# runtime evaluator actually denies is reward-fatal.
MAX_RULE_DIRECTED_NEIGHBOR_REQUESTS = 1024
MAX_RULE_DIRECTED_SECONDARY_REQUESTS_PER_RULE_OPERATION = 4
MAX_RULE_DIRECTED_RAW_PREIMAGES = 12
MAX_RULE_DIRECTED_NORMALIZED_BYTES = 4096
MAX_RULE_DIRECTED_RAW_BYTES = 16384
MIME_BOUNDARY_CHARS = set(
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'()+_,-./:=? "
)
MIME_UNQUOTED_BOUNDARY_CHARS = set(
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'+_-."
)
HTTP_TOKEN_CHARS = set(
    "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)


def _strict_utf8_text(value):
    if not isinstance(value, str):
        return False
    try:
        value.encode("utf-8", "strict")
    except UnicodeError:
        return False
    return True


def _legal_header_name(name):
    return isinstance(name, str) and bool(name) and all(char in HTTP_TOKEN_CHARS for char in name)


def _legal_header_value(value):
    return (
        _strict_utf8_text(value)
        and "\r" not in value and "\n" not in value and "\x00" not in value
        and all(
            char == "\t" or 0x20 <= ord(char) <= 0x7E or 0x80 <= ord(char) <= 0xFF
            for char in value
        )
    )


def _comparison_matches(value, condition):
    expected = condition.get("equals")
    if not isinstance(expected, str):
        return False
    return value == expected if condition.get("case_sensitive") else value.lower() == expected.lower()


def _common_condition_value(conditions, preferred=None):
    """Find one header occurrence satisfying every condition, or declare it unreachable.

    A legal HTTP request has one effective Content-Type.  Treating mutually inconsistent
    conditions as an excuse to manufacture duplicate semantic headers would not establish
    collateral damage on the published operation.
    """
    candidates = []
    if preferred is not None:
        candidates.append(preferred)
    candidates.extend(
        condition.get("equals") for condition in conditions
        if isinstance(condition.get("equals"), str)
    )
    for candidate in candidates:
        if _legal_header_value(candidate) and all(
            _comparison_matches(candidate, condition) for condition in conditions
        ):
            return candidate
    return None


def _legal_boundary(boundary):
    return (
        isinstance(boundary, str)
        and 1 <= len(boundary) <= 70
        and boundary[-1] != " "
        and all(char in MIME_BOUNDARY_CHARS for char in boundary)
    )


def _strict_content_type_syntax(value):
    """Parse ordinary RFC token/quoted-string Content-Type parameter grammar."""
    if not _legal_header_value(value):
        return None
    try:
        value.encode("ascii", "strict")
    except UnicodeError:
        return None
    length = len(value)
    index = 0

    def token():
        nonlocal index
        start = index
        while index < length and value[index] in HTTP_TOKEN_CHARS:
            index += 1
        return value[start:index] if index > start else None

    def ows():
        nonlocal index
        while index < length and value[index] in " \t":
            index += 1

    media_major = token()
    if not media_major or index >= length or value[index] != "/":
        return None
    index += 1
    media_minor = token()
    if not media_minor:
        return None
    ows()
    parameters = []
    while index < length:
        if value[index] != ";":
            return None
        index += 1
        ows()
        name = token()
        if not name:
            return None
        ows()
        if index >= length or value[index] != "=":
            return None
        index += 1
        ows()
        quoted = index < length and value[index] == '"'
        if quoted:
            index += 1
            chars = []
            closed = False
            while index < length:
                char = value[index]
                index += 1
                if char == '"':
                    closed = True
                    break
                if char == "\\":
                    if index >= length:
                        return None
                    char = value[index]
                    index += 1
                if ord(char) < 32 and char != "\t":
                    return None
                chars.append(char)
            if not closed:
                return None
            parameter_value = "".join(chars)
        else:
            parameter_value = token()
            if not parameter_value:
                return None
        ows()
        parameters.append((name, parameter_value, quoted))
    return (media_major + "/" + media_minor).lower(), parameters


def _multipart_header_boundary(content_type):
    """Parse one strict MIME header and confirm its boundary with the runtime parser."""
    syntax = _strict_content_type_syntax(content_type)
    if syntax is None or syntax[0] != "multipart/form-data":
        return None
    boundaries = [
        value for name, value, _ in syntax[1] if name.lower() == "boundary"
    ]
    if len(boundaries) != 1 or not _legal_boundary(boundaries[0]):
        return None
    try:
        raw = content_type.encode("ascii", "strict")
        message = BytesParser(policy=email_policy.default).parsebytes(
            b"Content-Type: " + raw + b"\r\nMIME-Version: 1.0\r\n\r\n"
        )
        parsed_boundary = message.get_boundary()
    except Exception:
        return None
    return boundaries[0] if parsed_boundary == boundaries[0] else None


def _boundary_was_quoted(content_type):
    syntax = _strict_content_type_syntax(content_type)
    if syntax is None:
        return None
    matches = [quoted for name, _, quoted in syntax[1] if name.lower() == "boundary"]
    return matches[0] if len(matches) == 1 else None


def _multipart_content_type_variants(candidate):
    """Place a hypothesis in full-header and legal parameter/boundary positions."""
    variants = [
        (candidate, "synthesized_full_content_type"),
        (
            "multipart/form-data; boundary=causal-boundary",
            "legal_multipart_baseline",
        ),
    ]
    if _legal_boundary(candidate):
        if all(char in MIME_UNQUOTED_BOUNDARY_CHARS for char in candidate):
            variants.append((
                f"multipart/form-data; boundary={candidate}",
                "synthesized_unquoted_boundary",
            ))
        variants.append((
            f'multipart/form-data; boundary="{candidate}"',
            "synthesized_quoted_boundary",
        ))
    if candidate and all(char in HTTP_TOKEN_CHARS for char in candidate):
        variants.append((
            f"multipart/form-data; witness={candidate}; boundary=causal-boundary",
            "synthesized_token_parameter_embedding",
        ))
    if candidate and _legal_header_value(candidate):
        escaped = candidate.replace("\\", "\\\\").replace('"', '\\"')
        variants.append((
            f'multipart/form-data; witness="{escaped}"; boundary=causal-boundary',
            "synthesized_quoted_parameter_embedding",
        ))

    out = []
    seen = set()
    for content_type, strategy in variants:
        boundary = _multipart_header_boundary(content_type)
        key = (content_type, boundary)
        if boundary is None or key in seen:
            continue
        seen.add(key)
        out.append({
            "content_type": content_type,
            "boundary": boundary,
            "quoted_boundary": _boundary_was_quoted(content_type),
            "embedding": strategy,
        })
    return out


def _utf8_text_bytes(value):
    if not isinstance(value, str):
        return None
    try:
        return len(value.encode("utf-8", "strict"))
    except UnicodeError:
        return None


def _predicate_hypotheses(predicate):
    """Return complete direct witnesses for every predicate accepted by EdgeShield v1."""
    op = predicate.get("op")
    generator = {
        "status": "generated",
        "reason": f"direct deterministic witness for {op}",
        "unsupported": [],
        "notes": [],
    }
    primary = []
    secondary = []
    if op == "equals":
        primary = [{
            "value": predicate.get("value", ""),
            "shape_ids": ["direct-equals"], "phase": "primary",
        }]
    elif op == "contains":
        needle = predicate.get("needle", "")
        primary = [{
            "value": needle,
            "shape_ids": ["direct-contains"], "phase": "primary",
        }]
        embedded = "ordinary-" + needle + "-neighbor"
        if _utf8_text_bytes(embedded) <= MAX_RULE_DIRECTED_NORMALIZED_BYTES:
            secondary = [{
                "value": embedded,
                "shape_ids": ["contains-embedded"], "phase": "secondary",
            }]
    elif op == "locator_outside":
        allowed = {
            str(scheme).lower()
            for scheme in predicate.get("allowed_schemes", [])
            if isinstance(scheme, str)
        }
        disallowed_scheme = next(
            scheme for scheme in ("file", "http", "zip", "witness")
            if scheme not in allowed
        ) if not {"file", "http", "zip", "witness"}.issubset(allowed) else None
        values = [
            ("../rule-directed-neighbor", "dot-underflow"),
            ("../../rule-directed-neighbor", "deep-dot-underflow"),
            ("/rule-directed-neighbor", "absolute-posix"),
            (r"\\server\share\rule-directed-neighbor", "absolute-unc"),
            ("C:/rule-directed-neighbor", "absolute-drive"),
            ("safe\x00outside", "embedded-nul"),
        ]
        if disallowed_scheme is not None:
            values.append((
                f"{disallowed_scheme}:/rule-directed-neighbor",
                "disallowed-scheme",
            ))
        primary = [
            {
                "value": value,
                "shape_ids": [f"locator-outside-{shape}"],
                "phase": "primary",
            }
            for value, shape in values
        ]
    else:
        generator = {
            "status": "unsupported",
            "reason": f"unsupported predicate {op!r}",
            "unsupported": [str(op)],
            "notes": [],
        }

    hypotheses = []
    for hypothesis in primary + secondary:
        size = _utf8_text_bytes(hypothesis.get("value"))
        # Validation admits equals/contains only through the same public 4096-byte cap.
        # Retain the full accepted value: there is deliberately no smaller private cutoff.
        if size is None or size > MAX_RULE_DIRECTED_NORMALIZED_BYTES:
            generator = dict(generator)
            generator["status"] = "bounded"
            generator["reason"] = "predicate hypothesis exceeded the public 4096-byte cap"
            continue
        item = dict(hypothesis)
        item["utf8_bytes"] = size
        hypotheses.append(item)
    generator = dict(generator)
    generator["primary_hypotheses"] = sum(
        item.get("phase") == "primary" for item in hypotheses
    )
    generator["secondary_hypotheses"] = sum(
        item.get("phase") == "secondary" for item in hypotheses
    )
    return hypotheses, generator


def _supported_predicate_matches(value, predicate):
    op = predicate.get("op")
    if op == "locator_outside":
        return locator_outside(value, predicate.get("allowed_schemes", []))
    if op == "equals":
        expected = predicate.get("value")
        return value == expected if predicate.get("case_sensitive") else value.lower() == expected.lower()
    if op == "contains":
        needle = predicate.get("needle")
        return needle in value if predicate.get("case_sensitive") else needle.lower() in value.lower()
    return False


def _raw_preimages(desired, transforms, predicate):
    """Produce bounded transform-aware raw hypotheses before legal-request replay."""
    desired_size = _utf8_text_bytes(desired)
    if desired_size is None or desired_size > MAX_RULE_DIRECTED_NORMALIZED_BYTES:
        return []
    states = [(desired, "literal_predicate_value")]
    for transform in reversed(transforms):
        expanded = list(states)
        for value, strategy in states:
            if transform == "percent_decode":
                expanded.append((percent_all(value), strategy + "+inverse_percent_decode"))
            elif transform == "lowercase" and value == value.lower():
                expanded.append((value.upper(), strategy + "+uppercase_preimage"))
            elif transform == "backslash_to_slash" and "/" in value:
                expanded.append((value.replace("/", "\\"), strategy + "+backslash_preimage"))
            elif transform == "trim_ascii" and value == value.strip(" \t\r\n\f\v"):
                expanded.append((" " + value + " ", strategy + "+trim_preimage"))
            elif transform == "unicode_nfkc" and unicodedata.normalize("NFKC", value) == value:
                expanded.append((value, strategy + "+nfkc_fixed_point"))
        states = [
            item for item in dict.fromkeys(expanded)
            if _utf8_text_bytes(item[0]) is not None
            and (
                item[1] == "literal_predicate_value"
                or _utf8_text_bytes(item[0]) <= MAX_RULE_DIRECTED_RAW_BYTES
            )
        ][:MAX_RULE_DIRECTED_RAW_PREIMAGES]

    out = []
    for raw, strategy in states:
        try:
            normalized = transform_value(raw, transforms)
        except (UnicodeError, ValueError):
            continue
        normalized_size = _utf8_text_bytes(normalized)
        if normalized_size is None:
            continue
        if not _supported_predicate_matches(normalized, predicate):
            continue
        out.append((raw, strategy, normalized))
    return out[:MAX_RULE_DIRECTED_RAW_PREIMAGES]


def _rule_headers(rule, operation, content_type, selected_header=None, selected_value=None):
    values = {
        "authorization": ("Authorization", "Bearer rule-directed-neighbor"),
        "x-request-id": ("X-Request-ID", "rule-directed-neighbor"),
    }
    if content_type is not None:
        values["content-type"] = ("Content-Type", content_type)
    if selected_header is not None:
        lower = selected_header.lower()
        if not _legal_header_name(selected_header) or not _legal_header_value(selected_value):
            return None, "illegal_selected_header"
        values[lower] = (selected_header, selected_value)

    grouped = {}
    for condition in rule.get("match", {}).get("headers", []):
        name = condition.get("name")
        if not _legal_header_name(name) or not _legal_header_value(condition.get("equals")):
            return None, "illegal_header_condition"
        grouped.setdefault(name.lower(), []).append(condition)

    for lower, conditions in grouped.items():
        preferred = values.get(lower, (conditions[0]["name"], None))[1]
        chosen = _common_condition_value(conditions, preferred)
        if chosen is None:
            return None, "unsatisfied_header_conditions"
        if lower == "content-type" and chosen != content_type:
            # Import has one effective legal multipart media type; events has one effective
            # JSON media type.  Do not invent duplicate Content-Type semantics.
            return None, "unsatisfied_operation_content_type_condition"
        if selected_header is not None and lower == selected_header.lower() and chosen != selected_value:
            return None, "selected_header_conflicts_with_condition"
        values[lower] = (conditions[0]["name"], chosen)

    headers = list(values.values())
    if any(not _legal_header_value(value) for _, value in headers):
        return None, "illegal_constructed_header"
    return [[name, value] for name, value in headers], None


def _replace_event_pointer(document, pointer, value):
    if pointer == "/event":
        document["event"] = value
    elif pointer == "/template":
        document["template"] = value
    elif pointer == "/payload/path":
        document.setdefault("payload", {})["path"] = value
    else:
        return False
    return True


def _token68(value):
    if not value:
        return False
    padding = len(value) - len(value.rstrip("="))
    core = value[:-padding] if padding else value
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~+/")
    return bool(core) and all(char in allowed for char in core) and "=" not in core


def _authorization_variants(candidate):
    variants = [("Bearer rule-directed-neighbor", "legal_bearer_baseline")]
    if candidate.startswith("Bearer ") and _token68(candidate[7:]):
        variants.append((candidate, "synthesized_full_bearer_authorization"))
    if _token68(candidate):
        variants.append(("Bearer " + candidate, "synthesized_bearer_token"))
    token_piece = candidate.strip("=")
    if token_piece and _token68(token_piece):
        variants.append((
            "Bearer witness." + token_piece + ".token",
            "synthesized_bearer_token_embedding",
        ))
    return list(dict.fromkeys(variants))


def _json_content_type(value):
    syntax = _strict_content_type_syntax(value)
    if syntax is None:
        return None
    media_type = syntax[0]
    if media_type == "application/json" or (
        media_type.startswith("application/") and media_type.endswith("+json")
    ):
        return media_type
    return None


def _json_content_type_variants(candidate):
    variants = [
        (candidate, "synthesized_full_json_content_type"),
        ("application/json", "legal_json_content_type_baseline"),
    ]
    if candidate and all(char in HTTP_TOKEN_CHARS for char in candidate):
        variants.extend([
            (
                f"application/vnd.{candidate}+json",
                "synthesized_json_subtype_embedding",
            ),
            (
                f"application/json; witness={candidate}",
                "synthesized_json_token_parameter_embedding",
            ),
        ])
    if candidate and _legal_header_value(candidate):
        escaped = candidate.replace("\\", "\\\\").replace('"', '\\"')
        variants.append((
            f'application/json; witness="{escaped}"',
            "synthesized_json_quoted_parameter_embedding",
        ))
    out = []
    seen = set()
    for content_type, strategy in variants:
        media_type = _json_content_type(content_type)
        if media_type is None or content_type in seen:
            continue
        seen.add(content_type)
        out.append((content_type, strategy))
    return out


def _ordinary_header_variants(field, candidate):
    lower = field.lower()
    if lower == "authorization":
        return _authorization_variants(candidate)
    if lower == "x-request-id":
        variants = [("rule-directed-neighbor", "legal_request_id_baseline")]
        if candidate and _legal_header_value(candidate):
            variants.append((candidate, "synthesized_full_request_id"))
        if candidate and all(char in HTTP_TOKEN_CHARS for char in candidate):
            variants.append((
                "rdw-" + candidate + "-id",
                "synthesized_request_id_embedding",
            ))
        return list(dict.fromkeys(variants))
    return []


def _content_type_condition_value(rule):
    conditions = [
        condition for condition in rule.get("match", {}).get("headers", [])
        if isinstance(condition.get("name"), str)
        and condition.get("name").lower() == "content-type"
    ]
    if not conditions:
        return None, None
    value = _common_condition_value(conditions)
    return (
        (value, None) if value is not None
        else (None, "unsatisfied_singleton_content_type_conditions")
    )


def _conditioned_import_media(rule):
    value, error = _content_type_condition_value(rule)
    if error:
        return None, error
    if value is None:
        return None, None
    boundary = _multipart_header_boundary(value)
    if boundary is None:
        return None, "unsatisfied_operation_content_type_condition"
    return [{
        "content_type": value, "boundary": boundary,
        "quoted_boundary": _boundary_was_quoted(value),
        "embedding": "satisfiable_match_condition_content_type",
    }], None


def _conditioned_events_media(rule):
    value, error = _content_type_condition_value(rule)
    if error:
        return None, error
    if value is None:
        return None, None
    if _json_content_type(value) is None:
        return None, "unsatisfied_operation_content_type_condition"
    return [(value, "satisfiable_match_condition_content_type")], None


def _neighbor_requests_for_value(rule, operation, selector, field, raw_value):
    """Build actual published operation shapes for one selector/value hypothesis."""
    location = selector.get("location")
    requests = []

    if operation["name"] == "template-import":
        content_types, conditioned_error = _conditioned_import_media(rule)
        if conditioned_error:
            return [{"skip": conditioned_error, "embedding": "match_condition"}]
        if content_types is None and location == "header" and field.lower() == "content-type":
            content_types = _multipart_content_type_variants(raw_value)
        elif content_types is None:
            content_types = [{
                "content_type": "multipart/form-data; boundary=rule-directed-boundary",
                "boundary": "rule-directed-boundary", "quoted_boundary": False,
                "embedding": "stable_import_content_type",
            }]
        for media in content_types:
            boundary = media["boundary"]
            fields = [("filename", "ordinary.tpl"), ("template", "ordinary import content")]
            if location == "multipart":
                fields = [(name, value) for name, value in fields if name != field]
                fields.insert(0, (field, raw_value))
            body, _ = multipart(fields, boundary)
            if location == "header" and field.lower() == "content-type":
                selected_variants = [(media["content_type"], media["embedding"])]
            elif location == "header":
                selected_variants = _ordinary_header_variants(field, raw_value)
            else:
                selected_variants = [(None, media["embedding"])]
            for selected_value, selected_strategy in selected_variants:
                headers, skipped = _rule_headers(
                    rule, operation, media["content_type"],
                    field if location == "header" else None,
                    selected_value if location == "header" else None,
                )
                if headers is None:
                    requests.append({"skip": skipped, "embedding": selected_strategy})
                    continue
                requests.append({
                    "request": {
                        "method": "POST", "target": "/v1/templates/import",
                        "headers": headers, "body": body,
                    },
                    "embedding": selected_strategy,
                    "extracted_raw": selected_value if location == "header" else raw_value,
                    "boundary_length": len(boundary),
                    "quoted_boundary": media["quoted_boundary"],
                })

    elif operation["name"] == "published-search":
        query = {"template": "ordinary-template-term", "q": "ordinary-query-term"}
        if location == "query":
            query[field] = raw_value
            selected_variants = [(None, "published_search_query_shape")]
        else:
            selected_variants = _ordinary_header_variants(field, raw_value)
        for selected_value, selected_strategy in selected_variants:
            headers, skipped = _rule_headers(
                rule, operation, None,
                field if location == "header" else None,
                selected_value if location == "header" else None,
            )
            if headers is None:
                requests.append({"skip": skipped, "embedding": selected_strategy})
                continue
            requests.append({
                "request": {
                    "method": "GET",
                    "target": "/v1/search?" + urllib.parse.urlencode(
                        query, quote_via=urllib.parse.quote,
                    ),
                    "headers": headers, "body": "",
                },
                "embedding": selected_strategy,
                "extracted_raw": selected_value if location == "header" else raw_value,
            })

    elif operation["name"] == "opaque-events":
        document = {
            "event": "routine", "template": "ordinary opaque content",
            "payload": {"path": "ordinary/opaque/path"},
        }
        if location == "json" and not _replace_event_pointer(document, field, raw_value):
            return []
        content_types, conditioned_error = _conditioned_events_media(rule)
        if conditioned_error:
            return [{"skip": conditioned_error, "embedding": "match_condition"}]
        if content_types is None and location == "header" and field.lower() == "content-type":
            content_types = _json_content_type_variants(raw_value)
        elif content_types is None:
            content_types = [("application/json", "stable_events_json_content_type")]
        for content_type, media_strategy in content_types:
            if location == "header" and field.lower() == "content-type":
                selected_variants = [(content_type, media_strategy)]
            elif location == "header":
                selected_variants = _ordinary_header_variants(field, raw_value)
            else:
                selected_variants = [(None, "published_events_json_shape")]
            for selected_value, selected_strategy in selected_variants:
                headers, skipped = _rule_headers(
                    rule, operation, content_type,
                    field if location == "header" else None,
                    selected_value if location == "header" else None,
                )
                if headers is None:
                    requests.append({"skip": skipped, "embedding": selected_strategy})
                    continue
                requests.append({
                    "request": {
                        "method": "POST", "target": "/v1/events",
                        "headers": headers,
                        "body": json.dumps(document, ensure_ascii=False),
                    },
                    "embedding": selected_strategy,
                    "extracted_raw": selected_value if location == "header" else raw_value,
                })
    return requests


def _legal_generated_http_header_semantics(req):
    grouped = {}
    for name, value in req.get("headers", []):
        grouped.setdefault(name.lower(), []).append(value)
    content_types = grouped.get("content-type", [])
    if len(content_types) > 1:
        return "multiple_effective_content_type_headers"
    authorizations = grouped.get("authorization", [])
    if len(authorizations) != 1 or not (
        authorizations[0].startswith("Bearer ") and _token68(authorizations[0][7:])
    ):
        return "unsupported_authorization_header_shape"
    lengths = grouped.get("content-length", [])
    if lengths:
        if len(lengths) != 1 or not lengths[0].isdigit() or str(int(lengths[0])) != lengths[0]:
            return "invalid_content_length_condition"
        try:
            actual = len(req.get("body", "").encode("utf-8", "strict"))
        except (AttributeError, UnicodeError):
            return "invalid_constructed_body_length"
        if int(lengths[0]) != actual:
            return "contradictory_content_length_condition"
    return None


def _independently_parsed_neighbor(req, operation, selector, field, expected_raw):
    header_semantics_error = _legal_generated_http_header_semantics(req)
    if header_semantics_error is not None:
        return None, header_semantics_error
    try:
        parsed = parse_request(req, {"max_fields": 256, "max_json_depth": 32})
    except Exception as exc:
        return None, f"envelope parse failed: {exc}"
    if parsed.parse_error is not None:
        return None, f"body parse failed: {parsed.parse_error}"
    if parsed.method != operation["method"] or parsed.route != operation["route"]:
        return None, "effective operation drifted"
    if operation["name"] == "template-import" and (
        parsed.media_type != "multipart/form-data" or not parsed.multipart
    ):
        return None, "import was not a parsed multipart request"
    if operation["name"] == "opaque-events" and parsed.json_value is None:
        return None, "events request was not parsed JSON"
    key = "pointers" if selector.get("location") == "json" else "names"
    singleton = {"location": selector.get("location"), key: [field]}
    leaf_extracted = extract_values(parsed, singleton)
    if not any(value == expected_raw for value, _, _ in leaf_extracted):
        return None, "targeted legal leaf did not extract the raw hypothesis"
    submitted_extracted = extract_values(parsed, selector)
    if not any(value == expected_raw for value, _, _ in submitted_extracted):
        return None, "submitted selector did not consume the legal active leaf"
    return {
        "success": True,
        "media_type": parsed.media_type,
        "field_count": parsed.field_count,
        "extracted": True,
        "submitted_selector_consumed": True,
    }, None


def rule_directed_neighbor_witnesses(candidate_policy):
    """Schedule every direct predicate witness before bounded secondary variants."""
    rows = []
    provenance = {}
    diagnostics = []

    for rule_index, rule in enumerate(candidate_policy.get("rules", [])):
        if rule.get("action", {}).get("type") != "block":
            continue
        match = rule.get("match", {})
        methods = {method.upper() for method in match.get("methods", [])}
        routes = {canonical_route(route) for route in match.get("routes", [])}
        hypotheses, generator = _predicate_hypotheses(rule.get("predicate", {}))

        for operation in SUPPORTED_NEIGHBOR_OPERATIONS:
            if operation["method"] not in methods or operation["route"] not in routes:
                continue
            primary_hypotheses = [
                item for item in hypotheses if item.get("phase") == "primary"
            ]
            secondary_hypotheses = [
                item for item in hypotheses if item.get("phase") == "secondary"
            ]
            diagnostic = {
                "classification": "bounded_rule_directed_synthesis",
                "reward_fatal": False,
                "rule_index": rule_index,
                "rule_id": rule.get("id"),
                "operation": operation["name"],
                "method": operation["method"],
                "route": operation["route"],
                "predicate_op": rule.get("predicate", {}).get("op"),
                "generator_status": generator.get("status"),
                "generator_reason": generator.get("reason"),
                "unsupported_predicate": generator.get("unsupported", []),
                "candidate_hypotheses": len(hypotheses),
                "primary_hypotheses": len(primary_hypotheses),
                "secondary_hypotheses": len(secondary_hypotheses),
                "confirmed_matching_hypotheses": generator.get(
                    "confirmed_matching_hypotheses",
                    len(hypotheses),
                ),
                "parsed_request_count": 0,
                "primary_shapes_scheduled": [],
                "primary_shapes_without_legal_request": [],
                "primary_dead_proofs": [],
                "primary_witness_complete": None,
                "skip_reasons": {},
                "case_ids": [],
            }
            local_seen_requests = set()

            def skipped(reason):
                diagnostic["skip_reasons"][reason] = (
                    diagnostic["skip_reasons"].get(reason, 0) + 1
                )

            def legal_constructions(hypothesis, hypothesis_index):
                desired = hypothesis["value"]
                for selector_index, selector in enumerate(rule.get("selectors", [])):
                    active_fields = selector_legal_active_fields(selector, operation)
                    if not active_fields:
                        skipped("no_documented_active_selector_for_operation")
                    for field in active_fields:
                        preimages = _raw_preimages(
                            desired, rule.get("transforms", []),
                            rule.get("predicate", {}),
                        )
                        if not preimages:
                            skipped("no_matching_raw_preimage")
                        for raw, raw_strategy, normalized in preimages:
                            built_rows = _neighbor_requests_for_value(
                                rule, operation, selector, field, raw,
                            )
                            if not built_rows:
                                skipped("no_documented_legal_embedding_for_selector")
                            for built in built_rows:
                                if "request" not in built:
                                    skipped(built.get("skip", "construction_failed"))
                                    continue
                                req = built["request"]
                                actual_raw = built.get("extracted_raw", raw)
                                try:
                                    actual_normalized = transform_value(
                                        actual_raw, rule.get("transforms", []),
                                    )
                                except (UnicodeError, ValueError):
                                    skipped("constructed_value_transform_failed")
                                    continue
                                normalized_bytes = _utf8_text_bytes(actual_normalized)
                                if normalized_bytes is None:
                                    skipped("constructed_value_is_not_utf8_text")
                                    continue
                                predicate = rule.get("predicate", {})
                                if not _supported_predicate_matches(
                                    actual_normalized, predicate,
                                ):
                                    skipped("constructed_value_missed_predicate")
                                    continue
                                match_confirmation = "deterministic_supported_semantics"
                                parsed_summary, parse_reason = _independently_parsed_neighbor(
                                    req, operation, selector, field, actual_raw,
                                )
                                if parsed_summary is None:
                                    skipped(parse_reason)
                                    continue
                                serialized = json.dumps(
                                    req, ensure_ascii=False, sort_keys=True,
                                )
                                digest = hashlib.sha256(serialized.encode()).hexdigest()
                                if digest in local_seen_requests:
                                    continue
                                yield {
                                    "request": req,
                                    "digest": digest,
                                    "selector_index": selector_index,
                                    "selector": selector,
                                    "field": field,
                                    "raw_strategy": raw_strategy,
                                    "normalized": actual_normalized,
                                    "normalized_bytes": normalized_bytes,
                                    "actual_raw": actual_raw,
                                    "parsed_summary": parsed_summary,
                                    "built": built,
                                    "hypothesis": hypothesis,
                                    "hypothesis_index": hypothesis_index,
                                    "match_confirmation": match_confirmation,
                                }

            def emit(construction, schedule_phase):
                if len(rows) >= MAX_RULE_DIRECTED_NEIGHBOR_REQUESTS:
                    skipped("global_bounded_request_cap")
                    return False
                local_seen_requests.add(construction["digest"])
                selector = construction["selector"]
                field = construction["field"]
                built = construction["built"]
                hypothesis = construction["hypothesis"]
                case_id = (
                    f"rule-directed-{operation['name']}-r{rule_index:02d}-"
                    f"s{construction['selector_index']:02d}-"
                    f"{field.lower().replace('/', '-').strip('-')}-{len(rows):03d}"
                )
                item_provenance = {
                    "origin": "rule_directed_causal_witness",
                    "rule_index": rule_index,
                    "target_rule_id": rule.get("id"),
                    "operation": operation["name"],
                    "predicate_op": rule.get("predicate", {}).get("op"),
                    "generator_status": generator.get("status"),
                    "selector_index": construction["selector_index"],
                    "selector_location": selector.get("location"),
                    "selector_field": field,
                    "raw_preimage_strategy": construction["raw_strategy"],
                    "request_embedding": built.get("embedding"),
                    "boundary_length": built.get("boundary_length"),
                    "quoted_boundary": built.get("quoted_boundary"),
                    "independent_parse": construction["parsed_summary"],
                    "normalized_length": len(construction["normalized"]),
                    "normalized_utf8_bytes": construction["normalized_bytes"],
                    "desired_hypothesis_index": construction["hypothesis_index"],
                    "hypothesis_shape_ids": hypothesis.get("shape_ids", []),
                    "hypothesis_schedule_phase": schedule_phase,
                    "predicate_match_confirmation": construction["match_confirmation"],
                }
                rows.append((
                    case_id, construction["request"],
                    "rule_directed_neighbor_witness",
                    "neighbor:" + operation["name"],
                ))
                provenance[case_id] = item_provenance
                diagnostic["parsed_request_count"] += 1
                diagnostic["case_ids"].append(case_id)
                if schedule_phase == "primary":
                    diagnostic["primary_shapes_scheduled"].extend(
                        hypothesis.get("shape_ids", [])
                    )
                return True

            # Phase one: find and schedule the first matching, independently parsed legal
            # request for every direct predicate value. No secondary construction
            # or per-operation cap can consume these slots.
            for hypothesis_index, hypothesis in enumerate(primary_hypotheses):
                emitted = False
                for construction in legal_constructions(hypothesis, hypothesis_index):
                    if emit(construction, "primary"):
                        emitted = True
                        break
                if not emitted:
                    diagnostic["primary_shapes_without_legal_request"].extend(
                        hypothesis.get("shape_ids", [])
                    )

            # Phase two: only after all primary shapes were considered, add a very small
            # set of distinct embedding/preimage variants for diagnostic breadth.
            secondary_emitted = 0
            all_secondary_sources = primary_hypotheses + secondary_hypotheses
            for hypothesis_index, hypothesis in enumerate(all_secondary_sources):
                if (
                    secondary_emitted
                    >= MAX_RULE_DIRECTED_SECONDARY_REQUESTS_PER_RULE_OPERATION
                ):
                    break
                for construction in legal_constructions(hypothesis, hypothesis_index):
                    if emit(construction, "secondary"):
                        secondary_emitted += 1
                        break
            diagnostic["primary_shapes_scheduled"] = list(dict.fromkeys(
                diagnostic["primary_shapes_scheduled"]
            ))
            diagnostic["primary_shapes_without_legal_request"] = list(dict.fromkeys(
                diagnostic["primary_shapes_without_legal_request"]
            ))
            if rule.get("predicate", {}).get("op") in {"equals", "contains"}:
                missing = diagnostic["primary_shapes_without_legal_request"]
                hard_dead_reason_names = {
                    "no_documented_active_selector_for_operation",
                    "unsatisfied_singleton_content_type_conditions",
                    "unsatisfied_operation_content_type_condition",
                    "illegal_header_condition",
                }
                observed_skip_reasons = set(diagnostic["skip_reasons"])
                all_construction_dispositions_are_hard_dead = (
                    bool(observed_skip_reasons)
                    and observed_skip_reasons <= hard_dead_reason_names
                )
                predicate = rule.get("predicate", {})
                direct_content_type_equals_dead = False
                if predicate.get("op") == "equals":
                    target = predicate.get("value", "")
                    try:
                        normalized_target = transform_value(
                            target, rule.get("transforms", []),
                        )
                    except (UnicodeError, ValueError):
                        normalized_target = None
                    active_selected_fields = [
                        (selector.get("location"), field.lower())
                        for selector in rule.get("selectors", [])
                        for field in selector_legal_active_fields(selector, operation)
                    ]
                    selects_only_content_type = (
                        bool(active_selected_fields)
                        and all(
                            location == "header" and field == "content-type"
                            for location, field in active_selected_fields
                        )
                    )
                    if selects_only_content_type and normalized_target is not None:
                        if operation["name"] == "template-import":
                            direct_content_type_equals_dead = (
                                _multipart_header_boundary(normalized_target) is None
                            )
                        elif operation["name"] == "opaque-events":
                            direct_content_type_equals_dead = (
                                _json_content_type(normalized_target) is None
                            )
                if missing and (
                    all_construction_dispositions_are_hard_dead
                    or direct_content_type_equals_dead
                ):
                    diagnostic["primary_dead_proofs"].append({
                        "shape_ids": missing,
                        "classification": "proven_dead_for_documented_operation",
                        "reason": (
                            "documented selector/header/media invariants prove that no "
                            "legal request for this operation can carry the direct "
                            "comparison witness"
                        ),
                        "exhaustive_skip_reasons": dict(diagnostic["skip_reasons"]),
                        "direct_content_type_equals_dead": (
                            direct_content_type_equals_dead
                        ),
                    })
                diagnostic["primary_witness_complete"] = (
                    not missing or bool(diagnostic["primary_dead_proofs"])
                )
            diagnostics.append(diagnostic)
    return rows, provenance, diagnostics


def systematic_multipart_grammar_controls():
    """Small explicit endpoint/morphology bank; rule synthesis remains the primary defense."""
    shapes = [
        ("unquoted-lower-1", "a", False),
        ("unquoted-upper-1", "Z", False),
        ("unquoted-digit-1", "7", False),
        ("unquoted-lower-70", "a" * 70, False),
        ("unquoted-upper-70", "Z" * 70, False),
        ("unquoted-digit-70", "7" * 70, False),
        ("unquoted-hyphen-70", "a" + "-" * 68 + "z", False),
        ("unquoted-mixed-70", ("aZ7-_" * 14)[:70], False),
        ("quoted-punctuation-1", "?", True),
        ("quoted-punctuation-70", ("?/:=(),.'+_-" * 6)[:70], True),
        ("quoted-space-mixed-70", ("a Z7-?/:=()_" * 6)[:70], True),
        ("quoted-lower-70", "m" * 70, True),
    ]
    rows = []
    issues = []
    for index, (label, boundary, quoted) in enumerate(shapes):
        if not _legal_boundary(boundary) or len(boundary) not in {1, 70}:
            issues.append(f"{label}: bank boundary is not a legal endpoint")
            continue
        rendered = f'"{boundary}"' if quoted else boundary
        content_type = f"multipart/form-data; boundary={rendered}"
        body, _ = multipart(
            [("filename", "grammar.tpl"), ("template", "ordinary grammar content")],
            boundary,
        )
        req = request(
            "POST", "/v1/templates/import", body,
            headers=[["Content-Type", content_type]],
            rid=f"multipart-grammar-{index:02d}",
        )
        parsed = parse_request(req, {"max_fields": 256, "max_json_depth": 32})
        if (
            parsed.parse_error is not None or parsed.media_type != "multipart/form-data"
            or len(parsed.multipart) != 2
        ):
            issues.append(f"{label}: independently parsed multipart fixture failed")
            continue
        rows.append((
            "multipart-grammar-" + label, req,
            "route_scope_import_systematic_multipart_grammar", "unrelated",
        ))
    return rows, issues, shapes


def varied_route(route, label):
    variants = {
        "/v1/render": ["/v1/render", "/v1/%72ender/", "/v1/slot/../render//"],
        "/v1/render/batch": ["/v1/render/batch", "/v1/render/stage/../batch//"],
        "/v1/templates/validate": ["/v1/templates/validate", "/v1/templates/%76alidate/", "/v1/templates/check/../validate//"],
    }[route]
    index = int(hashlib.sha256(label.encode()).hexdigest()[:8], 16) % len(variants)
    return variants[index]


def carrier_request(carrier, value, label, *, media_type=None, integration_mode="LeGaCy"):
    """Carry exactly ``value`` into the adapter after media parsing."""
    target = varied_route(carrier["route"], label)
    source = carrier["source"]
    field = carrier["field"]
    rid = "ctx-" + hashlib.sha256(label.encode()).hexdigest()[:16]
    if source == "query":
        return request(carrier["method"], target + "?" + field + "=" + percent_all(value), rid=rid)
    if source == "form":
        return request(
            carrier["method"], target, field + "=" + percent_all(value),
            "application/x-www-form-urlencoded; charset=UTF-8", rid=rid,
        )
    if source == "header":
        return request(carrier["method"], target, headers=[
            ["X-Integration-Mode", integration_mode], ["x-LEGACY-template", value],
        ], rid=rid)
    if source == "multipart":
        boundary = "ctx-" + hashlib.sha256(label.encode()).hexdigest()[:12]
        body, content_type = multipart([("note", "ordinary"), (field, value)], boundary)
        return request(carrier["method"], target, body, content_type, rid=rid)
    if carrier["route"] == "/v1/render/batch":
        job = ({"template": value} if field.endswith("/template") and "/options/" not in field
               else {"options": {"template": value}})
        return request(
            carrier["method"], target, json.dumps({"jobs": [job]}, ensure_ascii=False),
            media_type or "application/batch+json; charset=utf-8", rid=rid,
        )
    if field == "/template":
        body = {"template": value}
    elif field == "/options/template":
        body = {"options": {"template": value}}
    elif field == "/locator":
        body = {"locator": value}
    else:
        raise AssertionError(f"unhandled JSON carrier {carrier}")
    return request(
        carrier["method"], target, json.dumps(body, ensure_ascii=False),
        media_type or "application/vnd.northstar+json; charset=utf-8", rid=rid,
    )


def outside_after(value, transforms):
    return locator_outside(transform_value(value, transforms), ["asset"])


def witness_bank(label):
    token = generated_segment(label)
    seeds = [
        "../../" + token,
        "/" + token,
        "file:/" + token,
        "．．／" + token,
        "root＼..＼..＼" + token,
        "　/" + token + "　",
        "%2E%2E%2F" + token,
        "%5C..%5C..%5C" + token,
        "%20%2F" + token + "%20",
        "%EF%BC%8E%EF%BC%8E%EF%BC%8F" + token,
    ]
    values = set(seeds)
    for seed in seeds:
        value = seed
        for _ in range(4):
            value = percent_all(value)
            values.add(value)
        for wrapper in (" ", "　", "%20", "%E3%80%80"):
            values.add(wrapper + seed + wrapper)
    return sorted(values, key=lambda item: (len(item), item))


def substitution_witness(actual_profile, substitute_profile, label):
    actual = BACKEND_CONTEXT_PIPELINES[actual_profile]
    substitute = BACKEND_CONTEXT_PIPELINES[substitute_profile]
    for value in witness_bank(label):
        try:
            if outside_after(value, actual) != outside_after(value, substitute):
                return value
        except (UnicodeError, ValueError):
            continue
    raise AssertionError(f"no causal witness for {actual_profile} versus {substitute_profile}")


attacks = []
benign = []
legacy_controls = []
fixture_issues = []
published_capture_rows = []
published_capture_source = None
published_capture_rejected_candidates = []
try:
    (
        published_capture_rows,
        published_capture_source,
        published_capture_rejected_candidates,
    ) = load_published_capture()
except Exception as exc:
    fixture_issues.append(f"published representative capture: {exc}")
sensitive_tokens = set()
context_substitution_cases = 0
batch_index_context_cases = 0
batch_index_decode_cases = 0
batch_index_context_matrix = {}
audit_attribution = {}
carrier_by_name = {carrier["name"]: carrier for carrier in CARRIERS}


def carrier_attribution(carrier, batch_index=0):
    source, field = carrier["source"], carrier["field"]
    expected = {(source, field)}
    if source == "header":
        expected.add((source, field.lower()))
    if carrier["route"] == "/v1/render/batch":
        expected.add((source, field.replace("*", str(batch_index))))
    return expected


def remember_label(label):
    sensitive_tokens.add(generated_segment(label))
    sensitive_tokens.add(generated_segment(label + "-tail"))


def register_model_case(case_id, carrier, value, family, expected_outcome=None, **request_options):
    """Classify a carrier/value pair only through the independent frozen model."""
    remember_label(case_id)
    sensitive_tokens.update(re.findall(r"g[0-9a-f]{13}", value))
    req = carrier_request(carrier, value, case_id, **request_options)
    observed = legacy_assess(req)
    expected_pipeline = backend_pipeline(
        (carrier["method"], carrier["route"]), carrier["source"], carrier["field"],
    )
    expected_normalized = None
    try:
        expected_normalized = transform_value(value, expected_pipeline)
    except Exception as exc:
        fixture_issues.append(f"{case_id}: private transform unexpectedly failed: {exc}")
    locators = observed.get("locators", [])
    if len(locators) != 1 or locators[0].get("normalized") != expected_normalized:
        fixture_issues.append(f"{case_id}: carrier did not reach the intended adapter value")
    outcome = observed.get("outcome")
    if expected_outcome is not None and outcome != expected_outcome:
        fixture_issues.append(
            f"{case_id}: expected literal model outcome {expected_outcome!r}, got {outcome!r}"
        )
    row = (case_id, req, family, carrier["name"])
    if outcome == "outside_template_root":
        attacks.append(row)
        audit_attribution[case_id] = carrier_attribution(carrier)
    elif outcome == "rendered_within_root":
        benign.append(row)
    else:
        fixture_issues.append(f"{case_id}: unexpected legacy outcome {outcome!r}")
    legacy_controls.append((case_id, outcome, expected_normalized, carrier["profile"]))


# Every carrier gets ordinary malicious/safe, scheme, exact decode-depth, feature-order,
# and directed profile-substitution controls.  The same value can legitimately fall on
# opposite sides in different contexts; that is the capability being measured.
for carrier in CARRIERS:
    cname = carrier["name"]
    profile = carrier["profile"]
    pipeline = BACKEND_CONTEXT_PIPELINES[profile]
    decodes = pipeline.count("percent_decode")
    register_model_case(f"direct-bad-{cname}", carrier, outside_value("direct-bad-" + cname), "direct_boundary")
    register_model_case(f"direct-safe-{cname}", carrier, inside_value("direct-safe-" + cname), "within_root")
    register_model_case(f"scheme-bad-{cname}", carrier, "file:remote/" + generated_segment("scheme-bad-" + cname), "scheme_matrix")
    register_model_case(f"scheme-safe-{cname}", carrier, "AsSeT:" + inside_value("scheme-safe-" + cname), "allowed_scheme")

    # The complete published root boundary is exercised independently for every carrier.
    # Hash-derived schemes prevent a policy from keying only on familiar protocol names.
    for scheme_index, scheme in enumerate([
        "hTtP", generated_scheme(cname, 0), generated_scheme(cname, 1),
        generated_scheme(cname, 2),
    ]):
        label = f"boundary-scheme-{scheme_index}-{cname}"
        register_model_case(
            label, carrier, f"{scheme}:remote/{generated_segment(label)}",
            "boundary_unsupported_scheme", expected_outcome="outside_template_root",
        )
    drive_values = [
        "C:/Windows/" + generated_segment("drive-slash-" + cname),
        "z:\\Temp\\" + generated_segment("drive-backslash-" + cname),
        "c:\\Mixed/" + generated_segment("drive-mixed-" + cname),
        "AsSeT:D:/Windows/" + generated_segment("drive-asset-slash-" + cname),
        "asset:q:\\Temp\\" + generated_segment("drive-asset-backslash-" + cname),
    ]
    for drive_index, value in enumerate(drive_values):
        register_model_case(
            f"boundary-drive-{drive_index}-{cname}", carrier, value,
            "boundary_windows_drive", expected_outcome="outside_template_root",
        )
    unc_values = [
        "//srv-" + generated_segment("unc-slash-" + cname) + "/share/base",
        "\\\\srv-" + generated_segment("unc-backslash-" + cname) + "\\share\\base",
    ]
    for unc_index, value in enumerate(unc_values):
        register_model_case(
            f"boundary-unc-{unc_index}-{cname}", carrier, value,
            "boundary_unc_absolute", expected_outcome="outside_template_root",
        )
    nul_values = [
        "team/base\x00/" + generated_segment("nul-mid-" + cname),
        "asset:shared/" + generated_segment("nul-scheme-" + cname) + "\x00tail",
    ]
    for nul_index, value in enumerate(nul_values):
        register_model_case(
            f"boundary-nul-{nul_index}-{cname}", carrier, value,
            "boundary_embedded_nul", expected_outcome="outside_template_root",
        )
    for depth in (0, 1, 2, 4):
        prefix = "/".join(chr(ord("a") + index) for index in range(depth))
        bad = ((prefix + "/") if prefix else "") + "../" * (depth + 1) + generated_segment(
            f"underflow-{depth}-{cname}"
        )
        register_model_case(
            f"boundary-underflow-{depth}-{cname}", carrier, bad,
            "boundary_dot_underflow", expected_outcome="outside_template_root",
        )
    for depth in (1, 2, 3, 4):
        prefix = "/".join(chr(ord("a") + index) for index in range(depth))
        balanced = prefix + "/" + "../" * depth + "base/" + generated_segment(
            f"balanced-{depth}-{cname}"
        )
        register_model_case(
            f"boundary-balanced-{depth}-{cname}", carrier, balanced,
            "boundary_balanced_safe", expected_outcome="rendered_within_root",
        )

    register_model_case(
        f"decode-exact-{cname}", carrier,
        encoded(outside_value("decode-exact-" + cname), decodes),
        "context_decode_attack_" + profile,
    )
    register_model_case(
        f"decode-boundary-{cname}", carrier,
        encoded(outside_value("decode-boundary-" + cname), decodes + 1),
        "context_overdecode_boundary_" + profile,
    )

    token = generated_segment("features-" + cname)
    features = [
        ("encoded-unicode", percent_all("．．／" + token)),
        ("unicode-separator", "root＼..＼..＼" + token),
        ("encoded-unicode-separator", percent_all("root＼..＼..＼" + token)),
        ("compatibility-space", "　/" + token + "　"),
        ("encoded-compatibility-space", percent_all("　/" + token + "　")),
        ("encoded-ascii-space", "%20%2F" + token + "%20"),
        ("encoded-backslash", "%5C..%5C..%5C" + token),
    ]
    for feature_name, value in features:
        register_model_case(
            f"order-{feature_name}-{cname}", carrier, value,
            "context_order_" + feature_name,
        )

    for substitute_profile in sorted(BACKEND_CONTEXT_PIPELINES):
        if substitute_profile == profile:
            continue
        case_id = f"substitute-{profile}-with-{substitute_profile}-{cname}"
        value = substitution_witness(profile, substitute_profile, case_id)
        assert outside_after(value, pipeline) != outside_after(
            value, BACKEND_CONTEXT_PIPELINES[substitute_profile],
        )
        register_model_case(
            case_id, carrier, value,
            "context_substitution_" + profile + "_vs_" + substitute_profile,
        )
        context_substitution_cases += 1


# A bounded rule set cannot substitute enumeration for the documented case-insensitive
# integration mode.  The order is hash-derived while the three named controls stay explicit.
integration_carrier = carrier_by_name["integration-header"]
for mode_index, mode in enumerate(integration_case_variants()):
    label = f"integration-case-{mode_index:02d}-{mode}"
    register_model_case(
        label, integration_carrier, outside_value(label),
        "integration_case_insensitive", expected_outcome="outside_template_root",
        integration_mode=mode,
    )
for mode_index, mode in enumerate([
    "modern", "legacy ", " legacy", "legacy-v2", "xlegacy", "legacx",
    "compat-" + hashlib.sha256(b"northstar-ignored-mode").hexdigest()[:10],
]):
    label = f"integration-ignored-{mode_index:02d}"
    req = carrier_request(
        integration_carrier, outside_value(label), label, integration_mode=mode,
    )
    if legacy_assess(req).get("outcome") != "application_validation_error":
        fixture_issues.append(f"{label}: ignored integration mode unexpectedly consumed the header")
    benign.append((label, req, "integration_ignored_mode", integration_carrier["name"]))


# JSON suffix media are a syntax family, not an allowlist.  Every protected JSON pointer
# gets valid malicious and benign bodies under standard and hash-derived +json types.
json_carriers = [carrier for carrier in CARRIERS if carrier["source"] == "json"]
assert len(json_carriers) == 5
for carrier in json_carriers:
    for media_index, media_type in enumerate(suffix_media_types(carrier["name"])):
        bad_label = f"json-suffix-bad-{media_index}-{carrier['name']}"
        safe_label = f"json-suffix-safe-{media_index}-{carrier['name']}"
        register_model_case(
            bad_label, carrier, outside_value(bad_label), "json_suffix_media_attack",
            expected_outcome="outside_template_root", media_type=media_type,
        )
        register_model_case(
            safe_label, carrier, "a/b/../../base/" + generated_segment(safe_label),
            "json_suffix_media_safe", expected_outcome="rendered_within_root",
            media_type=media_type,
        )


# Manual ambiguity cases contain a malicious occurrence.  The application rejects the
# overall shape, but the edge must block before a convenient safe occurrence can hide the
# outside locator.  Every documented carrier gets a repeated-occurrence control.
def manual_attack(case_id, req, family, carrier, expected_attribution=None):
    attacks.append((case_id, req, family, carrier))
    sensitive_tokens.update(re.findall(r"g[0-9a-f]{13}", json.dumps(req, ensure_ascii=False)))
    if expected_attribution is not None:
        audit_attribution[case_id] = set(expected_attribution)
    elif carrier in carrier_by_name:
        audit_attribution[case_id] = carrier_attribution(carrier_by_name[carrier])
    else:
        raise AssertionError(f"manual attack {case_id} lacks audit attribution")


def duplicate_carrier_request(carrier, safe, bad, label):
    rid = "dup-" + hashlib.sha256(label.encode()).hexdigest()[:12]
    route = carrier["route"]
    source, field = carrier["source"], carrier["field"]
    if source == "query":
        target = route + "?" + field + "=" + percent_all(safe) + "&" + field + "=" + percent_all(bad)
        return request(carrier["method"], target, rid=rid)
    if source == "form":
        body = field + "=" + percent_all(safe) + "&" + field + "=" + percent_all(bad)
        return request(carrier["method"], route, body, "application/x-www-form-urlencoded", rid=rid)
    if source == "header":
        return request(carrier["method"], route, headers=[
            ["X-Integration-Mode", "legacy"], ["X-Legacy-Template", safe],
            ["X-Legacy-Template", bad],
        ], rid=rid)
    if source == "multipart":
        body, content_type = multipart([(field, safe), (field, bad)], "duplicate-multipart")
        return request(carrier["method"], route, body, content_type, rid=rid)

    safe_json, bad_json = json.dumps(safe, ensure_ascii=False), json.dumps(bad, ensure_ascii=False)
    if route == "/v1/render/batch":
        if "/options/" in field:
            body = '{"jobs":[{"options":{"template":' + safe_json + ',"template":' + bad_json + '}}]}'
        else:
            body = '{"jobs":[{"template":' + safe_json + ',"template":' + bad_json + '}]}'
    elif field == "/options/template":
        body = '{"options":{"template":' + safe_json + ',"template":' + bad_json + '}}'
    elif field == "/template":
        body = '{"template":' + safe_json + ',"template":' + bad_json + '}'
    elif field == "/locator":
        body = '{"locator":' + safe_json + ',"locator":' + bad_json + '}'
    else:
        raise AssertionError(carrier)
    return request(carrier["method"], route, body, "application/json", rid=rid)


for carrier in CARRIERS:
    case_id = "duplicate-carrier-" + carrier["name"]
    bad = outside_value(case_id)
    sensitive_tokens.update(re.findall(r"g[0-9a-f]{13}", bad))
    duplicate_req = duplicate_carrier_request(carrier, "asset:shared/base", bad, case_id)
    observed = legacy_assess(duplicate_req)
    if observed.get("outcome") != "application_validation_error":
        fixture_issues.append(f"{case_id}: duplicate fixture was not application-invalid")
    manual_attack(case_id, duplicate_req, "duplicates_all_carriers", carrier["name"])

bad = outside_value("duplicate-cross-carrier")
manual_attack(
    "duplicate-cross-carrier",
    request("POST", "/v1/render?view=shared%2Fbase", json.dumps({"template": bad}),
            "application/json", rid="dup-cross"),
    "duplicates_cross_carrier", "json-template",
)

# When multiple consumed carriers are independently unsafe, either precise attribution is
# useful.  An unrelated malicious-looking decoy, however, is never acceptable attribution.
query_bad = outside_value("ambiguous-query-bad")
json_bad = outside_value("ambiguous-json-bad")
manual_attack(
    "ambiguous-two-unsafe-carriers",
    request(
        "POST", "/v1/render?template=" + percent_all(query_bad),
        json.dumps({"template": json_bad}), "application/json", rid="ambiguous-two-bad",
    ),
    "duplicates_cross_carrier", "multi-carrier",
    {("query", "template"), ("json", "/template")},
)
decoy_bad = outside_value("audit-decoy")
actual_bad = outside_value("audit-actual")
manual_attack(
    "audit-decoy-misattribution",
    request(
        "POST", "/v1/render?diagnostic=" + percent_all(decoy_bad),
        json.dumps({"template": actual_bad}), "application/json", rid="audit-decoy",
    ),
    "audit_attribution_decoy", "json-template",
    {("json", "/template")},
)


def batch_envelope(jobs, label):
    return request(
        "POST", varied_route("/v1/render/batch", label),
        json.dumps({"jobs": jobs}, ensure_ascii=False),
        "application/batch+json; charset=utf-8",
        rid="batch-" + hashlib.sha256(label.encode()).hexdigest()[:14],
    )


def safe_batch_job(index):
    value = "a/b/../../base/" + generated_segment(f"batch-safe-{index}")
    return ({"template": value} if index % 2 == 0
            else {"options": {"template": value}})


# Preserve the original late-member counterexamples verbatim.  They ensure that a policy
# which only examines job zero cannot pass by relying on a convenient leading member.
for carrier_name in ("batch-template", "batch-options"):
    carrier = carrier_by_name[carrier_name]
    for late_index in (1, 4, 9, 15):
        label = f"batch-late-{late_index:02d}-{carrier_name}"
        jobs = [safe_batch_job(index) for index in range(late_index + 1)]
        bad_value = outside_value(label)
        jobs[late_index] = (
            {"template": bad_value} if carrier_name == "batch-template"
            else {"options": {"template": bad_value}}
        )
        req = batch_envelope(jobs, label)
        if legacy_assess(req).get("outcome") != "outside_template_root":
            fixture_issues.append(f"{label}: late batch locator did not reach the resolver")
        wildcard = carrier["field"]
        manual_attack(
            label, req, "batch_late_member", carrier_name,
            {("json", wildcard), ("json", wildcard.replace("*", str(late_index)))},
        )

# Behavioral wildcard coverage: each documented pointer shape is malicious at every
# supported position, with all fifteen neighboring jobs remaining safe and mixed between
# the two legitimate shapes.  This rejects finite enumeration of previously sampled
# positions without requiring the submitted policy to use the literal '*' spelling.
for carrier_name in ("batch-template", "batch-options"):
    carrier = carrier_by_name[carrier_name]
    wildcard = carrier["field"]
    for batch_index in range(16):
        label = f"batch-index-{batch_index:02d}-{carrier_name}"
        jobs = [safe_batch_job(index) for index in range(16)]
        bad_value = outside_value(label)
        jobs[batch_index] = (
            {"template": bad_value} if carrier_name == "batch-template"
            else {"options": {"template": bad_value}}
        )
        req = batch_envelope(jobs, label)
        if legacy_assess(req).get("outcome") != "outside_template_root":
            fixture_issues.append(f"{label}: indexed batch locator did not reach the resolver")
        manual_attack(
            label, req, "batch_all_positions", carrier_name,
            {("json", wildcard), ("json", wildcard.replace("*", str(batch_index)))},
        )

# Position coverage alone is not context coverage.  Repeat the directed batch-profile
# substitution bank at every supported index, inside a full mixed 16-job envelope.  For
# each position the bank contains both a malicious value that an under-normalizing
# substitute misses and a safe over-normalization neighbor that another profile denies.
# This defeats policies that use the recovered batch pipeline only for job zero and raw
# traversal rules (or empty transforms) for the remaining explicit pointers.
batch_pipeline = BACKEND_CONTEXT_PIPELINES["batch_dispatch"]
for carrier_name in ("batch-template", "batch-options"):
    carrier = carrier_by_name[carrier_name]
    wildcard = carrier["field"]
    for batch_index in range(16):
        matrix_key = f"{batch_index:02d}:{carrier_name}"
        matrix_counts = {
            "attack": 0,
            "safe_neighbor": 0,
            "encoded_attack": 0,
            "exact_decode_attack": 0,
            "overdecode_safe": 0,
        }
        batch_index_context_matrix[matrix_key] = matrix_counts

        # Two layers are consumed by the real batch adapter; a third layer is the
        # neighboring value that an over-decoding policy must not reject.
        for depth, expected_outside, direction, family in (
            (2, True, "exact-decode-attack", "batch_index_exact_decode_attack"),
            (3, False, "overdecode-safe", "batch_index_overdecode_safe"),
        ):
            case_id = (
                f"batch-context-{direction}-{batch_index:02d}-{carrier_name}"
            )
            value = encoded(outside_value(case_id), depth)
            actual_outside = outside_after(value, batch_pipeline)
            if actual_outside is not expected_outside:
                fixture_issues.append(
                    f"{case_id}: exact batch decode-depth control has the wrong model side"
                )
            remember_label(case_id)
            sensitive_tokens.update(re.findall(r"g[0-9a-f]{13}", value))
            jobs = [safe_batch_job(index) for index in range(16)]
            jobs[batch_index] = (
                {"template": value} if carrier_name == "batch-template"
                else {"options": {"template": value}}
            )
            req = batch_envelope(jobs, case_id)
            expected_outcome = (
                "outside_template_root" if expected_outside else "rendered_within_root"
            )
            if legacy_assess(req).get("outcome") != expected_outcome:
                fixture_issues.append(
                    f"{case_id}: indexed decode-depth control did not preserve its outcome"
                )
            if expected_outside:
                manual_attack(
                    case_id, req, family, carrier_name,
                    {
                        ("json", wildcard),
                        ("json", wildcard.replace("*", str(batch_index))),
                    },
                )
                matrix_counts["exact_decode_attack"] += 1
            else:
                benign.append((case_id, req, family, carrier_name))
                matrix_counts["overdecode_safe"] += 1
            batch_index_decode_cases += 1

        for substitute_profile in sorted(BACKEND_CONTEXT_PIPELINES):
            if substitute_profile == "batch_dispatch":
                continue
            witness_label = (
                f"batch-index-context-{batch_index:02d}-{carrier_name}-"
                f"vs-{substitute_profile}"
            )
            value = substitution_witness(
                "batch_dispatch", substitute_profile, witness_label,
            )
            actual_outside = outside_after(value, batch_pipeline)
            substitute_outside = outside_after(
                value, BACKEND_CONTEXT_PIPELINES[substitute_profile],
            )
            if actual_outside == substitute_outside:
                fixture_issues.append(
                    f"{witness_label}: batch/substitute witness is not causal"
                )
                continue

            direction = "attack" if actual_outside else "safe-neighbor"
            case_id = (
                f"batch-context-{direction}-{batch_index:02d}-{carrier_name}-"
                f"vs-{substitute_profile}"
            )
            remember_label(case_id)
            sensitive_tokens.update(re.findall(r"g[0-9a-f]{13}", value))
            jobs = [safe_batch_job(index) for index in range(16)]
            jobs[batch_index] = (
                {"template": value} if carrier_name == "batch-template"
                else {"options": {"template": value}}
            )
            req = batch_envelope(jobs, case_id)
            expected_outcome = (
                "outside_template_root" if actual_outside else "rendered_within_root"
            )
            if legacy_assess(req).get("outcome") != expected_outcome:
                fixture_issues.append(
                    f"{case_id}: indexed context witness did not preserve its modeled outcome"
                )
            family = (
                "batch_index_context_substitution_batch_dispatch_vs_"
                + substitute_profile
            )
            if actual_outside:
                manual_attack(
                    case_id, req, family, carrier_name,
                    {
                        ("json", wildcard),
                        ("json", wildcard.replace("*", str(batch_index))),
                    },
                )
                matrix_counts["attack"] += 1
                if "%" in value:
                    matrix_counts["encoded_attack"] += 1
            else:
                benign.append((case_id, req, family, carrier_name))
                matrix_counts["safe_neighbor"] += 1
            batch_index_context_cases += 1

# Mixed template/options jobs at several late boundaries are compatibility controls.
for size in (2, 7, 16):
    label = f"batch-mixed-safe-{size:02d}"
    req = batch_envelope([safe_batch_job(index) for index in range(size)], label)
    if legacy_assess(req).get("outcome") != "rendered_within_root":
        fixture_issues.append(f"{label}: mixed safe batch was not within root")
    benign.append((label, req, "batch_mixed_late_safe", "batch-mixed"))


# Neighboring routes, methods, look-alike fields, and maximum supported batch shape are
# compatibility controls independent of normalization profiles.
def manual_allow(case_id, req, family, carrier="unrelated"):
    benign.append((case_id, req, family, carrier))


(
    systematic_multipart_cases,
    systematic_multipart_issues,
    systematic_multipart_shapes,
) = systematic_multipart_grammar_controls()
benign.extend(systematic_multipart_cases)
fixture_issues.extend(systematic_multipart_issues)


# This is the exact request published both as traffic/safe-import.json and as the
# representative.jsonl b-import-lookalike row.  Keep both provenance labels in the replay
# accounting so a future fixture edit cannot silently remove either compatibility promise.
published_import_lookalike = {
    "method": "POST",
    "target": "/v1/templates/import",
    "headers": [
        ["Authorization", "Bearer lab-user"],
        ["X-Request-ID", "req-015"],
        ["Content-Type", "multipart/form-data; boundary=northstar-demo"],
    ],
    "body": (
        "--northstar-demo\r\n"
        "Content-Disposition: form-data; name=\"filename\"\r\n\r\n"
        "../../quarter.tpl\r\n"
        "--northstar-demo\r\n"
        "Content-Disposition: form-data; name=\"template\"\r\n\r\n"
        "Hello {{ ../../customer.name }}\r\n"
        "--northstar-demo--\r\n"
    ),
}
manual_allow(
    "published-safe-import-json", published_import_lookalike,
    "route_scope_import_published", "unrelated",
)
manual_allow(
    "published-representative-b-import-lookalike", published_import_lookalike,
    "route_scope_import_published", "unrelated",
)

imp, imp_ct = multipart(
    [("filename", "../../archive.tpl"), ("template", "Hello {{ ../../customer.name }}")],
    "safe-import",
)
manual_allow("neighbor-import", request("POST", "/v1/templates/import", imp, imp_ct, rid="neighbor-import"), "route_scope")

# Conventional browser multipart syntax is an executable witness for the semantic import
# grammar.  This concrete legal request makes the ``boundary=-{4}`` predicate's effective
# denial directly observable; structural scope alone is never reward-fatal.
webkit_boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
webkit_body, webkit_content_type = multipart(
    [("filename", "quarter.tpl"), ("template", "ordinary browser upload")],
    webkit_boundary,
)
manual_allow(
    "neighbor-import-webkit-boundary",
    request(
        "POST", "/v1/templates/import", webkit_body, webkit_content_type,
        rid="neighbor-import-webkit",
    ),
    "route_scope_import_webkit_grammar",
)
manual_allow("neighbor-search", request("GET", "/v1/search?template=../../archive&q=..%2F..%2F", rid="neighbor-search"), "route_scope")
manual_allow("neighbor-events", request("POST", "/v1/events", json.dumps({"template": "../../literal", "jobs": [{"template": "file:/literal"}]}), "application/json", headers=[["X-Event-Note", "../../opaque"]], rid="neighbor-events"), "route_scope")
manual_allow("neighbor-method", request("PUT", "/v1/render", json.dumps({"template": "../../literal"}), "application/json", rid="neighbor-method"), "method_scope")
manual_allow("neighbor-encoded-slash", request("POST", "/v1%2Frender", json.dumps({"template": "../../literal"}), "application/json", rid="neighbor-slash"), "route_scope")
manual_allow("ignored-integration-header", request("POST", "/v1/render", json.dumps({"template": "shared/base"}), "application/json", headers=[["X-Integration-Mode", "modern"], ["X-Legacy-Template", "../../ignored"]], rid="ignored-header"), "header_scope", "integration-header")
manual_allow("lookalike-interactive-jobs", request("POST", "/v1/render", json.dumps({"template": "shared/a", "jobs": [{"template": "../../literal"}]}), "application/json", rid="lookalike-i"), "request_shape")
manual_allow("lookalike-validation-options", request("PUT", "/v1/templates/validate", json.dumps({"locator": "shared/a", "options": {"template": "../../literal"}}), "application/json", rid="lookalike-v"), "request_shape")
manual_allow("batch-maximum", request("POST", "/v1/render/batch", json.dumps({"jobs": [{"template": f"teams/t{i}/../shared/base"} for i in range(16)]}), "application/batch+json", rid="batch-max"), "batch_capacity", "batch-template")

malformed = [
    ("malformed-json", request("POST", "/v1/render", '{"template":', "application/json", rid="mal-json"), "parse"),
    ("malformed-vendor-json", request("POST", "/v1/render/batch", '{"jobs":', "application/problem+json", rid="mal-batch"), "parse"),
    ("malformed-percent", request("PUT", "/v1/templates/validate?locator=%2525GG", rid="mal-percent"), "decode"),
    ("malformed-form-percent", request("POST", "/v1/render", "template=%2525QZ", "application/x-www-form-urlencoded", rid="mal-form"), "decode"),
]


def submitted_extra_scheme_attacks(policy):
    extras = set()
    for rule in policy.get("rules", []):
        predicate = rule.get("predicate", {})
        if predicate.get("op") != "locator_outside":
            continue
        for candidate in predicate.get("allowed_schemes", []):
            # Public validation has already admitted only canonical ASCII URI-scheme
            # spellings. Generate from the effective case-insensitive name rather than
            # filtering the submitter's original spelling a second time.
            canonical = candidate.lower()
            if canonical != "asset":
                extras.add(canonical)
    cases = []
    for scheme in sorted(extras):
        digest = hashlib.sha256(("submitted-extra-scheme:" + scheme).encode()).hexdigest()[:12]
        for carrier in CARRIERS:
            value = f"{scheme}:remote/{generated_segment(digest + '-' + carrier['name'])}"
            case_id = f"extra-{digest}-{carrier['name']}"
            req = carrier_request(carrier, value, case_id)
            audit_attribution[case_id] = carrier_attribution(carrier)
            cases.append((case_id, req, "submitted_scheme_matrix", carrier["name"]))
    return cases


errors = []
total_error_count = 0
error_counts_by_area = {}
checks = {}
category_counts = {}
attack_attempted_ids = set()
benign_attempted_ids = set()
attack_outcomes = {}
benign_outcomes = {}
max_work = 0
max_benign_elapsed = 0.0
primary_corpus_seconds = 0.0
attack_evaluated_cases = 0
benign_evaluated_cases = 0
full_benign_replay_seconds = 0.0
full_benign_replay_cases = 0
full_benign_replay_completed_cases = 0
malformed_evaluated_cases = 0
malformed_corpus_seconds = 0.0
capacity_completed_cases = 0
capacity_total_cases = 0
capacity_import_fixture_parsed = False
policy = {}
submitted_policy_bytes = b""
dynamic_scheme_cases = []
policy_dependent_import_cases = []
rule_directed_neighbor_cases = []
rule_directed_neighbor_provenance = {}
rule_directed_neighbor_synthesis = []
rule_directed_neighbor_outcomes = []
neighbor_non_interference_advisory_findings = []
neighbor_non_interference_causal_violations = []
published_capture_accounting = {
    "expected_rows": len(PUBLISHED_CAPTURE_EXPECTATIONS),
    "loaded_rows": len(published_capture_rows),
    "source": published_capture_source,
    "sha256": PUBLISHED_CAPTURE_SHA256,
    "rejected_mutable_candidates": published_capture_rejected_candidates,
    "primary": {"attempted": 0, "completed": 0, "matched": 0},
    "complete": {"attempted": 0, "completed": 0, "matched": 0},
}


def fail(area, message):
    global total_error_count
    total_error_count += 1
    error_counts_by_area[area] = error_counts_by_area.get(area, 0) + 1
    checks[area] = False
    if len(errors) < 120:
        errors.append(f"{area}: {message}")


def passed(area):
    checks.setdefault(area, True)


def deadline_call_audit():
    """Statically enforce that the raw runtime evaluator has exactly one guarded caller."""
    try:
        tree = ast.parse(Path(__file__).read_text(), filename=__file__)
    except Exception as exc:
        return [f"could not audit verifier evaluator calls: {exc}"]

    calls = []

    class CallVisitor(ast.NodeVisitor):
        def __init__(self):
            self.functions = []

        def visit_FunctionDef(self, node):
            self.functions.append(node.name)
            self.generic_visit(node)
            self.functions.pop()

        def visit_AsyncFunctionDef(self, node):
            self.visit_FunctionDef(node)

        def visit_Call(self, node):
            is_raw_call = (
                isinstance(node.func, ast.Name) and node.func.id == "evaluate_policy"
            ) or (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "evaluate_policy"
            )
            if is_raw_call:
                calls.append((self.functions[-1] if self.functions else "<module>", node.lineno))
            self.generic_visit(node)

    CallVisitor().visit(tree)
    if len(calls) != 1 or calls[0][0] != "guarded_evaluate":
        rendered = ", ".join(f"{owner}:{line}" for owner, line in calls) or "none"
        return [
            "evaluate_policy must have exactly one direct call inside guarded_evaluate; "
            f"found {rendered}"
        ]
    return []


def capture_guard_call_audit():
    """AST-check that both exact-capture passes enter only through the deadline guard."""
    try:
        tree = ast.parse(Path(__file__).read_text(), filename=__file__)
    except Exception as exc:
        return [f"could not audit published capture replay calls: {exc}"]

    prefixes = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not (isinstance(node.func, ast.Name) and node.func.id == "guarded_evaluate"):
            continue
        if len(node.args) < 3:
            continue
        label = node.args[2]
        if (
            isinstance(label, ast.BinOp)
            and isinstance(label.op, ast.Add)
            and isinstance(label.left, ast.Constant)
            and isinstance(label.left.value, str)
            and label.left.value in {"published-primary-", "published-complete-"}
        ):
            prefixes.append(label.left.value)
    expected = ["published-complete-", "published-primary-"]
    if sorted(prefixes) != expected:
        return [
            "exact published capture must have one primary and one complete "
            f"guarded_evaluate call site; found {sorted(prefixes)}"
        ]
    if len(PUBLISHED_CAPTURE_EXPECTATIONS) != 21:
        return [
            "published capture manifest must contain exactly 21 ordered rows; "
            f"found {len(PUBLISHED_CAPTURE_EXPECTATIONS)}"
        ]
    return []


def guarded_evaluate(policy, req, case_id, carrier_name, corpus=None):
    """The sole evaluator call site, with an interrupting request and optional corpus guard."""
    corpus_limited = False
    if corpus is not None:
        remaining = corpus.remaining()
        if remaining <= 0.0:
            fail(
                "performance",
                f"{case_id} [{carrier_name}] was not evaluated because the "
                f"{corpus.label} exceeded {corpus.seconds:.2f}s",
            )
            return None, 0.0, True
        corpus_limited = remaining <= PER_REQUEST_DEADLINE_SECONDS
        seconds = max(0.000001, min(PER_REQUEST_DEADLINE_SECONDS, remaining))
    else:
        seconds = PER_REQUEST_DEADLINE_SECONDS

    scope = "corpus" if corpus_limited else "request"
    started = time.perf_counter()
    try:
        with interrupting_deadline(seconds, scope, case_id):
            result = evaluate_policy(policy, req)
    except EvaluationDeadlineExceeded as exc:
        elapsed = time.perf_counter() - started
        if exc.scope == "corpus" and corpus is not None:
            fail(
                "performance",
                f"{case_id} [{carrier_name}] exhausted the {corpus.label} "
                f"deadline of {corpus.seconds:.2f}s",
            )
            return None, elapsed, True
        fail(
            "performance",
            f"{case_id} [{carrier_name}] evaluation timed out after "
            f"{PER_REQUEST_DEADLINE_SECONDS:.2f}s",
        )
        return None, elapsed, False

    elapsed = time.perf_counter() - started
    # The signal is the interrupting guard.  This secondary check covers delayed signal
    # delivery or scheduling anomalies without making elapsed time merely diagnostic.
    if elapsed > PER_REQUEST_DEADLINE_SECONDS:
        fail(
            "performance",
            f"{case_id} [{carrier_name}] evaluation exceeded the "
            f"{PER_REQUEST_DEADLINE_SECONDS:.2f}s per-request deadline",
        )
    return result, elapsed, False


def finish_corpus(corpus, final_case_id):
    elapsed = corpus.elapsed()
    if elapsed > corpus.seconds:
        fail(
            "performance",
            f"{final_case_id}: {corpus.label} exceeded {corpus.seconds:.2f}s",
        )
        return False
    return True


def normalized_attribution(source, field):
    if source == "header" and isinstance(field, str):
        field = field.lower()
    return source, field


def enforce_published_capture_result(phase, row, result):
    """Enforce one public decision and record causal compatibility failures."""
    case_id = row["id"]
    expected = row["decision"]
    actual = result.get("decision")
    bounded = actual == "allow" or (
        actual in {"block", "reject"}
        and 400 <= int(result.get("status", 0)) <= 499
    )
    if actual == expected and bounded:
        return True

    fail(
        "published_capture",
        f"{phase} replay {case_id} expected published decision {expected!r}, "
        f"got {actual!r} with status {result.get('status')!r}",
    )
    if expected == "allow" and actual != "allow":
        fail(
            "compatibility",
            f"{phase} replay {case_id} denied an exact solver-visible legal request",
        )
        if phase == "primary":
            causal_violation = witnessed_neighbor_denial(case_id, row["request"], result)
            if causal_violation is not None:
                causal_violation["published_capture_phase"] = phase
                neighbor_non_interference_causal_violations.append(causal_violation)
                fail("compatibility_non_interference", causal_violation["cause"])
    return False


deadline_call_issues = deadline_call_audit()
capture_guard_call_issues = capture_guard_call_audit()
for deadline_audit_issue in deadline_call_issues + capture_guard_call_issues:
    fail("verifier_consistency", deadline_audit_issue)


if not ARTIFACT.exists():
    fail("artifact", f"{ARTIFACT} is missing")
else:
    try:
        submitted_policy_bytes = ARTIFACT.read_bytes()
    except OSError as exc:
        fail("artifact", f"cannot read {ARTIFACT}: {exc}")
    policy, validation_errors = load_policy(ARTIFACT)
    if validation_errors:
        fail("configuration", "; ".join(validation_errors[:20]))
    else:
        passed("artifact")
        passed("configuration")

if policy and not errors:
    # Structural scope is diagnostic only.  The reward-fatal compatibility check is set
    # later, after actual legal neighboring requests run through guarded_evaluate.
    neighbor_non_interference_advisory_findings = (
        neighbor_non_interference_advisories(policy)
    )

    dynamic_scheme_cases = submitted_extra_scheme_attacks(policy)
    attacks.extend(dynamic_scheme_cases)
    policy_dependent_import_cases = policy_dependent_import_controls(
        submitted_policy_bytes,
    )
    benign.extend(policy_dependent_import_cases)
    (
        rule_directed_neighbor_cases,
        rule_directed_neighbor_provenance,
        rule_directed_neighbor_synthesis,
    ) = rule_directed_neighbor_witnesses(policy)
    benign.extend(rule_directed_neighbor_cases)
    incomplete_comparison_witnesses = [
        diagnostic for diagnostic in rule_directed_neighbor_synthesis
        if diagnostic.get("predicate_op") in {"equals", "contains"}
        and diagnostic.get("primary_witness_complete") is not True
    ]
    if incomplete_comparison_witnesses:
        fixture_issues.append(
            "accepted comparison primary hypotheses lacked either a complete causal "
            "request or an exhaustive dead-operation proof: "
            + ", ".join(
                f"{item.get('rule_id')}@{item.get('operation')}"
                for item in incomplete_comparison_witnesses[:8]
            )
        )

    if fixture_issues:
        for issue in fixture_issues[:20]:
            fail("verifier_consistency", issue)
    profile_counts = {profile: 0 for profile in BACKEND_CONTEXT_PIPELINES}
    carrier_counts = {carrier["name"]: {"attack": 0, "benign": 0} for carrier in CARRIERS}
    for _, _, _, carrier_name in attacks:
        if carrier_name in carrier_counts:
            carrier_counts[carrier_name]["attack"] += 1
    for _, _, _, carrier_name in benign:
        if carrier_name in carrier_counts:
            carrier_counts[carrier_name]["benign"] += 1
    for _, _, _, profile in legacy_controls:
        profile_counts[profile] += 1
    if context_substitution_cases != len(CARRIERS) * (len(BACKEND_CONTEXT_PIPELINES) - 1):
        fail("verifier_consistency", "directed context-substitution matrix is incomplete")
    expected_batch_index_context_cases = (
        2 * 16 * (len(BACKEND_CONTEXT_PIPELINES) - 1)
    )
    if batch_index_context_cases != expected_batch_index_context_cases:
        fail(
            "verifier_consistency",
            f"indexed batch context matrix generated {batch_index_context_cases} cases, "
            f"expected {expected_batch_index_context_cases}",
        )
    expected_batch_index_decode_cases = 2 * 16 * 2
    if batch_index_decode_cases != expected_batch_index_decode_cases:
        fail(
            "verifier_consistency",
            f"indexed batch decode matrix generated {batch_index_decode_cases} cases, "
            f"expected {expected_batch_index_decode_cases}",
        )
    incomplete_batch_contexts = [
        key for key, counts in batch_index_context_matrix.items()
        if not counts["attack"]
        or not counts["safe_neighbor"]
        or not counts["encoded_attack"]
        or counts["exact_decode_attack"] != 1
        or counts["overdecode_safe"] != 1
    ]
    if len(batch_index_context_matrix) != 32 or incomplete_batch_contexts:
        fail(
            "verifier_consistency",
            "each batch pointer/index must have encoded malicious and safe "
            "over-normalization substitution witnesses; incomplete: "
            + ", ".join(incomplete_batch_contexts[:8]),
        )
    generated_rows = attacks + benign
    generated_family_counts = {}
    for _, _, family, _ in generated_rows:
        generated_family_counts[family] = generated_family_counts.get(family, 0) + 1
    expected_generated_counts = {
        "boundary_unsupported_scheme": len(CARRIERS) * 4,
        "boundary_windows_drive": len(CARRIERS) * 5,
        "boundary_unc_absolute": len(CARRIERS) * 2,
        "boundary_embedded_nul": len(CARRIERS) * 2,
        "boundary_dot_underflow": len(CARRIERS) * 4,
        "boundary_balanced_safe": len(CARRIERS) * 4,
        "integration_case_insensitive": len(integration_case_variants()),
        "integration_ignored_mode": 7,
        "json_suffix_media_attack": len(json_carriers) * 6,
        "json_suffix_media_safe": len(json_carriers) * 6,
        "batch_late_member": 8,
        "batch_all_positions": 32,
        "batch_index_exact_decode_attack": 32,
        "batch_index_overdecode_safe": 32,
        "batch_mixed_late_safe": 3,
        "route_scope_import_published": 2,
        "route_scope_import_multipart_grammar": 8,
        "route_scope_import_webkit_grammar": 1,
    }
    for substitute_profile in BACKEND_CONTEXT_PIPELINES:
        if substitute_profile != "batch_dispatch":
            expected_generated_counts[
                "batch_index_context_substitution_batch_dispatch_vs_"
                + substitute_profile
            ] = 32
    for family, expected_count in expected_generated_counts.items():
        if generated_family_counts.get(family) != expected_count:
            fail("verifier_consistency", f"{family} generated {generated_family_counts.get(family, 0)} cases, expected {expected_count}")
    if any(not counts["attack"] or not counts["benign"] for counts in carrier_counts.values()):
        fail("verifier_consistency", "a documented carrier lacks malicious or benign model controls")
    if any(count == 0 for count in profile_counts.values()):
        fail("verifier_consistency", "a compatibility profile lacks private model controls")
    missing_attribution = [case_id for case_id, _, _, _ in attacks
                           if case_id not in audit_attribution]
    if missing_attribution:
        fail("verifier_consistency", "attack cases lack attribution expectations: "
             + ", ".join(missing_attribution[:8]))
    if checks.get("verifier_consistency") is not False:
        passed("verifier_consistency")

    audit_cfg = policy.get("audit", {})
    fields = set(audit_cfg.get("fields", [])) if isinstance(audit_cfg.get("fields"), list) else set()
    if not REQUIRED_AUDIT.issubset(fields):
        fail("audit_configuration", "audit fields do not provide complete request/rule/carrier attribution")
    elif len(audit_cfg.get("event", "").strip()) < 4 or audit_cfg.get("redact_values") is not True:
        fail("audit_configuration", "audit event category or redaction is not deployment quality")
    else:
        passed("audit_configuration")

    primary_corpus = ReplayCorpus("primary attack-and-benign corpus", PRIMARY_CORPUS_DEADLINE_SECONDS)
    primary_corpus_exhausted = False
    for case_id, req, family, carrier_name in attacks:
        attack_attempted_ids.add(case_id)
        result, elapsed, primary_corpus_exhausted = guarded_evaluate(
            policy, req, case_id, carrier_name, primary_corpus,
        )
        if primary_corpus_exhausted:
            break
        if result is None:
            continue
        attack_evaluated_cases += 1
        attack_outcomes[case_id] = result
        max_work = max(max_work, result.get("work", 0))
        category_counts[family] = category_counts.get(family, 0) + int(result.get("decision") == "block")
        if result.get("decision") != "block":
            fail("attack_replays", f"{case_id} [{carrier_name}] reached a protected resolver instead of being blocked")
            continue
        if not 400 <= int(result.get("status", 0)) <= 499:
            fail("attack_replays", f"{case_id} [{carrier_name}] did not produce a bounded denial")
        audit = result.get("audit")
        if not isinstance(audit, dict) or not ({"event"} | REQUIRED_AUDIT).issubset(audit):
            fail("audit_runtime", f"{case_id} [{carrier_name}] denial lacks structured attribution")
        else:
            expected_rid = next(v for k, v in req["headers"] if k.lower() == "x-request-id")
            if audit.get("event") != policy["audit"]["event"]:
                fail("audit_runtime", f"{case_id} [{carrier_name}] denial uses the wrong event category")
            if audit.get("request_id") != expected_rid:
                fail("audit_runtime", f"{case_id} [{carrier_name}] cannot be correlated to its request")
            if not all(isinstance(audit.get(k), str) and audit.get(k) for k in ("rule_id", "method", "route", "source", "field", "reason")):
                fail("audit_runtime", f"{case_id} [{carrier_name}] denial contains empty operational fields")
            if audit.get("rule_id") != result.get("rule_id") or audit.get("reason") != result.get("reason"):
                fail("audit_runtime", f"{case_id} [{carrier_name}] denial misstates its rule or reason")
            if audit.get("method") != req["method"].upper() or audit.get("route") != canonical_route(req["target"]):
                fail("audit_runtime", f"{case_id} [{carrier_name}] denial misstates its effective operation")
            actual_attribution = normalized_attribution(audit.get("source"), audit.get("field"))
            acceptable = {
                normalized_attribution(source, field)
                for source, field in audit_attribution.get(case_id, set())
            }
            if actual_attribution not in acceptable:
                rendered = ", ".join(f"{source}:{field}" for source, field in sorted(acceptable))
                fail(
                    "audit_runtime",
                    f"{case_id} [{carrier_name}] attributes {actual_attribution[0]}:{actual_attribution[1]} "
                    f"instead of the responsible carrier set {{{rendered}}}",
                )
            serialized = json.dumps(audit, ensure_ascii=False)
            if any(token in serialized for token in sensitive_tokens):
                fail("audit_runtime", f"{case_id} [{carrier_name}] audit leaked locator material")
    if checks.get("attack_replays") is not False:
        passed("attack_replays")
    if checks.get("audit_runtime") is not False:
        passed("audit_runtime")

    if not primary_corpus_exhausted:
        for case_id, req, family, carrier_name in benign:
            benign_attempted_ids.add(case_id)
            result, elapsed, primary_corpus_exhausted = guarded_evaluate(
                policy, req, case_id, carrier_name, primary_corpus,
            )
            if primary_corpus_exhausted:
                break
            max_benign_elapsed = max(max_benign_elapsed, elapsed)
            if result is None:
                continue
            benign_evaluated_cases += 1
            benign_outcomes[case_id] = result
            max_work = max(max_work, result.get("work", 0))
            category_counts[family] = category_counts.get(family, 0) + int(result.get("decision") == "allow")
            witness_provenance = rule_directed_neighbor_provenance.get(case_id)
            if witness_provenance is not None:
                rule_directed_neighbor_outcomes.append({
                    "case_id": case_id,
                    "decision": result.get("decision"),
                    "status": result.get("status"),
                    "actual_rule_id": result.get("rule_id"),
                    "reason": result.get("reason"),
                    "witness_provenance": witness_provenance,
                })
            if result.get("decision") != "allow":
                causal_violation = witnessed_neighbor_denial(
                    case_id, req, result, witness_provenance,
                )
                if causal_violation is not None:
                    neighbor_non_interference_causal_violations.append(causal_violation)
                    fail("compatibility_non_interference", causal_violation["cause"])
                fail("compatibility", f"{case_id} [{carrier_name}] was denied although its adapter keeps it within root or unrelated")

    # Replay all 21 byte-identified public rows as their own primary contract.  These are
    # deliberately not cherry-picked into the generated attack/benign lists: allow, block,
    # and reject decisions are enforced exactly and receive independent 21/21 accounting.
    if not primary_corpus_exhausted:
        for capture_row in published_capture_rows:
            capture_id = capture_row["id"]
            published_capture_accounting["primary"]["attempted"] += 1
            capture_result, _, primary_corpus_exhausted = guarded_evaluate(
                policy,
                capture_row["request"],
                "published-primary-" + capture_id,
                "published:" + capture_id,
                primary_corpus,
            )
            if primary_corpus_exhausted:
                break
            if capture_result is None:
                continue
            published_capture_accounting["primary"]["completed"] += 1
            max_work = max(max_work, capture_result.get("work", 0))
            if enforce_published_capture_result("primary", capture_row, capture_result):
                published_capture_accounting["primary"]["matched"] += 1

    finish_corpus(primary_corpus, "primary-corpus-complete")
    primary_corpus_seconds = primary_corpus.elapsed()
    if published_capture_accounting["primary"] != {
        "attempted": 21, "completed": 21, "matched": 21,
    }:
        fail(
            "published_capture",
            "primary exact-capture replay was not 21/21/21: "
            + json.dumps(published_capture_accounting["primary"], sort_keys=True),
        )
    if checks.get("compatibility") is not False:
        passed("compatibility")
    if checks.get("compatibility_non_interference") is not False:
        passed("compatibility_non_interference")

    malformed_corpus = ReplayCorpus(
        "malformed request corpus", MALFORMED_CORPUS_DEADLINE_SECONDS,
    )
    malformed_corpus_exhausted = False
    for case_id, req, family in malformed:
        result, _, malformed_corpus_exhausted = guarded_evaluate(
            policy, req, case_id, "malformed:" + family, malformed_corpus,
        )
        if malformed_corpus_exhausted:
            break
        if result is None:
            continue
        malformed_evaluated_cases += 1
        max_work = max(max_work, result.get("work", 0))
        if result.get("decision") != "reject" or not 400 <= int(result.get("status", 0)) <= 499:
            fail("malformed_handling", f"{case_id} did not fail closed with a bounded 4xx")
        audit = result.get("audit")
        if not isinstance(audit, dict) or audit.get("reason") not in {"parse_error", "decode_error"}:
            fail("audit_runtime", f"{case_id} safety rejection lacks a useful reason")
    finish_corpus(malformed_corpus, "malformed-corpus-complete")
    malformed_corpus_seconds = malformed_corpus.elapsed()
    if malformed_evaluated_cases != len(malformed):
        fail(
            "malformed_handling",
            f"completed {malformed_evaluated_cases} of {len(malformed)} malformed cases",
        )
    if checks.get("malformed_handling") is not False:
        passed("malformed_handling")

    # These independent capacity requests are deliberately post-primary.  Each still goes
    # through the same interrupting 0.75s guard, including the supported high-cardinality
    # and 1 MiB import paths used by deadline regressions.
    import_probe = "A" * 25
    import_limit_body, import_limit_content_type = exact_size_multipart(1048576)
    import_limit = request(
        "POST", "/v1/templates/import?deadline_probe=" + import_probe,
        import_limit_body, import_limit_content_type, rid="cap-import",
    )
    # This maintainer-side parse proves that the complete 1 MiB body, not just its payload,
    # is valid documented multipart/form-data before it enters solver-controlled policy
    # evaluation.  No generic binary-media compatibility promise is implied.
    parsed_import_limit = parse_request(
        import_limit, {"max_fields": 256, "max_json_depth": 32},
    )
    capacity_import_fixture_parsed = (
        len(import_limit_body.encode("ascii")) == 1048576
        and parsed_import_limit.parse_error is None
        and parsed_import_limit.media_type == "multipart/form-data"
        and len(parsed_import_limit.multipart) == 1
        and parsed_import_limit.multipart[0][0] == "template"
    )
    if not capacity_import_fixture_parsed:
        fail(
            "verifier_consistency",
            "the exact 1 MiB capacity fixture is not a successfully parsed multipart import",
        )
    del parsed_import_limit
    capacity_total_cases += 1
    limit_result, _, _ = guarded_evaluate(
        policy, import_limit, "capacity-import-limit", "capacity",
    )
    if limit_result is None:
        fail("capacity", "the contractual 1 MiB multipart import evaluation did not complete")
    else:
        capacity_completed_cases += 1
        max_work = max(max_work, limit_result.get("work", 0))
        if limit_result.get("decision") != "allow":
            fail("capacity", "the contractual 1 MiB multipart import is denied")

    oversize_body = '{"template":"' + ("A" * policy["limits"]["max_body_bytes"]) + '"}'
    capacity_total_cases += 1
    over_result, _, _ = guarded_evaluate(
        policy,
        request("POST", "/v1/render", oversize_body, "application/json", rid="cap-over"),
        "capacity-body-oversize", "capacity",
    )
    if over_result is None:
        fail("capacity", "the body-oversize evaluation did not complete")
    else:
        capacity_completed_cases += 1
        max_work = max(max_work, over_result.get("work", 0))
        if over_result.get("decision") != "reject" or over_result.get("reason") != "body_oversize":
            fail("capacity", "a body beyond the configured ceiling is not rejected at the edge")

    many = "&".join(f"x{i}=a" for i in range(policy["limits"]["max_fields"] + 1))
    capacity_total_cases += 1
    many_result, _, _ = guarded_evaluate(
        policy,
        request("PUT", "/v1/templates/validate", many,
                "application/x-www-form-urlencoded", rid="cap-fields"),
        "capacity-field-overflow", "capacity",
    )
    if many_result is None:
        fail("capacity", "the single-carrier field-overflow evaluation did not complete")
    else:
        capacity_completed_cases += 1
        max_work = max(max_work, many_result.get("work", 0))
        if many_result.get("decision") != "reject":
            fail("capacity", "single-carrier field-count overflow is not rejected")

    within_limit = ["deadline_probe=" + ("A" * 25)] + [
        f"x{i}=a" for i in range(1, policy["limits"]["max_fields"])
    ]
    capacity_total_cases += 1
    within_result, _, _ = guarded_evaluate(
        policy,
        request("PUT", "/v1/templates/validate", "&".join(within_limit),
                "application/x-www-form-urlencoded", rid="cap-many-within"),
        "capacity-many-fields-within-limit", "capacity",
    )
    if within_result is None:
        fail("capacity", "the supported maximum-field evaluation did not complete")
    else:
        capacity_completed_cases += 1
        max_work = max(max_work, within_result.get("work", 0))
        if within_result.get("decision") != "allow":
            fail("capacity", "a request at the supported field-count limit is denied")

    half = policy["limits"]["max_fields"] // 2 + 1
    qfields = "&".join(f"q{i}=a" for i in range(half))
    ffields = "&".join(f"f{i}=a" for i in range(policy["limits"]["max_fields"] - half + 1))
    capacity_total_cases += 1
    cross_result, _, _ = guarded_evaluate(
        policy,
        request("PUT", "/v1/templates/validate?" + qfields, ffields,
                "application/x-www-form-urlencoded", rid="cap-cross"),
        "capacity-cumulative-field-overflow", "capacity",
    )
    if cross_result is None:
        fail("capacity", "the cumulative field-overflow evaluation did not complete")
    else:
        capacity_completed_cases += 1
        max_work = max(max_work, cross_result.get("work", 0))
        if cross_result.get("decision") != "reject":
            fail("capacity", "cumulative query/body field-count overflow is not rejected")

    duplicates = "&".join(
        "locator=shared/base"
        for _ in range(policy["limits"]["max_values_per_rule"] + 1)
    )
    capacity_total_cases += 1
    duplicate_result, _, _ = guarded_evaluate(
        policy,
        request("PUT", "/v1/templates/validate?" + duplicates, rid="cap-values"),
        "capacity-value-overflow", "capacity",
    )
    if duplicate_result is None:
        fail("capacity", "the duplicate-value overflow evaluation did not complete")
    else:
        capacity_completed_cases += 1
        max_work = max(max_work, duplicate_result.get("work", 0))
        if duplicate_result.get("decision") != "reject" or duplicate_result.get("reason") != "value_count_limit":
            fail("capacity", "over-count duplicate locator shape is not rejected before transforms")
    if checks.get("capacity") is not False:
        passed("capacity")

    if max_work > 180:
        fail("performance", f"deterministic evaluation work {max_work} exceeds 180")
    else:
        # Replay the complete benign corpus a second time.  Both the whole replay and each
        # individual evaluation are interruptible, so one catastrophic re.search cannot
        # evade the published performance requirement or stall the verifier.
        replay_corpus = ReplayCorpus(
            "full benign replay corpus", FULL_BENIGN_REPLAY_DEADLINE_SECONDS,
        )
        replay_corpus_exhausted = False
        for case_id, req, _, carrier_name in benign:
            full_benign_replay_cases += 1
            replay_result, _, replay_corpus_exhausted = guarded_evaluate(
                policy, req, "full-replay-" + case_id, carrier_name, replay_corpus,
            )
            if replay_corpus_exhausted:
                break
            if replay_result is None:
                continue
            full_benign_replay_completed_cases += 1
            max_work = max(max_work, replay_result.get("work", 0))
            if replay_result.get("decision") != "allow":
                fail(
                    "compatibility",
                    f"full-replay-{case_id} [{carrier_name}] was denied on the "
                    "complete benign replay",
                )

        # A second, independently counted pass proves the complete replay did not silently
        # omit any public row after primary grading.  Every row still uses the same
        # interrupting per-request and corpus guard.
        if not replay_corpus_exhausted:
            for capture_row in published_capture_rows:
                capture_id = capture_row["id"]
                published_capture_accounting["complete"]["attempted"] += 1
                capture_result, _, replay_corpus_exhausted = guarded_evaluate(
                    policy,
                    capture_row["request"],
                    "published-complete-" + capture_id,
                    "published:" + capture_id,
                    replay_corpus,
                )
                if replay_corpus_exhausted:
                    break
                if capture_result is None:
                    continue
                published_capture_accounting["complete"]["completed"] += 1
                max_work = max(max_work, capture_result.get("work", 0))
                if enforce_published_capture_result("complete", capture_row, capture_result):
                    published_capture_accounting["complete"]["matched"] += 1

        finish_corpus(replay_corpus, "full-benign-and-published-replay-complete")
        full_benign_replay_seconds = replay_corpus.elapsed()
        if full_benign_replay_cases != len(benign):
            fail(
                "performance",
                f"full benign replay evaluated {full_benign_replay_cases} of "
                f"{len(benign)} cases before its corpus deadline",
            )
        if full_benign_replay_completed_cases != len(benign):
            fail(
                "performance",
                f"full benign replay completed {full_benign_replay_completed_cases} of "
                f"{len(benign)} cases within per-request deadlines",
            )
        passed("performance")

    if published_capture_accounting["complete"] != {
        "attempted": 21, "completed": 21, "matched": 21,
    }:
        fail(
            "published_capture",
            "complete exact-capture replay was not 21/21/21: "
            + json.dumps(published_capture_accounting["complete"], sort_keys=True),
        )
    if checks.get("published_capture") is not False:
        passed("published_capture")

reward = 1.0 if not errors else 0.0
LOG.mkdir(parents=True, exist_ok=True)
(LOG / "reward.txt").write_text(str(reward))
details = {
    "reward": reward,
    "metrics": {
        "attack_protection": replay_metrics(attacks, attack_attempted_ids, attack_outcomes, "block"),
        "benign_compatibility": replay_metrics(benign, benign_attempted_ids, benign_outcomes, "allow"),
        "contract_checks": checks,
    },
    "artifact": str(ARTIFACT),
    "checks": checks,
    "documented_carriers": len(CARRIERS),
    "private_context_profiles": len(BACKEND_CONTEXT_PIPELINES),
    "context_substitution_cases": context_substitution_cases,
    "batch_index_context_cases": batch_index_context_cases,
    "batch_index_decode_cases": batch_index_decode_cases,
    "batch_index_context_matrix": batch_index_context_matrix,
    "attack_cases": len(attacks),
    "attack_evaluated_cases": attack_evaluated_cases,
    "benign_cases": len(benign),
    "benign_evaluated_cases": benign_evaluated_cases,
    "malformed_cases": len(malformed),
    "malformed_evaluated_cases": malformed_evaluated_cases,
    "malformed_corpus_deadline_seconds": MALFORMED_CORPUS_DEADLINE_SECONDS,
    "malformed_corpus_seconds": round(malformed_corpus_seconds, 6),
    "capacity_total_cases": capacity_total_cases,
    "capacity_completed_cases": capacity_completed_cases,
    "capacity_import_contract": {
        "media_type": "multipart/form-data",
        "total_body_bytes": 1048576,
        "successfully_parsed_before_replay": capacity_import_fixture_parsed,
    },
    "deadline_call_audit_passed": not deadline_call_issues,
    "capture_guard_call_audit_passed": not capture_guard_call_issues,
    "published_capture": published_capture_accounting,
    "submitted_extra_scheme_cases": len(dynamic_scheme_cases),
    "published_import_replay_cases": 2,
    "webkit_import_replay_cases": 1,
    "policy_dependent_import_cases": len(policy_dependent_import_cases),
    "systematic_multipart_grammar": {
        "cases": len(systematic_multipart_cases),
        "endpoint_lengths": sorted({len(boundary) for _, boundary, _ in systematic_multipart_shapes}),
        "quoted_cases": sum(1 for _, _, quoted in systematic_multipart_shapes if quoted),
        "unquoted_cases": sum(1 for _, _, quoted in systematic_multipart_shapes if not quoted),
        "independently_parsed": not systematic_multipart_issues,
    },
    "neighbor_non_interference": {
        "model": "advisory structural overlap plus bounded rule-directed causal guarded legal-request replay",
        "supported_operations": [
            {
                "name": operation["name"],
                "method": operation["method"],
                "route": operation["route"],
                "selector_shapes": {
                    location: sorted(fields)
                    for location, fields in operation["selector_shapes"].items()
                },
                "contract": operation["contract"],
            }
            for operation in SUPPORTED_NEIGHBOR_OPERATIONS
        ],
        "checked_rules": len(policy.get("rules", [])) if isinstance(policy, dict) else 0,
        "structural_advisory_count": len(neighbor_non_interference_advisory_findings),
        "structural_advisories": neighbor_non_interference_advisory_findings,
        "rule_directed_request_cap": MAX_RULE_DIRECTED_NEIGHBOR_REQUESTS,
        "rule_directed_request_count": len(rule_directed_neighbor_cases),
        "comparison_direct_witness_contract": True,
        "comparison_primary_witness_complete": not any(
            item.get("predicate_op") in {"equals", "contains"}
            and item.get("primary_witness_complete") is not True
            for item in rule_directed_neighbor_synthesis
        ),
        "rule_directed_synthesis": rule_directed_neighbor_synthesis,
        "rule_directed_guarded_outcomes": rule_directed_neighbor_outcomes,
        "causal_violation_count": len(neighbor_non_interference_causal_violations),
        "causal_violations": neighbor_non_interference_causal_violations,
        "compatibility_non_interference": checks.get("compatibility_non_interference"),
        "explanation": (
            "Method/route and concrete selector-shape overlap is advisory only. The public "
            "validator admits only locator_outside, contains, and equals. Comparison "
            "rules exclude decoder transforms and require their public 4096-byte value to "
            "remain a direct matching witness after the permitted transform pipeline. Every "
            "such primary value, plus known locator_outside semantic witnesses, is injected "
            "into an independently parsed legal request before secondary variants, or receives "
            "an explicit exhaustive dead-operation proof for unsatisfiable selector/header/media "
            "conditions. No private raw-preimage limit may suppress a literal comparison "
            "primary. Predicate-disjoint legal operations remain advisory. "
            "compatibility_non_interference becomes false only when guarded_evaluate "
            "actually blocks or rejects a concrete legal POST /v1/templates/import, GET "
            "/v1/search, or POST /v1/events request; causal records include generator, "
            "value, embedding, parse, match-confirmation, and source/field provenance."
        ),
    },
    "legacy_control_cases": len(legacy_controls),
    "max_deterministic_work": max_work,
    "per_request_deadline_seconds": PER_REQUEST_DEADLINE_SECONDS,
    "primary_corpus_deadline_seconds": PRIMARY_CORPUS_DEADLINE_SECONDS,
    "primary_corpus_seconds": round(primary_corpus_seconds, 6),
    "max_benign_case_seconds": round(max_benign_elapsed, 6),
    "full_benign_replay_deadline_seconds": FULL_BENIGN_REPLAY_DEADLINE_SECONDS,
    "full_benign_replay_cases": full_benign_replay_cases,
    "full_benign_replay_completed_cases": full_benign_replay_completed_cases,
    "full_benign_replay_seconds": round(full_benign_replay_seconds, 6),
    "category_pass_counts": category_counts,
    "error_count": total_error_count,
    "reported_error_count": len(errors),
    "errors_truncated": total_error_count > len(errors),
    "error_counts_by_area": error_counts_by_area,
    "errors": errors,
    "summary": ("Policy passed carrier-complete context identification, attack/evasion, over-normalization, causally witnessed neighbor non-interference, compatibility, audit, capacity, and work checks."
                if reward else "Policy did not satisfy the context-specific runtime virtual-patch contract."),
}
(LOG / "details.json").write_text(json.dumps(details, indent=2, sort_keys=True) + "\n")
print(json.dumps(details, indent=2, sort_keys=True))
