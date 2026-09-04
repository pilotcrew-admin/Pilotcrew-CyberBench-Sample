#!/usr/bin/env python3
"""Public EdgeShield v1 compatibility runtime. Standard-library only."""
from __future__ import annotations

import base64
import hashlib
import json
import re
import time
import unicodedata
import urllib.parse
from dataclasses import dataclass
from email import policy as email_policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any

ALLOWED_TOP = {"schema_version", "mode", "limits", "failure_handling", "audit", "rules", "metadata"}
ALLOWED_RULE = {"id", "priority", "match", "selectors", "transforms", "predicate", "action"}
ALLOWED_MATCH = {"methods", "routes", "headers"}
ALLOWED_HEADER_MATCH = {"name", "equals", "case_sensitive"}
ALLOWED_SELECTOR = {"location", "names", "pointers"}
ALLOWED_ACTION = {"type", "status"}
ALLOWED_AUDIT = {"enabled", "event", "fields", "redact_values"}
ALLOWED_LIMITS = {"max_body_bytes", "max_fields", "max_json_depth", "max_values_per_rule"}
ALLOWED_FAILURE = {"parse_error", "decode_error", "oversize", "status"}
TRANSFORMS = {"percent_decode", "unicode_nfkc", "backslash_to_slash", "trim_ascii", "lowercase"}
COMPARISON_TRANSFORMS = {"unicode_nfkc", "backslash_to_slash", "trim_ascii", "lowercase"}
LOCATIONS = {"query", "header", "json", "form", "multipart"}
AUDIT_FIELDS = {"request_id", "rule_id", "method", "route", "source", "field", "reason"}
HEX = set("0123456789abcdefABCDEF")

COMPARISON_MAX_UTF8_BYTES = 4096
URI_SCHEME_MAX_CHARS = 64
URI_SCHEME_PATTERN = re.compile(
    rf"[A-Za-z][A-Za-z0-9+.-]{{0,{URI_SCHEME_MAX_CHARS - 1}}}", re.ASCII
)


def _utf8_budget(value: str, where: str, errors: list[str]) -> None:
    try:
        size = len(value.encode("utf-8", "strict"))
    except UnicodeEncodeError:
        errors.append(f"{where}: must be valid UTF-8 text (unpaired surrogate found)")
        return
    if size > COMPARISON_MAX_UTF8_BYTES:
        errors.append(
            f"{where}: UTF-8 length {size} exceeds {COMPARISON_MAX_UTF8_BYTES} bytes"
        )


class JSONObject(list):
    """List of pairs, distinct from a JSON array, so duplicate members survive."""

@dataclass
class ParsedRequest:
    method: str
    target: str
    route: str
    headers: list[tuple[str, str]]
    body: bytes
    query: list[tuple[str, str]]
    form: list[tuple[str, str]]
    multipart: list[tuple[str, str]]
    json_value: Any
    media_type: str
    parse_error: str | None
    field_count: int
    request_id: str | None


def _unknown(obj: dict, allowed: set[str], where: str, errors: list[str]) -> None:
    extra = set(obj) - allowed
    if extra:
        errors.append(f"{where}: unknown field(s): {', '.join(sorted(extra))}")


def _str_list(value: Any, where: str, errors: list[str], nonempty: bool = True) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(x, str) or not x for x in value):
        errors.append(f"{where}: must be an array of nonempty strings")
        return []
    if nonempty and not value:
        errors.append(f"{where}: must not be empty")
    if len(value) != len(set(value)):
        errors.append(f"{where}: contains duplicates")
    return value


def _legal_direct_header_text(value: str) -> bool:
    return (
        "\r" not in value
        and "\n" not in value
        and "\x00" not in value
        and all(
            char == "\t" or 0x20 <= ord(char) <= 0x7E or 0x80 <= ord(char) <= 0xFF
            for char in value
        )
    )


def _allowed_schemes(value: Any, where: str, errors: list[str]) -> list[str]:
    schemes = _str_list(value, where, errors, nonempty=False)
    effective: dict[str, int] = {}
    for index, scheme in enumerate(schemes):
        item_where = f"{where}[{index}]"
        if URI_SCHEME_PATTERN.fullmatch(scheme) is None:
            errors.append(
                f"{item_where}: must match ASCII URI scheme grammar "
                f"^[A-Za-z][A-Za-z0-9+.-]*$ and contain at most "
                f"{URI_SCHEME_MAX_CHARS} ASCII characters; Unicode schemes are not allowed"
            )
            continue
        canonical = scheme.lower()
        if canonical in effective:
            errors.append(
                f"{item_where}: duplicates {where}[{effective[canonical]}] "
                f"after case-insensitive URI scheme canonicalization ({canonical!r})"
            )
        else:
            effective[canonical] = index
    return schemes


def validate_policy(data: Any, raw_size: int | None = None) -> list[str]:
    errors: list[str] = []
    if raw_size is not None and raw_size > 32768:
        errors.append("policy exceeds 32768 bytes")
    if not isinstance(data, dict):
        return ["top level must be an object"]
    _unknown(data, ALLOWED_TOP, "policy", errors)
    if data.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if data.get("mode") != "enforce":
        errors.append("mode must be enforce")
    if "metadata" in data and not isinstance(data.get("metadata"), dict):
        errors.append("metadata must be an object when present")

    limits = data.get("limits")
    if not isinstance(limits, dict):
        errors.append("limits must be an object")
        limits = {}
    else:
        _unknown(limits, ALLOWED_LIMITS, "limits", errors)
    for key, lo, hi in [("max_body_bytes", 1048576, 2097152), ("max_fields", 32, 256), ("max_json_depth", 12, 32), ("max_values_per_rule", 1, 16)]:
        v = limits.get(key)
        if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
            errors.append(f"limits.{key} must be an integer from {lo} through {hi}")

    failure = data.get("failure_handling")
    if not isinstance(failure, dict):
        errors.append("failure_handling must be an object")
        failure = {}
    else:
        _unknown(failure, ALLOWED_FAILURE, "failure_handling", errors)
    for key in ("parse_error", "decode_error", "oversize"):
        if failure.get(key) != "reject":
            errors.append(f"failure_handling.{key} must be reject")
    st = failure.get("status")
    if isinstance(st, bool) or not isinstance(st, int) or not 400 <= st <= 499:
        errors.append("failure_handling.status must be a 4xx integer")

    audit = data.get("audit")
    if not isinstance(audit, dict):
        errors.append("audit must be an object")
        audit = {}
    else:
        _unknown(audit, ALLOWED_AUDIT, "audit", errors)
    if audit.get("enabled") is not True:
        errors.append("audit.enabled must be true")
    if not isinstance(audit.get("event"), str) or len(audit.get("event", "").strip()) < 4:
        errors.append("audit.event must contain at least four non-whitespace characters")
    af = _str_list(audit.get("fields"), "audit.fields", errors)
    if set(af) - AUDIT_FIELDS:
        errors.append("audit.fields contains an unsupported field")
    if audit.get("redact_values") is not True:
        errors.append("audit.redact_values must be true")

    rules = data.get("rules")
    if not isinstance(rules, list) or not rules:
        errors.append("rules must be a nonempty array")
        rules = []
    if len(rules) > 12:
        errors.append("rules exceeds 12")
    ids: set[str] = set()
    priorities: set[int] = set()
    selector_total = 0
    for i, rule in enumerate(rules):
        where = f"rules[{i}]"
        if not isinstance(rule, dict):
            errors.append(f"{where}: must be an object")
            continue
        _unknown(rule, ALLOWED_RULE, where, errors)
        rid = rule.get("id")
        if not isinstance(rid, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", rid or ""):
            errors.append(f"{where}.id: invalid stable identifier")
        elif rid in ids:
            errors.append(f"{where}.id: duplicate")
        else:
            ids.add(rid)
        prio = rule.get("priority")
        if isinstance(prio, bool) or not isinstance(prio, int) or not 0 <= prio <= 10000:
            errors.append(f"{where}.priority: must be an integer from 0 through 10000")
        elif prio in priorities:
            errors.append(f"{where}.priority: priorities must be unique")
        else:
            priorities.add(prio)
        match = rule.get("match")
        if not isinstance(match, dict):
            errors.append(f"{where}.match: must be an object")
            match = {}
        else:
            _unknown(match, ALLOWED_MATCH, f"{where}.match", errors)
        methods = _str_list(match.get("methods"), f"{where}.match.methods", errors)
        if any(m != m.upper() or not re.fullmatch(r"[A-Z]+", m) for m in methods):
            errors.append(f"{where}.match.methods: methods must be uppercase tokens")
        routes = _str_list(match.get("routes"), f"{where}.match.routes", errors)
        if any(not r.startswith("/") or "?" in r or canonical_route(r) != r for r in routes):
            errors.append(f"{where}.match.routes: routes must be canonical absolute paths")
        header_conditions = match.get("headers", [])
        if not isinstance(header_conditions, list) or len(header_conditions) > 4:
            errors.append(f"{where}.match.headers: must be an array of at most four conditions")
            header_conditions = []
        for j, condition in enumerate(header_conditions):
            hw = f"{where}.match.headers[{j}]"
            if not isinstance(condition, dict):
                errors.append(f"{hw}: must be an object")
                continue
            _unknown(condition, ALLOWED_HEADER_MATCH, hw, errors)
            if not isinstance(condition.get("name"), str) or not condition.get("name", "").strip():
                errors.append(f"{hw}.name: must be a nonempty header name")
            if not isinstance(condition.get("equals"), str):
                errors.append(f"{hw}.equals: must be a string")
            if not isinstance(condition.get("case_sensitive"), bool):
                errors.append(f"{hw}.case_sensitive: must be boolean")
        selectors = rule.get("selectors")
        if not isinstance(selectors, list) or not selectors:
            errors.append(f"{where}.selectors: must be a nonempty array")
            selectors = []
        selector_total += len(selectors)
        for j, sel in enumerate(selectors):
            sw = f"{where}.selectors[{j}]"
            if not isinstance(sel, dict):
                errors.append(f"{sw}: must be an object")
                continue
            _unknown(sel, ALLOWED_SELECTOR, sw, errors)
            loc = sel.get("location")
            if loc not in LOCATIONS:
                errors.append(f"{sw}.location: unsupported")
            if loc == "json":
                pts = _str_list(sel.get("pointers"), f"{sw}.pointers", errors)
                if "names" in sel:
                    errors.append(f"{sw}: JSON selectors use pointers, not names")
                for pt in pts:
                    if not pt.startswith("/"):
                        errors.append(f"{sw}: JSON pointer must start with /")
            else:
                _str_list(sel.get("names"), f"{sw}.names", errors)
                if "pointers" in sel:
                    errors.append(f"{sw}: non-JSON selectors use names, not pointers")
        transforms = rule.get("transforms")
        if not isinstance(transforms, list) or any(t not in TRANSFORMS for t in transforms):
            errors.append(f"{where}.transforms: contains an unsupported transform")
            transforms = []
        if len(transforms) > 8:
            errors.append(f"{where}.transforms: exceeds eight")
        pred = rule.get("predicate")
        if not isinstance(pred, dict) or not isinstance(pred.get("op"), str):
            errors.append(f"{where}.predicate: must be an operator object")
        else:
            op = pred.get("op")
            if op == "locator_outside":
                if set(pred) != {"op", "allowed_schemes"}:
                    errors.append(f"{where}.predicate: locator_outside requires only allowed_schemes")
                _allowed_schemes(
                    pred.get("allowed_schemes"),
                    f"{where}.predicate.allowed_schemes",
                    errors,
                )
            elif op in {"contains", "equals"}:
                member = "needle" if op == "contains" else "value"
                if set(pred) != {"op", member, "case_sensitive"}:
                    errors.append(f"{where}.predicate: malformed {op} predicate")
                forbidden = [
                    transform for transform in transforms
                    if transform not in COMPARISON_TRANSFORMS
                ]
                if forbidden:
                    errors.append(
                        f"{where}.transforms: percent_decode is not permitted with {op}; "
                        "comparison predicates permit only lowercase, trim_ascii, "
                        "backslash_to_slash, and unicode_nfkc"
                    )
                val = pred.get(member)
                if not isinstance(val, str) or not val:
                    errors.append(f"{where}.predicate.{member}: must be a nonempty string")
                else:
                    _utf8_budget(val, f"{where}.predicate.{member}", errors)
                    if any(
                        isinstance(selector, dict)
                        and selector.get("location") == "header"
                        for selector in selectors
                    ) and not _legal_direct_header_text(val):
                        errors.append(
                            f"{where}.predicate.{member}: must be representable directly as "
                            "a legal HTTP header value when the rule uses a header selector"
                        )
                    nfkc_stable = not (
                        "unicode_nfkc" in transforms
                        and unicodedata.normalize("NFKC", val) != val
                    )
                    if not nfkc_stable:
                        errors.append(
                            f"{where}.predicate.{member}: must already be NFKC-normalized "
                            f"when {where}.transforms uses unicode_nfkc"
                        )
                    if (
                        not forbidden
                        and nfkc_stable
                        and isinstance(pred.get("case_sensitive"), bool)
                    ):
                        try:
                            direct = transform_value(val, transforms)
                            direct.encode("utf-8", "strict")
                        except (UnicodeError, ValueError):
                            direct = None
                        if direct is not None:
                            if op == "equals":
                                matches_direct = (
                                    direct == val if pred["case_sensitive"]
                                    else direct.lower() == val.lower()
                                )
                            else:
                                matches_direct = (
                                    val in direct if pred["case_sensitive"]
                                    else val.lower() in direct.lower()
                                )
                            if not matches_direct:
                                errors.append(
                                    f"{where}.predicate.{member}: must match its own value "
                                    f"after {where}.transforms; comparison rules require a "
                                    "direct normalized witness"
                                )
                if not isinstance(pred.get("case_sensitive"), bool):
                    errors.append(f"{where}.predicate.case_sensitive: must be boolean")
            elif op == "regex":
                errors.append(
                    f"{where}.predicate: regex is not supported in EdgeShield v1; "
                    "use locator_outside/contains/equals"
                )
            else:
                errors.append(f"{where}.predicate: unsupported operator")
        action = rule.get("action")
        if not isinstance(action, dict):
            errors.append(f"{where}.action: must be an object")
        else:
            _unknown(action, ALLOWED_ACTION, f"{where}.action", errors)
            if action.get("type") != "block":
                errors.append(f"{where}.action.type: must be block")
            status = action.get("status")
            if isinstance(status, bool) or not isinstance(status, int) or not 400 <= status <= 499:
                errors.append(f"{where}.action.status: must be a 4xx integer")
    if selector_total > 32:
        errors.append("selectors exceeds 32 total")
    return errors


def load_policy(path: str | Path) -> tuple[dict, list[str]]:
    p = Path(path)
    try:
        raw = p.read_bytes()
        data = json.loads(raw)
    except Exception as exc:
        return {}, [f"cannot parse policy: {exc}"]
    return data, validate_policy(data, len(raw))


def canonical_route(target: str) -> str:
    try:
        raw = urllib.parse.urlsplit(target).path or "/"
    except Exception:
        raw = target.split("?", 1)[0] or "/"
    # Decode percent escapes only when they name an RFC3986 unreserved byte.
    unreserved = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
    def repl(m: re.Match[str]) -> str:
        try:
            c = chr(int(m.group(1), 16))
            return c if c in unreserved else m.group(0).upper()
        except Exception:
            return m.group(0)
    raw = re.sub(r"%([0-9A-Fa-f]{2})", repl, raw)
    raw = re.sub(r"/+", "/", raw)
    stack: list[str] = []
    for seg in raw.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if stack:
                stack.pop()
            continue
        stack.append(seg)
    out = "/" + "/".join(stack)
    return out if out == "/" else out.rstrip("/")


def _body_bytes(env: dict) -> bytes:
    if "body" in env and "body_b64" in env:
        raise ValueError("request has both body and body_b64")
    if "body_b64" in env:
        if not isinstance(env["body_b64"], str):
            raise ValueError("body_b64 must be a string")
        return base64.b64decode(env["body_b64"], validate=True)
    body = env.get("body", "")
    if not isinstance(body, str):
        raise ValueError("body must be a string")
    return body.encode("utf-8")


def _headers(value: Any) -> list[tuple[str, str]]:
    if isinstance(value, dict):
        pairs = list(value.items())
    elif isinstance(value, list):
        pairs = value
    else:
        raise ValueError("headers must be an object or pair array")
    out = []
    for pair in pairs:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2 or not all(isinstance(x, str) for x in pair):
            raise ValueError("header entry must be a string pair")
        out.append((pair[0], pair[1]))
    return out


def _last_header(headers: list[tuple[str, str]], name: str) -> str | None:
    vals = [v for k, v in headers if k.lower() == name.lower()]
    return vals[-1] if vals else None


def _json_depth(node: Any) -> int:
    if isinstance(node, JSONObject):
        return 1 + max((_json_depth(v) for _, v in node), default=0)
    if isinstance(node, list):
        return 1 + max((_json_depth(v) for v in node), default=0)
    return 1


def _json_fields(node: Any) -> int:
    if isinstance(node, JSONObject):
        return len(node) + sum(_json_fields(v) for _, v in node)
    if isinstance(node, list):
        return len(node) + sum(_json_fields(v) for v in node)
    return 0


def _multipart_fields(body: bytes, content_type: str) -> list[tuple[str, str]]:
    msg = BytesParser(policy=email_policy.default).parsebytes(
        b"Content-Type: " + content_type.encode("latin-1") + b"\r\nMIME-Version: 1.0\r\n\r\n" + body
    )
    if not msg.is_multipart():
        raise ValueError("invalid multipart framing")
    out: list[tuple[str, str]] = []
    for part in msg.iter_parts():
        name = part.get_param("name", header="content-disposition")
        if not isinstance(name, str):
            continue
        payload = part.get_payload(decode=True) or b""
        charset = part.get_content_charset() or "utf-8"
        try:
            value = payload.decode(charset, "strict")
        except Exception as exc:
            raise ValueError(f"multipart field is not valid text: {exc}")
        out.append((name, value))
    return out


def parse_request(env: Any, limits: dict | None = None, parse_body: bool = True) -> ParsedRequest:
    if not isinstance(env, dict):
        raise ValueError("request envelope must be an object")
    method = env.get("method")
    target = env.get("target")
    if not isinstance(method, str) or not method or not isinstance(target, str) or not target.startswith("/"):
        raise ValueError("request method and absolute target are required")
    headers = _headers(env.get("headers", {}))
    body = _body_bytes(env)
    max_fields = int((limits or {}).get("max_fields", 256))
    max_depth = int((limits or {}).get("max_json_depth", 32))
    parse_error = None
    query: list[tuple[str, str]] = []
    form: list[tuple[str, str]] = []
    multipart: list[tuple[str, str]] = []
    json_value: Any = None
    try:
        query = urllib.parse.parse_qsl(urllib.parse.urlsplit(target).query, keep_blank_values=True, max_num_fields=max_fields, encoding="utf-8", errors="strict")
    except Exception as exc:
        parse_error = f"query parse error: {exc}"
    ctv = _last_header(headers, "content-type") or ""
    media_type = ctv.split(";", 1)[0].strip().lower()
    try:
        if parse_body and body and (media_type == "application/json" or (media_type.startswith("application/") and media_type.endswith("+json"))):
            json_value = json.loads(body.decode("utf-8", "strict"), object_pairs_hook=JSONObject)
            if _json_depth(json_value) > max_depth:
                raise ValueError("JSON nesting exceeds max_json_depth")
            if _json_fields(json_value) + len(query) > max_fields:
                raise ValueError("field count exceeds max_fields")
        elif parse_body and body and media_type == "application/x-www-form-urlencoded":
            form = urllib.parse.parse_qsl(body.decode("ascii", "strict"), keep_blank_values=True, max_num_fields=max_fields, encoding="utf-8", errors="strict")
        elif parse_body and body and media_type == "multipart/form-data":
            multipart = _multipart_fields(body, ctv)
            if len(multipart) + len(query) > max_fields:
                raise ValueError("field count exceeds max_fields")
    except Exception as exc:
        parse_error = str(exc)
    field_count = len(query) + len(form) + len(multipart) + _json_fields(json_value)
    if field_count > max_fields and parse_error is None:
        parse_error = "cumulative field count exceeds max_fields"
    request_id = _last_header(headers, "x-request-id")
    if not request_id:
        digest_input = method.upper().encode() + b"\0" + target.encode("utf-8", "replace") + b"\0" + body
        request_id = "edge-" + hashlib.sha256(digest_input).hexdigest()[:16]
    return ParsedRequest(
        method=method.upper(), target=target, route=canonical_route(target), headers=headers,
        body=body, query=query, form=form, multipart=multipart, json_value=json_value,
        media_type=media_type, parse_error=parse_error, field_count=field_count,
        request_id=request_id,
    )


def _pointer_tokens(pointer: str) -> list[str]:
    return [p.replace("~1", "/").replace("~0", "~") for p in pointer.split("/")[1:]]


def _pointer_values(node: Any, tokens: list[str]) -> list[Any]:
    if not tokens:
        return [node]
    head, rest = tokens[0], tokens[1:]
    out: list[Any] = []
    if isinstance(node, JSONObject):
        for key, value in node:
            if head == "*" or key == head:
                out.extend(_pointer_values(value, rest))
    elif isinstance(node, list):
        if head == "*":
            for value in node:
                out.extend(_pointer_values(value, rest))
        elif head.isdigit() and int(head) < len(node):
            out.extend(_pointer_values(node[int(head)], rest))
    return out


def extract_values(req: ParsedRequest, selector: dict) -> list[tuple[str, str, str]]:
    loc = selector["location"]
    out: list[tuple[str, str, str]] = []
    if loc == "json":
        for pointer in selector.get("pointers", []):
            for value in _pointer_values(req.json_value, _pointer_tokens(pointer)):
                if isinstance(value, str):
                    out.append((value, loc, pointer))
        return out
    names = selector.get("names", [])
    if loc == "query":
        pairs = req.query
    elif loc == "form":
        pairs = req.form
    elif loc == "multipart":
        pairs = req.multipart
    else:
        pairs = req.headers
    for key, value in pairs:
        for name in names:
            if (key.lower() == name.lower()) if loc == "header" else (key == name):
                out.append((value, loc, name))
    return out


def strict_percent_decode(value: str) -> str:
    i = 0
    while i < len(value):
        if value[i] == "%":
            if i + 2 >= len(value) or value[i + 1] not in HEX or value[i + 2] not in HEX:
                raise ValueError("malformed percent escape")
            i += 3
        else:
            i += 1
    raw = urllib.parse.unquote_to_bytes(value)
    return raw.decode("utf-8", "strict")


def transform_value(value: str, transforms: list[str]) -> str:
    for transform in transforms:
        if transform == "percent_decode":
            value = strict_percent_decode(value)
        elif transform == "unicode_nfkc":
            value = unicodedata.normalize("NFKC", value)
        elif transform == "backslash_to_slash":
            value = value.replace("\\", "/")
        elif transform == "trim_ascii":
            value = value.strip(" \t\r\n\f\v")
        elif transform == "lowercase":
            value = value.lower()
    return value


def locator_outside(value: str, allowed_schemes: list[str]) -> bool:
    if "\x00" in value:
        return True
    allowed = {x.lower() for x in allowed_schemes}
    rest = value
    # Drive letters are paths, not schemes.
    if re.match(r"^[A-Za-z]:[/\\]", rest):
        return True
    scheme = None
    m = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*):(.*)$", rest, flags=re.S)
    if m:
        scheme, rest = m.group(1).lower(), m.group(2)
        if scheme not in allowed:
            return True
        # An allowed resolver namespace does not make an absolute drive path relative.
        if re.match(r"^[A-Za-z]:[/\\]", rest):
            return True
    if rest.startswith(("/", "\\")) or rest.startswith("//"):
        return True
    depth = 0
    for segment in rest.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if depth == 0:
                return True
            depth -= 1
        else:
            depth += 1
    return False


def predicate_matches(value: str, predicate: dict) -> bool:
    op = predicate["op"]
    if op == "locator_outside":
        return locator_outside(value, predicate.get("allowed_schemes", []))
    if op == "contains":
        needle = predicate["needle"]
        return needle in value if predicate["case_sensitive"] else needle.lower() in value.lower()
    if op == "equals":
        expected = predicate["value"]
        return value == expected if predicate["case_sensitive"] else value.lower() == expected.lower()
    return False


def rule_matches(req: ParsedRequest, rule: dict) -> bool:
    match = rule["match"]
    if req.method not in match["methods"] or req.route not in match["routes"]:
        return False
    for condition in match.get("headers", []):
        values = [value for name, value in req.headers if name.lower() == condition["name"].lower()]
        expected = condition["equals"]
        if condition["case_sensitive"]:
            ok = any(value == expected for value in values)
        else:
            ok = any(value.lower() == expected.lower() for value in values)
        if not ok:
            return False
    return True


def _audit(policy: dict, req: ParsedRequest, rule_id: str, source: str | None, field: str | None, reason: str) -> dict:
    values = {
        "request_id": req.request_id,
        "rule_id": rule_id,
        "method": req.method,
        "route": req.route,
        "source": source,
        "field": field,
        "reason": reason,
    }
    return {"event": policy["audit"]["event"], **{k: values[k] for k in policy["audit"]["fields"]}}


def evaluate_policy(policy: dict, env: Any) -> dict:
    limits = policy["limits"]
    try:
        raw_body = _body_bytes(env) if isinstance(env, dict) else b""
        if len(raw_body) > limits["max_body_bytes"]:
            req = parse_request(env, limits, parse_body=False)
            return {"decision": "reject", "status": policy["failure_handling"]["status"], "reason": "body_oversize", "work": 1,
                    "audit": _audit(policy, req, "request-guard", "body", None, "body_oversize")}
        req = parse_request(env, limits)
    except Exception as exc:
        return {"decision": "reject", "status": policy["failure_handling"]["status"], "reason": f"envelope_error:{exc}", "work": 1, "audit": None}
    work = 1
    indexed = list(enumerate(policy["rules"]))
    rules = [r for _, r in sorted(indexed, key=lambda x: (x[1]["priority"], x[0]))]
    matching = []
    for rule in rules:
        work += 1
        work += len(rule["match"].get("headers", []))
        if rule_matches(req, rule):
            matching.append(rule)
    if req.parse_error and matching:
        return {"decision": "reject", "status": policy["failure_handling"]["status"], "reason": "parse_error", "detail": req.parse_error, "work": work,
                "audit": _audit(policy, req, "request-guard", "body", None, "parse_error")}
    for rule in matching:
        selected = []
        for selector in rule["selectors"]:
            if work + 1 > 180:
                return {"decision": "reject", "status": policy["failure_handling"]["status"], "reason": "policy_work_limit", "work": work,
                        "audit": _audit(policy, req, "request-guard", "request", None, "policy_work_limit")}
            work += 1
            selected.extend(extract_values(req, selector))
        if work + len(selected) > 180:
            return {"decision": "reject", "status": policy["failure_handling"]["status"], "reason": "policy_work_limit", "work": work,
                    "audit": _audit(policy, req, "request-guard", "request", None, "policy_work_limit")}
        work += len(selected)
        if len(selected) > limits["max_values_per_rule"]:
            return {"decision": "reject", "status": policy["failure_handling"]["status"], "reason": "value_count_limit", "work": work,
                    "audit": _audit(policy, req, "request-guard", "request", None, "value_count_limit")}
        for value, source, field in selected:
            projected = work + len(rule["transforms"]) + 1
            if projected > 180:
                return {"decision": "reject", "status": policy["failure_handling"]["status"], "reason": "policy_work_limit", "work": work,
                        "audit": _audit(policy, req, "request-guard", source, field, "policy_work_limit")}
            try:
                work += len(rule["transforms"])
                normalized = transform_value(value, rule["transforms"])
            except Exception:
                return {"decision": "reject", "status": policy["failure_handling"]["status"], "reason": "decode_error", "work": work,
                        "audit": _audit(policy, req, "request-guard", source, field, "decode_error")}
            work += 1
            if predicate_matches(normalized, rule["predicate"]):
                return {"decision": "block", "status": rule["action"]["status"], "rule_id": rule["id"], "source": source, "field": field,
                        "reason": rule["predicate"]["op"], "work": work,
                        "audit": _audit(policy, req, rule["id"], source, field, rule["predicate"]["op"])}
    return {"decision": "allow", "status": None, "reason": "no_rule_triggered", "work": work, "audit": None}
