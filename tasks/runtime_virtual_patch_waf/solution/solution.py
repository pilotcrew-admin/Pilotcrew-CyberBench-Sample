#!/usr/bin/env python3
"""Expert black-box investigation and EdgeShield deployment.

The reference starts only from the public carrier contract and transform vocabulary.  It
fingerprints every carrier, searches candidate transform sequences against normalized
observations, groups fields only after their observations agree, and then validates the
resulting policy against both sides of each recovered compatibility boundary.
"""
from __future__ import annotations

import itertools
import json
import os
import subprocess
import tempfile
import unicodedata
import urllib.parse
from collections import OrderedDict
from pathlib import Path

ROOT = Path(os.environ.get("APP_ROOT", "/app"))
DOCS = ROOT / "docs"
CAPTURE = ROOT / "traffic" / "representative.jsonl"
OUTPUT = ROOT / "edge-policy.json"
WAFLAB = ROOT / "waflab"


def request(method, target, body="", content_type=None, headers=None, rid="oracle-probe"):
    pairs = [["Authorization", "Bearer reference-investigator"], ["X-Request-ID", rid]]
    if content_type:
        pairs.append(["Content-Type", content_type])
    if headers:
        pairs.extend(headers)
    return {"method": method, "target": target, "headers": pairs, "body": body}


def multipart(name, value, boundary="oracle-boundary"):
    body = (f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"{name}\"\r\n\r\n"
            f"{value}\r\n--{boundary}--\r\n")
    return body, f"multipart/form-data; boundary={boundary}"


def percent_all(value):
    return "".join(f"%{byte:02X}" for byte in value.encode("utf-8"))


def inspect_request(envelope, scratch, label):
    path = scratch / f"inspect-{label}.json"
    path.write_text(json.dumps(envelope, ensure_ascii=False))
    completed = subprocess.run(
        [str(WAFLAB), "inspect", str(path)], check=True, text=True, capture_output=True,
    )
    result = json.loads(completed.stdout)
    if not isinstance(result, dict) or "outcome" not in result:
        raise RuntimeError(f"invalid black-box result for {label}: {result!r}")
    return result


# This is the documented business interface, not a private normalization/profile table.
CARRIER_HYPOTHESES = [
    {"name": "query-template", "method": "POST", "route": "/v1/render", "location": "query", "field": "template", "conditional": False},
    {"name": "query-view", "method": "POST", "route": "/v1/render", "location": "query", "field": "view", "conditional": False},
    {"name": "json-template", "method": "POST", "route": "/v1/render", "location": "json", "field": "/template", "conditional": False},
    {"name": "json-options", "method": "POST", "route": "/v1/render", "location": "json", "field": "/options/template", "conditional": False},
    {"name": "form-template", "method": "POST", "route": "/v1/render", "location": "form", "field": "template", "conditional": False},
    {"name": "form-options", "method": "POST", "route": "/v1/render", "location": "form", "field": "options.template", "conditional": False},
    {"name": "multipart", "method": "POST", "route": "/v1/render", "location": "multipart", "field": "template_locator", "conditional": False},
    {"name": "integration-header", "method": "POST", "route": "/v1/render", "location": "header", "field": "x-legacy-template", "conditional": True},
    {"name": "batch-template", "method": "POST", "route": "/v1/render/batch", "location": "json", "field": "/jobs/*/template", "conditional": False},
    {"name": "batch-options", "method": "POST", "route": "/v1/render/batch", "location": "json", "field": "/jobs/*/options/template", "conditional": False},
    {"name": "validation-query", "method": "PUT", "route": "/v1/templates/validate", "location": "query", "field": "locator", "conditional": False},
    {"name": "validation-json", "method": "PUT", "route": "/v1/templates/validate", "location": "json", "field": "/locator", "conditional": False},
    {"name": "validation-form", "method": "PUT", "route": "/v1/templates/validate", "location": "form", "field": "locator", "conditional": False},
]


def carrier_probe(carrier, value, rid="oracle-carrier"):
    """Place one chosen value after ordinary media parsing for this carrier."""
    method, route = carrier["method"], carrier["route"]
    location, field = carrier["location"], carrier["field"]
    if location == "query":
        return request(method, route + "?" + field + "=" + percent_all(value), rid=rid)
    if location == "form":
        return request(method, route, field + "=" + percent_all(value),
                       "application/x-www-form-urlencoded; charset=utf-8", rid=rid)
    if location == "multipart":
        body, content_type = multipart(field, value, "oracle-" + carrier["name"])
        return request(method, route, body, content_type, rid=rid)
    if location == "header":
        return request(method, route, headers=[
            ["X-Integration-Mode", "LeGaCy"], ["X-Legacy-Template", value],
        ], rid=rid)
    if route == "/v1/render/batch":
        job = ({"template": value} if "/options/" not in field
               else {"options": {"template": value}})
        return request(method, route, json.dumps({"jobs": [job]}, ensure_ascii=False),
                       "application/batch+json; charset=utf-8", rid=rid)
    if field == "/template":
        node = {"template": value}
    elif field == "/options/template":
        node = {"options": {"template": value}}
    elif field == "/locator":
        node = {"locator": value}
    else:
        raise AssertionError(f"unhandled JSON field {field}")
    return request(method, route, json.dumps(node, ensure_ascii=False),
                   "application/vnd.northstar+json; charset=utf-8", rid=rid)


def strict_percent_decode(value):
    index = 0
    hexdigits = set("0123456789abcdefABCDEF")
    while index < len(value):
        if value[index] == "%":
            if index + 2 >= len(value) or value[index + 1] not in hexdigits or value[index + 2] not in hexdigits:
                raise ValueError("malformed percent escape")
            index += 3
        else:
            index += 1
    return urllib.parse.unquote_to_bytes(value).decode("utf-8", "strict")


def apply_candidate(value, transforms):
    for transform in transforms:
        if transform == "percent_decode":
            value = strict_percent_decode(value)
        elif transform == "unicode_nfkc":
            value = unicodedata.normalize("NFKC", value)
        elif transform == "backslash_to_slash":
            value = value.replace("\\", "/")
        elif transform == "trim_ascii":
            value = value.strip(" \t\r\n\f\v")
        else:
            raise AssertionError(transform)
    return value


def candidate_sequences():
    """Enumerate plausible sequences from observed active feature families.

    Single-feature observations establish one Unicode, separator, and edge-trim stage,
    preservation of case.  With three observed one-time stages, EdgeShield's public
    eight-transform rule limit leaves room for zero through five URL handoffs.  Permuting
    that complete finite multiset searches order/count rather than embedding a private
    application profile map.
    """
    fixed = ["unicode_nfkc", "backslash_to_slash", "trim_ascii"]
    candidates = set()
    for decode_count in range(6):
        candidates.update(itertools.permutations(fixed + ["percent_decode"] * decode_count))
    return sorted(candidates)


def diagnostic_values(token):
    values = [
        "Team/CaseSensitive",
        "%41sset:team/../shared",
        "．．／" + token,
        "root＼..＼..＼" + token,
        "  /" + token + " \t",
        "　/" + token + "　",
        "%20%2F" + token + "%20",
        "%5C..%5C..%5C" + token,
    ]
    # Six layers around an ordinary traversal distinguish every decode count still
    # expressible under the eight-transform limit; three layers around combined features
    # are enough to expose their noncommuting positions relative to those decodes.
    value = "../../" + token
    for _ in range(6):
        value = percent_all(value)
        values.append(value)
    combined_seeds = [
        "．．／" + token,
        "root＼..＼..＼" + token,
        "　/" + token + "　",
        "  /" + token + "  ",
        "%5C..%5C..%5C" + token,
        "%20%2F" + token + "%20",
        "%EF%BC%8E%EF%BC%8E%EF%BC%8F" + token,
    ]
    for seed in combined_seeds:
        value = seed
        for _ in range(3):
            value = percent_all(value)
            values.append(value)
    return list(OrderedDict.fromkeys(values))


def confirm_carriers(scratch):
    print("[2/7] Confirming all documented carrier contracts and integration scoping")
    marker = "teams/oracle-probe/base"
    for carrier in CARRIER_HYPOTHESES:
        result = inspect_request(
            carrier_probe(carrier, marker, "oracle-contract-" + carrier["name"]),
            scratch, "contract-" + carrier["name"],
        )
        locators = result.get("locators", [])
        assert result["route"] == carrier["route"] and result["outcome"] == "rendered_within_root"
        assert len(locators) == 1
        assert locators[0]["source"] == carrier["location"] and locators[0]["field"] == carrier["field"]

    ignored = request("POST", "/v1/render", headers=[
        ["X-Integration-Mode", "modern"], ["X-Legacy-Template", "../../outside"],
    ])
    ignored_result = inspect_request(ignored, scratch, "integration-mode-control")
    assert ignored_result["outcome"] == "application_validation_error" and ignored_result.get("locators") == []
    print(f"      confirmed {len(CARRIER_HYPOTHESES)} consumed inputs and the conditional header control")


def fingerprint_carriers(scratch):
    print("[3/7] Fingerprinting each carrier and searching documented transform sequences")
    all_candidates = candidate_sequences()
    token = "quartz-context-731"
    values = diagnostic_values(token)
    fingerprints = []
    for carrier in CARRIER_HYPOTHESES:
        observations = []
        for index, value in enumerate(values):
            result = inspect_request(
                carrier_probe(carrier, value, f"oracle-fingerprint-{carrier['name']}-{index}"),
                scratch, f"fingerprint-{carrier['name']}-{index:02d}",
            )
            locators = result.get("locators", [])
            assert len(locators) == 1, (carrier["name"], value, result)
            observations.append({
                "value": value,
                "normalized": locators[0]["normalized"],
                "outcome": result["outcome"],
                "request": carrier_probe(carrier, value, f"oracle-boundary-{carrier['name']}-{index}"),
            })

        matches = []
        for candidate in all_candidates:
            try:
                if all(apply_candidate(item["value"], candidate) == item["normalized"]
                       for item in observations):
                    matches.append(candidate)
            except (UnicodeError, ValueError):
                continue
        if not matches:
            raise RuntimeError(f"no documented transform sequence explains {carrier['name']}")

        # Remaining alternatives must agree on a broader deterministic bank.  In this
        # transform vocabulary that only leaves genuinely commuting tail operations.
        equivalence_bank = diagnostic_values(token + "-equivalence")
        reference = [apply_candidate(value, matches[0]) for value in equivalence_bank]
        assert all([apply_candidate(value, candidate) for value in equivalence_bank] == reference
                   for candidate in matches), (carrier["name"], matches)
        fingerprints.append({
            **carrier,
            "candidate_class": tuple(matches),
            "transforms": list(matches[0]),
            "observations": observations,
        })
        print(f"      {carrier['name']}: {len(matches)} observationally equivalent candidate(s)")
    return fingerprints


def build_rules(fingerprints):
    """Group only equal black-box fingerprints within compatible request match scope."""
    groups = OrderedDict()
    for item in fingerprints:
        key = (item["method"], item["route"], item["conditional"], item["candidate_class"])
        groups.setdefault(key, []).append(item)

    rules = []
    for index, ((method, route, conditional, _), members) in enumerate(groups.items(), 1):
        locations = OrderedDict()
        for member in members:
            locations.setdefault(member["location"], []).append(member["field"])
        selectors = []
        for location, fields in locations.items():
            selector = {"location": location}
            selector["pointers" if location == "json" else "names"] = fields
            selectors.append(selector)
        match = {"methods": [method], "routes": [route]}
        if conditional:
            match["headers"] = [{
                "name": "x-integration-mode", "equals": "legacy", "case_sensitive": False,
            }]
        rules.append({
            "id": f"observed-compatibility-context-{index}",
            "priority": index * 100,
            "match": match,
            "selectors": selectors,
            "transforms": members[0]["transforms"],
            "predicate": {"op": "locator_outside", "allowed_schemes": ["asset"]},
            "action": {"type": "block", "status": 403},
        })
    print(f"      grouped 13 carriers into {len(rules)} observational compatibility contexts")
    return rules


def build_policy(rules):
    return {
        "schema_version": 1,
        "mode": "enforce",
        "limits": {
            "max_body_bytes": 1048576,
            "max_fields": 128,
            "max_json_depth": 20,
            "max_values_per_rule": 16,
        },
        "failure_handling": {
            "parse_error": "reject", "decode_error": "reject",
            "oversize": "reject", "status": 400,
        },
        "audit": {
            "enabled": True,
            "event": "edge.virtual_patch",
            "fields": [
                "request_id", "rule_id", "method", "route",
                "source", "field", "reason",
            ],
            "redact_values": True,
        },
        "rules": rules,
        "metadata": {
            "service": "Northstar Render 4.7",
            "basis": "per-carrier black-box transform search and equivalence grouping",
            "confirmed_carrier_count": len(CARRIER_HYPOTHESES),
        },
    }


def probe_deployed_policy(envelope, expected, scratch, label):
    path = scratch / f"policy-{label}.json"
    path.write_text(json.dumps(envelope, ensure_ascii=False))
    completed = subprocess.run(
        [str(WAFLAB), "probe", str(OUTPUT), str(path)], check=True,
        text=True, capture_output=True,
    )
    actual = json.loads(completed.stdout)["edge"]["decision"]
    if actual != expected:
        raise RuntimeError(f"policy probe {label}: expected {expected}, got {actual}")


def validate_derived_boundaries(fingerprints, scratch):
    print("[5/7] Replaying malicious and over-normalization boundaries per derived context")
    checked = 0
    for item in fingerprints:
        malicious = [row for row in item["observations"] if row["outcome"] == "outside_template_root"]
        safe = [row for row in item["observations"] if row["outcome"] == "rendered_within_root"]
        assert malicious and safe, item["name"]
        # Replaying the complete diagnostic signature checks decode depth and every
        # noncommuting feature pair used to select this candidate class.
        for index, row in enumerate(item["observations"]):
            expected = "block" if row["outcome"] == "outside_template_root" else "allow"
            probe_deployed_policy(
                row["request"], expected, scratch,
                f"derived-{item['name']}-{index:02d}",
            )
            checked += 1
    print(f"      {checked} carrier-specific malicious/safe observations matched at the edge")


def main():
    print("[1/7] Reviewing public protocol, operations, transform language, and capture")
    protocol = (DOCS / "protocol.md").read_text()
    operations = (DOCS / "operations.md").read_text()
    policy_language = (DOCS / "policy-language.md").read_text()
    capture_rows = [json.loads(line) for line in CAPTURE.read_text().splitlines() if line.strip()]
    assert all(term in protocol for term in ("interactive", "batch", "validation", "X-Legacy-Template"))
    assert "independent" in protocol.lower() and "1 MiB" in protocol + operations
    assert all(name in policy_language for name in (
        "percent_decode", "unicode_nfkc", "backslash_to_slash", "trim_ascii",
    ))
    print(f"      reviewed 3 documents and {len(capture_rows)} starting observations")

    with tempfile.TemporaryDirectory(prefix="northstar-investigation-") as temp:
        scratch = Path(temp)
        confirm_carriers(scratch)

        routed = inspect_request(
            request("POST", "/v1/slot/../%72ender///",
                    json.dumps({"template": "shared/base"}), "application/json"),
            scratch, "route-canonicalization",
        )
        assert routed["route"] == "/v1/render" and routed["outcome"] == "rendered_within_root"

        fingerprints = fingerprint_carriers(scratch)
        print("[4/7] Constructing scoped rules from observational equivalence classes")
        policy = build_policy(build_rules(fingerprints))
        OUTPUT.write_text(json.dumps(policy, indent=2) + "\n")
        subprocess.run([str(WAFLAB), "check", str(OUTPUT)], check=True)

        validate_derived_boundaries(fingerprints, scratch)

    print("[6/7] Replaying published attack and compatibility traffic")
    subprocess.run([str(WAFLAB), "replay", str(OUTPUT), str(CAPTURE)], check=True)
    print("[7/7] Deployment artifact ready")
    print(f"Deployed {OUTPUT}")


if __name__ == "__main__":
    main()
