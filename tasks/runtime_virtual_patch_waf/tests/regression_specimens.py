#!/usr/bin/env python3
"""Maintainer regression matrix for context-specific behavioral grading.

Usage: python3 regression_specimens.py /path/to/oracle-edge-policy.json
Derivatives are temporary and are graded only through the semantic verifier.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
VERIFY = HERE / "verify.py"

PROFILE_PIPELINES = {
    "interactive_url_form": [
        "percent_decode", "percent_decode", "unicode_nfkc",
        "backslash_to_slash", "trim_ascii",
    ],
    "interactive_document": [
        "unicode_nfkc", "percent_decode", "backslash_to_slash", "trim_ascii",
    ],
    "legacy_integration": [
        "trim_ascii", "percent_decode", "unicode_nfkc", "backslash_to_slash",
    ],
    "batch_dispatch": [
        "percent_decode", "unicode_nfkc", "percent_decode",
        "trim_ascii", "backslash_to_slash",
    ],
    "validation_gateway": [
        "backslash_to_slash", "unicode_nfkc", "percent_decode",
        "percent_decode", "trim_ascii",
    ],
}
PROFILE_CARRIER = {
    "interactive_url_form": "query-template",
    "interactive_document": "json-template",
    "legacy_integration": "integration-header",
    "batch_dispatch": "batch-template",
    "validation_gateway": "validation-query",
}
DOCUMENTED_CARRIER_NAMES = {
    "query-template", "query-view", "json-template", "json-options",
    "form-template", "form-options", "multipart", "integration-header",
    "batch-template", "batch-options", "validation-query", "validation-json",
    "validation-form",
}
OLD_GLOBAL = PROFILE_PIPELINES["interactive_url_form"]

# Freeze the entire r11 matrix by identity, not merely by row count.  Directed substitution
# names are derived from the same stable five-profile cross-product used to create them.
PRIOR_R11_FIXED_SPECIMEN_NAMES = {
    "oracle",
    "equivalent-split-rule",
    "equivalent-selector-segmentation",
    "equivalent-batch-all-indexes",
    "equivalent-twelve-rule",
    "old-five-rule-global-pipeline",
    "extra-http-scheme",
    "missing-asset-scheme",
    "batch-job-zero-only",
    "batch-prior-sampled-indexes-only",
    "batch-index-zero-correct-late-empty",
    "batch-index-zero-correct-late-overdecode",
    "late-benign-pathological-regex",
    "capacity-many-fields-pathological-regex",
    "late-import-pathological-regex",
    "safe-import-boundary-only-exception",
    "import-webkit-boundary-four-hyphens",
    "inert-content-type-route-parser-guard",
    "harmless-neighbor-inactive-form-selector",
    "short-incomplete-boundary-regex",
    "two-case-integration-enumeration",
    "sampled-media-exact-scoping",
    "decoy-audit-misattribution",
}
NEW_R12_SPECIMEN_NAMES = {
    "public-search-q-equals-template",
    "public-events-event-equals-migration",
    "import-application-octet-stream-only-block",
}
NEW_R13_SPECIMEN_NAMES = {
    "import-regex-lowercase-boundary-70",
    "search-q-equals-rule-directed",
    "events-event-contains-rule-directed",
    "import-content-type-application-json-only",
    "contradictory-import-content-type-no-extraction",
}
REGEX_REJECTION = (
    "regex is not supported in EdgeShield v1; use locator_outside/contains/equals"
)

NEW_R14_SPECIMEN_NAMES = {
    "search-positive-lookahead-config-rejection",
    "import-negative-lookahead-branch-config-rejection",
    "search-groupref-config-rejection",
    "events-groupref-config-rejection",
    "import-groupref-config-rejection",
    "search-q-equals-257-rule-directed",
    "import-supported-alternation-later-boundary",
    "oversize-equals-config-rejection",
    "oversize-contains-config-rejection",
    "unbounded-repeat-config-rejection",
}
NEW_REGEX_REMOVAL_SPECIMEN_NAMES = {
    "r14-class-order-regex-config-rejection",
    "events-contains-257-rule-directed",
    "search-equals-4096-rule-directed",
    "events-contains-4096-rule-directed",
}
NEW_R15_SPECIMEN_NAMES = {
    "kelvin-allowed-scheme-config-rejection",
    "effective-uppercase-k-scheme-dynamic-coverage",
    "search-equals-two-percent-decode-config-rejection",
    "events-contains-two-percent-decode-config-rejection",
    "search-equals-4096-permitted-transforms-live",
    "events-contains-4096-permitted-transforms-live",
    "import-contains-4096-permitted-transforms-proven-dead",
}


def prior_r11_specimen_names():
    names = set(PRIOR_R11_FIXED_SPECIMEN_NAMES)
    names.update(
        f"substitute-{actual}-with-{substitute}"
        for actual in PROFILE_PIPELINES
        for substitute in PROFILE_PIPELINES
        if substitute != actual
    )
    return names


def locator_rules(policy):
    return [
        rule for rule in policy.get("rules", [])
        if rule.get("predicate", {}).get("op") == "locator_outside"
    ]


def inferred_rule_profile(rule):
    match = rule.get("match", {})
    routes = set(match.get("routes", []))
    selectors = rule.get("selectors", [])
    locations = {selector.get("location") for selector in selectors}
    if routes == {"/v1/render/batch"}:
        return "batch_dispatch"
    if routes == {"/v1/templates/validate"}:
        return "validation_gateway"
    if routes == {"/v1/render"} and match.get("headers"):
        return "legacy_integration"
    if routes == {"/v1/render"} and locations <= {"query", "form"}:
        return "interactive_url_form"
    if routes == {"/v1/render"} and locations <= {"json", "multipart"}:
        return "interactive_document"
    raise ValueError(f"known-good policy rule has an unexpected mixed context: {rule}")


def profile_rule_indexes(policy):
    indexes = {}
    for index, rule in enumerate(locator_rules(policy)):
        profile = inferred_rule_profile(rule)
        if profile in indexes:
            raise ValueError(f"known-good policy has multiple locator rules for {profile}")
        indexes[profile] = index
    if set(indexes) != set(PROFILE_PIPELINES):
        raise ValueError(f"known-good policy profiles differ from expected behavioral contexts: {indexes}")
    return indexes


def with_profile_transforms(base, profile, transforms):
    specimen = copy.deepcopy(base)
    indexes = profile_rule_indexes(specimen)
    locator_rules(specimen)[indexes[profile]]["transforms"] = list(transforms)
    return specimen


def old_global_policy(base):
    specimen = copy.deepcopy(base)
    for rule in locator_rules(specimen):
        rule["transforms"] = list(OLD_GLOBAL)
    specimen.setdefault("metadata", {})["regression_specimen"] = "copied-old-global-pipeline"
    return specimen


def with_extra_http(base):
    specimen = copy.deepcopy(base)
    for rule in locator_rules(specimen):
        allowed = rule["predicate"]["allowed_schemes"]
        if not any(item.lower() == "http" for item in allowed):
            allowed.append("http")
    return specimen


def without_asset(base):
    specimen = copy.deepcopy(base)
    for rule in locator_rules(specimen):
        rule["predicate"]["allowed_schemes"] = [
            item for item in rule["predicate"]["allowed_schemes"]
            if item.lower() != "asset"
        ]
    return specimen


def with_kelvin_scheme(base):
    """U+212A lowercases to ASCII k, so original-spelling validation is essential."""
    specimen = copy.deepcopy(base)
    for rule in locator_rules(specimen):
        rule["predicate"]["allowed_schemes"].append("K")
    return specimen


def with_effective_ascii_k_scheme(base):
    """Uppercase ASCII K is valid syntax but authorizes the effective k: namespace."""
    specimen = copy.deepcopy(base)
    for rule in locator_rules(specimen):
        rule["predicate"]["allowed_schemes"].append("K")
    return specimen


def batch_job_zero_only(base):
    specimen = copy.deepcopy(base)
    indexes = profile_rule_indexes(specimen)
    rule = locator_rules(specimen)[indexes["batch_dispatch"]]
    replacements = 0
    for selector in rule["selectors"]:
        if selector.get("location") != "json":
            continue
        updated = []
        for pointer in selector["pointers"]:
            replacement = pointer.replace("/jobs/*/", "/jobs/0/")
            replacements += int(replacement != pointer)
            updated.append(replacement)
        selector["pointers"] = updated
    if replacements != 2:
        raise ValueError(f"expected two wildcard batch pointers, replaced {replacements}")
    return specimen


def batch_prior_sampled_indexes_only(base):
    """Enumerate exactly the five positions exercised before the full matrix existed."""
    specimen = copy.deepcopy(base)
    indexes = profile_rule_indexes(specimen)
    rule = locator_rules(specimen)[indexes["batch_dispatch"]]
    prior_indexes = (0, 1, 4, 9, 15)
    replacements = 0
    for selector in rule["selectors"]:
        if selector.get("location") != "json":
            continue
        updated = []
        for pointer in selector["pointers"]:
            if "/jobs/*/" not in pointer:
                updated.append(pointer)
                continue
            replacements += 1
            updated.extend(
                pointer.replace("/jobs/*/", f"/jobs/{batch_index}/")
                for batch_index in prior_indexes
            )
        selector["pointers"] = updated
    if replacements != 2:
        raise ValueError(f"expected two wildcard batch pointers, replaced {replacements}")
    return specimen


def batch_all_indexes_equivalent(base):
    """Express wildcard-equivalent coverage without relying on literal '*' spelling."""
    specimen = copy.deepcopy(base)
    indexes = profile_rule_indexes(specimen)
    rule = locator_rules(specimen)[indexes["batch_dispatch"]]
    replacements = 0
    for selector in rule["selectors"]:
        if selector.get("location") != "json":
            continue
        updated = []
        for pointer in selector["pointers"]:
            if "/jobs/*/" not in pointer:
                updated.append(pointer)
                continue
            replacements += 1
            updated.extend(
                pointer.replace("/jobs/*/", f"/jobs/{batch_index}/")
                for batch_index in range(16)
            )
        selector["pointers"] = updated
    if replacements != 2:
        raise ValueError(f"expected two wildcard batch pointers, replaced {replacements}")
    return specimen


def batch_index_zero_correct_late_transforms(base, late_transforms, marker):
    """Keep job zero correct but assign one explicit wrong-transform rule to indices 1..15."""
    specimen = copy.deepcopy(base)
    indexes = profile_rule_indexes(specimen)
    original = locator_rules(specimen)[indexes["batch_dispatch"]]
    late = copy.deepcopy(original)
    replacements = 0

    for selector in original["selectors"]:
        if selector.get("location") != "json":
            continue
        updated = []
        for pointer in selector["pointers"]:
            if "/jobs/*/" not in pointer:
                updated.append(pointer)
                continue
            replacements += 1
            updated.append(pointer.replace("/jobs/*/", "/jobs/0/"))
        selector["pointers"] = updated

    for selector in late["selectors"]:
        if selector.get("location") != "json":
            continue
        updated = []
        for pointer in selector["pointers"]:
            if "/jobs/*/" not in pointer:
                updated.append(pointer)
                continue
            updated.extend(
                pointer.replace("/jobs/*/", f"/jobs/{batch_index}/")
                for batch_index in range(1, 16)
            )
        selector["pointers"] = updated
    if replacements != 2:
        raise ValueError(f"expected two wildcard batch pointers, replaced {replacements}")

    used_priorities = {rule["priority"] for rule in specimen["rules"]}
    late["id"] = f"batch-late-{marker}"
    late["priority"] = next(
        candidate for candidate in range(10001) if candidate not in used_priorities
    )
    late["transforms"] = list(late_transforms)
    specimen["rules"].append(late)
    return specimen


def batch_late_empty_transforms(base):
    return batch_index_zero_correct_late_transforms(base, [], "empty-transforms")


def batch_late_overdecode_transforms(base):
    return batch_index_zero_correct_late_transforms(
        base,
        [
            "percent_decode", "unicode_nfkc", "percent_decode",
            "percent_decode", "trim_ascii", "backslash_to_slash",
        ],
        "overdecode-transforms",
    )


def short_incomplete_boundary_regex(base):
    """Retain the prior incomplete-boundary negative with a supported predicate."""
    specimen = copy.deepcopy(base)
    rules = locator_rules(specimen)
    if len(rules) != len(PROFILE_PIPELINES):
        raise ValueError("known-good policy does not have five boundary rules")
    for rule in rules:
        rule["transforms"] = [
            transform for transform in rule.get("transforms", [])
            if transform != "percent_decode"
        ]
        rule["predicate"] = {
            "op": "contains", "needle": "../../", "case_sensitive": True,
        }
    return specimen


def two_case_integration_enumeration(base):
    specimen = copy.deepcopy(base)
    indexes = profile_rule_indexes(specimen)
    original = locator_rules(specimen)[indexes["legacy_integration"]]
    clone = copy.deepcopy(original)
    mode_conditions = [
        condition for condition in original["match"].get("headers", [])
        if condition.get("name", "").lower() == "x-integration-mode"
    ]
    if len(mode_conditions) != 1:
        raise ValueError("known-good integration rule lacks one mode condition")
    mode_conditions[0]["equals"] = "LeGaCy"
    mode_conditions[0]["case_sensitive"] = True
    clone_condition = next(
        condition for condition in clone["match"]["headers"]
        if condition.get("name", "").lower() == "x-integration-mode"
    )
    clone_condition["equals"] = "legacy"
    clone_condition["case_sensitive"] = True
    clone["id"] = "enumerated-integration-legacy"
    used_priorities = {rule["priority"] for rule in specimen["rules"]}
    clone["priority"] = next(
        priority for priority in range(10000, -1, -1)
        if priority not in used_priorities
    )
    specimen["rules"].append(clone)
    return specimen


def decoy_audit_misattribution(base):
    specimen = copy.deepcopy(base)
    used_priorities = {rule["priority"] for rule in specimen["rules"]}
    priority = next(value for value in range(0, 10001) if value not in used_priorities)
    specimen["rules"].append({
        "id": "decoy-query-attribution",
        "priority": priority,
        "match": {"methods": ["POST"], "routes": ["/v1/render"]},
        "selectors": [{"location": "query", "names": ["diagnostic"]}],
        "transforms": list(PROFILE_PIPELINES["interactive_url_form"]),
        "predicate": {"op": "locator_outside", "allowed_schemes": ["asset"]},
        "action": {"type": "block", "status": 403},
    })
    return specimen


def late_benign_pathological_regex(base):
    specimen = copy.deepcopy(base)
    used_priorities = {rule["priority"] for rule in specimen["rules"]}
    maximum = max(used_priorities)
    priority = next(
        (candidate for candidate in range(maximum + 1, 10001)
         if candidate not in used_priorities),
        None,
    )
    if priority is None:
        raise ValueError("known-good policy leaves no later priority for regression rule")
    specimen["rules"].append({
        "id": "late-benign-pathological-regex",
        "priority": priority,
        "match": {
            "methods": ["PUT"],
            "routes": ["/v1/templates/validate"],
            "headers": [{
                "name": "Content-Type",
                "equals": "application/problem+json",
                "case_sensitive": True,
            }],
        },
        "selectors": [{"location": "json", "pointers": ["/locator"]}],
        "transforms": [],
        "predicate": {"op": "regex", "pattern": r"(?:.{0,3}){11}Z"},
        "action": {"type": "block", "status": 403},
    })
    return specimen


def singleton_pathological_regex(base, *, rule_id, methods, routes, headers):
    """Add a catastrophic rule reachable only from one post-primary singleton check."""
    specimen = copy.deepcopy(base)
    used_priorities = {rule["priority"] for rule in specimen["rules"]}
    priority = next(
        candidate for candidate in range(10001) if candidate not in used_priorities
    )
    specimen["rules"].append({
        "id": rule_id,
        "priority": priority,
        "match": {
            "methods": list(methods),
            "routes": list(routes),
            "headers": copy.deepcopy(headers),
        },
        "selectors": [{"location": "header", "names": ["authorization"]}],
        "transforms": [],
        "predicate": {"op": "regex", "pattern": r"(?:.{0,3}){11}Z"},
        "action": {"type": "block", "status": 403},
    })
    return specimen


def capacity_many_fields_pathological_regex(base):
    return singleton_pathological_regex(
        base,
        rule_id="capacity-many-fields-pathological",
        methods=["PUT"],
        routes=["/v1/templates/validate"],
        headers=[{
            "name": "X-Request-ID",
            "equals": "cap-many-within",
            "case_sensitive": True,
        }],
    )


def late_import_pathological_regex(base):
    return singleton_pathological_regex(
        base,
        rule_id="late-import-pathological",
        methods=["POST"],
        routes=["/v1/templates/import"],
        headers=[{
            "name": "Content-Type",
            "equals": "multipart/form-data; boundary=capacity-import-1m",
            "case_sensitive": True,
        }],
    )


def safe_import_boundary_only_exception(base):
    """Retain the safe-import collateral negative with a supported contains rule."""
    specimen = copy.deepcopy(base)
    used_priorities = {rule["priority"] for rule in specimen["rules"]}
    priority = next(
        candidate for candidate in range(10001) if candidate not in used_priorities
    )
    specimen["rules"].append({
        "id": "safe-import-boundary-only-exception",
        "priority": priority,
        "match": {
            "methods": ["POST"],
            "routes": ["/v1/templates/import"],
        },
        "selectors": [{"location": "header", "names": ["Content-Type"]}],
        "transforms": ["lowercase"],
        "predicate": {
            "op": "contains", "needle": "multipart/form-data",
            "case_sensitive": True,
        },
        "action": {"type": "block", "status": 403},
    })
    return specimen


def import_webkit_boundary_four_hyphens(base):
    """Exact r9 blocker: deny any import Content-Type with four boundary hyphens."""
    specimen = copy.deepcopy(base)
    used_priorities = {rule["priority"] for rule in specimen["rules"]}
    priority = next(
        candidate for candidate in range(10001) if candidate not in used_priorities
    )
    specimen["rules"].append({
        "id": "deny-four-hyphen-import-boundary",
        "priority": priority,
        "match": {
            "methods": ["POST"],
            "routes": ["/v1/templates/import"],
        },
        "selectors": [{"location": "header", "names": ["Content-Type"]}],
        "transforms": ["lowercase"],
        "predicate": {
            "op": "contains", "needle": "boundary=----", "case_sensitive": True,
        },
        "action": {"type": "block", "status": 403},
    })
    return specimen


def inert_content_type_route_parser_guard(base):
    """Reachable scope with a transform-provably dead supported predicate."""
    specimen = copy.deepcopy(base)
    used_priorities = {rule["priority"] for rule in specimen["rules"]}
    priority = next(
        candidate for candidate in range(10001) if candidate not in used_priorities
    )
    specimen["rules"].append({
        "id": "inert-content-type-route-parser-guard",
        "priority": priority,
        "match": {
            "methods": ["POST"],
            "routes": ["/v1/templates/import"],
        },
        "selectors": [{"location": "header", "names": ["Content-Type"]}],
        "transforms": ["lowercase"],
        "predicate": {
            "op": "equals", "value": "application/json", "case_sensitive": True,
        },
        "action": {"type": "block", "status": 403},
    })
    return specimen


def harmless_neighbor_inactive_form_selector(base):
    """Broad neighbor scope whose form selector is inactive for every valid shape.

    The method/route arrays intentionally form a wide Cartesian scope covering the exact
    published import, search, and events paths.  Its predicate would block any extracted
    string, but imports are multipart/header, search is query/header, and events are
    JSON/header.  None of those supported request grammars populates ``form``.
    """
    specimen = copy.deepcopy(base)
    used_priorities = {rule["priority"] for rule in specimen["rules"]}
    priority = next(
        candidate for candidate in range(10001) if candidate not in used_priorities
    )
    specimen["rules"].append({
        "id": "harmless-neighbor-inactive-form",
        "priority": priority,
        "match": {
            "methods": ["GET", "POST"],
            "routes": [
                "/v1/templates/import", "/v1/search", "/v1/events",
            ],
        },
        "selectors": [{"location": "form", "names": ["locator"]}],
        "transforms": [],
        "predicate": {
            "op": "equals", "value": "application/json", "case_sensitive": True,
        },
        "action": {"type": "block", "status": 418},
    })
    return specimen


def public_search_q_template_block(base):
    """Exact r11 blocker: deny the public search row only because q == template."""
    specimen = copy.deepcopy(base)
    used_priorities = {rule["priority"] for rule in specimen["rules"]}
    priority = next(candidate for candidate in range(10001) if candidate not in used_priorities)
    specimen["rules"].append({
        "id": "deny-public-search-q-template",
        "priority": priority,
        "match": {"methods": ["GET"], "routes": ["/v1/search"]},
        "selectors": [{"location": "query", "names": ["q"]}],
        "transforms": [],
        "predicate": {
            "op": "equals", "value": "template", "case_sensitive": True,
        },
        "action": {"type": "block", "status": 403},
    })
    return specimen


def public_events_migration_block(base):
    """Exact r11 blocker: deny the public opaque event only at /event == migration."""
    specimen = copy.deepcopy(base)
    used_priorities = {rule["priority"] for rule in specimen["rules"]}
    priority = next(candidate for candidate in range(10001) if candidate not in used_priorities)
    specimen["rules"].append({
        "id": "deny-public-event-migration",
        "priority": priority,
        "match": {"methods": ["POST"], "routes": ["/v1/events"]},
        "selectors": [{"location": "json", "pointers": ["/event"]}],
        "transforms": [],
        "predicate": {
            "op": "equals", "value": "migration", "case_sensitive": True,
        },
        "action": {"type": "block", "status": 403},
    })
    return specimen


def import_octet_stream_only_block(base):
    """Positive control: exact octet-stream is outside the multipart import contract."""
    specimen = copy.deepcopy(base)
    used_priorities = {rule["priority"] for rule in specimen["rules"]}
    priority = next(candidate for candidate in range(10001) if candidate not in used_priorities)
    specimen["rules"].append({
        "id": "deny-import-application-octet-stream-only",
        "priority": priority,
        "match": {"methods": ["POST"], "routes": ["/v1/templates/import"]},
        "selectors": [{"location": "header", "names": ["Content-Type"]}],
        "transforms": ["lowercase"],
        "predicate": {
            "op": "equals", "value": "application/octet-stream",
            "case_sensitive": True,
        },
        "action": {"type": "block", "status": 415},
    })
    return specimen


def append_neighbor_rule(base, rule):
    specimen = copy.deepcopy(base)
    used_priorities = {item["priority"] for item in specimen["rules"]}
    appended = copy.deepcopy(rule)
    appended["priority"] = next(
        candidate for candidate in range(10001) if candidate not in used_priorities
    )
    specimen["rules"].append(appended)
    return specimen


def import_lowercase_boundary_70_block(base):
    return append_neighbor_rule(base, {
        "id": "deny-import-lowercase-boundary-70",
        "match": {"methods": ["POST"], "routes": ["/v1/templates/import"]},
        "selectors": [{"location": "header", "names": ["Content-Type"]}],
        "transforms": [],
        "predicate": {
            "op": "regex",
            "pattern": r"^multipart/form-data;\s{0,8}boundary=[a-z]{70}$",
        },
        "action": {"type": "block", "status": 415},
    })


def search_rule_directed_equals_block(base):
    return append_neighbor_rule(base, {
        "id": "deny-search-rule-directed-exact",
        "match": {"methods": ["GET"], "routes": ["/v1/search"]},
        "selectors": [{"location": "query", "names": ["q"]}],
        "transforms": [],
        "predicate": {
            "op": "equals", "value": "r13-rule-directed-search-term",
            "case_sensitive": True,
        },
        "action": {"type": "block", "status": 403},
    })


def events_rule_directed_contains_block(base):
    return append_neighbor_rule(base, {
        "id": "deny-events-rule-directed-fragment",
        "match": {"methods": ["POST"], "routes": ["/v1/events"]},
        "selectors": [{"location": "json", "pointers": ["/event"]}],
        "transforms": [],
        "predicate": {
            "op": "contains", "needle": "r13-rule-directed-event-fragment",
            "case_sensitive": True,
        },
        "action": {"type": "block", "status": 403},
    })


def inert_import_application_json_only(base):
    return append_neighbor_rule(base, {
        "id": "inert-import-application-json-only",
        "match": {"methods": ["POST"], "routes": ["/v1/templates/import"]},
        "selectors": [{"location": "header", "names": ["Content-Type"]}],
        "transforms": ["lowercase"],
        "predicate": {
            "op": "equals", "value": "application/json", "case_sensitive": True,
        },
        "action": {"type": "block", "status": 415},
    })


def inert_import_contradictory_media_no_extraction(base):
    return append_neighbor_rule(base, {
        "id": "inert-import-contradictory-media-no-extraction",
        "match": {
            "methods": ["POST"], "routes": ["/v1/templates/import"],
            "headers": [
                {"name": "Content-Type", "equals": "application/json", "case_sensitive": False},
                {"name": "Content-Type", "equals": "text/plain", "case_sensitive": False},
            ],
        },
        "selectors": [{"location": "multipart", "names": ["template"]}],
        "transforms": [],
        "predicate": {
            "op": "equals", "value": "application/json", "case_sensitive": True,
        },
        "action": {"type": "block", "status": 418},
    })


def search_positive_lookahead_config_rejection(base):
    return append_neighbor_rule(base, {
        "id": "reject-search-positive-lookahead",
        "match": {"methods": ["GET"], "routes": ["/v1/search"]},
        "selectors": [{"location": "query", "names": ["q"]}],
        "transforms": [],
        "predicate": {"op": "regex", "pattern": r"^(?=abc)ab.c$"},
        "action": {"type": "block", "status": 403},
    })


def import_negative_lookahead_branch_config_rejection(base):
    return append_neighbor_rule(base, {
        "id": "reject-import-negative-lookahead-branch",
        "match": {"methods": ["POST"], "routes": ["/v1/templates/import"]},
        "selectors": [{"location": "header", "names": ["Content-Type"]}],
        "transforms": [
            "percent_decode", "unicode_nfkc", "backslash_to_slash", "trim_ascii",
        ],
        "predicate": {
            "op": "regex",
            "pattern": (
                r"(?:(?!a)a|^multipart/form-data;\s*boundary=[b-z]{70}$)"
            ),
        },
        "action": {"type": "block", "status": 415},
    })


def search_groupref_config_rejection(base):
    return append_neighbor_rule(base, {
        "id": "reject-search-groupref",
        "match": {"methods": ["GET"], "routes": ["/v1/search"]},
        "selectors": [{"location": "query", "names": ["q"]}],
        "transforms": [],
        "predicate": {"op": "regex", "pattern": r"^(x)\1$"},
        "action": {"type": "block", "status": 403},
    })


def events_groupref_config_rejection(base):
    return append_neighbor_rule(base, {
        "id": "reject-events-groupref",
        "match": {"methods": ["POST"], "routes": ["/v1/events"]},
        "selectors": [{"location": "json", "pointers": ["/event"]}],
        "transforms": [],
        "predicate": {"op": "regex", "pattern": r"^(x)\1$"},
        "action": {"type": "block", "status": 403},
    })


def import_groupref_config_rejection(base):
    return append_neighbor_rule(base, {
        "id": "reject-import-groupref",
        "match": {"methods": ["POST"], "routes": ["/v1/templates/import"]},
        "selectors": [{"location": "header", "names": ["Content-Type"]}],
        "transforms": [],
        "predicate": {
            "op": "regex",
            "pattern": (
                r"^multipart/form-data;\s{0,8}boundary=([a-z]{20})-\1$"
            ),
        },
        "action": {"type": "block", "status": 415},
    })


def search_equals_257_block(base):
    return append_neighbor_rule(base, {
        "id": "deny-search-equals-257",
        "match": {"methods": ["GET"], "routes": ["/v1/search"]},
        "selectors": [{"location": "query", "names": ["q"]}],
        "transforms": [],
        "predicate": {
            "op": "equals", "value": "A" * 257, "case_sensitive": True,
        },
        "action": {"type": "block", "status": 403},
    })


def events_contains_257_block(base):
    return append_neighbor_rule(base, {
        "id": "deny-events-contains-257",
        "match": {"methods": ["POST"], "routes": ["/v1/events"]},
        "selectors": [{"location": "json", "pointers": ["/event"]}],
        "transforms": [],
        "predicate": {
            "op": "contains", "needle": "C" * 257, "case_sensitive": True,
        },
        "action": {"type": "block", "status": 403},
    })


def search_equals_4096_block(base):
    return append_neighbor_rule(base, {
        "id": "deny-search-equals-4096",
        "match": {"methods": ["GET"], "routes": ["/v1/search"]},
        "selectors": [{"location": "query", "names": ["q"]}],
        "transforms": [],
        "predicate": {
            "op": "equals", "value": "E" * 4096, "case_sensitive": True,
        },
        "action": {"type": "block", "status": 403},
    })


def events_contains_4096_block(base):
    return append_neighbor_rule(base, {
        "id": "deny-events-contains-4096",
        "match": {"methods": ["POST"], "routes": ["/v1/events"]},
        "selectors": [{"location": "json", "pointers": ["/event"]}],
        "transforms": [],
        "predicate": {
            "op": "contains", "needle": "N" * 4096, "case_sensitive": True,
        },
        "action": {"type": "block", "status": 403},
    })


def search_equals_two_percent_decode_config_rejection(base):
    return append_neighbor_rule(base, {
        "id": "reject-search-equals-two-percent-decode",
        "match": {"methods": ["GET"], "routes": ["/v1/search"]},
        "selectors": [{"location": "query", "names": ["q"]}],
        "transforms": ["percent_decode", "percent_decode"],
        "predicate": {
            "op": "equals", "value": "%" * 4096, "case_sensitive": True,
        },
        "action": {"type": "block", "status": 403},
    })


def events_contains_two_percent_decode_config_rejection(base):
    return append_neighbor_rule(base, {
        "id": "reject-events-contains-two-percent-decode",
        "match": {"methods": ["POST"], "routes": ["/v1/events"]},
        "selectors": [{"location": "json", "pointers": ["/event"]}],
        "transforms": ["percent_decode", "percent_decode"],
        "predicate": {
            "op": "contains", "needle": "%" * 4096, "case_sensitive": True,
        },
        "action": {"type": "block", "status": 403},
    })


def search_equals_4096_permitted_transforms_live(base):
    return append_neighbor_rule(base, {
        "id": "deny-search-equals-4096-permitted-live",
        "match": {"methods": ["GET"], "routes": ["/v1/search"]},
        "selectors": [{"location": "query", "names": ["q"]}],
        "transforms": [
            "unicode_nfkc", "backslash_to_slash", "trim_ascii", "lowercase",
        ],
        "predicate": {
            "op": "equals", "value": "İ" * 2048, "case_sensitive": False,
        },
        "action": {"type": "block", "status": 403},
    })


def events_contains_4096_permitted_transforms_live(base):
    return append_neighbor_rule(base, {
        "id": "deny-events-contains-4096-permitted-live",
        "match": {"methods": ["POST"], "routes": ["/v1/events"]},
        "selectors": [{"location": "json", "pointers": ["/event"]}],
        "transforms": [
            "unicode_nfkc", "backslash_to_slash", "trim_ascii", "lowercase",
        ],
        "predicate": {
            "op": "contains", "needle": "İ" * 2048, "case_sensitive": False,
        },
        "action": {"type": "block", "status": 403},
    })


def import_contains_4096_permitted_transforms_proven_dead(base):
    return append_neighbor_rule(base, {
        "id": "inert-import-contains-4096-permitted-dead",
        "match": {
            "methods": ["POST"],
            "routes": ["/v1/templates/import"],
            "headers": [{
                "name": "Content-Type", "equals": "application/json",
                "case_sensitive": False,
            }],
        },
        "selectors": [{"location": "multipart", "names": ["template"]}],
        "transforms": [
            "unicode_nfkc", "backslash_to_slash", "lowercase", "trim_ascii",
        ],
        "predicate": {
            "op": "contains", "needle": "b" * 4096, "case_sensitive": True,
        },
        "action": {"type": "block", "status": 415},
    })


def r14_class_order_regex_config_rejection(base):
    """Exact final allowed-regex fairness reproducer; regex is now schema-invalid."""
    return append_neighbor_rule(base, {
        "id": "reject-r14-class-order-import",
        "match": {"methods": ["POST"], "routes": ["/v1/templates/import"]},
        "selectors": [{"location": "header", "names": ["Content-Type"]}],
        "transforms": [],
        "predicate": {
            "op": "regex", "pattern": r"^mult[pi]part/form-data; boundary=q{37}$",
        },
        "action": {"type": "block", "status": 415},
    })


def import_supported_later_branch_boundary_block(base):
    """First branch cannot be a legal multipart import; the second is causal."""
    return append_neighbor_rule(base, {
        "id": "deny-import-supported-later-boundary",
        "match": {"methods": ["POST"], "routes": ["/v1/templates/import"]},
        "selectors": [{"location": "header", "names": ["Content-Type"]}],
        "transforms": [],
        "predicate": {
            "op": "regex",
            "pattern": (
                r"(?:^application/json$|"
                r"^multipart/form-data;\s{0,8}boundary=[b-z]{70}$)"
            ),
        },
        "action": {"type": "block", "status": 415},
    })


def oversize_equals_config_rejection(base):
    return append_neighbor_rule(base, {
        "id": "reject-search-oversize-equals",
        "match": {"methods": ["GET"], "routes": ["/v1/search"]},
        "selectors": [{"location": "query", "names": ["q"]}],
        "transforms": [],
        "predicate": {
            "op": "equals", "value": "E" * 4097, "case_sensitive": True,
        },
        "action": {"type": "block", "status": 403},
    })


def oversize_contains_config_rejection(base):
    return append_neighbor_rule(base, {
        "id": "reject-events-oversize-contains",
        "match": {"methods": ["POST"], "routes": ["/v1/events"]},
        "selectors": [{"location": "json", "pointers": ["/event"]}],
        "transforms": [],
        "predicate": {
            "op": "contains", "needle": "N" * 4097, "case_sensitive": True,
        },
        "action": {"type": "block", "status": 403},
    })


def unbounded_repeat_config_rejection(base):
    return append_neighbor_rule(base, {
        "id": "reject-search-unbounded-repeat",
        "match": {"methods": ["GET"], "routes": ["/v1/search"]},
        "selectors": [{"location": "query", "names": ["q"]}],
        "transforms": [],
        "predicate": {"op": "regex", "pattern": r"^a+$"},
        "action": {"type": "block", "status": 403},
    })


def sampled_media_exact_scoping(base):
    specimen = copy.deepcopy(base)
    emitted = []
    sampled = {
        "/v1/render": [
            "application/vnd.northstar+json; charset=utf-8", "application/json",
        ],
        "/v1/render/batch": [
            "application/batch+json; charset=utf-8", "application/json",
        ],
        "/v1/templates/validate": [
            "application/vnd.northstar+json; charset=utf-8", "application/json",
        ],
    }
    for rule in specimen["rules"]:
        json_selectors = [copy.deepcopy(selector) for selector in rule["selectors"]
                          if selector.get("location") == "json"]
        other_selectors = [copy.deepcopy(selector) for selector in rule["selectors"]
                           if selector.get("location") != "json"]
        if not json_selectors:
            emitted.append(copy.deepcopy(rule))
            continue
        routes = rule["match"].get("routes", [])
        if len(routes) != 1 or routes[0] not in sampled:
            raise ValueError(f"unexpected JSON rule route shape: {routes}")
        if other_selectors:
            other_rule = copy.deepcopy(rule)
            other_rule["selectors"] = other_selectors
            emitted.append(other_rule)
        for content_type in sampled[routes[0]]:
            scoped = copy.deepcopy(rule)
            scoped["selectors"] = copy.deepcopy(json_selectors)
            scoped["match"].setdefault("headers", []).append({
                "name": "Content-Type", "equals": content_type,
                "case_sensitive": False,
            })
            emitted.append(scoped)

    # This matching but nonextracting route guard preserves fail-closed malformed behavior
    # without protecting any valid unsampled +json body.
    emitted.append({
        "id": "sampled-media-malformed-guard",
        "priority": 9999,
        "match": {
            "methods": ["POST", "PUT"],
            "routes": ["/v1/render", "/v1/render/batch", "/v1/templates/validate"],
        },
        "selectors": [{"location": "header", "names": ["x-absent-media-guard"]}],
        "transforms": [],
        "predicate": {
            "op": "equals", "value": "application/json", "case_sensitive": True,
        },
        "action": {"type": "block", "status": 403},
    })
    if len(emitted) > 12:
        raise ValueError(f"sampled media specimen unexpectedly needs {len(emitted)} rules")
    for index, rule in enumerate(emitted):
        rule["id"] = f"sampled-media-{index:02d}"
        rule["priority"] = 700 + index * 19
    specimen["rules"] = emitted
    return specimen


def equivalent_base_choices(base):
    specimen = copy.deepcopy(base)
    specimen["audit"]["event"] = "edge.regression.equivalent"
    specimen["failure_handling"]["status"] = 422
    specimen["limits"]["max_fields"] = max(128, specimen["limits"]["max_fields"])
    specimen["limits"]["max_json_depth"] = max(20, specimen["limits"]["max_json_depth"])
    specimen.setdefault("metadata", {})["maintainer_note"] = "structural positive control"
    for index, rule in enumerate(specimen["rules"]):
        rule["id"] = f"equivalent-context-{index:02d}"
        rule["priority"] = 600 + index * 17
        rule["action"]["status"] = 451
        rule["selectors"] = list(reversed(rule["selectors"]))
        for selector in rule["selectors"]:
            key = "pointers" if selector.get("location") == "json" else "names"
            selector[key] = list(reversed(selector[key]))
        predicate = rule.get("predicate", {})
        if predicate.get("op") == "locator_outside":
            predicate["allowed_schemes"] = [
                "AsSeT" if item.lower() == "asset" else item
                for item in predicate["allowed_schemes"]
            ]
        for condition in rule.get("match", {}).get("headers", []):
            if condition["name"].lower() == "x-integration-mode":
                condition["name"] = "X-INTEGRATION-MODE"
                condition["equals"] = "LEGACY"
    return specimen


def equivalent_split_rule(base):
    specimen = equivalent_base_choices(base)
    index = next(
        (index for index, rule in enumerate(specimen["rules"])
         if len(rule.get("selectors", [])) > 1),
        None,
    )
    if index is None:
        raise ValueError("known-good policy has no multi-selector context to split")
    original = specimen["rules"][index]
    detached = copy.deepcopy(original)
    original["selectors"] = [original["selectors"][0]]
    detached["selectors"] = detached["selectors"][1:]
    detached["id"] = "equivalent-detached-context"
    specimen["rules"].append(detached)
    for rule_index, rule in enumerate(specimen["rules"]):
        rule["priority"] = 500 + rule_index * 19
    return specimen


def equivalent_selector_segmentation(base):
    specimen = equivalent_base_choices(base)
    for rule in specimen["rules"]:
        split = []
        for selector in rule["selectors"]:
            key = "pointers" if selector.get("location") == "json" else "names"
            for value in selector[key]:
                split.append({"location": selector["location"], key: [value]})
        rule["selectors"] = split
    return specimen


def equivalent_twelve_rule(base):
    """Split the 13 carriers across exactly 12 semantically correct rules."""
    specimen = equivalent_base_choices(base)
    per_carrier = []
    origins = []
    for origin, rule in enumerate(specimen["rules"]):
        for selector in rule["selectors"]:
            key = "pointers" if selector.get("location") == "json" else "names"
            for value in selector[key]:
                clone = copy.deepcopy(rule)
                clone["selectors"] = [{"location": selector["location"], key: [value]}]
                per_carrier.append(clone)
                origins.append(origin)
    if len(per_carrier) != 13 or origins[0] != origins[1]:
        raise ValueError("known-good policy did not expand to the expected 13 carriers")

    # Combining any two carriers from the same compatibility context yields 12 rules.
    combined = per_carrier[0]
    combined["selectors"].extend(per_carrier[1]["selectors"])
    specimen["rules"] = [combined] + per_carrier[2:]
    if len(specimen["rules"]) != 12:
        raise AssertionError("exactly-12-rule positive control construction failed")
    for index, rule in enumerate(specimen["rules"]):
        rule["id"] = f"equivalent-twelve-{index:02d}"
        rule["priority"] = 400 + index * 23
    return specimen


def verifier_source_contract():
    """Maintainer AST/hash gate for guarded, complete public-capture grading."""
    source = VERIFY.read_text()
    tree = ast.parse(source, filename=str(VERIFY))

    assignments = {}
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name) and target.id in {
                    "PUBLISHED_CAPTURE_SHA256", "PUBLISHED_CAPTURE_EXPECTATIONS",
                }:
                    assignments[target.id] = ast.literal_eval(node.value)
    expected_manifest = assignments.get("PUBLISHED_CAPTURE_EXPECTATIONS")
    expected_digest = assignments.get("PUBLISHED_CAPTURE_SHA256")
    if not isinstance(expected_manifest, tuple) or len(expected_manifest) != 21:
        raise AssertionError("verifier AST does not embed the exact 21-row capture manifest")

    private_capture = HERE / "public_representative.jsonl"
    public_capture = HERE.parent / "environment" / "assets" / "public" / "traffic" / "representative.jsonl"
    private_raw = private_capture.read_bytes()
    public_raw = public_capture.read_bytes()
    observed_digest = hashlib.sha256(private_raw).hexdigest()
    if private_raw != public_raw or observed_digest != expected_digest:
        raise AssertionError("public/private representative captures or embedded digest drifted")
    observed_manifest = tuple(
        (row.get("id"), row.get("decision"))
        for row in (json.loads(line) for line in private_raw.decode("utf-8").splitlines())
    )
    if observed_manifest != expected_manifest:
        raise AssertionError("capture bytes do not match the embedded ordered ID/decision manifest")

    raw_call_owners = []
    capture_guard_prefixes = []
    exact_multipart_sizes = []

    class ContractVisitor(ast.NodeVisitor):
        def __init__(self):
            self.functions = []

        def visit_FunctionDef(self, node):
            self.functions.append(node.name)
            self.generic_visit(node)
            self.functions.pop()

        def visit_Call(self, node):
            owner = self.functions[-1] if self.functions else "<module>"
            if isinstance(node.func, ast.Name) and node.func.id == "evaluate_policy":
                raw_call_owners.append(owner)
            if isinstance(node.func, ast.Name) and node.func.id == "guarded_evaluate" and len(node.args) >= 3:
                label = node.args[2]
                if (
                    isinstance(label, ast.BinOp)
                    and isinstance(label.op, ast.Add)
                    and isinstance(label.left, ast.Constant)
                    and label.left.value in {"published-primary-", "published-complete-"}
                ):
                    capture_guard_prefixes.append(label.left.value)
            if isinstance(node.func, ast.Name) and node.func.id == "exact_size_multipart" and node.args:
                try:
                    exact_multipart_sizes.append(ast.literal_eval(node.args[0]))
                except Exception:
                    exact_multipart_sizes.append(None)
            self.generic_visit(node)

    ContractVisitor().visit(tree)
    if raw_call_owners != ["guarded_evaluate"]:
        raise AssertionError(f"raw policy evaluator call sites are not exclusively guarded: {raw_call_owners}")
    if sorted(capture_guard_prefixes) != ["published-complete-", "published-primary-"]:
        raise AssertionError(f"exact capture is not guarded in both passes: {capture_guard_prefixes}")
    if exact_multipart_sizes != [1048576]:
        raise AssertionError(f"capacity multipart size call drifted: {exact_multipart_sizes}")
    octet_media_literals = [
        node.value for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and "application/octet-stream" in node.value.lower()
    ]
    if octet_media_literals:
        raise AssertionError(
            "verifier still encodes an application/octet-stream literal/allow contract: "
            f"{octet_media_literals}"
        )

    public_runtime = (
        HERE.parent / "environment" / "assets" / "public" / "waf_runtime.py"
    ).read_bytes()
    private_runtime = (HERE / "policy_runtime.py").read_bytes()
    if not private_runtime.startswith(public_runtime):
        raise AssertionError(
            "private policy runtime does not retain the public evaluator/validator as an exact prefix"
        )

    return {
        "capture_rows": len(expected_manifest),
        "capture_sha256": expected_digest,
        "raw_evaluator_call_owners": raw_call_owners,
        "runtime_public_prefix_bytes": len(public_runtime),
        "runtime_prefix_identical": True,
        "guarded_capture_passes": sorted(capture_guard_prefixes),
        "capacity_multipart_total_bytes": exact_multipart_sizes[0],
        "application_octet_stream_allow_contract_absent": True,
    }


def grade(policy, workdir, name):
    policy_path = workdir / f"{name}.json"
    log_dir = workdir / f"logs-{name}"
    policy_path.write_text(json.dumps(policy, indent=2) + "\n")
    env = os.environ.copy()
    env.update({
        "POLICY_PATH": str(policy_path),
        "LOG_DIR": str(log_dir),
        "PYTHONDONTWRITEBYTECODE": "1",
    })
    completed = subprocess.run(
        [sys.executable, str(VERIFY)], env=env, text=True,
        capture_output=True, timeout=120,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"verifier crashed for {name}: {completed.stderr or completed.stdout}")
    details = json.loads((log_dir / "details.json").read_text())
    assert details["error_count"] == sum(details["error_counts_by_area"].values())
    assert details["reported_error_count"] == len(details["errors"])
    assert details["errors_truncated"] == (details["error_count"] > len(details["errors"]))
    for domain, total_key in (("attack_protection", "attack_cases"), ("benign_compatibility", "benign_cases")):
        metric = details["metrics"][domain]
        assert metric["total"] == details[total_key]
        assert metric["passed"] + metric["failed"] + metric["not_evaluated"] == metric["total"]
        assert metric["evaluated"] <= metric["attempted"] <= metric["total"]
        for breakdown in ("by_family", "by_carrier"):
            for key in ("total", "attempted", "evaluated", "passed", "failed", "not_evaluated"):
                assert sum(row[key] for row in metric[breakdown].values()) == metric[key]
    return details


def main():
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {Path(sys.argv[0]).name} KNOWN_GOOD_POLICY.json")
    base = json.loads(Path(sys.argv[1]).read_text())
    profile_rule_indexes(base)
    source_contract = verifier_source_contract()

    specimens = {
        "oracle": {
            "policy": base, "expected": 1.0, "kind": "positive",
        },
        "equivalent-split-rule": {
            "policy": equivalent_split_rule(base), "expected": 1.0, "kind": "positive",
        },
        "equivalent-selector-segmentation": {
            "policy": equivalent_selector_segmentation(base), "expected": 1.0, "kind": "positive",
        },
        "equivalent-batch-all-indexes": {
            "policy": batch_all_indexes_equivalent(base), "expected": 1.0, "kind": "positive",
        },
        "equivalent-twelve-rule": {
            "policy": equivalent_twelve_rule(base), "expected": 1.0, "kind": "positive",
        },
        "old-five-rule-global-pipeline": {
            "policy": old_global_policy(base), "expected": 0.0, "kind": "old-global",
        },
        "extra-http-scheme": {
            "policy": with_extra_http(base), "expected": 0.0, "kind": "scheme",
        },
        "kelvin-allowed-scheme-config-rejection": {
            "policy": with_kelvin_scheme(base),
            "expected": 0.0, "kind": "configuration-rejection",
            "error_tokens": [
                "must match ASCII URI scheme grammar",
                "Unicode schemes are not allowed",
            ],
        },
        "effective-uppercase-k-scheme-dynamic-coverage": {
            "policy": with_effective_ascii_k_scheme(base),
            "expected": 0.0, "kind": "effective-scheme",
            "effective_scheme": "k",
        },
        "missing-asset-scheme": {
            "policy": without_asset(base), "expected": 0.0, "kind": "asset",
        },
        "batch-job-zero-only": {
            "policy": batch_job_zero_only(base), "expected": 0.0, "kind": "batch-index",
        },
        "batch-prior-sampled-indexes-only": {
            "policy": batch_prior_sampled_indexes_only(base),
            "expected": 0.0, "kind": "batch-sampled-index",
        },
        "batch-index-zero-correct-late-empty": {
            "policy": batch_late_empty_transforms(base),
            "expected": 0.0, "kind": "batch-late-empty",
        },
        "batch-index-zero-correct-late-overdecode": {
            "policy": batch_late_overdecode_transforms(base),
            "expected": 0.0, "kind": "batch-late-overdecode",
        },
        "late-benign-pathological-regex": {
            "policy": late_benign_pathological_regex(base),
            "expected": 0.0, "kind": "configuration-rejection",
            "error_tokens": [REGEX_REJECTION],
        },
        "capacity-many-fields-pathological-regex": {
            "policy": capacity_many_fields_pathological_regex(base),
            "expected": 0.0, "kind": "configuration-rejection",
            "error_tokens": [REGEX_REJECTION],
        },
        "late-import-pathological-regex": {
            "policy": late_import_pathological_regex(base),
            "expected": 0.0, "kind": "configuration-rejection",
            "error_tokens": [REGEX_REJECTION],
        },
        "safe-import-boundary-only-exception": {
            "policy": safe_import_boundary_only_exception(base),
            "expected": 0.0, "kind": "import-boundary-overfit",
        },
        "import-webkit-boundary-four-hyphens": {
            "policy": import_webkit_boundary_four_hyphens(base),
            "expected": 0.0, "kind": "import-semantic-interference",
        },
        "inert-content-type-route-parser-guard": {
            "policy": inert_content_type_route_parser_guard(base),
            "expected": 1.0, "kind": "positive-inert-neighbor",
        },
        "harmless-neighbor-inactive-form-selector": {
            "policy": harmless_neighbor_inactive_form_selector(base),
            "expected": 1.0, "kind": "positive",
        },
        "public-search-q-equals-template": {
            "policy": public_search_q_template_block(base),
            "expected": 0.0, "kind": "public-search-q",
        },
        "public-events-event-equals-migration": {
            "policy": public_events_migration_block(base),
            "expected": 0.0, "kind": "public-events-event",
        },
        "import-application-octet-stream-only-block": {
            "policy": import_octet_stream_only_block(base),
            "expected": 1.0, "kind": "positive-import-octet",
        },
        "import-regex-lowercase-boundary-70": {
            "policy": import_lowercase_boundary_70_block(base),
            "expected": 0.0, "kind": "configuration-rejection",
            "error_tokens": [REGEX_REJECTION],
        },
        "search-q-equals-rule-directed": {
            "policy": search_rule_directed_equals_block(base),
            "expected": 0.0, "kind": "r13-rule-directed-negative",
            "rule_id": "deny-search-rule-directed-exact",
            "predicate_op": "equals", "operation": "published-search",
            "method": "GET", "route": "/v1/search",
            "source": "query", "field": "q",
        },
        "events-event-contains-rule-directed": {
            "policy": events_rule_directed_contains_block(base),
            "expected": 0.0, "kind": "r13-rule-directed-negative",
            "rule_id": "deny-events-rule-directed-fragment",
            "predicate_op": "contains", "operation": "opaque-events",
            "method": "POST", "route": "/v1/events",
            "source": "json", "field": "/event",
        },
        "import-content-type-application-json-only": {
            "policy": inert_import_application_json_only(base),
            "expected": 1.0, "kind": "r13-rule-directed-positive",
            "rule_id": "inert-import-application-json-only",
            "operation": "template-import", "overlap_location": "header",
            "overlap_field": "content-type",
        },
        "contradictory-import-content-type-no-extraction": {
            "policy": inert_import_contradictory_media_no_extraction(base),
            "expected": 1.0, "kind": "r13-rule-directed-positive",
            "rule_id": "inert-import-contradictory-media-no-extraction",
            "operation": "template-import", "overlap_location": "multipart",
            "overlap_field": "template",
        },
        "search-positive-lookahead-config-rejection": {
            "policy": search_positive_lookahead_config_rejection(base),
            "expected": 0.0, "kind": "configuration-rejection",
            "error_tokens": [REGEX_REJECTION],
        },
        "import-negative-lookahead-branch-config-rejection": {
            "policy": import_negative_lookahead_branch_config_rejection(base),
            "expected": 0.0, "kind": "configuration-rejection",
            "error_tokens": [REGEX_REJECTION],
        },
        "search-groupref-config-rejection": {
            "policy": search_groupref_config_rejection(base),
            "expected": 0.0, "kind": "configuration-rejection",
            "error_tokens": [REGEX_REJECTION],
        },
        "events-groupref-config-rejection": {
            "policy": events_groupref_config_rejection(base),
            "expected": 0.0, "kind": "configuration-rejection",
            "error_tokens": [REGEX_REJECTION],
        },
        "import-groupref-config-rejection": {
            "policy": import_groupref_config_rejection(base),
            "expected": 0.0, "kind": "configuration-rejection",
            "error_tokens": [REGEX_REJECTION],
        },
        "search-q-equals-257-rule-directed": {
            "policy": search_equals_257_block(base),
            "expected": 0.0, "kind": "r13-rule-directed-negative",
            "rule_id": "deny-search-equals-257",
            "predicate_op": "equals", "operation": "published-search",
            "method": "GET", "route": "/v1/search",
            "source": "query", "field": "q",
            "expected_normalized_utf8_bytes": 257,
        },
        "events-contains-257-rule-directed": {
            "policy": events_contains_257_block(base),
            "expected": 0.0, "kind": "r13-rule-directed-negative",
            "rule_id": "deny-events-contains-257",
            "predicate_op": "contains", "operation": "opaque-events",
            "method": "POST", "route": "/v1/events",
            "source": "json", "field": "/event",
            "expected_normalized_utf8_bytes": 257,
        },
        "search-equals-4096-rule-directed": {
            "policy": search_equals_4096_block(base),
            "expected": 0.0, "kind": "r13-rule-directed-negative",
            "rule_id": "deny-search-equals-4096",
            "predicate_op": "equals", "operation": "published-search",
            "method": "GET", "route": "/v1/search",
            "source": "query", "field": "q",
            "expected_normalized_utf8_bytes": 4096,
        },
        "events-contains-4096-rule-directed": {
            "policy": events_contains_4096_block(base),
            "expected": 0.0, "kind": "r13-rule-directed-negative",
            "rule_id": "deny-events-contains-4096",
            "predicate_op": "contains", "operation": "opaque-events",
            "method": "POST", "route": "/v1/events",
            "source": "json", "field": "/event",
            "expected_normalized_utf8_bytes": 4096,
        },
        "search-equals-two-percent-decode-config-rejection": {
            "policy": search_equals_two_percent_decode_config_rejection(base),
            "expected": 0.0, "kind": "configuration-rejection",
            "error_tokens": [
                "transforms: percent_decode is not permitted with equals",
            ],
        },
        "events-contains-two-percent-decode-config-rejection": {
            "policy": events_contains_two_percent_decode_config_rejection(base),
            "expected": 0.0, "kind": "configuration-rejection",
            "error_tokens": [
                "transforms: percent_decode is not permitted with contains",
            ],
        },
        "search-equals-4096-permitted-transforms-live": {
            "policy": search_equals_4096_permitted_transforms_live(base),
            "expected": 0.0, "kind": "r15-permitted-transform-live",
            "rule_id": "deny-search-equals-4096-permitted-live",
            "predicate_op": "equals", "predicate_member": "value",
            "shape_id": "direct-equals", "operation": "published-search",
            "method": "GET", "route": "/v1/search",
            "source": "query", "field": "q",
            "expected_comparison_utf8_bytes": 4096,
            "expected_normalized_utf8_bytes": 6144,
        },
        "events-contains-4096-permitted-transforms-live": {
            "policy": events_contains_4096_permitted_transforms_live(base),
            "expected": 0.0, "kind": "r15-permitted-transform-live",
            "rule_id": "deny-events-contains-4096-permitted-live",
            "predicate_op": "contains", "predicate_member": "needle",
            "shape_id": "direct-contains", "operation": "opaque-events",
            "method": "POST", "route": "/v1/events",
            "source": "json", "field": "/event",
            "expected_comparison_utf8_bytes": 4096,
            "expected_normalized_utf8_bytes": 6144,
        },
        "import-contains-4096-permitted-transforms-proven-dead": {
            "policy": import_contains_4096_permitted_transforms_proven_dead(base),
            "expected": 1.0, "kind": "r15-permitted-transform-dead",
            "rule_id": "inert-import-contains-4096-permitted-dead",
            "predicate_op": "contains", "operation": "template-import",
            "expected_comparison_utf8_bytes": 4096,
            "overlap_location": "multipart", "overlap_field": "template",
        },
        "r14-class-order-regex-config-rejection": {
            "policy": r14_class_order_regex_config_rejection(base),
            "expected": 0.0, "kind": "configuration-rejection",
            "error_tokens": [REGEX_REJECTION],
        },
        "import-supported-alternation-later-boundary": {
            "policy": import_supported_later_branch_boundary_block(base),
            "expected": 0.0, "kind": "configuration-rejection",
            "error_tokens": [REGEX_REJECTION],
        },
        "oversize-equals-config-rejection": {
            "policy": oversize_equals_config_rejection(base),
            "expected": 0.0, "kind": "configuration-rejection",
            "error_tokens": ["predicate.value: UTF-8 length 4097 exceeds 4096 bytes"],
        },
        "oversize-contains-config-rejection": {
            "policy": oversize_contains_config_rejection(base),
            "expected": 0.0, "kind": "configuration-rejection",
            "error_tokens": ["predicate.needle: UTF-8 length 4097 exceeds 4096 bytes"],
        },
        "unbounded-repeat-config-rejection": {
            "policy": unbounded_repeat_config_rejection(base),
            "expected": 0.0, "kind": "configuration-rejection",
            "error_tokens": [REGEX_REJECTION],
        },
        "short-incomplete-boundary-regex": {
            "policy": short_incomplete_boundary_regex(base),
            "expected": 0.0, "kind": "boundary-contains",
        },
        "two-case-integration-enumeration": {
            "policy": two_case_integration_enumeration(base),
            "expected": 0.0, "kind": "integration-case",
        },
        "sampled-media-exact-scoping": {
            "policy": sampled_media_exact_scoping(base),
            "expected": 0.0, "kind": "media-scope",
        },
        "decoy-audit-misattribution": {
            "policy": decoy_audit_misattribution(base),
            "expected": 0.0, "kind": "audit-decoy",
        },
    }
    for actual_profile in PROFILE_PIPELINES:
        for substitute_profile, transforms in PROFILE_PIPELINES.items():
            if substitute_profile == actual_profile:
                continue
            name = f"substitute-{actual_profile}-with-{substitute_profile}"
            specimens[name] = {
                "policy": with_profile_transforms(base, actual_profile, transforms),
                "expected": 0.0,
                "kind": "substitution",
                "profile": actual_profile,
                "substitute": substitute_profile,
            }

    prior_r12_specimen_names = prior_r11_specimen_names() | NEW_R12_SPECIMEN_NAMES
    prior_r13_specimen_names = prior_r12_specimen_names | NEW_R13_SPECIMEN_NAMES
    prior_r14_specimen_names = prior_r13_specimen_names | NEW_R14_SPECIMEN_NAMES
    prior_r15_specimen_names = (
        prior_r14_specimen_names | NEW_REGEX_REMOVAL_SPECIMEN_NAMES
    )
    expected_specimen_names = prior_r15_specimen_names | NEW_R15_SPECIMEN_NAMES
    if (
        len(prior_r11_specimen_names()) != 43
        or len(prior_r12_specimen_names) != 46
        or len(prior_r13_specimen_names) != 51
        or len(prior_r14_specimen_names) != 61
        or len(prior_r15_specimen_names) != 65
        or len(expected_specimen_names) != 72
        or set(specimens) != expected_specimen_names
    ):
        missing = sorted(expected_specimen_names - set(specimens))
        extra = sorted(set(specimens) - expected_specimen_names)
        raise AssertionError(
            "regression matrix must retain all 65 prior row identities and add only the "
            f"seven r15 boundary rows; missing={missing}, extra={extra}"
        )

    # No accepted specimen may contain a regex policy. Every preserved regex reproducer
    # must fail through the one public EdgeShield v1 configuration error.
    for specimen_name, specimen in specimens.items():
        regex_rules = [
            rule for rule in specimen["policy"].get("rules", [])
            if rule.get("predicate", {}).get("op") == "regex"
        ]
        if regex_rules and not (
            specimen["kind"] == "configuration-rejection"
            and specimen.get("error_tokens") == [REGEX_REJECTION]
        ):
            raise AssertionError(
                f"{specimen_name}: regex policy is not an explicit public configuration rejection"
            )

    failures = []
    rows = []
    substitution_matrix = {}
    with tempfile.TemporaryDirectory(prefix="northstar-context-regressions-") as tmp:
        workdir = Path(tmp)
        for name, specimen in specimens.items():
            details = grade(specimen["policy"], workdir, name)
            actual = details.get("reward")
            observed_errors = details.get("errors", [])
            checks = details.get("checks", {})
            causal = True
            evidence = []
            if specimen["kind"] == "configuration-rejection":
                evidence = [
                    error for error in observed_errors
                    if any(token in error for token in specimen["error_tokens"])
                ]
                causal = (
                    checks == {"configuration": False}
                    and all(
                        any(token in error for error in observed_errors)
                        for token in specimen["error_tokens"]
                    )
                )
            elif specimen["kind"] == "substitution":
                carrier = PROFILE_CARRIER[specimen["profile"]]
                evidence = [error for error in observed_errors if carrier in error]
                causal = (
                    checks.get("configuration") is not False
                    and (checks.get("attack_replays") is False or checks.get("compatibility") is False)
                    and bool(evidence)
                )
                substitution_matrix.setdefault(specimen["profile"], {})[specimen["substitute"]] = {
                    "reward": actual,
                    "carrier": carrier,
                    "causal": causal,
                }
            elif specimen["kind"] == "old-global":
                mismatched = [
                    "json-template", "integration-header", "batch-template", "validation-query",
                ]
                evidence = [carrier for carrier in mismatched
                            if any(carrier in error for error in observed_errors)]
                causal = checks.get("configuration") is not False and set(evidence) == set(mismatched)
            elif specimen["kind"] == "scheme":
                causal = checks.get("attack_replays") is False and any("extra-" in error for error in observed_errors)
            elif specimen["kind"] == "effective-scheme":
                effective = specimen["effective_scheme"]
                digest = hashlib.sha256(
                    ("submitted-extra-scheme:" + effective).encode()
                ).hexdigest()[:12]
                expected_case_ids = {
                    f"extra-{digest}-{carrier}"
                    for carrier in DOCUMENTED_CARRIER_NAMES
                }
                witnessed_case_ids = {
                    case_id for case_id in expected_case_ids
                    if any(case_id in error for error in observed_errors)
                }
                evidence = sorted(witnessed_case_ids)
                causal = (
                    checks.get("configuration") is not False
                    and checks.get("attack_replays") is False
                    and details.get("submitted_extra_scheme_cases")
                    == len(DOCUMENTED_CARRIER_NAMES)
                    and witnessed_case_ids == expected_case_ids
                )
            elif specimen["kind"] == "asset":
                causal = checks.get("compatibility") is False and any("scheme-safe" in error for error in observed_errors)
            elif specimen["kind"] == "batch-index":
                evidence = [error for error in observed_errors if "batch-late-" in error]
                causal = (
                    checks.get("configuration") is not False
                    and checks.get("attack_replays") is False
                    and any("batch-template" in error for error in evidence)
                    and any("batch-options" in error for error in evidence)
                )
            elif specimen["kind"] == "batch-sampled-index":
                evidence = [error for error in observed_errors
                            if "batch-index-02-" in error]
                causal = (
                    checks.get("configuration") is not False
                    and checks.get("attack_replays") is False
                    and any("batch-template" in error for error in evidence)
                    and any("batch-options" in error for error in evidence)
                )
            elif specimen["kind"] == "batch-late-empty":
                evidence = [
                    error for error in observed_errors
                    if "batch-context-exact-decode-attack-01-" in error
                ]
                causal = (
                    checks.get("configuration") is not False
                    and checks.get("attack_replays") is False
                    and any("batch-template" in error for error in evidence)
                    and any("batch-options" in error for error in evidence)
                )
            elif specimen["kind"] == "batch-late-overdecode":
                evidence = [
                    error for error in observed_errors
                    if "batch-context-overdecode-safe-01-" in error
                ]
                causal = (
                    checks.get("configuration") is not False
                    and checks.get("compatibility") is False
                    and any("batch-template" in error for error in evidence)
                    and any("batch-options" in error for error in evidence)
                )
            elif specimen["kind"] == "import-boundary-overfit":
                evidence = [
                    error for error in observed_errors
                    if ("published-safe-import-json" in error
                        or "published-representative-b-import-lookalike" in error
                        or "safe-import-metamorphic-" in error)
                ]
                causal = (
                    checks.get("configuration") is not False
                    and checks.get("compatibility") is False
                    and any("published-" in error for error in evidence)
                    and any("safe-import-metamorphic-" in error for error in evidence)
                )
            elif specimen["kind"] == "import-semantic-interference":
                interference = details.get("neighbor_non_interference", {})
                violations = interference.get("causal_violations", [])
                exact_violations = [
                    violation for violation in violations
                    if violation.get("rule_id") == "deny-four-hyphen-import-boundary"
                    and violation.get("method") == "POST"
                    and violation.get("route") == "/v1/templates/import"
                    and violation.get("case_id") == "neighbor-import-webkit-boundary"
                    and violation.get("decision") == "block"
                    and violation.get("predicate_or_rejection_reason") == "contains"
                    and violation.get("extracted_source") == "header"
                    and str(violation.get("extracted_field", "")).lower() == "content-type"
                ]
                replay_evidence = [
                    error for error in observed_errors
                    if "neighbor-import-webkit-boundary" in error
                ]
                evidence = [
                    violation.get("cause", "") for violation in exact_violations
                ] + replay_evidence
                causal = (
                    checks.get("configuration") is not False
                    and checks.get("compatibility_non_interference") is False
                    and checks.get("compatibility") is False
                    and interference.get("causal_violation_count", 0) >= 1
                    and bool(exact_violations)
                    and bool(replay_evidence)
                )
            elif specimen["kind"] == "positive-inert-neighbor":
                interference = details.get("neighbor_non_interference", {})
                advisories = interference.get("structural_advisories", [])
                exact_advisories = [
                    advisory for advisory in advisories
                    if advisory.get("rule_id") == "inert-content-type-route-parser-guard"
                    and advisory.get("method") == "POST"
                    and advisory.get("route") == "/v1/templates/import"
                    and advisory.get("classification") == "advisory_structural_overlap_only"
                    and advisory.get("reward_fatal") is False
                    and any(
                        selector.get("location") == "header"
                        and "content-type" in selector.get("overlapping_fields", [])
                        for selector in advisory.get("overlapping_selectors", [])
                    )
                ]
                evidence = [
                    advisory.get("diagnostic", "") for advisory in exact_advisories
                ]
                causal = (
                    checks.get("configuration") is not False
                    and checks.get("compatibility_non_interference") is True
                    and checks.get("compatibility") is True
                    and interference.get("causal_violation_count") == 0
                    and bool(exact_advisories)
                )
            elif specimen["kind"] in {"public-search-q", "public-events-event"}:
                is_search = specimen["kind"] == "public-search-q"
                expected_case = "b-search-lookalike" if is_search else "b-events-opaque"
                expected_rule = (
                    "deny-public-search-q-template" if is_search
                    else "deny-public-event-migration"
                )
                expected_method = "GET" if is_search else "POST"
                expected_route = "/v1/search" if is_search else "/v1/events"
                expected_source = "query" if is_search else "json"
                expected_field = "q" if is_search else "/event"
                interference = details.get("neighbor_non_interference", {})
                violations = interference.get("causal_violations", [])
                exact_violations = [
                    violation for violation in violations
                    if violation.get("case_id") == expected_case
                    and violation.get("rule_id") == expected_rule
                    and violation.get("method") == expected_method
                    and violation.get("route") == expected_route
                    and violation.get("decision") == "block"
                    and violation.get("predicate_or_rejection_reason") == "equals"
                    and violation.get("extracted_source") == expected_source
                    and violation.get("extracted_field") == expected_field
                    and violation.get("published_capture_phase") == "primary"
                ]
                capture = details.get("published_capture", {})
                primary = capture.get("primary", {})
                complete = capture.get("complete", {})
                replay_evidence = [
                    error for error in observed_errors
                    if expected_case in error and "published decision 'allow'" in error
                ]
                evidence = [
                    violation.get("cause", "") for violation in exact_violations
                ] + replay_evidence
                causal = (
                    checks.get("configuration") is not False
                    and checks.get("published_capture") is False
                    and checks.get("compatibility") is False
                    and checks.get("compatibility_non_interference") is False
                    and primary == {"attempted": 21, "completed": 21, "matched": 20}
                    and complete == {"attempted": 21, "completed": 21, "matched": 20}
                    and bool(exact_violations)
                    and len(replay_evidence) >= 2
                )
            elif specimen["kind"] == "positive-import-octet":
                interference = details.get("neighbor_non_interference", {})
                advisories = interference.get("structural_advisories", [])
                exact_advisories = [
                    advisory for advisory in advisories
                    if advisory.get("rule_id") == "deny-import-application-octet-stream-only"
                    and advisory.get("method") == "POST"
                    and advisory.get("route") == "/v1/templates/import"
                    and advisory.get("classification") == "advisory_structural_overlap_only"
                    and advisory.get("reward_fatal") is False
                    and any(
                        selector.get("location") == "header"
                        and "content-type" in selector.get("overlapping_fields", [])
                        for selector in advisory.get("overlapping_selectors", [])
                    )
                ]
                capture = details.get("published_capture", {})
                evidence = [advisory.get("diagnostic", "") for advisory in exact_advisories]
                causal = (
                    checks.get("configuration") is not False
                    and checks.get("published_capture") is True
                    and checks.get("compatibility") is True
                    and checks.get("capacity") is True
                    and capture.get("primary") == {
                        "attempted": 21, "completed": 21, "matched": 21,
                    }
                    and capture.get("complete") == {
                        "attempted": 21, "completed": 21, "matched": 21,
                    }
                    and details.get("capacity_import_contract", {}).get("media_type")
                    == "multipart/form-data"
                    and interference.get("causal_violation_count") == 0
                    and bool(exact_advisories)
                )
            elif specimen["kind"] == "r15-permitted-transform-live":
                target_rule = next(
                    rule for rule in specimen["policy"]["rules"]
                    if rule.get("id") == specimen["rule_id"]
                )
                comparison = target_rule["predicate"][specimen["predicate_member"]]
                interference = details.get("neighbor_non_interference", {})
                violations = interference.get("causal_violations", [])
                exact_violations = []
                for violation in violations:
                    provenance = violation.get("witness_provenance", {})
                    parsed = provenance.get("independent_parse", {})
                    if (
                        violation.get("classification") == "causal_legal_request_denial"
                        and violation.get("reward_fatal") is True
                        and violation.get("rule_id") == specimen["rule_id"]
                        and violation.get("method") == specimen["method"]
                        and violation.get("route") == specimen["route"]
                        and violation.get("predicate_or_rejection_reason")
                        == specimen["predicate_op"]
                        and violation.get("extracted_source") == specimen["source"]
                        and violation.get("extracted_field") == specimen["field"]
                        and provenance.get("origin") == "rule_directed_causal_witness"
                        and provenance.get("operation") == specimen["operation"]
                        and provenance.get("raw_preimage_strategy")
                        == "literal_predicate_value"
                        and provenance.get("normalized_utf8_bytes")
                        == specimen["expected_normalized_utf8_bytes"]
                        and provenance.get("hypothesis_shape_ids") == [specimen["shape_id"]]
                        and provenance.get("hypothesis_schedule_phase") == "primary"
                        and parsed.get("success") is True
                        and parsed.get("submitted_selector_consumed") is True
                    ):
                        exact_violations.append(violation)
                synthesis = [
                    item for item in interference.get("rule_directed_synthesis", [])
                    if item.get("rule_id") == specimen["rule_id"]
                    and item.get("operation") == specimen["operation"]
                ]
                evidence = [
                    violation.get("cause", "") for violation in exact_violations
                ] + [
                    json.dumps({
                        "primary_shapes_scheduled": item.get("primary_shapes_scheduled"),
                        "primary_shapes_without_legal_request": item.get(
                            "primary_shapes_without_legal_request"
                        ),
                        "primary_witness_complete": item.get("primary_witness_complete"),
                    }, sort_keys=True)
                    for item in synthesis
                ]
                causal = (
                    len(comparison.encode("utf-8"))
                    == specimen["expected_comparison_utf8_bytes"]
                    and set(target_rule["transforms"]) == {
                        "unicode_nfkc", "backslash_to_slash", "lowercase", "trim_ascii",
                    }
                    and checks.get("configuration") is not False
                    and checks.get("verifier_consistency") is True
                    and checks.get("attack_replays") is True
                    and checks.get("published_capture") is True
                    and checks.get("capacity") is True
                    and checks.get("performance") is True
                    and checks.get("compatibility") is False
                    and checks.get("compatibility_non_interference") is False
                    and bool(exact_violations)
                    and len(synthesis) == 1
                    and synthesis[0].get("primary_hypotheses") == 1
                    and synthesis[0].get("parsed_request_count", 0) >= 1
                    and specimen["shape_id"] in synthesis[0].get(
                        "primary_shapes_scheduled", []
                    )
                    and not synthesis[0].get("primary_shapes_without_legal_request")
                    and synthesis[0].get("primary_witness_complete") is True
                )
            elif specimen["kind"] == "r15-permitted-transform-dead":
                target_rule = next(
                    rule for rule in specimen["policy"]["rules"]
                    if rule.get("id") == specimen["rule_id"]
                )
                comparison = target_rule["predicate"]["needle"]
                interference = details.get("neighbor_non_interference", {})
                advisories = [
                    advisory for advisory in interference.get("structural_advisories", [])
                    if advisory.get("rule_id") == specimen["rule_id"]
                    and advisory.get("operation") == specimen["operation"]
                    and advisory.get("classification") == "advisory_structural_overlap_only"
                    and advisory.get("reward_fatal") is False
                    and any(
                        selector.get("location") == specimen["overlap_location"]
                        and specimen["overlap_field"] in selector.get("overlapping_fields", [])
                        for selector in advisory.get("overlapping_selectors", [])
                    )
                ]
                synthesis = [
                    item for item in interference.get("rule_directed_synthesis", [])
                    if item.get("rule_id") == specimen["rule_id"]
                    and item.get("operation") == specimen["operation"]
                ]
                outcomes = [
                    item for item in interference.get("rule_directed_guarded_outcomes", [])
                    if item.get("witness_provenance", {}).get("target_rule_id")
                    == specimen["rule_id"]
                ]
                dead_proofs = (
                    synthesis[0].get("primary_dead_proofs", [])
                    if len(synthesis) == 1 else []
                )
                evidence = [
                    advisory.get("diagnostic", "") for advisory in advisories
                ] + [json.dumps(proof, sort_keys=True) for proof in dead_proofs]
                causal = (
                    len(comparison.encode("utf-8"))
                    == specimen["expected_comparison_utf8_bytes"]
                    and set(target_rule["transforms"]) == {
                        "unicode_nfkc", "backslash_to_slash", "lowercase", "trim_ascii",
                    }
                    and checks.get("configuration") is True
                    and checks.get("verifier_consistency") is True
                    and checks.get("attack_replays") is True
                    and checks.get("published_capture") is True
                    and checks.get("capacity") is True
                    and checks.get("performance") is True
                    and checks.get("compatibility") is True
                    and checks.get("compatibility_non_interference") is True
                    and interference.get("causal_violation_count") == 0
                    and not outcomes
                    and bool(advisories)
                    and len(synthesis) == 1
                    and synthesis[0].get("candidate_hypotheses") == 1
                    and synthesis[0].get("primary_hypotheses") == 1
                    and synthesis[0].get("parsed_request_count") == 0
                    and synthesis[0].get("primary_shapes_scheduled") == []
                    and synthesis[0].get("primary_shapes_without_legal_request")
                    == ["direct-contains"]
                    and synthesis[0].get("primary_witness_complete") is True
                    and any(
                        proof.get("classification")
                        == "proven_dead_for_documented_operation"
                        and proof.get("exhaustive_skip_reasons", {}).get(
                            "unsatisfied_operation_content_type_condition", 0
                        ) >= 1
                        for proof in dead_proofs
                    )
                )
            elif specimen["kind"] == "r13-rule-directed-negative":
                interference = details.get("neighbor_non_interference", {})
                violations = interference.get("causal_violations", [])
                exact_violations = []
                for violation in violations:
                    provenance = violation.get("witness_provenance", {})
                    parsed = provenance.get("independent_parse", {})
                    field_matches = str(violation.get("extracted_field", ""))
                    if specimen["source"] == "header":
                        field_matches = field_matches.lower()
                    if (
                        str(violation.get("case_id", "")).startswith("rule-directed-")
                        and violation.get("classification") == "causal_legal_request_denial"
                        and violation.get("reward_fatal") is True
                        and violation.get("rule_id") == specimen["rule_id"]
                        and violation.get("method") == specimen["method"]
                        and violation.get("route") == specimen["route"]
                        and violation.get("decision") == "block"
                        and violation.get("predicate_or_rejection_reason") == specimen["predicate_op"]
                        and violation.get("extracted_source") == specimen["source"]
                        and field_matches == specimen["field"]
                        and provenance.get("origin") == "rule_directed_causal_witness"
                        and provenance.get("operation") == specimen["operation"]
                        and provenance.get("predicate_op") == specimen["predicate_op"]
                        and parsed.get("success") is True
                        and parsed.get("submitted_selector_consumed") is True
                    ):
                        exact_violations.append(violation)
                synthesis = [
                    item for item in interference.get("rule_directed_synthesis", [])
                    if item.get("rule_id") == specimen["rule_id"]
                    and item.get("operation") == specimen["operation"]
                ]
                if specimen["operation"] == "template-import":
                    exact_violations = [
                        violation for violation in exact_violations
                        if violation.get("witness_provenance", {}).get("boundary_length") == 70
                        and violation.get("witness_provenance", {}).get(
                            "independent_parse", {}
                        ).get("media_type") == "multipart/form-data"
                    ]
                if "expected_normalized_utf8_bytes" in specimen:
                    exact_violations = [
                        violation for violation in exact_violations
                        if violation.get("witness_provenance", {}).get(
                            "normalized_utf8_bytes"
                        ) == specimen["expected_normalized_utf8_bytes"]
                    ]
                evidence = [
                    violation.get("cause", "") for violation in exact_violations
                ] + [
                    f"{item.get('generator_status')}:{item.get('parsed_request_count')}"
                    for item in synthesis
                ]
                causal = (
                    checks.get("configuration") is not False
                    and checks.get("verifier_consistency") is True
                    and checks.get("attack_replays") is True
                    and checks.get("published_capture") is True
                    and checks.get("capacity") is True
                    and checks.get("performance") is True
                    and checks.get("compatibility") is False
                    and checks.get("compatibility_non_interference") is False
                    and interference.get("causal_violation_count", 0) >= 1
                    and bool(exact_violations)
                    and any(item.get("parsed_request_count", 0) >= 1 for item in synthesis)
                )
            elif specimen["kind"] == "r13-rule-directed-positive":
                interference = details.get("neighbor_non_interference", {})
                advisories = [
                    advisory for advisory in interference.get("structural_advisories", [])
                    if advisory.get("rule_id") == specimen["rule_id"]
                    and advisory.get("operation") == specimen["operation"]
                    and advisory.get("classification") == "advisory_structural_overlap_only"
                    and advisory.get("reward_fatal") is False
                    and any(
                        selector.get("location") == specimen["overlap_location"]
                        and specimen["overlap_field"] in selector.get("overlapping_fields", [])
                        for selector in advisory.get("overlapping_selectors", [])
                    )
                ]
                synthesis = [
                    item for item in interference.get("rule_directed_synthesis", [])
                    if item.get("rule_id") == specimen["rule_id"]
                    and item.get("operation") == specimen["operation"]
                ]
                outcomes = [
                    item for item in interference.get("rule_directed_guarded_outcomes", [])
                    if item.get("witness_provenance", {}).get("target_rule_id")
                    == specimen["rule_id"]
                ]
                if specimen["rule_id"] == "inert-import-application-json-only":
                    considered_without_denial = (
                        bool(synthesis)
                        and all(item.get("generator_status") == "generated" for item in synthesis)
                        and all(item.get("candidate_hypotheses", 0) >= 1 for item in synthesis)
                        and all(item.get("parsed_request_count") == 0 for item in synthesis)
                        and not outcomes
                        and all(item.get("primary_shapes_without_legal_request") for item in synthesis)
                    )
                else:
                    considered_without_denial = (
                        bool(synthesis)
                        and all(item.get("generator_status") == "generated" for item in synthesis)
                        and all(item.get("candidate_hypotheses", 0) >= 1 for item in synthesis)
                        and all(item.get("parsed_request_count") == 0 for item in synthesis)
                        and not outcomes
                        and any(
                            item.get("skip_reasons", {}).get(
                                "unsatisfied_singleton_content_type_conditions", 0,
                            ) >= 1
                            for item in synthesis
                        )
                    )
                evidence = [
                    advisory.get("diagnostic", "") for advisory in advisories
                ] + [
                    json.dumps({
                        "generator_status": item.get("generator_status"),
                        "parsed_request_count": item.get("parsed_request_count"),
                        "skip_reasons": item.get("skip_reasons"),
                    }, sort_keys=True)
                    for item in synthesis
                ]
                capture = details.get("published_capture", {})
                causal = (
                    checks.get("configuration") is not False
                    and checks.get("compatibility") is True
                    and checks.get("compatibility_non_interference") is True
                    and checks.get("capacity") is True
                    and interference.get("causal_violation_count") == 0
                    and capture.get("primary") == {
                        "attempted": 21, "completed": 21, "matched": 21,
                    }
                    and capture.get("complete") == {
                        "attempted": 21, "completed": 21, "matched": 21,
                    }
                    and bool(advisories)
                    and considered_without_denial
                )
            elif specimen["kind"] == "boundary-contains":
                evidence = [error for error in observed_errors
                            if any(marker in error for marker in (
                                "boundary-scheme-", "boundary-drive-", "boundary-nul-",
                                "boundary-balanced-",
                            ))]
                causal = (
                    checks.get("configuration") is not False
                    and checks.get("attack_replays") is False
                    and bool(evidence)
                )
            elif specimen["kind"] == "integration-case":
                evidence = [error for error in observed_errors if "integration-case-" in error]
                causal = (
                    checks.get("configuration") is not False
                    and checks.get("attack_replays") is False
                    and any("LEGACY" in error for error in evidence)
                )
            elif specimen["kind"] == "media-scope":
                evidence = [error for error in observed_errors if "json-suffix-bad-" in error]
                causal = (
                    checks.get("configuration") is not False
                    and checks.get("attack_replays") is False
                    and len(evidence) >= 5
                    and all(any(carrier in error for error in evidence)
                            for carrier in ("json-template", "json-options", "batch-template",
                                            "batch-options", "validation-json"))
                )
            elif specimen["kind"] == "audit-decoy":
                evidence = [error for error in observed_errors
                            if "audit-decoy-misattribution" in error]
                causal = (
                    checks.get("configuration") is not False
                    and checks.get("attack_replays") is not False
                    and checks.get("audit_runtime") is False
                    and bool(evidence)
                )

            ok = actual == specimen["expected"] and causal
            rows.append({
                "specimen": name,
                "kind": specimen["kind"],
                "expected": specimen["expected"],
                "actual": actual,
                "causal": causal,
                "evidence": evidence[:6],
                "errors": observed_errors[:6],
                "ok": ok,
            })
            if not ok:
                failures.append(name)

    output = {
        "passed": not failures,
        "positive_controls": sum(
            1 for specimen in specimens.values() if specimen["expected"] == 1.0
        ),
        "negative_specimens": sum(
            1 for specimen in specimens.values() if specimen["expected"] == 0.0
        ),
        "retained_previous_specimens": 65,
        "new_configuration_rejection_specimens": 3,
        "new_semantic_negative_specimens": 3,
        "new_harmless_positive_specimens": 1,
        "total_specimens": len(specimens),
        "verifier_source_contract": source_contract,
        "directed_context_substitutions": 20,
        "substitution_matrix": substitution_matrix,
        "specimens": rows,
        "failures": failures,
    }
    print(json.dumps(output, indent=2))
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    main()
