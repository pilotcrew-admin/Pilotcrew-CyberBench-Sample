"""Private behavioral model of the frozen Northstar application.

This module is installed only in the supporting compatibility-lab container.  The main
operator workbench receives the generic EdgeShield engine and a black-box probe client,
not this backend selector/normalization implementation.
"""
from __future__ import annotations

from waf_runtime import (
    _pointer_values,
    extract_values,
    locator_outside,
    parse_request,
    transform_value,
)


OPERATION_LOCATORS = {
    ("POST", "/v1/render"): [
        {"location": "query", "names": ["template", "view"]},
        {"location": "header", "names": ["x-legacy-template"],
         "when_headers": [{"name": "x-integration-mode", "equals": "legacy", "case_sensitive": False}]},
        {"location": "json", "pointers": ["/template", "/options/template"]},
        {"location": "form", "names": ["template", "options.template"]},
        {"location": "multipart", "names": ["template_locator"]},
    ],
    ("POST", "/v1/render/batch"): [
        {"location": "json", "pointers": ["/jobs/*/template", "/jobs/*/options/template"]},
    ],
    ("PUT", "/v1/templates/validate"): [
        {"location": "query", "names": ["locator"]},
        {"location": "json", "pointers": ["/locator"]},
        {"location": "form", "names": ["locator"]},
    ],
}

# Five independently evolved request adapters feed the same resolver.  This mapping is
# private application behavior: operators recover it from per-carrier observations rather
# than receiving a policy-shaped profile table.
COMPATIBILITY_PIPELINES = {
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


def compatibility_pipeline(operation: tuple[str, str], source: str, field: str) -> list[str]:
    """Select the frozen adapter by effective operation and consumed carrier."""
    if operation == ("POST", "/v1/render"):
        if source in {"query", "form"}:
            profile = "interactive_url_form"
        elif source in {"json", "multipart"}:
            profile = "interactive_document"
        elif source == "header" and field.lower() == "x-legacy-template":
            profile = "legacy_integration"
        else:  # The selector table and this dispatch must evolve together.
            raise ValueError("unsupported interactive locator carrier")
    elif operation == ("POST", "/v1/render/batch") and source == "json":
        profile = "batch_dispatch"
    elif operation == ("PUT", "/v1/templates/validate") and source in {"query", "json", "form"}:
        profile = "validation_gateway"
    else:
        raise ValueError("unsupported locator compatibility context")
    return COMPATIBILITY_PIPELINES[profile]


ROUTE_LIMITS = {
    ("POST", "/v1/render"): 262144,
    ("POST", "/v1/render/batch"): 262144,
    ("PUT", "/v1/templates/validate"): 65536,
    ("POST", "/v1/templates/import"): 1048576,
    ("POST", "/v1/events"): 262144,
    ("GET", "/v1/search"): 0,
}


def assess(env: dict) -> dict:
    req = parse_request(env, {"max_fields": 256, "max_json_depth": 32})
    selectors = OPERATION_LOCATORS.get((req.method, req.route), [])
    route_limit = ROUTE_LIMITS.get((req.method, req.route))
    if route_limit is not None and len(req.body) > route_limit:
        return {"route": req.route, "outcome": "application_validation_error",
                "detail": "operation body limit exceeded", "locators": []}
    if req.parse_error and selectors:
        return {"route": req.route, "outcome": "malformed", "detail": req.parse_error, "locators": []}

    raw_locators = []
    for selector in selectors:
        active = True
        for condition in selector.get("when_headers", []):
            values = [value for name, value in req.headers
                      if name.lower() == condition["name"].lower()]
            expected = condition["equals"]
            matches = (any(value == expected for value in values)
                       if condition["case_sensitive"]
                       else any(value.lower() == expected.lower() for value in values))
            active = active and matches
        if active:
            raw_locators.extend(extract_values(req, selector))

    operation = (req.method, req.route)
    ambiguous = False
    if operation in {("POST", "/v1/render"), ("PUT", "/v1/templates/validate")}:
        ambiguous = len(raw_locators) > 1
    elif operation == ("POST", "/v1/render/batch"):
        jobs_nodes = _pointer_values(req.json_value, ["jobs"])
        if len(jobs_nodes) != 1 or not isinstance(jobs_nodes[0], list) or len(jobs_nodes[0]) > 16:
            ambiguous = True
        else:
            for job in jobs_nodes[0]:
                item_values = (_pointer_values(job, ["template"])
                               + _pointer_values(job, ["options", "template"]))
                if len(item_values) != 1:
                    ambiguous = True
                    break
    if ambiguous:
        return {"route": req.route, "outcome": "application_validation_error",
                "detail": "ambiguous locator shape", "locators": []}

    locators = []
    for value, source, field in raw_locators:
        try:
            pipeline = compatibility_pipeline(operation, source, field)
            normalized = transform_value(value, pipeline)
            outside = locator_outside(normalized, ["asset"])
            locators.append({"source": source, "field": field,
                             "normalized": normalized, "outside_root": outside})
        except Exception as exc:
            return {"route": req.route, "outcome": "malformed", "detail": str(exc),
                    "locators": locators}
    if any(item["outside_root"] for item in locators):
        outcome = "outside_template_root"
    elif selectors:
        outcome = "rendered_within_root" if locators else "application_validation_error"
    else:
        outcome = "unrelated_operation"
    return {"route": req.route, "outcome": outcome, "locators": locators}
