#!/usr/bin/env python3
"""Small client for the isolated Northstar compatibility-model service.

The legacy application implementation is intentionally not installed in the operator
workbench.  This client exposes the same single-request observation used by waflab and
the HTTP lab without publishing application internals as EdgeShield policy constants.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

LEGACY_LAB_URL = os.environ.get("LEGACY_LAB_URL", "http://legacy:9090").rstrip("/")


class LegacyLabError(RuntimeError):
    pass


def assess_legacy(request_envelope: dict) -> dict:
    raw = json.dumps(request_envelope, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        LEGACY_LAB_URL + "/assess",
        data=raw,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            result = json.loads(response.read().decode("utf-8"))
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        raise LegacyLabError(f"legacy compatibility lab is unavailable: {exc}") from exc
    if not isinstance(result, dict):
        raise LegacyLabError("legacy compatibility lab returned an invalid result")
    return result


def redact_assessment(result: dict) -> dict:
    """HTTP responses omit normalized locator strings; waflab inspect remains the probe."""
    out = dict(result)
    out["locators"] = [
        {key: value for key, value in item.items() if key != "normalized"}
        for item in result.get("locators", [])
        if isinstance(item, dict)
    ]
    return out
