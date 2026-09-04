#!/usr/bin/env python3
"""Meridian tool-boundary guard: JSONL stdin -> JSONL decisions."""
import fnmatch
import json
import sys

TRUST = {"untrusted": 0, "collaborative": 1, "signed": 2}


def deny(*reasons):
    return {"decision": "deny", "reasons": list(reasons) or ["invalid request"]}


def names(items, key="id"):
    if not isinstance(items, list):
        raise ValueError("collection is not an array")
    out = {}
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get(key), str) or item[key] in out:
            raise ValueError("malformed or duplicate object")
        out[item[key]] = item
    return out


def host_matches(host, pattern):
    if not isinstance(host, str) or not isinstance(pattern, str):
        return False
    host = host.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*.") and "*" not in pattern[2:]:
        return host.endswith(pattern[1:]) and host != pattern[2:]
    return "*" not in pattern and host == pattern


def decide(case):
    try:
        if not isinstance(case, dict) or set(case) != {"sources", "memories", "registry", "credentials", "approvals", "request"}:
            return deny("malformed evaluation case")
        sources = names(case["sources"]); memories = names(case["memories"])
        registry = names(case["registry"], "plugin_id"); credentials = names(case["credentials"])
        approvals = names(case["approvals"])
        req = case["request"]
        req_keys = {"plugin_id", "capability", "destinations", "credential_id", "memory_ids",
                    "approval_id", "target", "args_digest", "forwards_credential"}
        if not isinstance(req, dict) or set(req) != req_keys:
            return deny("malformed request")
        if not all(isinstance(req[x], str) for x in ("plugin_id", "capability", "credential_id", "target", "args_digest")):
            return deny("malformed request identifiers")
        if type(req["forwards_credential"]) is not bool or not isinstance(req["destinations"], list) or not req["destinations"] or any(not isinstance(x, str) for x in req["destinations"]):
            return deny("malformed destinations or forwarding marker")
        if not isinstance(req["memory_ids"], list) or any(not isinstance(x, str) for x in req["memory_ids"]):
            return deny("malformed memory references")
        plugin = registry.get(req["plugin_id"])
        if not plugin:
            return deny("unregistered plugin")
        required_plugin = {"plugin_id", "status", "capability", "risk", "required_scopes", "allowed_hosts", "catalog_trust", "catalog_signature_valid"}
        if set(plugin) != required_plugin or plugin["status"] != "active" or plugin["catalog_trust"] != "signed" or plugin["catalog_signature_valid"] is not True:
            return deny("plugin registration is not active signed authority")
        if plugin["risk"] not in ("low", "high") or req["capability"] != plugin["capability"]:
            return deny("capability or risk mismatch")
        if not isinstance(plugin["required_scopes"], list) or not isinstance(plugin["allowed_hosts"], list) or not plugin["allowed_hosts"]:
            return deny("malformed plugin authority")
        cred = credentials.get(req["credential_id"])
        if not cred or set(cred) != {"id", "status", "scopes", "plugin_ids"}:
            return deny("unknown or malformed credential")
        if (cred["status"] != "active" or not isinstance(cred["plugin_ids"], list)
                or any(not isinstance(x, str) for x in cred["plugin_ids"])
                or req["plugin_id"] not in cred["plugin_ids"]):
            return deny("credential is inactive or not consumer-bound")
        if not isinstance(cred["scopes"], list) or any(not isinstance(x, str) for x in cred["scopes"]):
            return deny("malformed credential scopes")
        if not set(plugin["required_scopes"]).issubset(set(cred["scopes"])):
            return deny("credential lacks required scopes")
        if any(not any(host_matches(host, pat) for pat in plugin["allowed_hosts"]) for host in req["destinations"]):
            return deny("a destination is outside signed registration")
        if not req["destinations"] or req["destinations"][0].lower().rstrip(".") != req["target"].lower().rstrip("."):
            return deny("primary destination does not match target")
        if req["forwards_credential"]:
            return deny("credential forwarding forbidden")

        roots = []
        visiting = set(); visited = set()
        def walk(mid):
            if mid in visiting:
                raise ValueError("memory lineage cycle")
            if mid in visited:
                return
            memory = memories.get(mid)
            if not memory or set(memory) != {"id", "status", "source_ids", "parent_memory_ids"} or memory["status"] != "active":
                raise ValueError("missing, malformed, or inactive memory")
            if not isinstance(memory["source_ids"], list) or not isinstance(memory["parent_memory_ids"], list):
                raise ValueError("malformed memory lineage")
            visiting.add(mid)
            for sid in memory["source_ids"]:
                source = sources.get(sid)
                if not source or set(source) != {"id", "status", "trust", "signature_valid"} or source["status"] != "active" or source["trust"] not in TRUST or type(source["signature_valid"]) is not bool:
                    raise ValueError("missing, malformed, or inactive source")
                roots.append(source)
            for parent in memory["parent_memory_ids"]:
                walk(parent)
            visiting.remove(mid); visited.add(mid)
        for mid in req["memory_ids"]:
            walk(mid)
        if plugin["risk"] == "high":
            if not roots or any(root["trust"] != "signed" or root["signature_valid"] is not True for root in roots):
                return deny("high-risk lineage lacks active signed roots")
            approval = approvals.get(req["approval_id"]) if isinstance(req["approval_id"], str) else None
            required_approval = {"id", "status", "type", "plugin_id", "capability", "target", "args_digest"}
            if not approval or set(approval) != required_approval or approval["status"] != "approved" or approval["type"] != "change_ticket":
                return deny("valid change-ticket approval absent")
            if approval["plugin_id"] != req["plugin_id"] or approval["capability"] != req["capability"]:
                return deny("approval plugin or capability mismatch")
            if approval["target"].lower().rstrip(".") != req["target"].lower().rstrip(".") or approval["args_digest"] != req["args_digest"]:
                return deny("approval target or arguments mismatch")
        elif req["approval_id"] is not None:
            optional = approvals.get(req["approval_id"]) if isinstance(req["approval_id"], str) else None
            required_approval = {"id", "status", "type", "plugin_id", "capability", "target", "args_digest"}
            if not optional or set(optional) != required_approval or optional["status"] != "approved":
                return deny("referenced optional approval is missing, malformed, or inactive")
        return {"decision": "allow", "reasons": ["signed registration and runtime constraints satisfied"]}
    except Exception as exc:
        return deny(f"fail closed: {type(exc).__name__}")


def main():
    for line in sys.stdin:
        try:
            case = json.loads(line)
            result = decide(case)
        except Exception as exc:
            result = deny(f"fail closed: {type(exc).__name__}")
        print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
