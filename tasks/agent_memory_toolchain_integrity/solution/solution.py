#!/usr/bin/env python3
"""Reference defender workflow for Meridian's durable-state incident."""
import json
import shutil
import subprocess
import urllib.request
import urllib.parse
from pathlib import Path

BASE = "http://agent-control:8080"
OUT = Path("/app/submission")


def call(method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data, method=method,
        headers={"Content-Type": "application/json"} if data else {})
    with urllib.request.urlopen(req, timeout=15) as response:
        return json.load(response)


def ids(items):
    return {x["id"]: x for x in items}


print("[1/8] Exporting live durable state and immutable audit evidence")
state = call("GET", "/v1/export")
audit = state["audit"]
sources = ids(state["sources"]); memories = ids(state["memories"])
plugins = ids(state["plugins"]); actions = ids(state["actions"])
credentials = ids(state["credentials"])

print("[2/8] Reconstructing invalid roots and their controlling descendants")
descendant_sources = set()
for event in audit:
    if event["type"] == "memory_derivation":
        descendant_sources.update(event.get("source_ids", []))
    if event["type"] == "plugin_metadata_update":
        descendant_sources.add(event["new_source_id"])
bad_sources = {e["source_id"] for e in audit if e["type"] == "source_fetch"
               and e["source_id"] in descendant_sources
               and (e.get("signature_valid") is False or e.get("digest_match") is False)}
bad_memories = {m["id"] for m in state["memories"] if set(m["source_ids"]) & bad_sources}
bad_actions = {a["id"] for a in state["actions"] if set(a["memory_ids"]) & bad_memories}
if not bad_sources or not bad_memories or not bad_actions:
    raise SystemExit("forensic joins did not reconstruct a complete unsafe branch")
print("  roots:", sorted(bad_sources))
print("  memories:", sorted(bad_memories))
print("  actions:", sorted(bad_actions))

print("[3/8] Recovering the authoritative archive registration from signed catalog material")
archive_id = next(p["id"] for p in state["plugins"] if p["capability"] == "archive.export")
catalog_source = None; archive_spec = None
for source in state["sources"]:
    if source["trust"] != "signed" or not source["signature"]["valid"]:
        continue
    for spec in source.get("document", {}).get("registrations", []):
        if spec["plugin_id"] == archive_id:
            catalog_source, archive_spec = source, spec
if not archive_spec:
    raise SystemExit("no signed archive registration")
print("  authoritative endpoint:", archive_spec["endpoint"])

print("[4/8] Selectively quarantining poisoned roots and memories")
for source_id in sorted(bad_sources):
    call("PATCH", f"/v1/sources/{source_id}",
         {"status": "quarantined", "reason": "invalid transport/signature with controlling descendants"})
for memory_id in sorted(bad_memories):
    call("PATCH", f"/v1/memories/{memory_id}",
         {"status": "quarantined", "reason": "controlling lineage reaches invalid incident source"})

print("[5/8] Rotating exposed credential generation and restoring plugin registration")
exposed_old = {e["credential_id"] for e in audit if e["type"] == "credential_forwarded"}
if len(exposed_old) != 1:
    raise SystemExit("expected one evidence-backed exposed credential")
old_id = next(iter(exposed_old))
new_cred = call("POST", f"/v1/credentials/{old_id}/rotate",
    {"scopes": archive_spec["required_scopes"], "reason": "credential material crossed untrusted archive destination"})
call("PATCH", f"/v1/plugins/{archive_id}", {
    "endpoint": archive_spec["endpoint"],
    "required_scopes": archive_spec["required_scopes"],
    "approval_mode": archive_spec["approval_mode"],
    "metadata_source_id": catalog_source["id"],
    "credential_id": new_cred["id"],
    "status": "active"
})

print("[6/8] Cancelling unsafe intent while rebinding the approved queued publication")
for action_id in sorted(bad_actions):
    call("PATCH", f"/v1/actions/{action_id}",
         {"status": "cancelled", "reason": "queued intent depends on poisoned controlling memory"})
for action in state["actions"]:
    if action["capability"] == "archive.export" and action["id"] not in bad_actions and action["status"] == "queued":
        call("PATCH", f"/v1/actions/{action['id']}",
             {"credential_id": new_cred["id"], "reason": "rebind approved publication after credential rotation"})

print("[7/8] Installing capability-based provenance and authorization boundary")
allowlists = {}
for workflow in state["workflow_contracts"]:
    allowlists.setdefault(workflow["capability"], []).append(workflow["host"])
for cap in allowlists:
    allowlists[cap] = sorted(set(allowlists[cap]))
policy = {
    "schema_version": 1,
    "default_decision": "deny",
    "deny_unregistered_plugins": True,
    "require_active_lineage_for_high_risk": True,
    "min_trust_for_high_risk": "signed",
    "require_bound_approval_for_high_risk": True,
    "approval_type_by_risk": {"high": "change_ticket"},
    "allowed_hosts_by_capability": allowlists,
    "forbid_credential_forwarding": True,
    "require_active_credential": True
}
call("PUT", "/v1/boundary-policy", policy)

print("[8/8] Verifying state and writing an evidence-connected incident submission")
final = call("GET", "/v1/export")
final_memories = ids(final["memories"]); final_sources = ids(final["sources"])
relevant_ids = bad_sources | bad_memories | bad_actions | {archive_id, old_id}
causal_events = []
for event in final["audit"]:
    if event["type"] == "credential_rotated":
        continue
    tokens = set()
    for value in event.values():
        if isinstance(value, str): tokens.add(value)
        elif isinstance(value, list): tokens.update(x for x in value if isinstance(x, str))
    if tokens & relevant_ids and event["type"] in {
        "source_fetch", "memory_derivation", "plugin_metadata_update",
        "action_planned", "credential_forwarded"
    }:
        causal_events.append(event["id"])
preserved_signed = next(m["id"] for m in final["memories"] if m["status"] == "active" and
    any(final_sources[s]["trust"] == "signed" and final_sources[s]["signature"]["valid"] for s in m["source_ids"]))
preserved_collab = next(m["id"] for m in final["memories"] if m["status"] == "active" and
    any(final_sources[s]["trust"] == "collaborative" for s in m["source_ids"]))
report = {
    "schema_version": 1,
    "incident_summary": "Invalid redirected retrieval and mirror metadata entered controlling memory, rewrote the archive plugin, queued an external export, and forwarded its credential generation.",
    "causal_chains": [{
        "source_ids": sorted(bad_sources),
        "memory_ids": sorted(bad_memories),
        "plugin_ids": [archive_id],
        "action_ids": sorted(bad_actions),
        "audit_event_ids": causal_events
    }],
    "quarantined_source_ids": sorted(bad_sources),
    "quarantined_memory_ids": sorted(bad_memories),
    "cancelled_action_ids": sorted(bad_actions),
    "rotated_credentials": [{"old_id": old_id, "new_id": new_cred["id"]}],
    "repaired_plugin_ids": [archive_id],
    "preserved_memory_ids": [preserved_signed, preserved_collab],
    "policy_rationale": "High-risk calls now require active signed lineage and a ticket bound to capability, target, and argument digest; every destination is capability-allowlisted, unregistered tools and credential forwarding fail closed, while low-risk collaborative lookup remains usable."
}
OUT.mkdir(parents=True, exist_ok=True)
(OUT / "incident.json").write_text(json.dumps(report, indent=2, sort_keys=True))
(OUT / "README.md").write_text(
    "# Meridian recovery\n\nThe invalid redirect and catalog mirror were traced through durable derivations to the archive plugin, unsafe queued export, and credential-forwarding event. Their branch was selectively quarantined, the exposed credential was rotated and rebound, the signed registration restored, and a fail-closed provenance-aware boundary installed. Signed operational knowledge and collaborative finance retention knowledge remain active.\n")

# Install the general runtime-snapshot guard and verify malformed input fails closed.
guard_source = Path(__file__).with_name("boundary_guard.py")
guard_target = OUT / "boundary_guard.py"
shutil.copyfile(guard_source, guard_target)
guard_target.chmod(0o755)
probe = subprocess.run(["python3", str(guard_target)], input="{}\n", text=True,
                       capture_output=True, timeout=5, check=True)
if json.loads(probe.stdout)["decision"] != "deny":
    raise SystemExit("boundary guard did not fail closed")
print("Recovery complete; structured evidence and boundary guard written to", OUT)
