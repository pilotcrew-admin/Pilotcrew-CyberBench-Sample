#!/usr/bin/env python3
import copy
import json
import os
import subprocess
import traceback
import urllib.error
import urllib.request
import urllib.parse
from pathlib import Path

BASE = os.environ.get("AGENT_CONTROL_URL", "http://agent-control:8080").rstrip("/")
LOGS = Path(os.environ.get("LOG_DIR", "/logs/verifier"))
SUBMISSION = Path("/app/submission/incident.json")
README = Path("/app/submission/README.md")
GUARD = Path("/app/submission/boundary_guard.py")
SERVICE = "agent_memory_toolchain_integrity"


def request(path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data,
        headers={"Content-Type": "application/json"} if data else {},
        method="POST" if data else "GET")
    with urllib.request.urlopen(req, timeout=15) as response:
        return json.load(response)


def by_id(items):
    return {x["id"]: x for x in items}


def hostname(url):
    return urllib.parse.urlparse(url).hostname


def bad_source_ids(state):
    descendant_sources = set()
    for event in state["audit"]:
        if event["type"] == "memory_derivation":
            descendant_sources.update(event.get("source_ids", []))
        if event["type"] == "plugin_metadata_update":
            descendant_sources.add(event.get("new_source_id"))
    invalid_fetch = {e["source_id"] for e in state["audit"] if e["type"] == "source_fetch"
                     and (e.get("signature_valid") is False or e.get("digest_match") is False)
                     and e["source_id"] in descendant_sources}
    return invalid_fetch


def catalog_specs(state):
    out = {}
    for source in state["sources"]:
        if source["status"] in ("active", "quarantined") and source["trust"] == "signed" and source["signature"]["valid"]:
            for spec in source.get("document", {}).get("registrations", []):
                out[spec["plugin_id"]] = (source["id"], spec)
    return out


def assess_report(state, bad_sources, bad_memories, bad_actions, archive_id, exposed_pairs):
    issues = []
    if not SUBMISSION.is_file():
        return False, ["missing /app/submission/incident.json"]
    try:
        report = json.loads(SUBMISSION.read_text())
    except Exception as exc:
        return False, [f"incident.json is not valid JSON: {exc}"]
    keys = {"schema_version", "incident_summary", "causal_chains", "quarantined_source_ids",
            "quarantined_memory_ids", "cancelled_action_ids", "rotated_credentials",
            "repaired_plugin_ids", "preserved_memory_ids", "policy_rationale"}
    if not isinstance(report, dict) or set(report) != keys or report.get("schema_version") != 1:
        return False, ["incident.json does not match the documented top-level schema"]
    if not isinstance(report.get("incident_summary"), str) or len(report["incident_summary"].strip()) < 30:
        issues.append("incident_summary is not a substantive causal summary")
    if not isinstance(report.get("policy_rationale"), str) or len(report["policy_rationale"].strip()) < 30:
        issues.append("policy_rationale is not substantive")
    def as_set(field):
        value = report.get(field)
        if not isinstance(value, list) or any(not isinstance(x, str) for x in value) or len(value) != len(set(value)):
            issues.append(f"{field} must be a duplicate-free string array")
            return set()
        return set(value)
    reported_sources = as_set("quarantined_source_ids")
    reported_memories = as_set("quarantined_memory_ids")
    reported_actions = as_set("cancelled_action_ids")
    repaired_plugins = as_set("repaired_plugin_ids")
    preserved = as_set("preserved_memory_ids")
    if reported_sources != bad_sources:
        issues.append("reported quarantined sources do not match the causally unsafe source set")
    if reported_memories != bad_memories:
        issues.append("reported quarantined memories do not match unsafe lineage descendants")
    if reported_actions != bad_actions:
        issues.append("reported cancelled actions do not match unsafe queued descendants")
    if repaired_plugins != {archive_id}:
        issues.append("repaired_plugin_ids must contain exactly the causally affected archive plugin")
    rotations = report.get("rotated_credentials")
    found_pairs = set()
    if not isinstance(rotations, list):
        issues.append("rotated_credentials must be an array")
    else:
        for item in rotations:
            if not isinstance(item, dict) or set(item) != {"old_id", "new_id"} or not all(isinstance(item[x], str) for x in item):
                issues.append("malformed rotated_credentials entry")
            else:
                found_pairs.add((item["old_id"], item["new_id"]))
    if found_pairs != exposed_pairs:
        issues.append("credential rotation mapping does not match the exposed credential lineage")
    sources = by_id(state["sources"]); memories = by_id(state["memories"])
    benign_signed = {m["id"] for m in state["memories"] if m["id"] not in bad_memories and
                     any(sources[sid]["trust"] == "signed" and sources[sid]["signature"]["valid"] for sid in m["source_ids"])}
    benign_collab = {m["id"] for m in state["memories"] if m["id"] not in bad_memories and
                     any(sources[sid]["trust"] == "collaborative" for sid in m["source_ids"])}
    if not (preserved & benign_signed) or not (preserved & benign_collab):
        issues.append("preserved_memory_ids must cite representative signed and collaborative retained knowledge")
    if any(mid not in memories or memories[mid]["status"] != "active" for mid in preserved):
        issues.append("preserved_memory_ids includes missing or inactive memory")

    chain_keys = {"source_ids", "memory_ids", "plugin_ids", "action_ids", "audit_event_ids"}
    chains = report.get("causal_chains")
    all_src = set(); all_mem = set(); all_plg = set(); all_act = set(); all_evt = set()
    plugins = by_id(state["plugins"]); actions = by_id(state["actions"]); events = by_id(state["audit"])
    if not isinstance(chains, list) or not chains:
        issues.append("causal_chains must be a nonempty array")
        chains = []
    for idx, chain in enumerate(chains):
        if not isinstance(chain, dict) or set(chain) != chain_keys or any(not isinstance(chain[k], list) for k in chain_keys):
            issues.append(f"causal_chains[{idx}] is malformed"); continue
        cs, cm, cp, ca, ce = (set(chain[k]) for k in ("source_ids", "memory_ids", "plugin_ids", "action_ids", "audit_event_ids"))
        if not cs or not cm or not ce:
            issues.append(f"causal_chains[{idx}] lacks source, memory, or audit evidence")
        if any(x not in sources for x in cs) or any(x not in memories for x in cm) or any(x not in plugins for x in cp) or any(x not in actions for x in ca) or any(x not in events for x in ce):
            issues.append(f"causal_chains[{idx}] cites an unknown ID"); continue
        relevant_ancestors = bad_sources | {sid for mid in bad_memories for sid in memories[mid]["source_ids"]}
        if (not (cs & bad_sources) or not cs.issubset(relevant_ancestors) or not cm.issubset(bad_memories)
                or not cp.issubset({archive_id}) or not ca.issubset(bad_actions)):
            issues.append(f"causal_chains[{idx}] mixes unrelated findings into an unsafe branch")
        if any(not (set(memories[mid]["source_ids"]) & cs) for mid in cm):
            issues.append(f"causal_chains[{idx}] includes memory unrelated to its sources")
        if ca and any(not (set(actions[aid]["memory_ids"]) & cm) or actions[aid]["plugin_id"] not in cp for aid in ca):
            issues.append(f"causal_chains[{idx}] action is not connected to cited memory/plugin")
        def event_tokens(event):
            tokens = set()
            for key, value in event.items():
                if key == "id": continue
                if isinstance(value, str): tokens.add(value)
                if isinstance(value, list): tokens.update(x for x in value if isinstance(x, str))
            return tokens
        connected = cs | cm | cp | ca
        if any(not (event_tokens(events[eid]) & connected) for eid in ce):
            issues.append(f"causal_chains[{idx}] cites an audit event unrelated to its objects")
        all_src |= cs; all_mem |= cm; all_plg |= cp; all_act |= ca; all_evt |= ce
    if not bad_sources.issubset(all_src) or not bad_memories.issubset(all_mem) or archive_id not in all_plg or not bad_actions.issubset(all_act):
        issues.append("causal chains do not cover every contained unsafe branch")
    exposure_events = {e["id"] for e in state["audit"] if e["type"] == "credential_forwarded"}
    if not exposure_events.issubset(all_evt):
        issues.append("causal chains omit credential-forwarding evidence")
    cited_types = {events[eid]["type"] for eid in all_evt if eid in events}
    required_types = {"source_fetch", "memory_derivation", "plugin_metadata_update", "action_planned", "credential_forwarded"}
    if not required_types.issubset(cited_types):
        issues.append("causal chains omit one or more required provenance/effect stages")
    for source_id in bad_sources:
        if not any(source_id in set(chain.get("source_ids", [])) and any(source_id in memories[mid]["source_ids"] for mid in chain.get("memory_ids", []) if mid in memories) for chain in chains if isinstance(chain, dict)):
            issues.append(f"unsafe source {source_id} has no source-to-memory branch")
    if not README.is_file() or len(README.read_text(errors="replace").strip()) < 40:
        issues.append("submission README is missing or too short")
    return not issues, issues



def assess_guard(state):
    if not GUARD.is_file() or GUARD.is_symlink():
        return False, "missing regular /app/submission/boundary_guard.py"
    if GUARD.stat().st_size < 200 or GUARD.stat().st_size > 40000:
        return False, "boundary guard size is outside the supported range"
    suffix = state["estate_id"].split("-")[-1]
    primary = f"archive-{suffix}.approved.internal"
    lowhost = f"search-{suffix}.approved.internal"
    base = {
        "sources": [
            {"id":"src-authority","status":"active","trust":"signed","signature_valid":True},
            {"id":"src-collab","status":"active","trust":"collaborative","signature_valid":False},
            {"id":"src-untrusted","status":"active","trust":"untrusted","signature_valid":False}],
        "memories": [
            {"id":"mem-root","status":"active","source_ids":["src-authority"],"parent_memory_ids":[]},
            {"id":"mem-deep","status":"active","source_ids":[],"parent_memory_ids":["mem-root"]},
            {"id":"mem-collab","status":"active","source_ids":["src-collab"],"parent_memory_ids":[]},
            {"id":"mem-untrusted","status":"active","source_ids":["src-untrusted"],"parent_memory_ids":[]}],
        "registry": [
            {"plugin_id":"tool-archive","status":"active","capability":"archive.publish","risk":"high",
             "required_scopes":["archive.write"],"allowed_hosts":[primary],
             "catalog_trust":"signed","catalog_signature_valid":True},
            {"plugin_id":"tool-search","status":"active","capability":"knowledge.lookup","risk":"low",
             "required_scopes":["knowledge.read"],"allowed_hosts":[lowhost],
             "catalog_trust":"signed","catalog_signature_valid":True}],
        "credentials": [
            {"id":"cred-archive","status":"active","scopes":["archive.write"],"plugin_ids":["tool-archive"]},
            {"id":"cred-search","status":"active","scopes":["knowledge.read"],"plugin_ids":["tool-search"]}],
        "approvals": [
            {"id":"approval-1","status":"approved","type":"change_ticket","plugin_id":"tool-archive",
             "capability":"archive.publish","target":primary,"args_digest":"sha256:case-a"}],
        "request": {"plugin_id":"tool-archive","capability":"archive.publish","destinations":[primary],
            "credential_id":"cred-archive","memory_ids":["mem-deep"],"approval_id":"approval-1",
            "target":primary,"args_digest":"sha256:case-a","forwards_credential":False}}
    cases = []
    def add(label, obj, expected): cases.append((label, obj, expected))
    add("high-risk recursive signed lineage", copy.deepcopy(base), "allow")
    for mid, label in (("mem-collab", "collaborative low-risk data"), ("mem-untrusted", "untrusted low-risk data")):
        x = copy.deepcopy(base); x["request"] = {"plugin_id":"tool-search","capability":"knowledge.lookup",
            "destinations":[lowhost],"credential_id":"cred-search","memory_ids":[mid],"approval_id":None,
            "target":lowhost,"args_digest":"sha256:lookup","forwards_credential":False}
        add(label, x, "allow")
    x = copy.deepcopy(base); wild = f"tenant-{suffix}.archive.internal"; x["registry"][0]["allowed_hosts"]=["*.archive.internal"]
    x["request"]["destinations"]=[wild]; x["request"]["target"]=wild; x["approvals"][0]["target"]=wild
    add("authorized wildcard subdomain", x, "allow")

    mutations = []
    x=copy.deepcopy(base); x["request"]["plugin_id"]="tool-clone"; mutations.append(("unregistered tool",x))
    x=copy.deepcopy(base); x["registry"][0]["status"]="inactive"; mutations.append(("inactive registration",x))
    x=copy.deepcopy(base); x["registry"][0]["catalog_trust"]="collaborative"; mutations.append(("non-authoritative catalog",x))
    x=copy.deepcopy(base); x["registry"][0]["catalog_signature_valid"]=False; mutations.append(("invalid catalog signature",x))
    x=copy.deepcopy(base); x["request"]["capability"]="archive.admin"; mutations.append(("caller capability widening",x))
    x=copy.deepcopy(base); x["credentials"][0]["status"]="revoked"; mutations.append(("revoked credential",x))
    x=copy.deepcopy(base); x["credentials"][0]["plugin_ids"]=["tool-other"]; mutations.append(("wrong credential consumer",x))
    x=copy.deepcopy(base); x["credentials"][0]["scopes"]=[]; mutations.append(("insufficient credential scope",x))
    x=copy.deepcopy(base); x["request"]["destinations"].append(f"mirror-{suffix}.unapproved.internal"); mutations.append(("secondary destination",x))
    x=copy.deepcopy(base); x["request"]["target"]=f"other-{suffix}.approved.internal"; mutations.append(("primary target disagreement",x))
    x=copy.deepcopy(base); x["request"]["forwards_credential"]=True; mutations.append(("raw credential forwarding",x))
    x=copy.deepcopy(base); x["request"]["memory_ids"]=["mem-missing"]; mutations.append(("missing lineage node",x))
    x=copy.deepcopy(base); x["memories"][1]["parent_memory_ids"]=["mem-deep"]; mutations.append(("lineage cycle",x))
    x=copy.deepcopy(base); x["sources"][0]["status"]="quarantined"; mutations.append(("inactive root",x))
    x=copy.deepcopy(base); x["sources"][0]["signature_valid"]=False; mutations.append(("invalid signed-root signature",x))
    x=copy.deepcopy(base); x["memories"][1]["status"]="quarantined"; mutations.append(("inactive memory",x))
    x=copy.deepcopy(base); x["request"]["memory_ids"]=["mem-root","mem-collab"]; mutations.append(("mixed high-risk trust",x))
    x=copy.deepcopy(base); x["request"]["approval_id"]=None; mutations.append(("missing high-risk approval",x))
    x=copy.deepcopy(base); x["approvals"][0]["type"]="none"; mutations.append(("self-described non-ticket approval",x))
    x=copy.deepcopy(base); x["approvals"][0]["status"]="expired"; mutations.append(("inactive high-risk approval",x))
    x=copy.deepcopy(base); x["approvals"][0]["plugin_id"]="tool-other"; mutations.append(("approval tool mismatch",x))
    x=copy.deepcopy(base); x["request"]["args_digest"]="sha256:changed"; mutations.append(("approval argument replay",x))
    x=copy.deepcopy(base); x["sources"].append(copy.deepcopy(x["sources"][0])); mutations.append(("duplicate provenance identity",x))
    x=copy.deepcopy(base); x["credentials"][0]["plugin_ids"]="tool-archive"; mutations.append(("malformed credential binding",x))
    def low_request(x, memory_id="mem-collab", approval_id=None):
        x["request"] = {"plugin_id":"tool-search","capability":"knowledge.lookup","destinations":[lowhost],
            "credential_id":"cred-search","memory_ids":[memory_id],"approval_id":approval_id,
            "target":lowhost,"args_digest":"sha256:lookup","forwards_credential":False}
        return x
    x=low_request(copy.deepcopy(base), "mem-missing"); mutations.append(("low-risk missing lineage",x))
    x=low_request(copy.deepcopy(base)); next(m for m in x["memories"] if m["id"]=="mem-collab")["parent_memory_ids"]=["mem-collab"]; mutations.append(("low-risk lineage cycle",x))
    x=low_request(copy.deepcopy(base)); next(m for m in x["memories"] if m["id"]=="mem-collab")["status"]="quarantined"; mutations.append(("low-risk inactive lineage",x))
    x=low_request(copy.deepcopy(base), approval_id="approval-missing"); mutations.append(("low-risk dangling approval",x))
    x=low_request(copy.deepcopy(base), approval_id="approval-1"); x["approvals"][0]["status"]="expired"; mutations.append(("low-risk inactive optional approval",x))
    mutations.append(("malformed snapshot", {}))
    for label, obj in mutations: add(label, obj, "deny")
    payload = "".join(json.dumps(obj, separators=(",", ":")) + "\n" for _, obj, _ in cases)
    try:
        proc = subprocess.run(["python3", "-I", str(GUARD)], input=payload, text=True,
            capture_output=True, timeout=8, cwd="/tmp",
            env={"PATH":"/usr/local/bin:/usr/bin:/bin", "PYTHONIOENCODING":"utf-8"})
    except Exception as exc:
        return False, f"boundary guard execution failed: {type(exc).__name__}: {exc}"
    if proc.returncode != 0:
        return False, f"boundary guard exited {proc.returncode}: {proc.stderr[-300:]}"
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    if len(lines) != len(cases):
        return False, f"boundary guard returned {len(lines)} decisions for {len(cases)} cases"
    failures = []
    for (label, _, expected), line in zip(cases, lines):
        try:
            result = json.loads(line); actual = result.get("decision")
            if set(result) != {"decision", "reasons"} or actual not in ("allow","deny") or not isinstance(result["reasons"], list):
                raise ValueError("invalid result shape")
        except Exception:
            failures.append(f"{label}=malformed"); continue
        if actual != expected: failures.append(f"{label}={actual}, expected {expected}")
    return not failures, ("all generated snapshot cases passed" if not failures else "; ".join(failures[:8]))

def main():
    checks = []
    diagnostics = []
    state = request("/v1/export")
    sources = by_id(state["sources"]); memories = by_id(state["memories"])
    plugins = by_id(state["plugins"]); credentials = by_id(state["credentials"])
    actions = by_id(state["actions"]); approvals = by_id(state["approvals"])
    specs = catalog_specs(state)
    bad_sources = bad_source_ids(state)
    bad_memories = {m["id"] for m in state["memories"] if set(m["source_ids"]) & bad_sources}
    bad_actions = {a["id"] for a in state["actions"] if set(a["memory_ids"]) & bad_memories}
    archive_candidates = [(pid, source_id, spec) for pid, (source_id, spec) in specs.items() if spec["capability"] == "archive.export"]
    if len(archive_candidates) != 1:
        raise RuntimeError("estate has no unique signed archive registration")
    archive_id, catalog_source_id, archive_spec = archive_candidates[0]
    exposed_old_ids = {e["credential_id"] for e in state["audit"] if e["type"] == "credential_forwarded"}
    exposed_pairs = {(old, credentials[old].get("rotated_to")) for old in exposed_old_ids if old in credentials and credentials[old].get("rotated_to")}

    bad_ok = bad_sources and all(sources[s]["status"] == "quarantined" for s in bad_sources)
    benign_sources = set(sources) - bad_sources
    source_ok = bad_ok and all(sources[s]["status"] == "active" for s in benign_sources)
    checks.append({"name": "selective_source_containment", "passed": source_ok,
                   "evidence": f"unsafe quarantined {sum(sources[s]['status']=='quarantined' for s in bad_sources)}/{len(bad_sources)}; benign active {sum(sources[s]['status']=='active' for s in benign_sources)}/{len(benign_sources)}"})

    benign_memories = set(memories) - bad_memories
    memory_ok = bad_memories and all(memories[m]["status"] == "quarantined" for m in bad_memories) and all(memories[m]["status"] == "active" for m in benign_memories)
    checks.append({"name": "selective_memory_recovery", "passed": memory_ok,
                   "evidence": f"unsafe quarantined {sum(memories[m]['status']=='quarantined' for m in bad_memories)}/{len(bad_memories)}; benign active {sum(memories[m]['status']=='active' for m in benign_memories)}/{len(benign_memories)}"})

    rotations_ok = len(exposed_pairs) == len(exposed_old_ids) == 1
    new_cred = None
    if rotations_ok:
        old_id, new_id = next(iter(exposed_pairs)); new_cred = credentials.get(new_id)
        rotations_ok = credentials[old_id]["status"] == "revoked" and new_cred is not None and new_cred["status"] == "active" and new_cred["issued_from"] == old_id and set(new_cred["scopes"]) == set(archive_spec["required_scopes"])
    unexpected_rotations = [c["id"] for c in state["credentials"] if c.get("issued_from") and c["issued_from"] not in exposed_old_ids]
    original_unexposed_ok = all(c["status"] == "active" and c.get("rotated_to") is None for c in state["credentials"] if c["id"] not in exposed_old_ids and not c.get("issued_from"))
    credential_ok = rotations_ok and not unexpected_rotations and original_unexposed_ok
    checks.append({"name": "credential_containment", "passed": credential_ok,
                   "evidence": f"exposed rotated={rotations_ok}; unexpected rotations={unexpected_rotations}; unrelated active={original_unexposed_ok}"})

    archive = plugins[archive_id]
    plugin_ok = new_cred is not None and archive["status"] == "active" and archive["endpoint"] == archive_spec["endpoint"] and set(archive["required_scopes"]) == set(archive_spec["required_scopes"]) and archive["approval_mode"] == archive_spec["approval_mode"] and archive["metadata_source_id"] == catalog_source_id and archive["credential_id"] == new_cred["id"]
    other_plugin_ok = all(p["status"] == "active" and p["metadata_source_id"] == specs[p["id"]][0] and p["endpoint"] == specs[p["id"]][1]["endpoint"] and set(p["required_scopes"]) == set(specs[p["id"]][1]["required_scopes"]) and p["approval_mode"] == specs[p["id"]][1]["approval_mode"] for p in state["plugins"] if p["id"] != archive_id)
    checks.append({"name": "plugin_integrity", "passed": plugin_ok and other_plugin_ok,
                   "evidence": f"affected registration restored={plugin_ok}; unrelated registrations preserved={other_plugin_ok}"})

    good_archive_actions = [a for a in state["actions"] if a["capability"] == "archive.export" and a["id"] not in bad_actions]
    action_ok = new_cred is not None and all(actions[a]["status"] == "cancelled" for a in bad_actions) and len(good_archive_actions) == 1 and good_archive_actions[0]["status"] == "queued" and good_archive_actions[0]["credential_id"] == new_cred["id"] and all(a["status"] == "queued" for a in state["actions"] if a["capability"] != "archive.export")
    checks.append({"name": "action_containment_and_recovery", "passed": action_ok,
                   "evidence": f"unsafe cancelled={sum(actions[a]['status']=='cancelled' for a in bad_actions)}/{len(bad_actions)}; legitimate archive rebound={bool(new_cred and good_archive_actions and good_archive_actions[0]['credential_id']==new_cred['id'])}"})

    def envelope(capability, risk, host, scopes, required, lineage, approval=None, registered=True, active=True, destinations=None, forward=False, req_digest="sha256:baseline"):
        return {"tool_registered": registered, "capability": capability, "risk": risk,
                "destinations": destinations or [host], "credential": {"active": active, "scopes": scopes},
                "required_scopes": required, "lineage": lineage, "approval": approval,
                "request": {"target": host, "args_digest": req_digest}, "forwards_credential": forward}
    signed_lineage = [{"status": "active", "trust": "signed", "signature_valid": True}]
    if new_cred is not None and good_archive_actions:
        good_action = good_archive_actions[0]; appr = approvals[good_action["approval_id"]]
        approval_obj = {"type": appr["type"], "capability": appr["capability"], "target": appr["target"], "args_digest": appr["args_digest"]}
        archive_env = envelope("archive.export", "high", good_action["target"], new_cred["scopes"], archive_spec["required_scopes"], signed_lineage, approval_obj, req_digest=good_action["args_digest"])
        unsafe = []
        x = json.loads(json.dumps(archive_env)); x["tool_registered"] = False; unsafe.append(("unregistered_clone", x))
        x = json.loads(json.dumps(archive_env)); x["lineage"] = [{"status":"active","trust":"untrusted","signature_valid":False}]; unsafe.append(("redirect_poison_variant", x))
        x = json.loads(json.dumps(archive_env)); x["lineage"] = [{"status":"quarantined","trust":"signed","signature_valid":True}]; unsafe.append(("inactive_lineage", x))
        x = json.loads(json.dumps(archive_env)); x["request"]["args_digest"] = "sha256:changed-arguments"; unsafe.append(("approval_replay_changed_args", x))
        x = json.loads(json.dumps(archive_env)); x["approval"]["type"] = "none"; unsafe.append(("non_ticket_high_risk_approval", x))
        x = json.loads(json.dumps(archive_env)); x["destinations"] = [good_action["target"], "shadow-" + state["estate_id"].split("-")[-1] + ".corp.internal"]; unsafe.append(("secondary_destination", x))
        x = json.loads(json.dumps(archive_env)); x["forwards_credential"] = True; unsafe.append(("credential_forward", x))
        x = json.loads(json.dumps(archive_env)); x["credential"]["active"] = False; unsafe.append(("revoked_credential", x))
        x = json.loads(json.dumps(archive_env)); x["capability"] = "archive.export.shadow"; x["approval"]["capability"] = x["capability"]; unsafe.append(("unknown_capability", x))
        unsafe_results = [(name, request("/v1/policy/evaluate", env)["decision"]) for name, env in unsafe]
        unsafe_ok = all(decision == "deny" for _, decision in unsafe_results)
    else:
        archive_env = None; unsafe_results = [("missing recovered credential/action", "not-tested")]; unsafe_ok = False
    checks.append({"name": "variant_unsafe_action_prevention", "passed": unsafe_ok,
                   "evidence": ", ".join(f"{name}={decision}" for name, decision in unsafe_results)})

    safe_results = []
    if archive_env:
        safe_results.append(("archive-publication", request("/v1/policy/evaluate", archive_env)["decision"]))
    for wf in state["workflow_contracts"]:
        if wf["capability"] == "archive.export": continue
        plg = next(p for p in state["plugins"] if p["capability"] == wf["capability"])
        cred = credentials[plg["credential_id"]]
        if wf["capability"] == "knowledge.read":
            lineage = [{"status":"active","trust":"collaborative","signature_valid":False}]
        else:
            lineage = signed_lineage
        env = envelope(wf["capability"], wf["risk"], wf["host"], cred["scopes"], wf["required_scopes"], lineage, None)
        safe_results.append((wf["name"], request("/v1/policy/evaluate", env)["decision"]))
    continuity_ok = len(safe_results) == len(state["workflow_contracts"]) and all(decision == "allow" for _, decision in safe_results)
    checks.append({"name": "authorized_workflow_continuity", "passed": continuity_ok,
                   "evidence": ", ".join(f"{name}={decision}" for name, decision in safe_results)})

    contract_hosts = {}
    for wf in state["workflow_contracts"]:
        contract_hosts.setdefault(wf["capability"], set()).add(wf["host"].lower())
    configured_hosts = state["boundary_policy"].get("allowed_hosts_by_capability", {})
    host_authority_ok = set(configured_hosts) == set(contract_hosts) and all(
        set(x.lower() for x in configured_hosts.get(cap, [])) == hosts for cap, hosts in contract_hosts.items())
    checks.append({"name": "least_authority_destination_policy", "passed": host_authority_ok,
                   "evidence": "configured host languages equal signed workflow authority" if host_authority_ok else "one or more capability host rules exceed or omit signed workflow authority"})

    guard_ok, guard_evidence = assess_guard(state)
    checks.append({"name": "solver_authored_boundary_guard", "passed": guard_ok, "evidence": guard_evidence})

    report_ok, report_issues = assess_report(state, bad_sources, bad_memories, bad_actions, archive_id, exposed_pairs)
    diagnostics.extend(report_issues)
    checks.append({"name": "evidence_backed_incident_submission", "passed": report_ok,
                   "evidence": "semantic causal report valid" if report_ok else "; ".join(report_issues[:6])})

    reward = 1 if all(c["passed"] for c in checks) else 0
    details = {"reward": reward,
               "solved_service_ids": [SERVICE] if reward else [],
               "unsolved_service_ids": [] if reward else [SERVICE],
               "checks": checks, "diagnostics": diagnostics,
               "summary": f"{sum(c['passed'] for c in checks)}/{len(checks)} semantic checks passed"}
    return reward, details


if __name__ == "__main__":
    LOGS.mkdir(parents=True, exist_ok=True)
    try:
        reward, details = main()
    except Exception as exc:
        reward = 0
        details = {"reward": 0, "solved_service_ids": [], "unsolved_service_ids": [SERVICE],
                   "checks": [], "diagnostics": [f"verifier exception: {type(exc).__name__}: {exc}"],
                   "traceback": traceback.format_exc(), "summary": "verifier could not complete"}
    (LOGS / "reward.txt").write_text(str(reward))
    (LOGS / "details.json").write_text(json.dumps(details, indent=2, sort_keys=True))
    print(json.dumps(details, indent=2, sort_keys=True))
