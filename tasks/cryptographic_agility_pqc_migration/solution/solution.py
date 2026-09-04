#!/usr/bin/env python3
"""Reference expert workflow for the Helios cryptographic-agility migration."""
from __future__ import annotations
import hashlib,hmac,json,os
from pathlib import Path
ROOT=Path(os.environ.get("CRYPTO_CASE_ROOT","/opt/crypto-case")); OUT=Path(os.environ.get("MIGRATION_PLAN_OUTPUT","/app/submission/migration-plan.json")); RINGS=("canary","fleet")
def load(n): return json.loads((ROOT/"case"/n).read_text(encoding="utf-8"))
def lines(n): return [json.loads(x) for x in (ROOT/"case"/n).read_text(encoding="utf-8").splitlines() if x.strip()]
def main():
 print("[1/7] Replaying deployment bindings and selecting current effective observations")
 incident=load("incident-evidence.json"); material_doc=load("materials.json"); estate=load("estate.json"); compat=load("compatibility.json"); archives_doc=load("archives.json"); baseline=load("policy-baseline.json"); execution=load("execution-fixtures.json")
 materials={x["id"]:x for x in material_doc["materials"]}; consumers={x["id"]:x for x in estate["consumers"]}; versions=compat["versions"]; packages={x["id"]:x for x in compat["packages"]}
 active={}
 for event in sorted(lines("deployment-events.jsonl"),key=lambda x:(x["time"],x["id"])):
  if event["time"]>estate["captured_at"]: continue
  if event["event"]=="bind": active[event["subject"]]=event["consumer"]
  elif event["event"]=="unbind" and active.get(event["subject"])==event["consumer"]: active.pop(event["subject"],None)
 runtime=lines("tls-negotiations.jsonl")+lines("signature-verifications.jsonl")+lines("ssh-sessions.jsonl"); interruption_rows=lines("interruption-observations.jsonl")
 latest={}
 for row in runtime:
  subject=row.get("subject"); cid=active.get(subject)
  if not cid or cid not in consumers or not consumers[cid].get("required") or row.get("result")!="success" or row.get("observed_at","")>estate["captured_at"]: continue
  key=(cid,subject)
  if key not in latest or (row["observed_at"],row["id"])>(latest[key]["observed_at"],latest[key]["id"]): latest[key]=row
 grouped={}
 for (cid,_),row in latest.items(): grouped.setdefault(cid,[]).append(row)
 dependencies=[]
 for cid in sorted(grouped):
  rows=grouped[cid]
  dependencies.append({"surface":consumers[cid]["surface"],"consumer":cid,"effective_algorithms":sorted({x for r in rows for x in r["algorithms"]}),"materials":sorted({x for r in rows for x in r["materials"]}),"evidence":sorted(r["id"] for r in rows)})
 for ar in archives_doc["archives"]: dependencies.append({"surface":ar["surface"],"consumer":ar["id"],"effective_algorithms":sorted({ar["data_cipher"],ar["wrap_algorithm"]}),"materials":[ar["wrap_material"]],"evidence":[ar["evidence"]]})
 compromised=sorted({x["material"] for x in incident["events"] if x.get("confidence")=="confirmed" and x.get("type") in {"hsm_export_confirmed","unauthorized_signing_session"}})
 retire=sorted(x["id"] for x in materials.values() if x.get("disposition")=="retire_at_completion")

 print("[2/7] Joining policy scope to issuer, identity, independence, and restore metadata")
 approved=set(baseline["approved_sources"])
 def candidates(surface,role,allowed): return [m for m in materials.values() if m.get("surface")==surface and m.get("role")==role and m.get("approved")=="final" and m.get("source") in approved and set(m.get("algorithms",[])).issubset(set(allowed))]
 t=baseline["surfaces"]["tls:telemetry-api"]
 roots=[m for m in candidates("tls:telemetry-api","trust_anchor",t["trust_anchor_algorithms"]) if m.get("trust_domain")==t["trust_domain"]]
 creds=[m for m in candidates("tls:telemetry-api","server_credential",t["allowed_server_signatures"]) if m.get("issuer") in {x["id"] for x in roots} and t["server_dns_name"] in m.get("dns_names",[]) and set(t["required_key_usage"]).issubset(m.get("key_usage",[]))]
 s=baseline["surfaces"]["signing:device-update"]
 signer_pool=[m for m in candidates("signing:device-update","release_signer",s["allowed_signature_algorithms"]) if m.get("signing_context")==s["signing_context"]]
 signers=[]
 from itertools import combinations,product
 signer_sets=[list(xs) for xs in combinations(signer_pool,s["threshold"]) if {a for x in xs for a in x["algorithms"]}==set(s["required_independent_algorithms"]) and (not s["require_distinct_independence_domains"] or len({x.get("independence_domain") for x in xs})==len(xs))]
 h=baseline["surfaces"]["ssh:ops-bastion"]
 hosts=[m for m in candidates("ssh:ops-bastion","host_key",h["allowed_host_key_algorithms"]) if m.get("host_identity")==h["host_identity"]]
 cas=[m for m in candidates("ssh:ops-bastion","user_ca",h["allowed_user_ca_algorithms"]) if set(h["required_principal_scopes"]).issubset(m.get("principal_scopes",[]))]
 a=baseline["surfaces"]["archive:compliance"]
 wraps=[m for m in candidates("archive:compliance","wrapping_key",[a["wrap_algorithm"]]) if set(a["required_restore_profiles"]).issubset(m.get("restore_profiles",[]))]
 if len(roots)!=1 or not all((creds,signer_sets,hosts,cas,wraps)): raise RuntimeError("no locally scope-compatible material combination")
 gc=baseline["global_constraints"]; counted=set(gc["counted_private_roles"]); limit=gc["max_final_private_keys_per_custody_domain"]
 valid=[]
 for cred,signer_set,host,ca,wrap in product(creds,signer_sets,hosts,cas,wraps):
  private=[cred,*signer_set,host,ca,wrap]; counts={}
  for m in private:
   if m["role"] not in counted: continue
   domain=m.get("custody_domain"); counts[domain]=counts.get(domain,0)+1
  if None not in counts and all(n<=limit for n in counts.values()): valid.append((cred,signer_set,host,ca,wrap))
 if not valid: raise RuntimeError("no scope-compatible combination satisfies global custody capacity")
 cred,signers,host,ca,wrap=sorted(valid,key=lambda xs:(xs[0]["id"],tuple(x["id"] for x in xs[1]),xs[2]["id"],xs[3]["id"],xs[4]["id"]))[0]
 creds=[cred]; hosts=[host]; cas=[ca]; wraps=[wrap]
 selected={x["id"] for x in roots+creds+signers+hosts+cas+wraps}
 final_policies={
  "tls:telemetry-api":{"minimum_protocol":t["minimum_protocol"],"allowed_kex":t["required_kex"],"allowed_server_credentials":[cred["id"]],"trusted_roots":[roots[0]["id"]],"reject_downgrade":t["reject_downgrade"]},
  "signing:device-update":{"required_signers":sorted(x["id"] for x in signers),"allowed_algorithms":sorted(s["allowed_signature_algorithms"]),"threshold":s["threshold"],"context":s["signing_context"],"reject_revoked":s["reject_revoked"]},
  "ssh:ops-bastion":{"allowed_host_keys":[host["id"]],"allowed_user_cas":[ca["id"]],"allowed_signature_algorithms":h["allowed_host_key_algorithms"],"strict_host_identity":h["strict_host_identity"],"reject_sha1":h["reject_sha1"]},
  "archive:compliance":{"data_cipher":a["data_cipher"],"wrap_algorithm":a["wrap_algorithm"],"wrap_material":wrap["id"],"require_aead":a["require_aead"]}}

 def supports(surface,ver):
  if surface=="tls:telemetry-api": return t["minimum_protocol"] in ver.get("protocols",[]) and set(t["required_kex"]).issubset(ver.get("kex",[])) and set(t["allowed_server_signatures"]).issubset(ver.get("server_signatures",[])) and set(t["trust_anchor_algorithms"]).issubset(ver.get("trust_anchor_algorithms",[]))
  if surface=="signing:device-update": return set(s["allowed_signature_algorithms"]).issubset(ver.get("signature_algorithms",[])) and ver.get("max_threshold",0)>=s["threshold"] and s["signing_context"] in ver.get("contexts",[])
  if surface=="ssh:ops-bastion": return set(h["allowed_host_key_algorithms"]).issubset(ver.get("host_key_algorithms",[])) and set(h["allowed_user_ca_algorithms"]).issubset(ver.get("user_ca_algorithms",[]))
  if surface=="archive:compliance": return a["data_cipher"] in ver.get("data_ciphers",[]) and a["wrap_algorithm"] in ver.get("wrap_algorithms",[])
  return False
 upgrades={}
 for cid,c in consumers.items():
  if supports(c["surface"],versions[c["version"]]): continue
  choices=[p for p in packages.values() if p.get("approved") and p.get("channel")=="offline-recovery" and p.get("from")==c["version"] and p.get("to") in versions and supports(c["surface"],versions[p["to"]])]
  if len(choices)!=1: raise RuntimeError(f"{cid}: target-compatible upgrade is not unique: {[x['id'] for x in choices]}")
  upgrades[cid]=choices[0]

 actions=[]; n=0
 def add(op,**fields):
  nonlocal n; n+=1; actions.append({"id":f"migration-{n:03d}","op":op,**fields})
 upgrade_states={x["consumer"]:x for x in execution["upgrade_states"]}; archive_objects={x["archive"]:x for x in execution["archive_objects"]}
 def effective_faults(cid,ring,pkg):
  latest={}; cutoff=execution["interruption_capture_cutoff"]
  for row in interruption_rows:
   if row.get("consumer")!=cid or row.get("ring")!=ring or row.get("package")!=pkg["id"] or row.get("result")!="captured" or row.get("observed_at","")>cutoff: continue
   fault=row.get("fault_point"); key=(row.get("observed_at",""),row.get("id",""))
   if fault in execution["fault_points"] and (fault not in latest or key>(latest[fault]["observed_at"],latest[fault]["id"])): latest[fault]=row
  return latest
 def recovery_decision(c,state):
  if state.get("write_phase")=="not_started": return "retry_same_image"
  if state.get("write_phase")=="complete_uncommitted" and state.get("journal_integrity")=="valid" and state.get("new_image_integrity")=="verified" and state.get("resume_token")=="valid": return "resume_commit"
  if state.get("rollback_snapshot")=="verified": return "rollback_then_retry"
  if state.get("image_cache")=="verified" and c["rollout"].get("reimage_allowed") is True: return "reimage_then_retry"
  raise RuntimeError("captured upgrade state has no safe recovery branch")
 def recovery_steps(cid,ring,pkg,canary_parent=None):
  c=consumers[cid]; seed=bytes.fromhex(upgrade_states[cid]["state_seed_hex"]); context="\0".join((cid,ring,pkg["id"],pkg["to"],pkg["image_digest"])).encode(); key=hashlib.sha256(seed+context).digest()
  parent=hashlib.sha256(b"captured-v2\0"+seed).digest() if ring=="canary" else bytes.fromhex(canary_parent); rows=effective_faults(cid,ring,pkg); out=[]; total=0
  for fault in execution["fault_points"]:
   row=rows[fault]; digest=hashlib.sha256(json.dumps(row["state"],sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
   if digest!=row["state_digest"]: raise RuntimeError(f"{row['id']}: invalid captured state digest")
   decision=recovery_decision(c,row["state"]); work=execution["recovery_action_work_units"][decision]
   message=b"recover-v2\0"+parent+b"\0"+fault.encode()+b"\0"+row["id"].encode()+b"\0"+bytes.fromhex(digest)+b"\0"+decision.encode()+b"\0"+str(work).encode(); receipt=hmac.new(key,message,hashlib.sha256).hexdigest()
   out.append({"fault_point":fault,"evidence":row["id"],"decision":decision,"work_units":work,"receipt":receipt}); parent=bytes.fromhex(receipt); total+=work
  if total>c["rollout"]["max_recovery_work_units"]: raise RuntimeError(f"{cid}/{ring}: recovery work budget exceeded")
  return out,parent.hex()
 def archive_receipts(ar):
  context="\0".join((ar["id"],a["data_cipher"],wrap["id"],ar["digest"])).encode(); obj=archive_objects[ar["id"]]
  message=bytes.fromhex(obj["legacy_envelope_hex"])+bytes.fromhex(obj["object_nonce_hex"])+context
  envelope=hmac.new(bytes.fromhex(wrap["rewrap_share_hex"]),message,hashlib.sha256).hexdigest(); proof=hmac.new(bytes.fromhex(envelope),b"restore-v1\0"+context,hashlib.sha256).hexdigest()
  return envelope,proof
 print("[3/7] Containing the signer and staging only scope-compatible final material")
 for mid in compromised: add("contain_signer",material=mid)
 for mid in sorted(selected): add("stage_material",material=mid)

 print("[4/7] Executing interrupted canary gates before every fleet upgrade")
 for cid,pkg in sorted(upgrades.items()):
  c=consumers[cid]; domains=sorted(c["rollout"]["failure_domains"])
  add("upgrade_consumer",consumer=cid,package=pkg["id"],ring="canary",failure_domains=domains,batch={"max_total":len(domains)*c["rollout"]["canary_max_per_failure_domain"],"max_per_failure_domain":c["rollout"]["canary_max_per_failure_domain"]},on_interrupt=c["rollout"]["on_interrupt"])
  steps,canary_chain=recovery_steps(cid,"canary",pkg); add("upgrade_gate",consumer=cid,ring="canary",package=pkg["id"],expected_version=pkg["to"],recovery_steps=steps)
  add("upgrade_consumer",consumer=cid,package=pkg["id"],ring="fleet",failure_domains=domains,batch={"max_total":c["availability"]["max_total_offline"],"max_per_failure_domain":c["availability"]["max_per_failure_domain"]},on_interrupt=c["rollout"]["on_interrupt"])
  steps,_=recovery_steps(cid,"fleet",pkg,canary_chain); add("upgrade_gate",consumer=cid,ring="fleet",package=pkg["id"],expected_version=pkg["to"],recovery_steps=steps)

 print("[5/7] Distributing ring-local trust and proving both rings of every workflow")
 for cid,c in sorted(consumers.items()):
  for ring in RINGS:
   if c["surface"]=="tls:telemetry-api": add("distribute_trust",consumer=cid,ring=ring,material=roots[0]["id"])
   elif c["surface"]=="signing:device-update":
    for m in sorted(signers,key=lambda x:x["id"]): add("distribute_trust",consumer=cid,ring=ring,material=m["id"])
   elif c["surface"]=="ssh:ops-bastion": add("distribute_trust",consumer=cid,ring=ring,material=hosts[0]["id"])
 for m in creds+list(signers)+hosts+cas+wraps: add("activate_material",surface=m["surface"],material=m["id"])
 current={x["id"]:set(x.get("active_materials",[])) for x in estate["surfaces"]}
 add("configure_transition",surface="tls:telemetry-api",allowed_materials=sorted(current["tls:telemetry-api"]|{creds[0]["id"]}))
 add("configure_transition",surface="signing:device-update",allowed_materials=sorted(x["id"] for x in signers))
 add("configure_transition",surface="ssh:ops-bastion",allowed_materials=sorted(current["ssh:ops-bastion"]|{hosts[0]["id"],cas[0]["id"]}))
 for cid,c in sorted(consumers.items()):
  if c["surface"] in {"tls:telemetry-api","signing:device-update","ssh:ops-bastion"}:
   for ring in RINGS: add("workflow_gate",surface=c["surface"],consumer=cid,ring=ring,profile="target")

 print("[6/7] Migrating every archive after both restore rings support AEAD/hybrid wrapping")
 for ar in sorted(archives_doc["archives"],key=lambda x:x["id"]):
  envelope,proof=archive_receipts(ar)
  add("migrate_archive",archive=ar["id"],data_cipher=a["data_cipher"],wrap_material=wraps[0]["id"],mode=ar["migration_mode"],new_envelope_hex=envelope,restore_proof=proof)
  add("archive_gate",archive=ar["id"],consumers=sorted(ar["required_consumers"]),expected_digest=ar["digest"])
 print("[7/7] Enforcing final policy and retiring every displaced dependency")
 for surface in sorted(final_policies): add("set_final_policy",surface=surface)
 for mid in retire: add("retire_material",material=mid)
 plan={"format_version":1,"case_id":estate["case_id"],"findings":{"compromised_material":compromised,"retire_material":retire},"dependencies":dependencies,"final_policies":final_policies,"actions":actions}
 OUT.parent.mkdir(parents=True,exist_ok=True); OUT.write_text(json.dumps(plan,indent=2,sort_keys=True)+"\n",encoding="utf-8")
 print(f"wrote {len(dependencies)} dependency rows and {len(actions)} transitions to {OUT}")
if __name__=="__main__": main()
