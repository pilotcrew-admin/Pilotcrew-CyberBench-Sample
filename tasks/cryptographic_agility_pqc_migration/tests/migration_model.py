#!/usr/bin/env python3
"""Deterministic semantic model for the Helios cryptographic migration history."""
from __future__ import annotations
import hashlib,hmac,json
from pathlib import Path
from itertools import combinations
RINGS=("canary","fleet")
OPS={"contain_signer","stage_material","upgrade_consumer","upgrade_gate","distribute_trust","activate_material","configure_transition","workflow_gate","migrate_archive","archive_gate","set_final_policy","retire_material"}
FIELDS={"contain_signer":("material",),"stage_material":("material",),"upgrade_consumer":("consumer","package","ring","failure_domains","batch","on_interrupt"),"upgrade_gate":("consumer","ring","package","expected_version","recovery_steps"),"distribute_trust":("consumer","ring","material"),"activate_material":("surface","material"),"configure_transition":("surface","allowed_materials"),"workflow_gate":("surface","consumer","ring","profile"),"migrate_archive":("archive","data_cipher","wrap_material","mode","new_envelope_hex","restore_proof"),"archive_gate":("archive","consumers","expected_digest"),"set_final_policy":("surface",),"retire_material":("material",)}
def _json(p): return json.loads(p.read_text(encoding="utf-8"))
def _jsonl(p): return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]
def load_case(root):
 root=Path(root); c=root/"case"; estate=_json(c/"estate.json"); compat=_json(c/"compatibility.json")
 return {"estate":estate,"policy":_json(c/"policy-baseline.json"),"incident":_json(c/"incident-evidence.json"),"materials":{x["id"]:x for x in _json(c/"materials.json")["materials"]},"consumers":{x["id"]:x for x in estate["consumers"]},"surfaces":{x["id"]:x for x in estate["surfaces"]},"versions":compat["versions"],"packages":{x["id"]:x for x in compat["packages"]},"archives":{x["id"]:x for x in _json(c/"archives.json")["archives"]},"execution":_json(c/"execution-fixtures.json"),"interruptions":_jsonl(c/"interruption-observations.jsonl"),"deployments":_jsonl(c/"deployment-events.jsonl"),"runtime":_jsonl(c/"tls-negotiations.jsonl")+_jsonl(c/"signature-verifications.jsonl")+_jsonl(c/"ssh-sessions.jsonl")}
def _strings(v,nonempty=False): return isinstance(v,list) and (not nonempty or bool(v)) and all(isinstance(x,str) and x for x in v)
def _int(v): return isinstance(v,int) and not isinstance(v,bool)
def structural_errors(plan):
 e=[]
 if not isinstance(plan,dict): return ["plan must be a JSON object"]
 if plan.get("format_version")!=1 or isinstance(plan.get("format_version"),bool): e.append("format_version must be integer 1")
 if not isinstance(plan.get("case_id"),str): e.append("case_id must be a string")
 f=plan.get("findings")
 if not isinstance(f,dict): e.append("findings must be an object")
 else:
  for k in ("compromised_material","retire_material"):
   if not _strings(f.get(k)): e.append(f"findings.{k} must be an ID array")
   elif len(f[k])!=len(set(f[k])): e.append(f"findings.{k} has duplicates")
 deps=plan.get("dependencies")
 if not isinstance(deps,list) or not deps: e.append("dependencies must be a non-empty array")
 else:
  for i,d in enumerate(deps):
   if not isinstance(d,dict): e.append(f"dependencies[{i}] must be an object"); continue
   for k in ("surface","consumer"):
    if not isinstance(d.get(k),str) or not d[k]: e.append(f"dependencies[{i}].{k} must be a string")
   for k in ("effective_algorithms","materials","evidence"):
    if not _strings(d.get(k),True): e.append(f"dependencies[{i}].{k} must be a non-empty ID array")
    elif len(d[k])!=len(set(d[k])): e.append(f"dependencies[{i}].{k} has duplicates")
 if not isinstance(plan.get("final_policies"),dict): e.append("final_policies must be an object")
 actions=plan.get("actions")
 if not isinstance(actions,list) or not actions: e.append("actions must be a non-empty array"); return e
 seen=set()
 for i,a in enumerate(actions):
  label=f"actions[{i}]"
  if not isinstance(a,dict): e.append(label+" must be an object"); continue
  aid=a.get("id"); op=a.get("op")
  if not isinstance(aid,str) or not aid: e.append(label+".id must be non-empty")
  elif aid in seen: e.append(label+f".id duplicates {aid!r}")
  else: seen.add(aid)
  if op not in OPS: e.append(label+f".op is unknown: {op!r}"); continue
  for x in FIELDS[op]:
   if x not in a: e.append(label+f" is missing {x!r}")
 return e
def expected_scope(case):
 compromised={x["material"] for x in case["incident"]["events"] if x.get("confidence")=="confirmed" and x.get("type") in {"hsm_export_confirmed","unauthorized_signing_session"}}
 retire={m["id"] for m in case["materials"].values() if m.get("disposition")=="retire_at_completion"}
 return compromised,retire
def dep_key(d):
 try: return (d["surface"],d["consumer"],frozenset(d["effective_algorithms"]),frozenset(d["materials"]),frozenset(d["evidence"]))
 except (KeyError,TypeError): return None
def current_observations(case):
 capture=case["estate"]["captured_at"]; active={}
 for ev in sorted(case["deployments"],key=lambda x:(x["time"],x["id"])):
  if ev["time"]>capture: continue
  if ev["event"]=="bind": active[ev["subject"]]=ev["consumer"]
  elif ev["event"]=="unbind" and active.get(ev["subject"])==ev["consumer"]: active.pop(ev["subject"],None)
 latest={}
 for row in case["runtime"]:
  cid=active.get(row.get("subject")); c=case["consumers"].get(cid)
  if not c or not c.get("required") or row.get("result")!="success" or row.get("observed_at","")>capture: continue
  key=(cid,row["subject"])
  if key not in latest or (row["observed_at"],row["id"])>(latest[key]["observed_at"],latest[key]["id"]): latest[key]=row
 return active,latest
def expected_dependencies(case):
 _,latest=current_observations(case); grouped={}
 for (cid,_),r in latest.items(): grouped.setdefault(cid,[]).append(r)
 rows=[]
 for cid,rs in grouped.items(): rows.append({"surface":case["consumers"][cid]["surface"],"consumer":cid,"effective_algorithms":list({x for r in rs for x in r["algorithms"]}),"materials":list({x for r in rs for x in r["materials"]}),"evidence":[r["id"] for r in rs]})
 for a in case["archives"].values(): rows.append({"surface":a["surface"],"consumer":a["id"],"effective_algorithms":[a["data_cipher"],a["wrap_algorithm"]],"materials":[a["wrap_material"]],"evidence":[a["evidence"]]})
 return {dep_key(x) for x in rows}
def expected_material(case):
 p=case["policy"]["surfaces"]; mats=case["materials"]; approved=set(case["policy"]["approved_sources"])
 def pool(surface,role,algs): return [m for m in mats.values() if m.get("surface")==surface and m.get("role")==role and m.get("approved")=="final" and m.get("source") in approved and set(m.get("algorithms",[])).issubset(set(algs))]
 t=p["tls:telemetry-api"]; roots=[m for m in pool("tls:telemetry-api","trust_anchor",t["trust_anchor_algorithms"]) if m.get("trust_domain")==t["trust_domain"]]
 creds=[m for m in pool("tls:telemetry-api","server_credential",t["allowed_server_signatures"]) if m.get("issuer") in {x["id"] for x in roots} and t["server_dns_name"] in m.get("dns_names",[]) and set(t["required_key_usage"]).issubset(m.get("key_usage",[]))]
 s=p["signing:device-update"]; sp=[m for m in pool("signing:device-update","release_signer",s["allowed_signature_algorithms"]) if m.get("signing_context")==s["signing_context"]]
 signer_sets=[list(xs) for xs in combinations(sp,s["threshold"]) if {a for x in xs for a in x["algorithms"]}==set(s["required_independent_algorithms"]) and (not s["require_distinct_independence_domains"] or len({x.get("independence_domain") for x in xs})==len(xs))]
 h=p["ssh:ops-bastion"]; hosts=[m for m in pool("ssh:ops-bastion","host_key",h["allowed_host_key_algorithms"]) if m.get("host_identity")==h["host_identity"]]; cas=[m for m in pool("ssh:ops-bastion","user_ca",h["allowed_user_ca_algorithms"]) if set(h["required_principal_scopes"]).issubset(m.get("principal_scopes",[]))]
 a=p["archive:compliance"]; wraps=[m for m in pool("archive:compliance","wrapping_key",[a["wrap_algorithm"]]) if set(a["required_restore_profiles"]).issubset(m.get("restore_profiles",[]))]
 return {"roots":roots,"creds":creds,"signer_sets":signer_sets,"hosts":hosts,"cas":cas,"wraps":wraps}
def selected_policy_ids(plan):
 p=plan.get("final_policies",{}) if isinstance(plan,dict) else {}
 return set((p.get("tls:telemetry-api",{}).get("trusted_roots") or [])+(p.get("tls:telemetry-api",{}).get("allowed_server_credentials") or [])+(p.get("signing:device-update",{}).get("required_signers") or [])+(p.get("ssh:ops-bastion",{}).get("allowed_host_keys") or [])+(p.get("ssh:ops-bastion",{}).get("allowed_user_cas") or [])+([p.get("archive:compliance",{}).get("wrap_material")] if p.get("archive:compliance",{}).get("wrap_material") else []))
def custody_capacity_ok(plan,case):
 ids=selected_policy_ids(plan); mats=case["materials"]; gc=case["policy"]["global_constraints"]; counted=set(gc["counted_private_roles"]); counts={}
 for mid in ids:
  m=mats.get(mid)
  if not m or m.get("role") not in counted: continue
  domain=m.get("custody_domain")
  if not domain: return False
  counts[domain]=counts.get(domain,0)+1
 return all(n<=gc["max_final_private_keys_per_custody_domain"] for n in counts.values())
def target_version_support(surface,ver,case):
 p=case["policy"]["surfaces"]
 if surface=="tls:telemetry-api":
  b=p[surface]; return b["minimum_protocol"] in ver.get("protocols",[]) and set(b["required_kex"]).issubset(ver.get("kex",[])) and set(b["allowed_server_signatures"]).issubset(ver.get("server_signatures",[])) and set(b["trust_anchor_algorithms"]).issubset(ver.get("trust_anchor_algorithms",[]))
 if surface=="signing:device-update":
  b=p[surface]; return set(b["allowed_signature_algorithms"]).issubset(ver.get("signature_algorithms",[])) and ver.get("max_threshold",0)>=b["threshold"] and b["signing_context"] in ver.get("contexts",[])
 if surface=="ssh:ops-bastion":
  b=p[surface]; return set(b["allowed_host_key_algorithms"]).issubset(ver.get("host_key_algorithms",[])) and set(b["allowed_user_ca_algorithms"]).issubset(ver.get("user_ca_algorithms",[]))
 if surface=="archive:compliance":
  b=p[surface]; return b["data_cipher"] in ver.get("data_ciphers",[]) and b["wrap_algorithm"] in ver.get("wrap_algorithms",[])
 return False
def policy_errors(plan,case):
 e=[]; pol=plan.get("final_policies",{}); wanted=set(case["policy"]["surfaces"]); em=expected_material(case); b=case["policy"]["surfaces"]
 if not isinstance(pol,dict): return ["final_policies must be an object"]
 if set(pol)!=wanted: e.append("final_policies must define exactly all four surfaces")
 t=pol.get("tls:telemetry-api",{}); bt=b["tls:telemetry-api"]
 if t.get("minimum_protocol")!=bt["minimum_protocol"] or set(t.get("allowed_kex",[]))!=set(bt["required_kex"]) or t.get("reject_downgrade") is not True: e.append("TLS policy does not enforce the complete downgrade-resistant baseline")
 roots=t.get("trusted_roots",[]); creds=t.get("allowed_server_credentials",[])
 if not _strings(roots,True) or len(roots)!=1 or set(roots)!={x["id"] for x in em["roots"]} or not _strings(creds,True) or len(creds)!=1 or creds[0] not in {x["id"] for x in em["creds"]}: e.append("TLS policy selects material outside the required trust/identity scope")
 s=pol.get("signing:device-update",{}); bs=b["signing:device-update"]; signer_ids=s.get("required_signers",[])
 valid_signer_sets=[{x["id"] for x in xs} for xs in em["signer_sets"]]
 if not _strings(signer_ids,True) or len(signer_ids)!=bs["threshold"] or set(signer_ids) not in valid_signer_sets or set(s.get("allowed_algorithms",[]))!=set(bs["allowed_signature_algorithms"]) or s.get("threshold")!=bs["threshold"] or s.get("context")!=bs["signing_context"] or s.get("reject_revoked") is not True: e.append("signing policy lacks independent scoped signers, threshold, context, or revocation behavior")
 h=pol.get("ssh:ops-bastion",{}); bh=b["ssh:ops-bastion"]; hosts=h.get("allowed_host_keys",[]); cas=h.get("allowed_user_cas",[])
 if not _strings(hosts,True) or len(hosts)!=1 or hosts[0] not in {x["id"] for x in em["hosts"]} or not _strings(cas,True) or len(cas)!=1 or cas[0] not in {x["id"] for x in em["cas"]} or set(h.get("allowed_signature_algorithms",[]))!=set(bh["allowed_host_key_algorithms"]) or h.get("strict_host_identity") is not True or h.get("reject_sha1") is not True: e.append("SSH policy lacks the required host/principal scope or algorithm controls")
 a=pol.get("archive:compliance",{}); ba=b["archive:compliance"]
 if a.get("data_cipher")!=ba["data_cipher"] or a.get("wrap_algorithm")!=ba["wrap_algorithm"] or a.get("wrap_material") not in {x["id"] for x in em["wraps"]} or a.get("require_aead") is not True: e.append("archive policy lacks scoped AEAD/hybrid protection")
 if not custody_capacity_ok(plan,case): e.append("combined final private keys exceed a custody-domain capacity")
 return e
def supported(ver,m):
 alg=set(m.get("algorithms",[])); r=m.get("role")
 return bool(alg&set(ver.get({"trust_anchor":"trust_anchor_algorithms","release_signer":"signature_algorithms","host_key":"host_key_algorithms","user_ca":"user_ca_algorithms","wrapping_key":"wrap_algorithms"}.get(r,"__none__"),[]))) if r in {"trust_anchor","release_signer","host_key","user_ca","wrapping_key"} else True
def can_target(surface,cid,ring,state,plan,case):
 c=case["consumers"][cid]; ver=case["versions"].get(state["versions"][cid][ring],{}); trust=state["trust"][cid][ring]; p=plan["final_policies"].get(surface,{}); active=state["active"].get(surface,set())
 if not target_version_support(surface,ver,case): return False
 if surface=="tls:telemetry-api":
  creds=[case["materials"].get(x,{}) for x in p.get("allowed_server_credentials",[])]; return set(p.get("allowed_server_credentials",[])).issubset(active) and set(p.get("trusted_roots",[])).issubset(trust) and all(x.get("issuer") in trust for x in creds)
 if surface=="signing:device-update": return set(p.get("required_signers",[])).issubset(active) and set(p.get("required_signers",[])).issubset(trust)
 if surface=="ssh:ops-bastion": return set(p.get("allowed_host_keys",[])+p.get("allowed_user_cas",[])).issubset(active) and set(p.get("allowed_host_keys",[])).issubset(trust)
 return False
def transition_available(surface,allowed,state,case):
 mats=case["materials"]
 for cid,c in case["consumers"].items():
  if c["surface"]!=surface or not c.get("required"): continue
  for ring in RINGS:
   ver=case["versions"].get(state["versions"][cid][ring],{}); trust=state["trust"][cid][ring]
   if surface=="tls:telemetry-api":
    creds=[mats[x] for x in allowed if x in mats and mats[x].get("role")=="server_credential"]
    if not any(m.get("issuer") in trust and set(m.get("algorithms",[]))&set(ver.get("server_signatures",[])) for m in creds): return False
   elif surface=="ssh:ops-bastion":
    hosts=[mats[x] for x in allowed if x in mats and mats[x].get("role")=="host_key"]; cas=[mats[x] for x in allowed if x in mats and mats[x].get("role")=="user_ca"]
    if not any(m["id"] in trust and supported(ver,m) for m in hosts) or not any(supported(ver,m) for m in cas): return False
   elif surface=="signing:device-update":
    sig=[mats[x] for x in allowed if x in mats and mats[x].get("role")=="release_signer"]
    if not sig or any(m["id"] in state["contained"] for m in sig) or not any(m["id"] in trust and supported(ver,m) for m in sig): return False
 return True
def effective_interruption_rows(case,cid,ring,package):
 cutoff=case["execution"]["interruption_capture_cutoff"]; latest={}
 for row in case["interruptions"]:
  if row.get("consumer")!=cid or row.get("ring")!=ring or row.get("package")!=package or row.get("result")!="captured" or row.get("observed_at","")>cutoff: continue
  fault=row.get("fault_point"); key=(row.get("observed_at",""),row.get("id",""))
  if fault in case["execution"]["fault_points"] and (fault not in latest or key>(latest[fault].get("observed_at",""),latest[fault].get("id",""))): latest[fault]=row
 return latest
def recovery_decision(consumer,state):
 if not isinstance(state,dict): return None
 if state.get("write_phase")=="not_started": return "retry_same_image"
 if state.get("write_phase")=="complete_uncommitted" and state.get("journal_integrity")=="valid" and state.get("new_image_integrity")=="verified" and state.get("resume_token")=="valid": return "resume_commit"
 if state.get("rollback_snapshot")=="verified": return "rollback_then_retry"
 if state.get("image_cache")=="verified" and consumer.get("rollout",{}).get("reimage_allowed") is True: return "reimage_then_retry"
 return None
def expected_upgrade_steps(case,cid,ring,package,expected_version,canary_parent=None):
 if not all(isinstance(x,str) for x in (cid,ring,package,expected_version)): return None
 states={x["consumer"]:x for x in case["execution"]["upgrade_states"]}; pkg=case["packages"].get(package); c=case["consumers"].get(cid)
 if not pkg or not c or cid not in states or ring not in RINGS: return None
 context="\0".join((cid,ring,package,expected_version,pkg["image_digest"])).encode(); seed=bytes.fromhex(states[cid]["state_seed_hex"]); base=hashlib.sha256(seed+context).digest()
 if ring=="canary": parent=hashlib.sha256(b"captured-v2\0"+seed).digest()
 elif isinstance(canary_parent,str) and len(canary_parent)==64:
  try: parent=bytes.fromhex(canary_parent)
  except ValueError: return None
 else: return None
 rows=effective_interruption_rows(case,cid,ring,package); steps=[]; total=0; costs=case["execution"]["recovery_action_work_units"]
 for fault in case["execution"]["fault_points"]:
  row=rows.get(fault)
  if not row or not isinstance(row.get("state"),dict): return None
  digest=hashlib.sha256(json.dumps(row["state"],sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
  if row.get("state_digest")!=digest: return None
  decision=recovery_decision(c,row["state"])
  if decision not in costs: return None
  work=costs[decision]; message=b"recover-v2\0"+parent+b"\0"+fault.encode()+b"\0"+row["id"].encode()+b"\0"+bytes.fromhex(digest)+b"\0"+decision.encode()+b"\0"+str(work).encode()
  receipt=hmac.new(base,message,hashlib.sha256).hexdigest(); steps.append({"fault_point":fault,"evidence":row["id"],"decision":decision,"work_units":work,"receipt":receipt}); parent=bytes.fromhex(receipt); total+=work
 return steps,parent.hex(),total
def expected_archive_receipts(case,archive,data_cipher,wrap_material):
 if not all(isinstance(x,str) for x in (archive,data_cipher,wrap_material)): return None
 objects={x["archive"]:x for x in case["execution"]["archive_objects"]}; ar=case["archives"].get(archive); m=case["materials"].get(wrap_material); obj=objects.get(archive)
 if not ar or not m or not obj or not m.get("rewrap_share_hex"): return None
 context="\0".join((archive,data_cipher,wrap_material,ar["digest"])).encode()
 message=bytes.fromhex(obj["legacy_envelope_hex"])+bytes.fromhex(obj["object_nonce_hex"])+context
 envelope=hmac.new(bytes.fromhex(m["rewrap_share_hex"]),message,hashlib.sha256).hexdigest()
 proof=hmac.new(bytes.fromhex(envelope),b"restore-v1\0"+context,hashlib.sha256).hexdigest()
 return envelope,proof
def simulate(plan,root):
 case=load_case(root); errors=structural_errors(plan); dimensions={}
 if errors: return {"passed":False,"errors":errors,"history":[],"dimensions":dimensions}
 case_ok=plan.get("case_id")==case["estate"]["case_id"]; dimensions["case_binding"]=case_ok
 if not case_ok: errors.append("case_id does not match the captured estate")
 scope,retire_expected=expected_scope(case); gotc=set(plan["findings"].get("compromised_material",[])); gotr=set(plan["findings"].get("retire_material",[])); evidence_ok=gotc==scope and gotr==retire_expected; dimensions["evidence_scope"]=evidence_ok
 if gotc!=scope: errors.append("compromised material does not match confirmed custody evidence")
 if gotr!=retire_expected: errors.append("retirement scope does not match lifecycle disposition")
 gotdeps=[dep_key(x) for x in plan["dependencies"]]; inv_ok=None not in gotdeps and len(gotdeps)==len(set(gotdeps)) and set(gotdeps)==expected_dependencies(case); dimensions["effective_inventory"]=inv_ok
 if not inv_ok: errors.append("dependencies do not match the temporal active-subject evidence join and archives")
 pe=policy_errors(plan,case); errors.extend(pe); policy_ok=not pe; dimensions["policy_design"]=policy_ok
 mats=case["materials"]; cons=case["consumers"]; packages=case["packages"]; archives=case["archives"]
 state={"contained":set(),"staged":set(),"versions":{cid:{r:c["version"] for r in RINGS} for cid,c in cons.items()},"trust":{cid:{r:set(c.get("initial_trust",[])) for r in RINGS} for cid,c in cons.items()},"upgraded":{},"upgrade_gates":set(),"upgrade_chain":{},"interruptions":set(),"active":{s:set(x.get("active_materials",[])) for s,x in case["surfaces"].items()},"transition":{},"gates":set(),"migrated":{},"archive_gates":set(),"final":set(),"retired":set()}
 history=[]; transition_safe=True; compatibility=True; archive_ok=True; lifecycle=True
 for i,a in enumerate(plan["actions"]):
  before=len(errors); op=a.get("op"); aid=a.get("id"); label=f"action {i} {aid!r}"
  if i==0 and op!="contain_signer": errors.append("confirmed signer containment must be first")
  if op!="contain_signer" and not scope.issubset(state["contained"]): errors.append(label+" mutates replacement state before containment")
  if op=="contain_signer":
   mid=a.get("material")
   if mid not in scope or mid in state["contained"]: errors.append(label+" contains unconfirmed or duplicate material")
   else: state["contained"].add(mid)
  elif op=="stage_material":
   m=mats.get(a.get("material"))
   if not m or m.get("approved")!="final" or m.get("source") not in case["policy"]["approved_sources"]: errors.append(label+" stages material without final vault approval")
   else: state["staged"].add(m["id"])
  elif op=="upgrade_consumer":
   cid=a.get("consumer"); ring=a.get("ring"); c=cons.get(cid); pkg=packages.get(a.get("package")); domains=a.get("failure_domains"); batch=a.get("batch")
   if not c or ring not in RINGS or not pkg or not pkg.get("approved") or pkg.get("channel")!="offline-recovery" or pkg.get("from")!=state["versions"].get(cid,{}).get(ring): errors.append(label+" has a mismatched approved upgrade")
   elif not _strings(domains,True) or set(domains)!=set(c["rollout"]["failure_domains"]): errors.append(label+" does not cover every failure domain")
   elif a.get("on_interrupt")!=c["rollout"]["on_interrupt"]: errors.append(label+" has the wrong interruption recovery")
   elif not isinstance(batch,dict) or not all(_int(batch.get(x)) and batch[x]>0 for x in ("max_total","max_per_failure_domain")): errors.append(label+" has invalid batch caps")
   elif ring=="canary" and (batch["max_per_failure_domain"]>c["rollout"]["canary_max_per_failure_domain"] or batch["max_total"]>len(domains)*c["rollout"]["canary_max_per_failure_domain"]): errors.append(label+" exceeds canary failure-domain caps")
   elif ring=="fleet" and (cid,"canary") not in state["upgrade_gates"]: errors.append(label+" precedes its canary upgrade gate")
   elif ring=="fleet" and (batch["max_total"]>c["availability"]["max_total_offline"] or batch["max_per_failure_domain"]>c["availability"]["max_per_failure_domain"]): errors.append(label+" exceeds fleet availability caps")
   else:
    state["versions"][cid][ring]=pkg["to"]; state["upgraded"][(cid,ring)]=pkg["id"]
  elif op=="upgrade_gate":
   cid=a.get("consumer"); ring=a.get("ring"); package=a.get("package"); version=a.get("expected_version"); parent=state["upgrade_chain"].get((cid,"canary")) if ring=="fleet" else None
   expected=expected_upgrade_steps(case,cid,ring,package,version,parent); submitted=a.get("recovery_steps")
   normalized=[{k:x.get(k) for k in ("fault_point","evidence","decision","work_units","receipt")} for x in submitted] if isinstance(submitted,list) and all(isinstance(x,dict) for x in submitted) else None
   if cid not in cons or ring not in RINGS or state["upgraded"].get((cid,ring))!=package or state["versions"].get(cid,{}).get(ring)!=version: errors.append(label+" does not match the actual applied ring upgrade")
   elif not expected or normalized!=expected[0]: errors.append(label+" has stale evidence, an unsafe recovery decision, or an invalid stateful receipt chain")
   elif expected[2]>cons[cid]["rollout"].get("max_recovery_work_units",-1): errors.append(label+" exceeds the captured ring recovery work budget")
   else:
    state["upgrade_gates"].add((cid,ring)); state["upgrade_chain"][(cid,ring)]=expected[1]; state["interruptions"].update((cid,ring,x) for x in case["execution"]["fault_points"])
  elif op=="distribute_trust":
   cid=a.get("consumer"); ring=a.get("ring"); c=cons.get(cid); m=mats.get(a.get("material")); ver=case["versions"].get(state["versions"].get(cid,{}).get(ring),{})
   if not c or ring not in RINGS or not m or m.get("surface")!=c.get("surface") or m["id"] not in state["staged"]: errors.append(label+" distributes unstaged or cross-surface trust")
   elif m.get("role") not in {"trust_anchor","release_signer","host_key"} or not supported(ver,m): errors.append(label+" is unsupported by the installed ring")
   else: state["trust"][cid][ring].add(m["id"])
  elif op=="activate_material":
   m=mats.get(a.get("material")); surface=a.get("surface")
   if not m or m.get("surface")!=surface or m["id"] not in state["staged"] or m.get("role") not in {"server_credential","release_signer","host_key","user_ca","wrapping_key"}: errors.append(label+" activates unstaged, cross-surface, or client-only material")
   else: state["active"].setdefault(surface,set()).add(m["id"])
  elif op=="configure_transition":
   surface=a.get("surface"); allowed=a.get("allowed_materials")
   if surface not in {"tls:telemetry-api","signing:device-update","ssh:ops-bastion"} or not _strings(allowed,True) or not set(allowed).issubset(state["active"].get(surface,set())): errors.append(label+" has invalid/inactive transition material")
   elif not transition_available(surface,set(allowed),state,case): errors.append(label+" strands a required consumer ring or permits a contained signer")
   else: state["transition"][surface]=set(allowed)
  elif op=="workflow_gate":
   surface=a.get("surface"); cid=a.get("consumer"); ring=a.get("ring"); c=cons.get(cid)
   if not c or ring not in RINGS or c.get("surface")!=surface or surface not in {"tls:telemetry-api","signing:device-update","ssh:ops-bastion"} or a.get("profile")!="target": errors.append(label+" is not a valid target ring gate")
   elif surface not in state["transition"]: errors.append(label+" precedes its surface transition configuration")
   elif (cid,ring) in state["upgraded"] and (cid,ring) not in state["upgrade_chain"]: errors.append(label+" precedes its valid recovery-health chain")
   elif not policy_ok or not can_target(surface,cid,ring,state,plan,case): errors.append(label+" target workflow cannot complete")
   else: state["gates"].add((surface,cid,ring))
  elif op=="migrate_archive":
   ar=archives.get(a.get("archive")); m=mats.get(a.get("wrap_material")); p=plan["final_policies"].get("archive:compliance",{})
   if not ar or not m or m["id"] not in state["staged"] or m.get("role")!="wrapping_key": errors.append(label+" names unknown archive or unstaged wrap material")
   elif a.get("mode")!=ar["migration_mode"] or a.get("data_cipher")!=p.get("data_cipher") or a.get("wrap_material")!=p.get("wrap_material"): errors.append(label+" violates storage mode or final archive policy")
   elif any(not target_version_support("archive:compliance",case["versions"].get(state["versions"][cid][ring],{}),case) for cid in ar["required_consumers"] for ring in RINGS): errors.append(label+" strands a required restore ring")
   elif expected_archive_receipts(case,ar["id"],a.get("data_cipher"),m["id"])!=(a.get("new_envelope_hex"),a.get("restore_proof")): errors.append(label+" has invalid or unbound archive rewrap/restore receipts")
   else: state["migrated"][ar["id"]]={"data_cipher":a["data_cipher"],"wrap_material":m["id"],"digest":ar["digest"],"new_envelope_hex":a["new_envelope_hex"],"restore_proof":a["restore_proof"]}
  elif op=="archive_gate":
   ar=archives.get(a.get("archive")); mig=state["migrated"].get(a.get("archive"))
   if not ar or not mig or not _strings(a.get("consumers"),True) or set(a["consumers"])!=set(ar["required_consumers"]) or a.get("expected_digest")!=ar["digest"]: errors.append(label+" fails archive consumers or digest")
   else: state["archive_gates"].add(ar["id"])
  elif op=="set_final_policy":
   surface=a.get("surface")
   if surface not in case["surfaces"] or not policy_ok: errors.append(label+" has no valid final policy")
   elif surface=="archive:compliance" and state["archive_gates"]!=set(archives): errors.append(label+" precedes all archive gates")
   elif surface!="archive:compliance":
    req={(surface,cid,r) for cid,c in cons.items() if c["surface"]==surface and c.get("required") for r in RINGS}
    if not req.issubset(state["gates"]): errors.append(label+" precedes every required ring gate")
    elif not all(can_target(surface,cid,r,state,plan,case) for _,cid,r in req): errors.append(label+" blocks a benign target ring")
    else: state["final"].add(surface)
   else: state["final"].add(surface)
   if surface in state["final"]:
    p=plan["final_policies"][surface]
    if surface=="tls:telemetry-api": state["active"][surface]=set(p["allowed_server_credentials"])
    elif surface=="signing:device-update": state["active"][surface]=set(p["required_signers"])
    elif surface=="ssh:ops-bastion": state["active"][surface]=set(p["allowed_host_keys"]+p["allowed_user_cas"])
    else: state["active"][surface]={p["wrap_material"]}
  elif op=="retire_material":
   mid=a.get("material"); m=mats.get(mid)
   if not m or mid not in retire_expected or m["surface"] not in state["final"] or mid in state["active"].get(m["surface"],set()) or any(x.get("wrap_material")==mid for x in state["migrated"].values()) or mid in state["retired"]: errors.append(label+" retires out-of-scope, active, premature, or duplicate material")
   else:
    state["retired"].add(mid)
    for rings in state["trust"].values():
     for trust in rings.values(): trust.discard(mid)
  if len(errors)>before:
   transition_safe=False
   if op in {"upgrade_consumer","upgrade_gate","distribute_trust","configure_transition","workflow_gate"}: compatibility=False
   if op in {"migrate_archive","archive_gate"}: archive_ok=False
   if op in {"contain_signer","retire_material"}: lifecycle=False
   history.append({"id":aid,"op":op,"applied":False,"diagnostic":errors[-1]})
  else: history.append({"id":aid,"op":op,"applied":True})
 blockers={cid for cid,c in cons.items() if not target_version_support(c["surface"],case["versions"][c["version"]],case)}; expected_up={(cid,r) for cid in blockers for r in RINGS}; required_gates={(c["surface"],cid,r) for cid,c in cons.items() if c.get("required") and c["surface"] in {"tls:telemetry-api","signing:device-update","ssh:ops-bastion"} for r in RINGS}
 selected=selected_policy_ids(plan); containment=state["contained"]==scope
 compatibility=compatibility and state["upgrade_gates"]==expected_up and state["gates"]==required_gates and set(state["transition"])=={"tls:telemetry-api","signing:device-update","ssh:ops-bastion"}
 interruption_ok=len(state["interruptions"])==len(expected_up)*len(case["execution"]["fault_points"]) and all((cid,r,x) in state["interruptions"] for cid,r in expected_up for x in case["execution"]["fault_points"])
 archive_ok=archive_ok and set(state["migrated"])==set(archives) and state["archive_gates"]==set(archives)
 lifecycle=lifecycle and state["retired"]==retire_expected and selected.issubset(state["staged"]); final_ok=state["final"]==set(case["surfaces"])
 if not containment: errors.append("confirmed containment is incomplete")
 if state["upgrade_gates"]!=expected_up: errors.append("canary/fleet upgrade gates are incomplete or unnecessary gates were added")
 if state["gates"]!=required_gates: errors.append("both rings of every required workflow were not gated")
 if not interruption_ok: errors.append("effective post-fault states were not safely recovered into complete health chains")
 if not archive_ok: errors.append("archive migration/restore is incomplete")
 if state["retired"]!=retire_expected: errors.append("completion retirement is incomplete")
 if not final_ok: errors.append("not every surface reached final policy")
 dimensions.update({"signer_containment":containment,"compatibility_and_ring_gates":compatibility,"interruption_recovery":interruption_ok,"transition_safety":transition_safe,"archive_migration":archive_ok,"key_lifecycle":lifecycle,"final_state":final_ok})
 return {"passed":not errors and all(dimensions.values()),"errors":errors,"history":history,"dimensions":dimensions,"state_summary":{"contained":sorted(state["contained"]),"staged":sorted(state["staged"]),"upgrade_gates":len(state["upgrade_gates"]),"recovery_health_chains":len(state["upgrade_chain"]),"workflow_gates":len(state["gates"]),"interruption_scenarios":len(state["interruptions"]),"archive_gates":len(state["archive_gates"]),"final_surfaces":sorted(state["final"]),"retired":sorted(state["retired"])}}
def eval_tls(p,protocol,kex,cred,root,case): return p.get("reject_downgrade") is True and protocol==p.get("minimum_protocol") and kex in p.get("allowed_kex",[]) and cred in p.get("allowed_server_credentials",[]) and root in p.get("trusted_roots",[]) and case["materials"].get(cred,{}).get("issuer")==root
def eval_sign(p,ids,algs,context,revoked,case):
 domains={case["materials"].get(x,{}).get("independence_domain") for x in ids}
 return p.get("reject_revoked") is True and context==p.get("context") and not(set(ids)&set(revoked)) and len(ids)==len(set(ids)) and set(ids)==set(p.get("required_signers",[])) and set(algs)==set(p.get("allowed_algorithms",[])) and len(ids)>=p.get("threshold",99) and len(domains)==len(ids)
def eval_ssh(p,host,ca,alg): return p.get("strict_host_identity") is True and p.get("reject_sha1") is True and host in p.get("allowed_host_keys",[]) and ca in p.get("allowed_user_cas",[]) and alg in p.get("allowed_signature_algorithms",[]) and "SHA1" not in alg
def eval_archive(p,cipher,wrap,material,authenticated): return p.get("require_aead") is True and authenticated and cipher==p.get("data_cipher") and wrap==p.get("wrap_algorithm") and material==p.get("wrap_material")
def exercise_adversarial_scenarios(plan,root):
 case=load_case(root); p=plan.get("final_policies",{}) if isinstance(plan,dict) else {}; out={}; em=expected_material(case)
 t=p.get("tls:telemetry-api",{}); cred=(t.get("allowed_server_credentials") or [None])[0]; rootid=(t.get("trusted_roots") or [None])[0]; kex=(t.get("allowed_kex") or [None])[0]
 out["tls_compliant_hybrid_handshake"]=eval_tls(t,"TLS1.3",kex,cred,rootid,case); out["tls12_downgrade_rejected"]=not eval_tls(t,"TLS1.2",kex,cred,rootid,case); out["classical_only_kex_rejected"]=not eval_tls(t,"TLS1.3","X25519",cred,rootid,case); out["legacy_certificate_rejected"]=not eval_tls(t,"TLS1.3",kex,"tls-api-2024","tls-root-2019",case); out["wrong_trust_domain_certificate_rejected"]=not eval_tls(t,"TLS1.3",kex,"tls-api-2027-analytics","tls-root-2027-analytics",case)
 s=p.get("signing:device-update",{}); ids=list(s.get("required_signers",[])); algs=list(s.get("allowed_algorithms",[])); out["dual_independent_release_accepted"]=eval_sign(s,ids,algs,s.get("context"),[],case); out["single_signature_rejected"]=not eval_sign(s,ids[:1],algs[:1],s.get("context"),[],case); out["revoked_signer_replay_rejected"]=not eval_sign(s,["sign-release-rsa"],["RSA_PKCS1_SHA256"],"helios-release-v1",["sign-release-rsa"],case); out["old_context_rejected"]=not eval_sign(s,ids,algs,"helios-release-v1",[],case); out["same_domain_threshold_rejected"]=not eval_sign(s,["sign-release-ed","sign-release-pq-backup"],algs,s.get("context"),[],case)
 h=p.get("ssh:ops-bastion",{}); host=(h.get("allowed_host_keys") or [None])[0]; ca=(h.get("allowed_user_cas") or [None])[0]; alg=(h.get("allowed_signature_algorithms") or [None])[0]; out["ssh_compliant_session_accepted"]=eval_ssh(h,host,ca,alg); out["ssh_sha1_rejected"]=not eval_ssh(h,"ssh-host-rsa1024","ssh-user-ca-rsa","SSH_RSA_SHA1"); out["ssh_wrong_host_identity_rejected"]=not eval_ssh(h,"ssh-host-ed25519-dr",ca,"SSH_ED25519"); out["ssh_wrong_principal_ca_rejected"]=not eval_ssh(h,host,"ssh-user-ca-ed-vendor",alg)
 a=p.get("archive:compliance",{}); out["archive_aead_hybrid_restore_accepted"]=eval_archive(a,a.get("data_cipher"),a.get("wrap_algorithm"),a.get("wrap_material"),True); out["archive_legacy_wrap_rejected"]=not eval_archive(a,"AES_256_GCM","RSA_2048_OAEP_SHA256","archive-wrap-rsa",True); out["archive_modified_ciphertext_rejected"]=not eval_archive(a,a.get("data_cipher"),a.get("wrap_algorithm"),a.get("wrap_material"),False); out["archive_wrong_restore_profile_rejected"]=not eval_archive(a,"AES_256_GCM","X25519_MLKEM768","archive-wrap-hybrid-edge",True)
 got={dep_key(x) for x in plan.get("dependencies",[]) if isinstance(x,dict)}; expected=expected_dependencies(case); out["stale_and_unbound_evidence_excluded"]=got==expected
 out["scoped_material_selection"]=not policy_errors(plan,case)
 out["custody_domain_capacity_enforced"]=custody_capacity_ok(plan,case)
 return out
