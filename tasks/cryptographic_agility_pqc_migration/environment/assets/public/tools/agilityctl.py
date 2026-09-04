#!/usr/bin/env python3
"""Inspect and rehearse the offline Helios cryptographic migration case."""
from __future__ import annotations
import argparse,json,re
from pathlib import Path

RINGS=("canary","fleet")
HEX64=re.compile(r"^[0-9a-f]{64}$")
ACTION_FIELDS={
 "contain_signer":("material",),"stage_material":("material",),
 "upgrade_consumer":("consumer","package","ring","failure_domains","batch","on_interrupt"),
 "upgrade_gate":("consumer","ring","package","expected_version","recovery_steps"),
 "distribute_trust":("consumer","ring","material"),"activate_material":("surface","material"),
 "configure_transition":("surface","allowed_materials"),"workflow_gate":("surface","consumer","ring","profile"),
 "migrate_archive":("archive","data_cipher","wrap_material","mode","new_envelope_hex","restore_proof"),"archive_gate":("archive","consumers","expected_digest"),
 "set_final_policy":("surface",),"retire_material":("material",)}
def read_json(p): return json.loads(p.read_text(encoding="utf-8"))
def read_jsonl(p): return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]
def load(root):
 c=root/"case"; estate=read_json(c/"estate.json"); compat=read_json(c/"compatibility.json")
 return {"estate":estate,"incident":read_json(c/"incident-evidence.json"),"policy":read_json(c/"policy-baseline.json"),
  "materials":{x["id"]:x for x in read_json(c/"materials.json")["materials"]},"consumers":{x["id"]:x for x in estate["consumers"]},
  "surfaces":{x["id"]:x for x in estate["surfaces"]},"versions":compat["versions"],"packages":{x["id"]:x for x in compat["packages"]},
  "archives":{x["id"]:x for x in read_json(c/"archives.json")["archives"]},"execution":read_json(c/"execution-fixtures.json"),
  "interruptions":read_jsonl(c/"interruption-observations.jsonl"),"deployments":read_jsonl(c/"deployment-events.jsonl"),
  "runtime":read_jsonl(c/"tls-negotiations.jsonl")+read_jsonl(c/"signature-verifications.jsonl")+read_jsonl(c/"ssh-sessions.jsonl")}
def _strings(v,nonempty=False): return isinstance(v,list) and (not nonempty or bool(v)) and all(isinstance(x,str) and x for x in v)
def lint(plan):
 e=[]
 if not isinstance(plan,dict): return ["plan must be a JSON object"]
 if plan.get("format_version")!=1: e.append("format_version must be 1")
 if plan.get("case_id")!="helios-2027-02": e.append("case_id must be helios-2027-02")
 f=plan.get("findings")
 if not isinstance(f,dict): e.append("findings must be an object")
 else:
  for k in ("compromised_material","retire_material"):
   if not _strings(f.get(k)): e.append(f"findings.{k} must be an ID array")
 deps=plan.get("dependencies")
 if not isinstance(deps,list) or not deps: e.append("dependencies must be a non-empty array")
 else:
  for i,d in enumerate(deps):
   if not isinstance(d,dict): e.append(f"dependencies[{i}] must be an object"); continue
   for k in ("surface","consumer"):
    if not isinstance(d.get(k),str) or not d[k]: e.append(f"dependencies[{i}].{k} must be a string")
   for k in ("effective_algorithms","materials","evidence"):
    if not _strings(d.get(k),True): e.append(f"dependencies[{i}].{k} must be a non-empty ID array")
 if not isinstance(plan.get("final_policies"),dict): e.append("final_policies must be an object")
 actions=plan.get("actions")
 if not isinstance(actions,list) or not actions: e.append("actions must be a non-empty array"); return e
 seen=set()
 for i,a in enumerate(actions):
  label=f"actions[{i}]"
  if not isinstance(a,dict): e.append(label+" must be an object"); continue
  aid=a.get("id"); op=a.get("op")
  if not isinstance(aid,str) or not aid or aid in seen: e.append(label+".id must be unique and non-empty")
  else: seen.add(aid)
  if op not in ACTION_FIELDS: e.append(label+".op is unknown"); continue
  missing=[x for x in ACTION_FIELDS[op] if x not in a]
  if missing: e.append(label+" is missing "+", ".join(missing))
 return e
def supported(ver,m):
 alg=set(m.get("algorithms",[])); role=m.get("role")
 if role=="trust_anchor": return bool(alg&set(ver.get("trust_anchor_algorithms",[])))
 if role=="release_signer": return bool(alg&set(ver.get("signature_algorithms",[])))
 if role=="host_key": return bool(alg&set(ver.get("host_key_algorithms",[])))
 if role=="user_ca": return bool(alg&set(ver.get("user_ca_algorithms",[])))
 if role=="wrapping_key": return bool(alg&set(ver.get("wrap_algorithms",[])))
 return True
def target_gate(surface,cid,ring,state,policy,case):
 ver=case["versions"].get(state["versions"][cid][ring],{}); trust=state["trust"][cid][ring]
 if surface=="tls:telemetry-api":
  creds=[case["materials"].get(x,{}) for x in policy.get("allowed_server_credentials",[])]
  return (policy.get("minimum_protocol") in ver.get("protocols",[]) and set(policy.get("allowed_kex",[])).issubset(set(ver.get("kex",[]))) and
    set(policy.get("trusted_roots",[])).issubset(trust) and all(set(x.get("algorithms",[]))&set(ver.get("server_signatures",[])) and x.get("issuer") in trust for x in creds))
 if surface=="signing:device-update":
  keys=[case["materials"].get(x,{}) for x in policy.get("required_signers",[])]
  return (set(policy.get("required_signers",[])).issubset(trust) and set(policy.get("allowed_algorithms",[])).issubset(set(ver.get("signature_algorithms",[]))) and
    policy.get("threshold",99)<=ver.get("max_threshold",0) and policy.get("context") in ver.get("contexts",[]) and len({a for x in keys for a in x.get("algorithms",[])})>=policy.get("threshold",99))
 if surface=="ssh:ops-bastion":
  hosts=[case["materials"].get(x,{}) for x in policy.get("allowed_host_keys",[])]; cas=[case["materials"].get(x,{}) for x in policy.get("allowed_user_cas",[])]
  return (set(policy.get("allowed_host_keys",[])).issubset(trust) and all(set(x.get("algorithms",[]))&set(ver.get("host_key_algorithms",[])) for x in hosts) and
    all(set(x.get("algorithms",[]))&set(ver.get("user_ca_algorithms",[])) for x in cas))
 return True
def rehearse(plan,case):
 e=lint(plan)
 if e: return {"passed":False,"violations":e,"applied":0}
 cons=case["consumers"]; mats=case["materials"]; packages=case["packages"]; archives=case["archives"]
 state={"contained":set(),"staged":set(),"versions":{cid:{r:c["version"] for r in RINGS} for cid,c in cons.items()},
  "trust":{cid:{r:set(c.get("initial_trust",[])) for r in RINGS} for cid,c in cons.items()},"upgraded":{},"upgrade_gates":set(),
  "active":{s:set(x.get("active_materials",[])) for s,x in case["surfaces"].items()},"transition":set(),"gates":set(),"migrated":set(),"archive_gates":set(),"final":set()}
 policies=plan.get("final_policies",{})
 for i,a in enumerate(plan["actions"]):
  label=f"actions[{i}] {a.get('id')!r}"; op=a["op"]
  if i==0 and op!="contain_signer": e.append("confirmed signer containment must be first")
  if op!="contain_signer" and not state["contained"]: e.append(label+" occurs before signer containment")
  if op=="contain_signer":
   m=mats.get(a["material"])
   if not m or m.get("role")!="release_signer": e.append(label+" names no release signer")
   else: state["contained"].add(m["id"])
  elif op=="stage_material":
   m=mats.get(a["material"])
   if not m or m.get("approved")!="final" or m.get("source") not in case["policy"]["approved_sources"]: e.append(label+" is not final-approved vault material")
   else: state["staged"].add(m["id"])
  elif op=="upgrade_consumer":
   cid=a["consumer"]; ring=a["ring"]; c=cons.get(cid); pkg=packages.get(a["package"]); b=a["batch"]
   domains=a["failure_domains"] if isinstance(a["failure_domains"],list) else []
   if not c or ring not in RINGS or not pkg or not pkg.get("approved") or pkg.get("channel")!="offline-recovery" or pkg.get("from")!=state["versions"].get(cid,{}).get(ring): e.append(label+" has an unknown or mismatched approved upgrade")
   elif set(domains)!=set(c["rollout"]["failure_domains"]): e.append(label+" must cover every published failure domain")
   elif a["on_interrupt"]!=c["rollout"]["on_interrupt"]: e.append(label+" uses the wrong interruption strategy")
   elif not isinstance(b,dict) or not all(isinstance(b.get(x),int) and not isinstance(b.get(x),bool) and b[x]>0 for x in ("max_total","max_per_failure_domain")): e.append(label+" has invalid batch caps")
   elif ring=="canary" and (b["max_per_failure_domain"]>c["rollout"]["canary_max_per_failure_domain"] or b["max_total"]>len(domains)*c["rollout"]["canary_max_per_failure_domain"]): e.append(label+" exceeds canary caps")
   elif ring=="fleet" and (cid,"canary") not in state["upgrade_gates"]: e.append(label+" precedes its canary upgrade gate")
   elif ring=="fleet" and (b["max_total"]>c["availability"]["max_total_offline"] or b["max_per_failure_domain"]>c["availability"]["max_per_failure_domain"]): e.append(label+" exceeds fleet availability caps")
   else: state["versions"][cid][ring]=pkg["to"]; state["upgraded"][(cid,ring)]=pkg["id"]
  elif op=="upgrade_gate":
   cid=a["consumer"]; ring=a["ring"]; steps=a["recovery_steps"]; faults=case["execution"]["fault_points"]; decisions=set(case["execution"]["recovery_action_work_units"])
   step_shape=(isinstance(steps,list) and len(steps)==len(faults) and all(isinstance(x,dict) for x in steps) and [x.get("fault_point") for x in steps]==faults and all(isinstance(x.get("evidence"),str) and x["evidence"] and x.get("decision") in decisions and isinstance(x.get("work_units"),int) and not isinstance(x.get("work_units"),bool) and x["work_units"]>=0 and isinstance(x.get("receipt"),str) and HEX64.fullmatch(x["receipt"]) for x in steps))
   if cid not in cons or ring not in RINGS or state["upgraded"].get((cid,ring))!=a["package"] or state["versions"].get(cid,{}).get(ring)!=a["expected_version"]: e.append(label+" does not match the actual applied ring upgrade")
   elif not step_shape: e.append(label+" must provide ordered evidence/decision/work/receipt steps for every fault point")
   elif sum(x["work_units"] for x in steps)>cons[cid]["rollout"].get("max_recovery_work_units",0): e.append(label+" exceeds the published recovery work budget")
   else: state["upgrade_gates"].add((cid,ring))
  elif op=="distribute_trust":
   cid=a["consumer"]; ring=a["ring"]; c=cons.get(cid); m=mats.get(a["material"]); ver=case["versions"].get(state["versions"].get(cid,{}).get(ring),{})
   if not c or ring not in RINGS or not m or m.get("surface")!=c.get("surface") or m["id"] not in state["staged"]: e.append(label+" has unstaged or cross-surface trust")
   elif not supported(ver,m): e.append(label+" is not parseable by the installed ring version")
   else: state["trust"][cid][ring].add(m["id"])
  elif op=="activate_material":
   m=mats.get(a["material"])
   if not m or m.get("surface")!=a["surface"] or m["id"] not in state["staged"]: e.append(label+" activates unstaged or cross-surface material")
   else: state["active"].setdefault(a["surface"],set()).add(m["id"])
  elif op=="configure_transition":
   allowed=a["allowed_materials"]
   if not _strings(allowed,True) or not set(allowed).issubset(state["active"].get(a["surface"],set())): e.append(label+" references inactive material")
   elif a["surface"]=="signing:device-update" and any(x in state["contained"] for x in allowed): e.append(label+" permits a contained signer")
   else: state["transition"].add(a["surface"])
  elif op=="workflow_gate":
   cid=a["consumer"]; ring=a["ring"]; c=cons.get(cid); p=policies.get(a["surface"])
   if not c or ring not in RINGS or c.get("surface")!=a["surface"] or a["profile"]!="target" or not isinstance(p,dict): e.append(label+" has no matching target consumer/ring/policy")
   elif a["surface"] not in state["transition"]: e.append(label+" precedes its surface transition configuration")
   elif (cid,ring) in state["upgraded"] and (cid,ring) not in state["upgrade_gates"]: e.append(label+" precedes its ring recovery-health chain")
   elif not target_gate(a["surface"],cid,ring,state,p,case): e.append(label+" target workflow is incompatible with installed ring version/trust")
   else: state["gates"].add((a["surface"],cid,ring))
  elif op=="migrate_archive":
   ar=archives.get(a["archive"]); m=mats.get(a["wrap_material"])
   if not ar or not m or m["id"] not in state["staged"]: e.append(label+" names unknown archive or unstaged wrap material")
   elif a["mode"]!=ar["migration_mode"]: e.append(label+" violates archive storage mode")
   elif any(a["data_cipher"] not in case["versions"].get(state["versions"][cid][ring],{}).get("data_ciphers",[]) or not supported(case["versions"].get(state["versions"][cid][ring],{}),m) for cid in ar["required_consumers"] for ring in RINGS): e.append(label+" strands a restore consumer ring")
   elif not all(isinstance(a.get(x),str) and HEX64.fullmatch(a[x]) for x in ("new_envelope_hex","restore_proof")): e.append(label+" has malformed execution receipts")
   else: state["migrated"].add(ar["id"])
  elif op=="archive_gate":
   ar=archives.get(a["archive"])
   if not ar or ar["id"] not in state["migrated"] or set(a["consumers"])!=set(ar["required_consumers"]) or a["expected_digest"]!=ar["digest"]: e.append(label+" does not prove the archive restore contract")
   else: state["archive_gates"].add(ar["id"])
  elif op=="set_final_policy":
   surface=a["surface"]
   required={(surface,cid,ring) for cid,c in cons.items() if c["surface"]==surface and c.get("required") for ring in RINGS}
   if surface=="archive:compliance" and state["archive_gates"]!=set(archives): e.append(label+" precedes all archive gates")
   elif surface!="archive:compliance" and not required.issubset(state["gates"]): e.append(label+" precedes all required ring workflow gates")
   else: state["final"].add(surface)
  elif op=="retire_material":
   m=mats.get(a["material"])
   if not m or m["surface"] not in state["final"]: e.append(label+" precedes its final policy")
 return {"passed":not e,"violations":e,"applied":len(plan["actions"]),"upgrade_gates":len(state["upgrade_gates"]),"target_gates":len(state["gates"]),"archive_gates":len(state["archive_gates"]),"note":"Representative rehearsal validates recovery-step shape/work budgets and transition preconditions; final assessment also selects temporal fault evidence, diagnoses state, and recomputes chained receipts, evidence joins, candidate scope, policy behavior, interrupted rollouts, and retirement."}
def evidence(case):
 print(json.dumps({"captured_at":case["estate"]["captured_at"],"consumers":list(case["consumers"].values()),"deployment_events":case["deployments"],"runtime_observations":case["runtime"],"interruption_observations":case["interruptions"],"custody_events":case["incident"]["events"],"archives":list(case["archives"].values())},indent=2,sort_keys=True))
def main():
 ap=argparse.ArgumentParser(description=__doc__); ap.add_argument("--root",default=str(Path(__file__).resolve().parents[1]),help=argparse.SUPPRESS)
 sub=ap.add_subparsers(dest="command",required=True); sub.add_parser("evidence")
 for name in ("lint","rehearse"): p=sub.add_parser(name); p.add_argument("plan")
 args=ap.parse_args(); case=load(Path(args.root))
 if args.command=="evidence": evidence(case); return 0
 try: plan=json.loads(Path(args.plan).read_text(encoding="utf-8"))
 except (OSError,json.JSONDecodeError) as exc: print(json.dumps({"passed":False,"violations":[str(exc)]},indent=2)); return 1
 errors=lint(plan); result={"passed":not errors,"violations":errors} if args.command=="lint" else rehearse(plan,case)
 print(json.dumps(result,indent=2,sort_keys=True)); return 0 if result["passed"] else 1
if __name__=="__main__": raise SystemExit(main())
