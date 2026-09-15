#!/usr/bin/env python3
"""Semantic verifier for defensive cryptographic-agility migration state and history."""
from __future__ import annotations
import json, os, stat, sys
from pathlib import Path

SERVICE_ID="cryptographic_agility_pqc_migration"
SUBMISSION=Path(os.environ.get("SUBMISSION","/app/submission/migration-plan.json"))
LOGS=Path(os.environ.get("LOG_DIR","/logs/verifier"))
FIXTURES=Path(os.environ.get("VERIFIER_FIXTURES","/tests/fixtures"))
if not FIXTURES.exists(): FIXTURES=Path(__file__).resolve().parent/"fixtures"
sys.path.insert(0,str(Path(__file__).resolve().parent))
from migration_model import exercise_adversarial_scenarios, simulate

def no_constant(v): raise ValueError(f"non-finite number {v!r} is invalid JSON")
def unique_object(pairs):
    out={}
    for k,v in pairs:
        if k in out: raise ValueError(f"duplicate JSON key {k!r}")
        out[k]=v
    return out

def load_plan():
    info=SUBMISSION.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode): raise ValueError("migration-plan.json must be a regular non-symlink file")
    if info.st_size>1_000_000: raise ValueError("migration-plan.json exceeds 1,000,000 bytes")
    return json.loads(SUBMISSION.read_text(encoding="utf-8"),parse_constant=no_constant,object_pairs_hook=unique_object)

def emit(result,fatal=None,adversarial=None):
    dimensions=result.get("dimensions",{}); diagnostics=list(result.get("errors",[])); adversarial=adversarial or {}
    if fatal: diagnostics.insert(0,fatal)
    failed=[k for k,v in adversarial.items() if v is not True]
    diagnostics.extend(f"scenario failed: {x}" for x in failed)
    passed=bool(result.get("passed")) and bool(dimensions) and all(x is True for x in dimensions.values()) and bool(adversarial) and not failed and not fatal
    reward=1.0 if passed else 0.0
    scenario_metrics={}
    scenario_domains={
      "tls":("tls_compliant_hybrid_handshake","tls12_downgrade_rejected","classical_only_kex_rejected","legacy_certificate_rejected","wrong_trust_domain_certificate_rejected"),
      "signing":("dual_independent_release_accepted","single_signature_rejected","revoked_signer_replay_rejected","old_context_rejected","same_domain_threshold_rejected"),
      "ssh":("ssh_compliant_session_accepted","ssh_sha1_rejected","ssh_wrong_host_identity_rejected","ssh_wrong_principal_ca_rejected"),
      "archives":("archive_aead_hybrid_restore_accepted","archive_legacy_wrap_rejected","archive_modified_ciphertext_rejected","archive_wrong_restore_profile_rejected"),
      "inventory_and_custody":("stale_and_unbound_evidence_excluded","scoped_material_selection","custody_domain_capacity_enforced")}
    for domain,names in scenario_domains.items():
        evaluated=sum(k in adversarial for k in names); successes=sum(adversarial.get(k) is True for k in names)
        scenario_metrics[domain]={"passed":successes,"evaluated":evaluated,"required":len(names),"rate":successes/len(names) if evaluated else None}
    detail={"task_mode":"defensive","reward":reward,"solved_service_ids":[SERVICE_ID] if passed else [],"unsolved_service_ids":[] if passed else [SERVICE_ID],
      "dimensions":dimensions,"scenario_groups":{"temporal_effective_dependency_inventory":bool(dimensions.get("effective_inventory")),"custody_scope_and_signer_containment":bool(dimensions.get("evidence_scope") and dimensions.get("signer_containment")),
       "tls_signing_ssh_downgrade_resistance":bool(dimensions.get("policy_design") and dimensions.get("compatibility_and_ring_gates")),"archive_decryption_integrity_and_rewrap":bool(dimensions.get("archive_migration")),
       "failure_domain_interruption_and_transition_order":bool(dimensions.get("interruption_recovery") and dimensions.get("transition_safety")),"trust_rotation_and_final_retirement":bool(dimensions.get("key_lifecycle") and dimensions.get("final_state"))},
      "adversarial_scenarios":adversarial,"processed_actions":len(result.get("history",[])),"transition_history":result.get("history",[]),"state_summary":result.get("state_summary",{}),"diagnostics":diagnostics[:120],
      "diagnostics_count":len(diagnostics),"diagnostics_truncated":len(diagnostics)>120,
      "metrics":{"migration_coverage":result.get("coverage",{}),"policy_scenarios":scenario_metrics,"strict_completion":passed}}
    LOGS.mkdir(parents=True,exist_ok=True); (LOGS/"reward.txt").write_text(f"{reward:.1f}\n",encoding="utf-8"); (LOGS/"details.json").write_text(json.dumps(detail,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps(detail,indent=2,sort_keys=True)); return passed

def main():
    empty={"passed":False,"errors":[],"history":[],"dimensions":{}}
    try: plan=load_plan()
    except FileNotFoundError: return emit(empty,"/app/submission/migration-plan.json is missing")
    except (OSError,ValueError,json.JSONDecodeError) as exc: return emit(empty,f"submission is not safe bounded JSON: {exc}")
    try:
        result=simulate(plan,FIXTURES); adversarial=exercise_adversarial_scenarios(plan,FIXTURES)
    except Exception as exc: return emit(empty,f"semantic simulation failed: {type(exc).__name__}: {exc}")
    return emit(result,adversarial=adversarial)
if __name__=="__main__": raise SystemExit(0 if main() else 1)
