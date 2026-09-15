"""Check submitted receipt encoding, without selecting evidence or recovery actions."""
from __future__ import annotations

import hashlib
import hmac
import json


def check_receipts(plan, case):
    """Validate the documented byte contract against the solver's supplied inputs.

    This intentionally does not choose the latest observation, diagnose a fault,
    or establish migration safety. Those remain part of the investigation.
    """
    violations = []
    checked = 0
    valid = 0
    chains = {}
    execution = case["execution"]
    seeds = {x["consumer"]: x for x in execution["upgrade_states"]}
    objects = {x["archive"]: x for x in execution["archive_objects"]}
    observations = {x["id"]: x for x in case["interruptions"]}

    def utf8(*values):
        return "\0".join(values).encode("utf-8")

    for index, action in enumerate(plan.get("actions", [])):
        if not isinstance(action, dict) or action.get("op") not in {"upgrade_gate", "migrate_archive"}:
            continue
        checked += 1
        label = f"actions[{index}] {action.get('id')!r}"
        try:
            if action["op"] == "migrate_archive":
                archive = case["archives"][action["archive"]]
                obj = objects[action["archive"]]
                material = case["materials"][action["wrap_material"]]
                context = utf8(action["archive"], action["data_cipher"], action["wrap_material"], archive["digest"])
                message = bytes.fromhex(obj["legacy_envelope_hex"]) + bytes.fromhex(obj["object_nonce_hex"]) + context
                envelope = hmac.digest(bytes.fromhex(material["rewrap_share_hex"]), message, "sha256")
                proof = hmac.digest(envelope, b"restore-v1\0" + context, "sha256")
                if action.get("new_envelope_hex") != envelope.hex():
                    raise ValueError("new_envelope_hex does not bind the supplied archive, cipher and wrapping material")
                if action.get("restore_proof") != proof.hex():
                    raise ValueError("restore_proof does not bind the submitted rewrap")
            else:
                cid, ring, package = action["consumer"], action["ring"], action["package"]
                seed = bytes.fromhex(seeds[cid]["state_seed_hex"])
                image = case["packages"][package]["image_digest"]
                key = hashlib.sha256(seed + utf8(cid, ring, package, action["expected_version"], image)).digest()
                if ring == "canary":
                    parent = hashlib.sha256(b"captured-v2\0" + seed).digest()
                elif ring == "fleet":
                    parent = chains[(cid, package)]
                else:
                    raise ValueError("ring must be canary or fleet")
                steps = action["recovery_steps"]
                if [x["fault_point"] for x in steps] != execution["fault_points"]:
                    raise ValueError("recovery_steps must follow the documented fault_points order")
                for step in steps:
                    row = observations[step["evidence"]]
                    if (row["consumer"], row["ring"], row["package"], row["fault_point"]) != (cid, ring, package, step["fault_point"]):
                        raise ValueError("selected evidence belongs to a different consumer, ring, package or fault")
                    digest = hashlib.sha256(json.dumps(row["state"], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
                    if digest != row["state_digest"]:
                        raise ValueError("selected observation has an inconsistent state_digest")
                    work = step["work_units"]
                    if not isinstance(work, int) or isinstance(work, bool) or work < 0:
                        raise ValueError("work_units must be a nonnegative integer")
                    message = (b"recover-v2\0" + parent + b"\0" + utf8(step["fault_point"], step["evidence"])
                               + b"\0" + bytes.fromhex(digest) + b"\0" + utf8(step["decision"], str(work)))
                    parent = hmac.digest(key, message, "sha256")
                    if step.get("receipt") != parent.hex():
                        raise ValueError(f"receipt byte contract failed at fault {step['fault_point']!r}")
                if ring == "canary":
                    chains[(cid, package)] = parent
            valid += 1
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            violations.append(f"{label}: {exc}")
    return {"assessment": "receipt_encoding_only", "checks_passed": checked > 0 and not violations,
            "complete_migration_verified": False, "checked_actions": checked, "valid_actions": valid,
            "violations": violations,
            "unchecked": ["evidence_freshness", "recovery_decision_safety", "policy_scope_and_custody",
                          "transition_availability", "workflow_completion", "retirement"]}
