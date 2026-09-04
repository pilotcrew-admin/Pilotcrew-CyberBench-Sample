# Migration plan schema

Submit one JSON object with `format_version: 1`, `case_id`, `findings`, `dependencies`,
`final_policies`, and a non-empty ordered `actions` array. Unknown descriptive fields are
ignored. Action IDs must be unique non-empty strings. `case_id` must match the captured
estate.

## Findings and dependencies

`findings` contains `compromised_material` and `retire_material`, both arrays of material
IDs. `dependencies` is an array of:

```json
{"surface":"surface-id", "consumer":"consumer-or-archive-id",
 "effective_algorithms":["label"], "materials":["material-id"],
 "evidence":["observation-id"]}
```

Supply exactly the current effective dependencies reconstructed by the evidence contract.
Array order does not matter; values are compared as sets.

## Final policies

`final_policies` maps all four surface IDs to objects:

- TLS: `minimum_protocol`, `allowed_kex`, `allowed_server_credentials`,
  `trusted_roots`, `reject_downgrade`.
- signing: `required_signers`, `allowed_algorithms`, `threshold`, `context`,
  `reject_revoked`.
- SSH: `allowed_host_keys`, `allowed_user_cas`, `allowed_signature_algorithms`,
  `strict_host_identity`, `reject_sha1`.
- archive: `data_cipher`, `wrap_algorithm`, `wrap_material`, `require_aead`.

Policies are evaluated behaviorally against the baseline, material scope metadata, and
compatibility catalog; object/list order is not significant.

## Actions

Every action has `id` and `op`, plus these required fields:

- `contain_signer`: `material`
- `stage_material`: `material`
- `upgrade_consumer`: `consumer`, `package`, `ring` (`canary` or `fleet`),
  `failure_domains`, `batch`, and `on_interrupt`
- `upgrade_gate`: `consumer`, `ring`, `package`, `expected_version`, and
  `recovery_steps` in public fault-point order. Each step has `fault_point`, `evidence`,
  `decision`, `work_units`, and `receipt` as defined by `receipt-contract.md`.
- `distribute_trust`: `consumer`, `ring`, `material`
- `activate_material`: `surface`, `material`
- `configure_transition`: `surface`, `allowed_materials`
- `workflow_gate`: `surface`, `consumer`, `ring`, `profile` (the assessed target is
  `target`)
- `migrate_archive`: `archive`, `data_cipher`, `wrap_material`, `mode`,
  `new_envelope_hex`, and `restore_proof`
- `archive_gate`: `archive`, `consumers`, `expected_digest`
- `set_final_policy`: `surface`
- `retire_material`: `material`

`failure_domains`, `allowed_materials`, and `consumers` are non-empty ID arrays. `batch`
has positive integer `max_total` and `max_per_failure_domain`. Step evidence/decisions must
come from the effective captured state, work units are non-negative integers, and receipt
strings use lowercase 64-character hexadecimal. The state chain is recomputed under
`receipt-contract.md`; format-only or copied values are not accepted. Upgrade actions
cover every failure domain in the named consumer ring as a set; the documented rollout
contract defines safe interruption, work-budget, gate, and canary-before-fleet behavior.
