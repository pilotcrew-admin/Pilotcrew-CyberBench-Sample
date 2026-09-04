# Deterministic execution-receipt contract

The migration artifact includes receipts from the supplied faithful offline archive and
interruption simulators. These are substantive evidence that the selected material and
recovery path were executed; they are not arbitrary report hashes. All text is UTF-8,
`NUL` is the single byte `0x00`, `||` is byte concatenation, SHA-256/HMAC-SHA256 have their
standard meanings, and encoded outputs are lowercase 64-character hexadecimal. Python's
stdlib `hashlib` and `hmac` are sufficient. `case/execution-fixtures.json.self_test`
provides a neutral HMAC test vector for encoding validation.

## Archive rewrap and restore

For a `migrate_archive` action, find its object fixture and selected wrapping material.
Let:

```text
context = UTF8(archive_id NUL data_cipher NUL wrap_material NUL published_digest)
message = HEX(legacy_envelope_hex) || HEX(object_nonce_hex) || context
new_envelope = HMAC-SHA256(key=HEX(material.rewrap_share_hex), message=message)
restore_proof = HMAC-SHA256(
    key=HEX(new_envelope), message=UTF8("restore-v1") || NUL || context)
```

Put the two hex results in the action as `new_envelope_hex` and `restore_proof`. The
simulator binds them to the selected target wrapper, cipher, object identity, and published
plaintext digest. Any modified envelope, nonce, material, cipher, object ID, digest, or
proof must fail before plaintext is released.

## Interrupted upgrade recovery

`case/interruption-observations.jsonl` contains captured and distracting interruption
states. For every tuple `(consumer, ring, package, fault_point)`, select the row with
`result == "captured"` having the latest `(observed_at, id)` at or before
`execution-fixtures.json.interruption_capture_cutoff`. Ignore collection failures and
post-cutoff rows. Verify its `state_digest` as:

```text
SHA256(UTF8(JSON(state, sort_keys=true, separators=(",", ":"))))
```

where `JSON` is compact JSON with lower-case JSON booleans/null and no ASCII escaping for
these ASCII-only states. Diagnose each selected state using the first matching rule:

1. `write_phase == "not_started"` -> `retry_same_image`.
2. `write_phase == "complete_uncommitted"`, `journal_integrity == "valid"`,
   `new_image_integrity == "verified"`, and `resume_token == "valid"` -> `resume_commit`.
3. `rollback_snapshot == "verified"` -> `rollback_then_retry`.
4. `image_cache == "verified"` and the consumer permits reimage -> `reimage_then_retry`.
5. Otherwise the captured state is unrecoverable and the gate cannot pass.

Work units for each decision are public in
`execution-fixtures.json.recovery_action_work_units`. Their gate sum may not exceed the
consumer's `max_recovery_work_units`. Each `upgrade_gate` names the actual package and
contains `recovery_steps` in the exact public `fault_points` order. Every step has
`fault_point`, selected `evidence` ID, `decision`, `work_units`, and `receipt`.

Receipts are stateful. Let:

```text
base_context = UTF8(consumer NUL ring NUL package NUL expected_version NUL image_digest)
base_key = SHA256(HEX(state_seed_hex) || base_context)
```

For the canary gate, initialize:

```text
parent = SHA256(UTF8("captured-v2") || NUL || HEX(state_seed_hex))
```

For the fleet gate, `parent` is instead `HEX(final canary receipt)` for the same consumer
and package. Then, for each selected step in `fault_points` order:

```text
message = UTF8("recover-v2") || NUL || parent || NUL ||
          UTF8(fault_point) || NUL || UTF8(evidence_id) || NUL ||
          HEX(state_digest) || NUL || UTF8(decision) || NUL ||
          UTF8(decimal_work_units)
receipt = HMAC-SHA256(key=base_key, message=message)
parent = HEX(receipt)
```

The final parent is the ring's recovery-health chain. A fleet upgrade is ineligible until
the matching canary chain is valid, and later target workflow gates are ineligible until
their upgraded ring has a valid chain. Thus stale evidence, a copied decision/receipt,
wrong recovery branch, excess work, or a changed consumer/ring/package/version/image/fault
prevents later rollout rather than merely failing a standalone string check.
