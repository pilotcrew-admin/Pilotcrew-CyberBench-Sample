# Helios cryptographic-agility case bundle

Identifiers and algorithm labels are case-sensitive. The captured time and migration
completion deadline are recorded in the case files. Everything required is offline.

## Evidence and inventory

- `case/estate.json` — current services, consumer versions, trust, availability caps,
  rollout rings, and failure domains.
- `case/deployment-events.jsonl` — time-ordered subject-to-consumer binding lifecycle.
- `case/materials.json` — current and candidate keys, credentials, issuers, sources,
  lifecycle disposition, approval scope, identity scope, and cryptographic properties.
- `case/compatibility.json` — version capabilities and authorized offline upgrade choices.
- `case/tls-negotiations.jsonl`, `signature-verifications.jsonl`, and
  `ssh-sessions.jsonl` — current, stale, retired-subject, and failed runtime observations.
- `case/archives.json` — stored-object protection, integrity digests, readers, and allowed
  storage migration modes.
- `case/incident-evidence.json` — custody evidence, confirmed and cleared leads, and
  signed-artifact observations.
- `case/execution-fixtures.json` — captured archive envelopes/nonces, upgrade state seeds,
  fault order, recovery work costs, and a neutral receipt self-test vector.
- `case/interruption-observations.jsonl` — temporal post-fault states for diagnosis,
  including stale, failed-collection, and post-capture distractions.
- `case/policy-baseline.json` — normative completion controls.

## Contracts

- `docs/evidence-semantics.md` explains how to scope effective dependencies and incidents.
- `docs/plan-schema.md` defines every submitted field and action.
- `docs/migration-contract.md` defines replay, compatibility, availability, gates,
  lifecycle, and final-policy behavior.
- `docs/receipt-contract.md` defines byte-exact archive and interruption execution
  receipts using standard SHA-256 and HMAC-SHA256.
- `plan.schema.json` is a structural schema; semantic assessment is stricter.

Useful commands:

```sh
agilityctl evidence
agilityctl lint /app/submission/migration-plan.json
agilityctl rehearse /app/submission/migration-plan.json
```

The rehearsal checks representative referential and ordering constraints. It does not
select material, solve the cross-surface custody allocation, construct the inventory, or
prove all downgrade and replay scenarios.
