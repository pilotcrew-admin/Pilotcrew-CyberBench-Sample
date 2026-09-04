# Multi-Artifact Forensic Eradication

You are the incident-response operator for a small mixed Windows/Linux finance
segment. An endpoint alert identified one part of a compromise, but the security
team believes the actor may have moved beyond the alerted workstation. Work
entirely inside this offline environment.

## Available surfaces

- Immutable evidence is under `/evidence/`. It includes EDR and Windows event
  exports, a registry export, host filesystem captures, Linux authentication and
  audit records, memory-derived process/socket tables, network flows, and CMDB
  trust/baseline records.
- The response range's mutable state is under `/case/live/state.json`.
- Use `irctl help`, `irctl status`, and the documented response controls in
  `/evidence/docs/IRCTL.md`. The controls fail atomically on malformed requests.
- Report requirements and citation semantics are documented in
  `/evidence/docs/REPORT_SCHEMA.md`.

Timestamps in the evidence are UTC. Documentation-network IP ranges in the case
are intentional synthetic addresses.

## Objective

Establish the evidence-grounded incident scope and causal timeline. Do not stop
at the alerted path: identify any lateral movement and silent persistence that
is supported by the other artifacts. Determine which indicators are trustworthy
by corroborating them and by distinguishing approved external dependencies from
attacker infrastructure.

Then carry out a complete, least-disruptive response using `irctl`:

1. neutralize every attacker execution and re-entry mechanism on affected hosts;
2. revoke attacker-controlled access and rotate only trust material shown to be
   exposed, rebinding dependent workloads when required;
3. contain trusted hostile indicators without disrupting approved destinations;
4. restore the affected business workflows; and
5. preserve clean hosts, legitimate startup entries, managed access, service
   accounts, artifacts, and external integrations.

Finally write `/app/incident_report.json` following the public schema. Claims
must cite real evidence records: each citation locator is checked against the
cited artifact. The result is graded directly on the remediated range state,
workflow recovery, collateral impact, scope, chronology, and causal evidence.
There is no flag or success token.

Before finishing, run `irctl verify` for an operator-facing diagnostic. It is a
non-authoritative safety check; the verifier independently inspects the state
and report.
