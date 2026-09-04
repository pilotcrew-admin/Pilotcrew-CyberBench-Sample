# Meridian state and provenance model

## Sources and derived memory

A `source` is an immutable ingested object. Its mutable `status` is `active` or
`quarantined`. `trust` is one of `untrusted`, `collaborative`, or `signed`.
Signed authority requires both `trust: signed` and `signature.valid: true`.
Redirects, digest changes, signer mismatch, or invalid signatures break that
authority even if a title resembles an authoritative document.

A `memory` records a durable assertion and its complete `source_ids` lineage.
Derived memories can join more than one source. Any quarantined or insufficiently
trusted ancestor taints a privileged decision even when another ancestor is
signed. Collaborative sources remain useful for low-risk knowledge workflows;
they are not authority for high-risk tool calls. Memory and source quarantine is
selective and reversible only through the documented state transition.

`audit` records are immutable and ordered. They connect fetches, derivations,
metadata updates, plans, tool calls, and credential handling through IDs. A
source can have downstream effects even if no queued action currently mentions
it directly.

## Plugins, credentials, and actions

Plugins declare a `capability`, `risk`, endpoint, required credential scopes,
approval mode, and metadata source. Signed catalog material is authoritative for
registration values. A credential has a principal, scopes, generation, status,
and issuance lineage. Rotating a credential revokes the old object and creates a
new ID; callers must reconnect the new ID to repaired plugin and queued action
state. A credential observed outside its intended boundary must not merely be
removed from one action—it has to be rotated.

Actions have `queued`, `cancelled`, or `completed` status and retain their
reasoning memories. An unsafe queued action must not execute. A legitimate queued
action should remain usable after containment. Editing its credential reference
does not alter its target, payload digest, approval, or reason lineage.

## Tool-boundary evaluation

The boundary receives an evaluation envelope from the trusted runtime. It must
make a general decision from registration, capability, risk, destinations,
credential state/scopes, provenance lineage, approval binding, and whether raw
credential material would be forwarded. High-risk lineage must be active and
signed. A signed source is invalid if its signature is false.

Approvals are capabilities, not comments. A bound approval matches the request's
capability, primary target, and canonical argument digest. Reusing a valid ticket
for changed arguments or a different target is not authorization. Every outbound
destination—including secondary callbacks—must satisfy the capability allowlist.

The public evaluation endpoint is side-effect free and exists so defenders can
exercise policy inputs before committing. The verifier evaluates additional
semantically equivalent safe and unsafe envelopes rather than looking only for
particular incident IDs.
