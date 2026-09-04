# Migration replay and security contract

The verifier starts from `case/estate.json` and replays submitted actions in order. An
action with an unsatisfied precondition is rejected without mutating state. The result
must preserve required workflow availability throughout and satisfy every final policy.

## Candidate and upgrade selection

Final approval is scoped. Use `policy-baseline.json` together with material metadata;
approval or algorithm strength alone does not make a material valid for a different trust
domain, DNS identity, signing independence domain, SSH host/principal scope, or archive
restore profile. After forming locally valid choices, enforce the global custody-domain
capacity across all selected private-key roles. Multiple combinations are valid; the
transition and final policy must use one capacity-safe combination consistently.

A consumer's captured `version` applies to both rollout rings. Determine whether it
supports its surface target from `compatibility.json`. If it does not, choose an approved
`offline-recovery` package whose `from` matches that ring's installed version and whose
`to` capabilities satisfy the complete target. The catalog includes approved partial
upgrades that improve one property but do not satisfy the final workflow.

`upgrade_consumer` names one ring and every published failure domain for that consumer.
For `canary`, `batch.max_per_failure_domain` must not exceed
`rollout.canary_max_per_failure_domain`, and `batch.max_total` may not exceed that value
times the number of named domains. Fleet batches use the two normal availability caps.
`on_interrupt` must match the published `state_aware_recover` strategy. The simulator
injects failure before write, during write, and after write before commit; the captured
states do not all admit the same safe remediation.

An `upgrade_gate` proves the installed version after diagnosing the interruption
schedules. It names the actual package and includes ordered evidence-bound recovery steps.
The temporal selection, decision precedence, work budget, and stateful byte construction
in `receipt-contract.md` bind the resulting health chain to the captured states, canary
parent, consumer, ring, package image, target version, and chosen recovery branches. A
fleet upgrade is forbidden until that consumer's valid canary recovery chain has passed;
an upgraded ring cannot pass a target workflow without its own chain. A consumer that
already supports the target needs no upgrade action or upgrade gate.

## Material, trust, and transitions

Confirmed exposed signing material must be contained before any replacement mutation.
Containment freezes new signing by that key; already authorized releases and offline
recovery packages remain installable. `stage_material` accepts only final-approved
material from an approved source and never grants trust by itself; final policy gates also
check its documented identity/scope constraints.

Trust is ring-local. `distribute_trust` installs staged material only after that ring's
version can parse the material's role and algorithm. TLS roots go to TLS consumers,
release identities to signing consumers, and SSH host identities to SSH clients. Archive
wrapping keys and server-side SSH user CAs are staged/activated rather than distributed.

Activating a server credential, host key, user CA, signing key, or archive wrapping key
adds it alongside transition material. Before the first target workflow gate on each TLS,
signing, and SSH surface, execute `configure_transition`. It may name only active material
for its surface and must preserve a usable path for every required consumer ring. A
confirmed compromised signer is never a permissible signing transition path.

## Workflow gates and archives

A `workflow_gate` with profile `target` exercises the submitted final policy against the
named consumer ring's installed version and trust. It proves a compatible TLS handshake,
two-signature release verification, or SSH host/user trust exchange. Both canary and fleet
of every required TLS, signing, and SSH consumer must pass before that surface's final
policy is installed.

`migrate_archive` decrypts/authenticates the captured object, preserves its published
plaintext digest, and protects it with the named final cipher and staged wrapping key. It
includes the deterministic `new_envelope_hex` and `restore_proof` constructed from the
captured envelope/nonce and selected material as specified in `receipt-contract.md`; copied
or modified receipts do not establish migration. Its `mode` must equal the archive's
storage contract: hot objects allow `in_place`; WORM and replicated objects require
`copy_verify_swap`, retaining the old readable copy until verification. Both rings of
every required restore consumer must support the protection layers. `archive_gate` names
all required restore consumers and the published digest. Every archive must pass before
archive policy cutover.

## Completion and adversarial behavior

`set_final_policy` enforces the corresponding object from `final_policies` and removes
transition fallback. At that point all required consumer rings must remain functional.
Hybrid means both the named classical and post-quantum components. Signing threshold
identities must cover the required independent algorithms, come from distinct required
independence domains, and bind the new context. Strict SSH identity does not accept a
different valid host key. AEAD archives authenticate before releasing plaintext.

The assessment supplies stale and unbound evidence, conditionally scoped candidates,
partial upgrades, interrupted canary/fleet writes, downgrade offers, TLS certificate
substitution, single or repeated signature bundles, revoked-key replay, SSH SHA-1 and
wrong-host attempts, archive-wrap stripping, modified ciphertext, and compliant traffic.
Final policies must reject adversarial variants without blocking required benign flows.

A material may be retired only after every surface or stored object has stopped depending
on it, the relevant final policy is active, and required gates have passed. Completion
requires exactly the catalog material marked `retire_at_completion`.
