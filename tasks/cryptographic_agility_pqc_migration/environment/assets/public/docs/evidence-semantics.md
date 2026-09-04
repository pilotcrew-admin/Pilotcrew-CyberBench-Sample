# Evidence semantics

Runtime successes, not configured preference lists, establish captured effective
cryptographic dependencies. Runtime rows name subjects rather than cohorts. Reconstruct
the estate at `estate.json.captured_at` by replaying `deployment-events.jsonl` in timestamp
order: `bind` makes the subject an active member of the named consumer cohort and `unbind`
removes that exact binding. Ignore events after capture.

For each still-active subject in a required TLS, signing, or SSH consumer, select the
latest successful runtime observation at or before capture. Older successes for that same
subject, successes for subjects later unbound, failed probes, and observations from a
subject with no active binding are context rather than current dependencies. Aggregate
selected observations by consumer into one dependency row: union their algorithms and
materials and cite every selected observation ID in `evidence`. A required consumer with
multiple active subjects may therefore cite more than one observation. Times are UTC and
identifiers are case-sensitive.

Each archive record is also one effective dependency row: use the archive ID as
`consumer`, its two protection algorithms, its wrapping material, and its `evidence` ID.
Sorting is not significant; sets are. Do not infer dependencies from a material merely
because it exists in a catalog.

A custody event scopes compromise only when `confidence` is `confirmed` and its type
establishes material export or an unauthorized signing session. A suspected event with a
clearing attestation and an authorized copy are not compromise. An unauthorized artifact
corroborates the exposed signing path but does not make unrelated trust roots or candidate
material compromised.

`materials.json` field `disposition: retire_at_completion` is the authoritative lifecycle
scope. Transition-only material may remain usable during a safe bridge unless it is
confirmed compromised; it must not remain at completion.

`approved: final` and an approved source are necessary, not sufficient, for candidate
selection. Join every final policy constraint to material metadata: TLS trust domain,
server identity, issuer, and key usage; signing context, algorithm coverage, and
independence domains; SSH host identity and user-CA principal scopes; and archive restore
profiles. Plausible final-approved material for a different trust/restore scope must not
be deployed merely because its algorithm is modern.

Several correctly scoped private-key choices remain interchangeable locally. Apply
`policy-baseline.json.global_constraints` to the combined final selections across all
surfaces. Count each selected material whose role is listed, group it by `custody_domain`,
and keep every domain at or below the published maximum. This is a blast-radius control,
not a preference for one canonical set; any scope-correct combination within the domain
capacity is valid.

Interruption evidence is a second temporal join rather than part of `dependencies`. For
each consumer/ring/package/fault tuple, use only `result: captured` rows at or before the
published interruption cutoff and select the latest `(observed_at, id)`. Validate the
compact-canonical state digest before applying the recovery precedence and stateful chain
in `receipt-contract.md`. Older captured states, collection failures, and post-cutoff
repairs cannot justify a recovery branch.
