# Migrate the Helios cryptographic estate

You are the authorized security operator for the isolated Helios production estate. A
release-signing custody incident occurred while several TLS, SSH, signing, and encrypted
archive consumers were already approaching policy deadlines. Required client cohorts
cannot be abandoned during the transition.

The read-only case bundle is under `/opt/crypto-case/`; begin with its `README.md`.
Inventory the effective dependencies shown by runtime evidence, distinguish the confirmed
incident from cleared leads, and create an executable migration history at:

`/app/submission/migration-plan.json`

Your plan must:

- account for effective protocol, algorithm, key, issuer, and wrapping dependencies;
- contain confirmed exposed signing material before replacement mutations;
- stage approved material, select compatible upgrades, and distribute trust before
  cutovers;
- execute interruption-safe canary then fleet upgrades across every documented failure
  domain, diagnose the effective post-fault states, choose safe recovery branches within
  their work budgets, chain the resulting health evidence into later rollout eligibility,
  and demonstrate target workflows in both rings while respecting availability caps;
- migrate and restore-check every archive using its permitted storage transition, with
  rewrap and restore receipts bound to the chosen wrapping material and object digest;
- enforce completion policies that reject TLS downgrade, weak SSH negotiation, signature
  substitution/replay, and non-hybrid or unauthenticated archive protection while
  respecting cross-surface custody-domain concentration limits; and
- retire all material marked for completion retirement only after its dependents have
  safely moved.

`agilityctl` can inspect evidence, lint structure, and rehearse representative transition
preconditions. The verifier replays the history and directly tests benign and adversarial
handshake, signature, SSH, archive-restore, lifecycle, and interruption scenarios. It
grades the JSON state and history, not prose. There is no flag or success token. Do not
use the public internet or modify the supplied case bundle.
