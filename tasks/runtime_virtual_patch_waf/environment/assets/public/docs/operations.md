# Deployment SLO and acceptance notes

Northstar is frozen, not disposable. The virtual patch is accepted only if it protects all
three locator-bearing operations while maintaining the surrounding API contract.

* **Availability:** safe interactive, batch, validation, integration, import, search, and
  event requests must continue. Blanket route/method/media/auth denial is unacceptable.
* **Input handling:** JSON suffix types, media-type parameters, multipart framing, arrays,
  duplicate inputs, and canonical routes follow `protocol.md`. Malformed protected input
  must terminate at the edge with a bounded 4xx.
* **Capacity:** imports up to exactly 1 MiB are contractual. The WAF body ceiling may be at
  most 2 MiB. Parser and policy bounds are specified in `policy-language.md`.
* **Work:** the deterministic 180-unit/request ceiling is enforced by the runtime. A rule
  inspects at most 16 values, matching the maximum batch size; over-budget or over-count
  shapes fail safely. The local replay prints maximum work. The grader also executes the
  full corpus under a generous wall-clock guard to catch unexpected evaluation stalls.
* **Audit:** every security denial and safety rejection must be attributable by request,
  stable rule, effective route, carrier/field where applicable, and reason. Values and
  bodies are sensitive and must be redacted.

The published capture is representative and intentionally not exhaustive. In particular,
passing it with raw substring filters—or copying one observed adapter pipeline to every
carrier—does not establish equivalence with the documented legacy resolver. Use
`waflab inspect` on per-carrier malicious and benign variants while developing the policy.
