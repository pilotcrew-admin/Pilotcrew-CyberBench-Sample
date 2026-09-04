# Northstar compatibility lab

Read `protocol.md`, `policy-language.md`, and `operations.md`. Captured request
envelopes live in `/app/traffic/representative.jsonl`; several individual requests are
included for convenient inspection.

The service at `127.0.0.1:8080` is safe: before a policy exists, a boundary-crossing
request returns an `outside_template_root` description rather than touching a file. Once
`/app/edge-policy.json` exists and validates, the service evaluates it on each request.
Policy changes are picked up without a restart.

The frozen application model is available only as a black-box compatibility service. It
accepts one request observation at a time through these workbench commands; its backend
implementation is not installed in `/app`.

```
waflab check POLICY
waflab inspect REQUEST.json
waflab probe POLICY REQUEST.json
waflab replay POLICY [CAPTURE.jsonl]
```

`inspect` shows the effective route, discovered locator carriers, normalized locator view,
and legacy resolver classification for the supplied envelope. Frozen request adapters
come from independent compatibility generations, so do not assume an observation from one
carrier defines a global resolver pipeline. Controlled comparisons—hold the value fixed
while changing a carrier, or change one encoding layer, compatibility character,
separator, edge space, or route spelling at a time—produce deterministic signatures that
can be collected with ordinary shell or Python scripts. Pair a security observation with
an extra-normalization or within-root neighbor before grouping carriers.

`probe` shows the edge action, structured audit record, deterministic work, and (when
allowed) the same upstream classification. A JSONL capture entry has `id`, `request`, and
expected edge `decision` (`allow`, `block`, or `reject`). The capture is only a starting
sample; exact adapter grouping and transform sequences remain black-box facts recoverable
through `inspect`.
