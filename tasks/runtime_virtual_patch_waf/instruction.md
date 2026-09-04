# Deploy a virtual patch for Northstar Render

You are the defensive edge operator for an authorized, isolated compatibility lab.
Northstar's legacy render API cannot be upgraded during the current release freeze. An
incident indicates that template locators can cross the configured template root after
legacy canonicalization. The same operation is used by interactive clients, batch jobs,
and an authenticated integration, while neighboring upload and search endpoints carry
look-alike data that must remain available.

Investigate the protocol, policy language, operational constraints, and captured traffic
under `/app/docs/` and `/app/traffic/`. The safe lab service listens on
`http://127.0.0.1:8080`; it reports what the legacy resolver would attempt but never reads
an outside file. `/app/waflab` can inspect request envelopes, validate policies, replay the
published traffic, and test a policy without the HTTP service.

Create the deployable policy:

```
/app/edge-policy.json
```

The artifact must use the documented EdgeShield v1 language, run in enforcement mode,
and virtual-patch every documented locator-bearing render operation. It must handle the
observed legacy route behavior and the independently evolved locator adapter behavior for
every supported carrier, including container members, duplicates, malformed protected
requests, and evasive encodings. Do
not solve the incident by denying an entire route, authentication mode, body format, or
client class. Preserve safe relative and `asset:` locators, within-root normalization,
complex JSON and multipart requests, batch jobs, the legacy integration, uploads,
search, and unrelated API traffic.

The policy must also meet the published request-size, parser, deterministic work, and
configuration budgets. Security denials need structured audit records with useful request
and rule attribution while excluding locator values and bodies. Invalid or oversized
protected requests must fail safely rather than reach the legacy resolver.

Useful commands:

```sh
/app/waflab inspect /app/traffic/<request-file>.json
/app/waflab check /app/edge-policy.json
/app/waflab replay /app/edge-policy.json /app/traffic/representative.jsonl
/app/waflab probe /app/edge-policy.json /path/to/request.json
```

The verifier directly loads the policy in an independent runtime and replays deterministic
malicious, evasive, malformed, and benign requests, including unpublished request-shape
and encoding variants. It grades effective security decisions, compatibility and false
positives, audit semantics, resource cost, and policy validity. There is no flag, secret,
or success token.
