# EdgeShield policy language, version 1

A policy is a JSON object. `waflab check` performs the same schema and budget checks used
by the lab edge. Unknown fields and unsupported operators are errors rather than ignored
configuration.

## Top level

The following is an unrelated small-policy example, not a Northstar deployment profile.

```json
{
  "schema_version": 1,
  "mode": "enforce",
  "limits": {
    "max_body_bytes": 131072,
    "max_fields": 64,
    "max_json_depth": 16,
    "max_values_per_rule": 8
  },
  "failure_handling": {
    "parse_error": "reject",
    "decode_error": "reject",
    "oversize": "reject",
    "status": 422
  },
  "audit": {
    "enabled": true,
    "event": "edge.example",
    "fields": ["request_id", "rule_id", "method", "route", "reason"],
    "redact_values": true
  },
  "rules": []
}
```

An optional top-level `metadata` object is ignored at runtime. Enforcement is the only
mode accepted for deployment. Operational bounds are:

- `max_body_bytes`: 1,048,576 through 2,097,152 bytes;
- `max_fields`: 32 through 256;
- `max_json_depth`: 12 through 32;
- `max_values_per_rule`: 1 through 16 extracted values (16 preserves the contractual batch maximum);
- no more than 12 rules, 32 selectors, eight transforms per rule, or 32 KiB of
  policy JSON;
- `equals.value` and `contains.needle` are nonempty UTF-8 text capped at 4,096 bytes.

The runtime and independent grader cap deterministic evaluation work at 180 units per
request. A method/route comparison costs one unit; extracting a value and each transform
or predicate costs one. Before transforms run, a rule that extracts more than
`max_values_per_rule` is safely rejected. A policy that would exceed 180 is also safely
rejected instead of continuing unbounded work. This avoids timing noise while representing
the production latency budget. Exact route/selector rules are normally far below the cap.

Failure actions apply on a canonical protected method/route (a route matched by at least
one rule). `reject` returns the configured 4xx status without invoking the resolver.
Oversize protection is global and runs on raw body length before supported media is
parsed. Field counts are cumulative across query and body carriers. An unsupported media
type is left for the application, while malformed syntax in a supported body format is a
parse error.

## Rules

This generic document-state rule illustrates syntax only.

```json
{
  "id": "deny-retired-document-state",
  "priority": 250,
  "match": {
    "methods": ["PATCH"],
    "routes": ["/documents/state"]
  },
  "selectors": [
    {"location": "json", "pointers": ["/requested_state"]}
  ],
  "transforms": ["trim_ascii", "lowercase"],
  "predicate": {"op": "equals", "value": "retired", "case_sensitive": true},
  "action": {"type": "block", "status": 409}
}
```

Rules run by ascending unique `priority` and stop at the first block. IDs are
unique; priorities are unique integers from 0 through 10,000. Methods are uppercase tokens. Routes are exact **canonical** paths. A match must
name at least one method and route; globs are not used for routes. The optional `headers`
array has at most four `{"name":..., "equals":..., "case_sensitive":...}` conditions.
All conditions must match one occurrence of the named header. Header names are always
case-insensitive; the value comparison follows `case_sensitive`.

Selectors return every matching scalar string, including duplicate members:

- `query`, `form`, and `multipart` selectors use nonempty `names` arrays and preserve all
  occurrences;
- `header` uses `names`, compared case-insensitively;
- `json` uses nonempty RFC-6901-like `pointers`. `~0` and `~1` escapes are supported. `*`
  selects every array element or every member at that level. Duplicate JSON members are
  preserved for inspection.

A selector never changes a value merely because it came from a particular carrier.
Normal media parsing (query/form percent decoding, JSON string decoding, or multipart
framing) happens before the rule transform list.

Supported transforms are `percent_decode`, `unicode_nfkc`, `backslash_to_slash`,
`trim_ascii`, and `lowercase`. They run in listed order and may be repeated. A strict
percent decoder rejects malformed escapes or invalid UTF-8 according to
`failure_handling.decode_error`.

Transform capability is predicate-specific. `locator_outside` may use all five transforms,
including repeated `percent_decode`, because its purpose is to reproduce a resolver's
canonicalization boundary. `contains` and `equals` permit only `lowercase`, `trim_ascii`,
`backslash_to_slash`, and `unicode_nfkc`; decoder transforms such as `percent_decode` are
configuration errors for comparison predicates. When a comparison rule uses
`unicode_nfkc`, its `needle` or `value` must itself already be NFKC-normalized. The direct
comparison text, after the listed transforms, must still satisfy its own predicate;
`waflab check` reports the specific rule and comparison member otherwise. The 4,096-byte
cap applies to the configured `needle` or `value`, not to a transformed request value,
which Unicode case conversion can expand. If a comparison rule uses a `header` selector,
the configured comparison text must also be directly representable as a legal HTTP header
value. These restrictions keep every accepted comparison directly testable rather than
requiring an unbounded encoded or compatibility-normalization preimage.

EdgeShield v1 accepts only these supported predicates:

- `{"op":"locator_outside","allowed_schemes":[...]}`: true for NUL, absolute,
  drive/UNC, dot-underflow, or a scheme not in the case-insensitive allowed set. Each
  allowed-scheme entry must contain 1 through 64 ASCII characters and match the URI scheme
  grammar `^[A-Za-z][A-Za-z0-9+.-]*$`. Entries are canonicalized to lowercase for
  case-insensitive duplicate and effective-scheme checks; Unicode spellings are rejected.
  The predicate does not perform hidden decoding or character normalization.
- `{"op":"contains","needle":"text","case_sensitive":true}`. The needle is capped at
  4,096 UTF-8 bytes.
- `{"op":"equals","value":"text","case_sensitive":true}`. The value is capped at
  4,096 UTF-8 bytes.

Regular-expression predicates are not part of EdgeShield v1. `waflab check` rejects every
`regex` predicate with an actionable error directing the author to
`locator_outside`, `contains`, or `equals`.

Only `{"type":"block","status":403}`-style actions are supported: `status` may be any
integer from 400 through 499. An empty selector match does nothing. This is a deny-on-
violation language; requests that trigger no rule continue to the application.

## Audit contract

Every policy block and edge rejection creates an in-memory structured audit object.
`event` must be a useful category of at least four non-whitespace characters. `fields` may select from `request_id`,
`rule_id`, `method`, `route`, `source`, `field`, and `reason`. A deployment-quality policy
includes all seven so an operator can correlate a denial and locate the enforcing rule.
If `X-Request-ID` is absent, the edge creates a deterministic opaque `edge-...` correlation ID.
`redact_values` must be true. Raw locator values, headers, and bodies are not available as audit fields. `waflab probe` shows the audit object.
