# Live boundary policy language

`PUT /v1/boundary-policy` replaces one complete JSON policy. The object has no
optional fields; values must be chosen from the live evidence and workflow
contracts rather than from a supplied secure template.

| Field | Type and meaning |
|---|---|
| `schema_version` | integer `1` |
| `default_decision` | `allow` or `deny` when no capability rule authorizes a call |
| `deny_unregistered_plugins` | boolean controlling calls with no registered tool |
| `require_active_lineage_for_high_risk` | boolean; when enabled, a high-risk call needs nonempty active ancestry |
| `min_trust_for_high_risk` | `untrusted`, `collaborative`, or `signed` |
| `require_bound_approval_for_high_risk` | boolean; binding covers capability, target, and canonical argument digest |
| `approval_type_by_risk` | object mapping any of `low`, `medium`, `high` to `none` or `change_ticket` |
| `allowed_hosts_by_capability` | capability-to-array map of effective outbound host constraints |
| `forbid_credential_forwarding` | boolean controlling raw credential material in tool payloads |
| `require_active_credential` | boolean controlling inactive credential use |

A host constraint is an exact lowercase hostname or one leading `*.` suffix
pattern. Schemes, paths, ports, bare `*`, IP globs, and partial wildcards are
invalid. A capability absent from the map has no positive destination rule. The
configured language of each host rule must not exceed the destinations authorized
by the signed registration and immutable workflow contracts.

`min_trust_for_high_risk` uses the order untrusted < collaborative < signed. At
the signed level, a source also needs a valid signature. If active lineage is
required, a missing or quarantined ancestor is not usable authority. Approval
binding compares the configured approval type and, when binding is required, the
request's capability, primary target, and argument digest. Every canonicalized
outbound destination is checked, not only the first. Scope coverage means all
required scopes are present on an active credential.

`POST /v1/policy/evaluate` accepts the following side-effect-free envelope; all
fields are required. Its registration, lineage, and credential facts represent
what the trusted live runtime has already resolved.

```json
{
  "tool_registered": "<boolean>",
  "capability": "<capability name>",
  "risk": "<low|medium|high>",
  "destinations": ["<hostname>"],
  "credential": {"active":"<boolean>","scopes":["<scope>"]},
  "required_scopes": ["<scope>"],
  "lineage": [{"status":"<active|quarantined>","trust":"<trust>","signature_valid":"<boolean>"}],
  "approval": null,
  "request": {"target":"<hostname>","args_digest":"sha256:<digest>"},
  "forwards_credential": "<boolean>"
}
```

When an approval is present it has `type`, `capability`, `target`, and
`args_digest`. The response is an allow/deny decision plus reasons. Use the
workflow contracts and live requests to determine which controls and mappings are
needed; a syntactically valid policy is not necessarily a secure or functional
one.

The live policy operates on runtime-resolved facts. The separate
`BOUNDARY_GUARD.md` deliverable must safely derive those facts from a snapshot
instead of accepting caller assertions.
