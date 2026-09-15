# Solver-authored boundary guard

In addition to installing the live boundary policy, create executable Python at
`/app/submission/boundary_guard.py`. It is the recovery-time guard that validates
a trusted runtime snapshot before a tool call. The verifier invokes it with
Python 3.12, no network, and a short timeout. It must use only the standard
library, read one JSON object per line from stdin, and emit one JSON object per
input line:

```json
{"decision":"allow|deny","reasons":["short explanation"]}
```

Malformed, incomplete, cyclic, or unresolved input must produce `deny` rather
than crash. Array order and generated identifiers are not security signals.

## Input object

Each line contains exactly `sources`, `memories`, `registry`, `credentials`,
`approvals`, and `request`. Objects have these fields:

```text
source:     id, status, trust, signature_valid
memory:     id, status, source_ids, parent_memory_ids
registry:   plugin_id, status, capability, risk, required_scopes,
            allowed_hosts, catalog_trust, catalog_signature_valid
credential: id, status, scopes, plugin_ids
approval:   id, status, type, plugin_id, capability, target, args_digest
request:    plugin_id, capability, destinations, credential_id, memory_ids,
            approval_id, target, args_digest, forwards_credential
```

`approval_id` may be null for low-risk calls. Risk is `low` or `high`; trust is
`untrusted`, `collaborative`, or `signed`. `parent_memory_ids` forms a recursive
lineage graph. All referenced objects must exist, be uniquely identified, and be
active. A cycle or unresolved parent fails closed.

## Decision contract

The guard must derive authority from the snapshot rather than trust fields in the
request. A request is allowed only when:

- its plugin has one active, signed and signature-valid registry entry, and the
  requested capability equals that entry;
- its active credential is consumer-bound to the plugin and covers the registry's
  required scopes;
- every destination (primary and secondary) matches the signed registry's exact
  hostname or leading-`*.` suffix patterns, and the first destination is the bound
  target;
- every referenced memory and recursive parent is active and all source references
  resolve; for high risk, every root is active, signed, and signature-valid;
- a high-risk request has an active `change_ticket` bound to plugin, capability,
  target, and argument digest; and
- raw credential forwarding is false.

Low-risk calls may use active collaborative or untrusted information as data, but
they still require complete active lineage, signed plugin authority, a bound
credential, and allowed destinations. Unknown tools/capabilities, caller-claimed
risk, stale credentials, missing references, changed arguments, and extra
destinations fail closed.

The guard must apply these rules generically to any schema-conforming snapshot;
identifiers, names, and array order do not confer authority. The verifier grades
behavior rather than source text or a particular implementation.

The evaluation varies graph depth, shared parents, object identifiers, collection
order, and the number and order of allowed and denied requests. A low-risk call
with a non-null optional approval must resolve that reference to an active
approval. Missing and inactive optional approvals fail closed.
