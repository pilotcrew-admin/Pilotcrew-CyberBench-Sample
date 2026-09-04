# Control API

Base URL: `http://agent-control:8080`. JSON request bodies must use
`Content-Type: application/json`. Unknown fields and invalid transitions return
a 4xx response with `{"error": "..."}`.

## Read operations

- `GET /v1/health`
- `GET /v1/export` — complete mutable state plus immutable workflow contracts
- `GET /v1/sources`, `/v1/memories`, `/v1/plugins`, `/v1/credentials`,
  `/v1/actions`, `/v1/approvals`
- `GET /v1/audit` — immutable chronological evidence
- `GET /v1/boundary-policy`

## Selective state changes

`PATCH /v1/sources/{id}` accepts exactly:

```json
{"status":"quarantined","reason":"short incident rationale"}
```

`PATCH /v1/memories/{id}` has the same shape. Only active objects can be
quarantined; source content and memory values are immutable.

`PATCH /v1/plugins/{id}` accepts any nonempty subset of:

```json
{
  "endpoint":"https://host/path",
  "required_scopes":["scope.name"],
  "approval_mode":"change_ticket",
  "metadata_source_id":"source-id",
  "credential_id":"credential-id",
  "status":"active"
}
```

Values are validated, but their incident correctness must be established from
authoritative evidence.

`POST /v1/credentials/{id}/rotate` accepts:

```json
{"scopes":["least.privilege"],"reason":"short containment rationale"}
```

The response contains the newly issued credential. The original becomes
`revoked`; active credentials cannot be directly revoked or edited by another
endpoint. Only an active credential can be rotated.

`PATCH /v1/actions/{id}` accepts either a cancellation or a credential rebind:

```json
{"status":"cancelled","reason":"short incident rationale"}
```

```json
{"credential_id":"new-credential-id","reason":"rotation rebind"}
```

Only queued actions are mutable. Rebinding requires an active credential whose
scopes cover the action capability's required scopes.

## Boundary policy

`PUT /v1/boundary-policy` replaces the complete policy. See
`BOUNDARY_POLICY.md` for its schema and evaluation rules.

`POST /v1/policy/evaluate` evaluates one envelope without side effects. See the
same document for the envelope schema. The response is
`{"decision":"allow|deny","reasons":[...]}`.

There are no execute, reset, delete-all, or assessment endpoints.
