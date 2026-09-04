# Meridian evidence workspace

Meridian's mutable control plane is reachable at `http://agent-control:8080`.
All supported defender operations are described in `docs/CONTROL_API.md`.

Suggested first steps:

```sh
curl -s http://agent-control:8080/v1/export | jq .
curl -s http://agent-control:8080/v1/audit | jq .
```

The export includes durable sources, memories, plugin registrations,
credentials, queued actions, approvals, the current boundary policy, and
workflow contracts. Audit records are append-only incident evidence. Document
bodies are deliberately included where their operational assertions must be
compared; transport metadata and signatures determine how much authority those
assertions have.

Read all documents in `docs/` before changing state. The API rejects unknown
fields and unsafe lifecycle transitions with explanatory JSON errors. Changes
are persistent for the lifetime of the task service. There is no reset endpoint.
