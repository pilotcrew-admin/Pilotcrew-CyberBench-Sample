# Incident submission

Create `/app/submission/incident.json` as one JSON object:

```json
{
  "schema_version": 1,
  "incident_summary": "concise causal summary",
  "causal_chains": [
    {
      "source_ids": ["source-id"],
      "memory_ids": ["memory-id"],
      "plugin_ids": ["plugin-id"],
      "action_ids": ["action-id"],
      "audit_event_ids": ["event-id"]
    }
  ],
  "quarantined_source_ids": ["source-id"],
  "quarantined_memory_ids": ["memory-id"],
  "cancelled_action_ids": ["action-id"],
  "rotated_credentials": [
    {"old_id":"credential-id","new_id":"credential-id"}
  ],
  "repaired_plugin_ids": ["plugin-id"],
  "preserved_memory_ids": ["memory-id"],
  "policy_rationale": "why the boundary handles variants and preserves work"
}
```

IDs must exist in the live estate. Each causal chain is evaluated against actual
source-to-memory lineage plus audit links to metadata changes, plans, actions, or
credential handling; array order is irrelevant. A chain may cite multiple
sources where a derived memory joined them. The report need not enumerate benign
audit noise, but it must substantiate every contained branch and the credential
exposure. `preserved_memory_ids` should include representative legitimate signed
and collaborative knowledge, not every retained object.

Also write `/app/submission/README.md` with a human-readable summary and
`/app/submission/boundary_guard.py` with the JSONL interface specified in
`BOUNDARY_GUARD.md`. Prose is diagnostic; the structured report, corrected live
state, and guard behavior are graded semantically.
