# Incident report schema

Write one JSON object to `/app/incident_report.json`. This is a controlled
forensic finding format rather than a prose template. Use only the fields shown;
unexpected fields are rejected so a label cannot be contradicted by an
unstructured side claim. Array order is not significant.

```json
{
  "case_id": "case identifier from the evidence",
  "affected_hosts": ["host names assessed as compromised"],
  "initial_access": {
    "host": "host name",
    "vector": "controlled label",
    "execution": "controlled label",
    "assessment": "confirmed_compromise|suspected|benign",
    "evidence": [{"path": "relative/path", "locator": "unique record locator"}]
  },
  "lateral_movement": [
    {
      "source": "host name",
      "destination": "host name",
      "account": "principal",
      "channel": "ssh|rdp|smb|winrm|api|other",
      "assessment": "confirmed_compromise|suspected|benign",
      "evidence": [{"path": "...", "locator": "..."}]
    }
  ],
  "persistence": [
    {
      "host": "host name",
      "kind": "registry_run|scheduled_task|systemd_service|systemd_timer|ssh_authorized_key|shell_profile|other",
      "object": "concrete value name, unit, path, key fingerprint, or other captured identifier",
      "effect": "execution|reentry",
      "assessment": "malicious|suspicious|benign",
      "evidence": [{"path": "...", "locator": "..."}]
    }
  ],
  "timeline": [
    {
      "time_utc": "ISO-8601 UTC",
      "kind": "initial_execution|credential_access|lateral_access|persistence_activation",
      "evidence": [{"path": "...", "locator": "..."}]
    }
  ],
  "indicators": [
    {
      "type": "ip|sha256|key_fingerprint",
      "value": "normalized indicator",
      "disposition": "hostile|suspicious|approved",
      "evidence": [{"path": "...", "locator": "..."}]
    }
  ]
}
```

Suggested `vector` labels are `malicious_document`, `drive_by_download`,
`stolen_credential`, and `public_service_exploit`; suggested `execution` labels
are `powershell`, `native_binary`, `script_interpreter`, and `remote_service`.
Select the values supported by this case. Include every malicious persistence
finding and a trusted hostile indicator set covering the initial payload, later
payloads, attacker infrastructure, and re-entry material. You may additionally
include other evidence-backed observed hashes, benign persistence/baseline
objects, and approved IP, hash, or key-fingerprint indicators when they help
document collateral-impact decisions; unsupported context is rejected.

## Citation rules

Each evidence object has exactly `path` and `locator`. `path` must be a regular
file relative to `/evidence` (no absolute paths or `..`). `locator` must be a
case-insensitive literal substring that uniquely selects one source record or
line in that file, such as a record ID, full timestamp, fingerprint, hash, or
distinctive log excerpt. Generic field names, headers, or repeated program
names are not record locators. The selected records must contain the submitted
host, time, object, channel, or indicator facts they support.

`lateral_movement` contains one finding per evidence-supported hop in the causal
chain. Lateral-movement and silent-persistence findings require corroboration
from at least two independently produced source families. The four timeline `kind`
values are lifecycle categories, not prescribed answers; each category needs at
least one supported event and every distinct lateral hop needs its own
`lateral_access` event. Additional distinct events are accepted when their
timestamp occurs in the uniquely selected source record.

Eradication, containment, trust rotation, collateral impact, and recovery are
not self-attested in this report. They are graded directly from the mutable
range state after your `irctl` actions.
