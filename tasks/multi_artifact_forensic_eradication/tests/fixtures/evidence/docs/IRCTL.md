# Response control contract

`irctl status` prints current range state. `irctl help` prints command syntax.
Identifiers accepted by commands are displayed by `status` and are stable for
this captured range.

Commands:

- `irctl quarantine HOST ARTIFACT_ID`
- `irctl disable-startup HOST ENTRY_ID`
- `irctl remove-key HOST KEY_ID`
- `irctl revoke-session SESSION_ID`
- `irctl rotate-credential PRINCIPAL`
- `irctl rebind-service SERVICE_ID PRINCIPAL`
- `irctl block INDICATOR`
- `irctl start-service HOST SERVICE_ID`
- `irctl verify`

Quarantine preserves evidence metadata while preventing execution. Disabling a
startup entry preserves the record while preventing launch. Rotation creates a
new credential version; dependent services do not recover until explicitly
rebound to the current version. Removing a key affects only that key. Blocks are
exact indicators, not CIDR rules.

Each mutating command validates all arguments before a single atomic state-file
replacement. Repeating an already-applied action is safe. The public `verify`
checks general safety and service-binding invariants, but does not identify which
items belong to this incident.
