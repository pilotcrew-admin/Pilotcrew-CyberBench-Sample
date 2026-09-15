# Evidence guide

All clocks are UTC and were normalized without reordering source records.

- `cmdb/` contains the pre-incident asset, identity, approved-key, service, and
  external-dependency baselines. It is the authority for what must be preserved.
- `alerts/` and `windows/` contain alert and event exports from `acct-ws-04`.
- `registry/` and `filesystem/` contain captured configuration/content.
- `linux/` contains journal-style authentication and audit records from the
  Linux assets.
- `memory/` contains volatile process and socket records captured from those hosts.
- `network/` contains normalized flow telemetry for the segment.

A conclusion is stronger when independently produced sources agree. An external
address is not automatically hostile: compare observed behavior with the CMDB
approved-destination record. Hashes and key fingerprints are already normalized.
Treat traffic involving any asset as a hypothesis, not a scope decision; compare each observed behavior with independent host and baseline evidence.
