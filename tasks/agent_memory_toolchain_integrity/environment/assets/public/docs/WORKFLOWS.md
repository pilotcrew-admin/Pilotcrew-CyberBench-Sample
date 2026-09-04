# Required workflow contracts

The live export contains generated IDs and concrete hosts. These contracts are
immutable and state what must continue to work.

- **Archive publication** is a high-risk export performed by the registered
  archive plugin. It sends encrypted archives only to the primary archive host
  named by the signed plugin catalog, uses the catalog's exact minimum scopes,
  and requires a change ticket bound to capability, target, and argument digest.
  A legitimate queued publication is present and must survive credential
  containment.
- **Change-ticket validation** contacts only the ticket service named in its
  signed registration. It is a low-risk supporting call and does not itself
  require another ticket.
- **Knowledge lookup** may use active collaborative notes and contacts only the
  registered knowledge host. Treating all unsigned collaborative material as
  disposable would break this workflow.
- **On-call notification** uses its signed registration and remains available
  during the incident.

A workflow is not preserved merely because a plugin is still marked active: its
credential must be active and sufficiently scoped, its endpoint must be allowed,
and the boundary must allow the representative contract envelope. Conversely,
blanket-denying all low-risk calls is excessive collateral damage.
