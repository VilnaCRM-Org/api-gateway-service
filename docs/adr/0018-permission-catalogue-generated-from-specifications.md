# 0018. Permission catalogue generated from OpenAPI and GraphQL specifications

Status: accepted. Story 5.3 applies it to the first catalogue write, the activation of a GraphQL version.

Planning decisions: functional requirements FR-1, FR-2, FR-32, FR-36 and FR-38 of `specs/8-iam-scaffolding-and-spikes/prd.md`, and the sections of its architecture on the permission catalogue and on orphaned grants.

## Context

An administrator grants permissions to roles. If every grantable key were typed in by hand, a new field or operation of a service could ship without anything to grant, or a typo could grant nothing. A key that a service no longer offers must not keep granting access either. The catalogue therefore has to follow the specifications that the services publish, and the effect of a new version on existing grants has to be visible before it is applied.

## Decision

- **The catalogue is generated.** A GraphQL schema or an OpenAPI document is loaded as a draft version of one service. Activating the version makes its coordinates or operations the permission keys `gql:{service}:{Type}.{field}` and `rest:{service}:{METHOD} {template}`, and, once a GraphQL version of the service is active, `gql:{service}:__introspection`. Nobody creates a key by hand.
- **The catalogue is the union of the active versions.** A service may have several active versions at once, for example during a rolling release. A key that several versions hold carries the most restrictive flags of them (`@iamSensitive`, `@iamAuditAlways`). Activating a version that is active already is a no-op that answers 200.
- **An activation is one change.** The status of the version, the new, re-flagged and reactivated catalogue entries, the orphaned and renamed grants and the next catalogue epoch are committed in one transaction of the unit of work, together with the next policy version, `iam.graphql_permissions.created` (or `iam.rest_permissions.created`), `iam.permissions.orphaned` when grants were orphaned, the audit record and the change receipt. The change is guarded by the policy version it was decided against, so a role change that lands in between refuses the activation with a conflict instead of leaving a grant unexamined.
- **Renames keep grants.** A request may rename coordinates: the grants of each old key move to its new key before anything is orphaned. A rename must name an old key that the catalogue no longer holds and a new key that it holds.
- **Orphaning is explicit.** A grant of an exact key that leaves the catalogue becomes inactive (`orphaned_at`), and stays inactive when the key comes back: only a new grant makes the key usable again. An activation that would orphan grants is refused with 409 (`/problems/orphan-confirmation-required`, GraphQL `ORPHAN_CONFIRMATION_REQUIRED`) and lists the grants, unless the request sets `confirmOrphans`.
- **Flag downgrades are explicit.** An activation that would remove the sensitive or the always-audit flag from a key is refused with 409 (`/problems/flag-downgrade-confirmation-required`, GraphQL `FLAG_DOWNGRADE_CONFIRMATION_REQUIRED`) and lists the keys, unless the request sets `confirmFlagDowngrade`. The `iam:grant:sensitive` requirement for a confirmed downgrade is enforced by Story 6.14, and the revocation-class write mode of an orphaning activation by Story 13.8.
- **Replays return the original result.** An activation sent with an `Idempotency-Key` returns the original keys and policy version when it is replayed, read from the change receipt and from the recorded event, and commits nothing a second time.

| Option | Outcome | Reason |
| --- | --- | --- |
| Generate the catalogue from the specifications | Chosen | A shipped field or operation is grantable at once, and a removed one stops granting |
| Administrators create keys by hand | Rejected | Keys drift from the services and typos grant nothing |
| Delete the grants of a removed key | Rejected | The audit trail loses who held what; an orphaned grant stays visible and inactive |
| Reactivate an orphaned grant when its key returns | Rejected | A key that disappears and returns may mean something else; access must be granted again on purpose |

## Consequences

The catalogue reads are Stories 5.4 and 5.5 of the same epic, and the retirement of a version follows the same statement. The decision path reads only active grants, so an orphaned grant never grants access. A new catalogue key is never granted by an existing exact-key grant: only wildcard grants cover it, and `@iamSensitive` keys are never covered by a wildcard.
