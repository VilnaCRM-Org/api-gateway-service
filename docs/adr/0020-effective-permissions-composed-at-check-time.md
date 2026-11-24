# 0020. Effective permissions composed at check time

Status: accepted. Story 6.15 applies it to the effective-permissions read model.

Planning decisions: functional requirements FR-1 and FR-39 and non-functional requirement NFR-16 of `specs/8-iam-scaffolding-and-spikes/prd.md`, and the decision log of the IAM architecture (decision 0020, kept from the earlier plan).

## Context

An administrator has to answer "why can this user do that?". The straightforward design stores a `UserRolePermission` row per user and refreshes it whenever a role, a grant, an assignment or the catalogue changes. That design has to be kept consistent with the decision rule on every one of those writes, and a missed refresh makes the answer disagree with what the gateway enforces.

## Decision

- **Nothing is stored per user.** The decision path keeps compiled per-role sets and a list of assignments per subject. The read model `UserRolePermission` is composed from the same two inputs when it is asked for, by the domain service `EffectivePermissionComposer`.
- **One rule.** The composer applies the filters of `DecisionPolicy`: an assignment grants only while it is active at the time of the `Clock` port, a role without a compiled set contributes nothing, orphaned grants are already left out of the compiled sets, and a reserved `iam:` key counts only through a global assignment. A wildcard is listed as itself and never covers a sensitive key.
- **What an entry says.** Each held key or wildcard is listed with the roles whose active assignments grant it, its scopes (`all` when a global assignment grants it, else the project ids), the shortest expiry among the contributing assignments that expire (absent when none does) and the `policyVersion` of the snapshot the answer was read in.
- **Computed by `iam-control` from PostgreSQL.** `GetUserRolePermissionsQueryHandler` reads the subject's policy through the `PolicyReadRepository`, which returns the assignments, the role sets and the policy epoch in one consistent snapshot, and names the roles through the `RoleRepository`. The read API is `GET /api/users/{userId}/role-permissions` and the GraphQL field `userRolePermissions(userId, projectId, service)`; both need the catalogue key of the operation.
- **Proof.** A property test compares the read model with `DecisionPolicy` over random policies: for every key of the catalogue the read model holds it exactly where the decision rule allows it, with the same scopes. An end-to-end scenario compares the read model with the decision API.

| Option | Outcome | Reason |
| --- | --- | --- |
| Compose from compiled role sets and assignments when asked | Chosen | Cannot drift from the decision rule; no refresh on any write |
| Store a `UserRolePermission` row per user | Rejected | Every write to a role, a grant, an assignment or the catalogue would have to refresh it |
| Compose on the gateway from the snapshot | Deferred | The read API belongs to the control plane; the gateway needs no administrative reads |

## Consequences

The read cost grows with the number of assignments of one user and the grants of their roles, both small, so the answer is computed on every request and never cached. A change of the decision rule changes the read model with it, because the composer reuses the same predicates.
