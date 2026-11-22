# 0013. IAM bounded context `authorization/iam`, with the gateway as modules inside it

Planning decisions: section 3 of `specs/8-iam-scaffolding-and-spikes/architecture.md` (bounded context and crates, owner item D19) and section 2.5 of its `research.md` (naming).

## Context

The service becomes VilnaCRM's authorization service and API gateway. The planning board draws IAM and the gateway as two parts and labels the code in Go. The repository is built from the Rust service template, whose architecture gate places every crate in one layer of one bounded context and lets a context depend on itself and on the shared kernel only: `architecture.toml` accepts no other key than `shared` under `[contexts]`, and that file is protected. The template synchronises the group `crates/company-subdomain/`, so code placed there would meet every template update.

## Decision

IAM is one bounded context, `authorization/iam`, made of the three crates `iam-domain`, `iam-application` and `iam-infrastructure` under `crates/authorization/iam/`. The gateway is not a context of its own: its code will live as modules inside these three crates, in the layer each part belongs to, and the composition root `service` wires both run modes. The context was created with `make new-context group=authorization context=iam`, and its first slice is the policy epoch: the value objects, the `PolicyEpochRepository` port, the query that reads it, the PostgreSQL adapter and the table `iam_policy_epoch`.

The code is Rust, not the Go of the board's labels, and the names follow the Rust API guidelines:

- An acronym is one word in a type name: `GraphQl`, `OpenApi`, `UserApi`.
- A handler name starts with its verb: `GetPolicyEpochQueryHandler`, later `CreateGraphQlPermissionsCommandHandler` for the board's `GraphQLCreatePermissionsCommandHandler`.
- The board's `LoadGraphQLCommandHandler` gains the `Spec` suffix, `LoadGraphQlSpecCommandHandler`, to match `LoadOpenApiSpecCommandHandler`.
- A PostgreSQL adapter is prefixed `Pg`: `PgPolicyEpochRepository`.

The IAM router and the GraphQL roots `IamQuery` and `IamMutation` exist but expose no operation yet. They are merged into the schema, and the `iam` tag and the `bearerAuth` scheme are added to the OpenAPI document, by the change that adds the first operation, because an object type without fields is not valid GraphQL and an unused tag or scheme is a contract-lint finding.

## Consequences

The gateway code can use the IAM domain directly, with no cross-context rule and no protected change. The cost is one large context: its modules must keep the gateway and the control plane apart by naming and by the ports they use, because the architecture gate cannot tell them apart. The group `authorization` keeps the context out of the template-synchronised `company-subdomain` group, so a template update does not touch IAM code. Third-party crates the gateway needs in the infrastructure layer wait for an owner-approved allow-list change; until then such code stays in the composition root or in its tests.

Alternatives rejected: a separate `gateway` context, which could not depend on `iam` without a protected change to `architecture.toml`; two services, which would put a network hop and a second deployment between the decision and its enforcement; placing IAM in `company-subdomain`, which the template synchronises.
