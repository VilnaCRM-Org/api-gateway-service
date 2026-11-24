# Architecture overview

This document describes how the service is built, why the code is arranged the way it is, and which assumptions about the deployment the design relies on. It is written for a reviewer who has not read the planning bundle. The reasons behind each structural choice are in the [decision records](adr/README.md); the C4 model of the system is in [`workspace.dsl`](../workspace.dsl) at the repository root and is served by the Structurizr viewer of the development environment on `http://localhost:8080`.

## What the service is

One Rust service binary, `service`, that gives a new VilnaCRM service the platform baseline of the PHP template. It serves REST under `/api` with a code-first OpenAPI 3.1.0 document, a GraphQL endpoint at `/api/graphql`, a readiness probe at `GET /api/health`, a liveness probe at `GET /ping` and problem documents (RFC 9457) for every error. A small example bounded context shows how a use case, an aggregate, a domain event, a repository and a PostgreSQL adapter fit together.

## Layers

Every bounded context is split into three layers, each its own crate. Cargo enforces the direction of the dependencies, because a crate can only use what its manifest lists, and `cargo xtask arch` enforces the rest ([ADR 0001](adr/0001-workspace-and-layers.md), [ADR 0002](adr/0002-architecture-gate.md)).

| Layer | What belongs in it | May depend on |
| --- | --- | --- |
| Domain | Aggregates, value objects, domain events, domain errors, repository ports and every other port that an adapter implements (`Cache`, `Clock`, `UuidGenerator`, the three bus ports, `HealthProbe`). No framework. Only `thiserror`, `uuid` and `async-trait` are allowed from outside the workspace. | Domain crates only |
| Application | Use cases (commands, queries, handlers, event subscribers, application errors) and the API-facing adapters (HTTP handlers, request and response types, OpenAPI annotations, GraphQL types and resolvers). The use-case modules do not import `axum`, `utoipa` or `async-graphql`; the `http` and `graphql` modules do. | Domain and Application crates |
| Infrastructure | Driven adapters: SQL and row mapping, the in-process buses, the cache, the clock, the UUID generator, the SQS client factory, the health probes. | Domain and Infrastructure crates |

Application and Infrastructure never depend on each other. A handler therefore cannot run SQL, and an adapter cannot call a use case. Only the composition root, the `service` crate, depends on all three layers and is where adapters meet use cases (`service::bootstrap::Adapters`).

## Crates and bounded contexts

The workspace has sixteen crates: twelve layer crates (four bounded contexts times three layers), the composition root `service` (a library plus the binary), the test-double crate `test-support`, the Gherkin suite `e2e-tests` and the tooling crate `xtask`.

| Bounded context | Purpose | Crates |
| --- | --- | --- |
| `shared` | The shared kernel: aggregate root, domain event, bus ports and their in-process adapters, technical ports and adapters, the problem type and the problem-aware extractors | `shared-domain`, `shared-application`, `shared-infrastructure` |
| `health-check` | The readiness check: the probe port, the orchestration of the three probes, and the PostgreSQL, cache and SQS probes | `health-check-domain`, `health-check-application`, `health-check-infrastructure` |
| `some-module` | The example context: create, read by id and list `ExampleApiResource`, REST and GraphQL | `some-module-domain`, `some-module-application`, `some-module-infrastructure` |
| `iam` | The authorization context (`authorization/iam`), with the gateway as modules inside it ([ADR 0013](adr/0013-iam-bounded-context.md)): the policy epoch, read from PostgreSQL ([ADR 0014](adr/0014-postgresql-and-replicated-policy-snapshot.md)), the hash-chained security audit log ([ADR 0019](adr/0019-security-audit-log-and-access-decision-log.md)), and the unit of work that commits a change with its outbox event rows, audit record, change receipt and idempotency record in one transaction under the policy version ([ADR 0017](adr/0017-policy-state-topic-transactional-outbox-and-fenced-relay.md)); the token-resolution operation (`POST /api/token-resolutions`, query `resolveToken`) on both interfaces ([ADR 0021](adr/0021-rest-and-graphql-parity.md)); the creation, reading, updating and deletion of roles (`POST /api/roles`, `GET /api/roles/{id}`, `PATCH /api/roles/{id}`, `DELETE /api/roles/{id}`, `GET /api/roles`, mutations `createRole`, `updateRole` and `deleteRole`, queries `role` and `roles`) on both interfaces, with idempotency keys and change receipts, where a deletion revokes every assignment of the role in the same transaction and reports how many it revoked; the reading and replacement of the grants of a role (`GET /api/roles/{id}/permissions`, `PUT /api/roles/{id}/permissions`, field `Role.permissions`, mutation `setRolePermissions`) on both interfaces, which checks every key against the active catalogue (a wildcard against a service that has one), takes a policy version, records `iam.role_permissions.changed` and audits an added wildcard with `coversFutureElements=true`; the activation of a GraphQL specification version (`POST /api/graphql-specs/{id}/permissions`, mutation `createGraphqlPermissions`) on both interfaces, which makes its fields grantable permissions as the union of the active versions of the service, takes a policy version, records `iam.graphql_permissions.created` and, for orphaned grants, `iam.permissions.orphaned`, and asks for confirmation before it removes a flag or orphans a grant ([ADR 0018](adr/0018-permission-catalogue-generated-from-specifications.md)); the activation of an `OpenAPI` specification version (`POST /api/openapi-specs/{id}/permissions`, mutation `createRestPermissions`) on both interfaces, with the same rules for the REST catalogue, which records `iam.rest_permissions.created`; the reading of the GraphQL permission catalogue (`GET /api/graphql-permissions`, `GET /api/graphql-permissions/{id}`, queries `graphqlPermissions` and `graphqlPermission`) on both interfaces, filtered by service, type, active state, the sensitive flag and key prefix, where each entry shows its key, flags, the active versions that contain it and the roles that grant it by its exact key; the assignment, reading, expiry change and revocation of role assignments (`POST /api/user-roles`, `GET /api/user-roles/{id}`, `GET /api/user-roles`, `PATCH /api/user-roles/{id}`, `DELETE /api/user-roles/{id}`, mutations `assignUserRole`, `updateUserRole` and `revokeUserRole`, queries `userRole` and `userRoles`) on both interfaces, which take a policy version and record `iam.user_role.assigned` and, for a role that grants a wildcard or a reserved key, `iam.privileged_role.assigned`, `iam.user_role.updated` and `iam.user_role.revoked`; the validation of access for a REST request or a list of permission keys (`POST /api/access-validations`, query `validateAccess`) on both interfaces, which decides one check through the decision path and always answers 200 with a decision body (an internal failure is the deny `unavailable`), except that a `minPolicyVersion` above the current policy version is a 422; the validation of 1 to 100 such checks in one call (`POST /api/access-validations/batch`, query `validateAccessBatch`) on both interfaces, which decides each check independently through the same decision path and returns one decision per check in request order, each with its own `decisionId`, resolves each distinct credential once per batch, decides an item that cannot be read as the deny `malformed_operation` without failing the others, and refuses a batch of no check or of more than 100 with a 422 or `VALIDATION_FAILED`; the creation, reading, listing, updating and deletion of upstreams (`POST /api/upstreams`, `GET /api/upstreams/{id}`, `GET /api/upstreams`, `PATCH /api/upstreams/{id}` with `If-Match`, `DELETE /api/upstreams/{id}`, mutations `createUpstream`, `updateUpstream` and `deleteUpstream`, queries `upstream` and `upstreams`) on both interfaces, where each change is a versioned write with its `upstream/<name>` state record, its `iam.upstream.created`, `iam.upstream.updated` or `iam.upstream.deleted` event and an audit record, a deletion is refused with 409 while a route references the upstream, `RouteScopeGuard` needs `iam:route:{service}` or `iam:route:*` for the catalogue service of the upstream, and an upstream of the service `iam` or flagged `system` is refused with 409 `system_entry` and audited | `iam-domain`, `iam-application`, `iam-infrastructure` |

A crate belongs to the context named by the text its layer pattern matches in `architecture.toml` (`some-module-domain` belongs to `some-module`). A context may use itself and the shared kernel and nothing else, so adding a context changes no rule file. `cargo xtask new-context <group> <context>` creates the three crates and registers them in the workspace. The layer crates live at `crates/<group>/<context>/<layer>`; the shared kernel lives at `crates/shared/<layer>`; `service` is at `crates/service`, `test-support` at `tests/support/`, `e2e-tests` at `tests/e2e/` and `xtask` at `xtask/`.

## Request flow

A request to the REST API passes through these steps, from the socket to the database and back.

1. The router assembled by `service::http::router::assemble` receives it. Eight layers wrap every route, outermost first: sanitising of an inbound `x-request-id`, generation of the id, echo of the id on the response, the four security headers, the request span and access log, the panic catcher, the request time budget and the body limit. Because these wrap the fallbacks too, a 404, a 405, a timeout and a panic all carry the request id and the security headers and are logged.
2. The route matches a handler in the `http` module of an Application crate. The problem-aware extractors parse the path, query and JSON body and validate them. A request that cannot be parsed or validated is answered here with a problem document.
3. The handler builds a command or a query with a UUID that it generated through the `UuidGenerator` port, and dispatches it through the command bus or the query bus. The buses are ports defined in the shared Domain crate and implemented in memory in the shared Infrastructure crate. Handlers are registered explicitly in `service::bootstrap`. The health endpoint is the one handler that calls its service directly, so that a health check never depends on bus registration.
4. The use-case handler works on the aggregate and talks to the repository port. The PostgreSQL adapter in an Infrastructure crate implements the port with one checked SQL statement per method. A command changes one aggregate and returns no data.
5. After a successful save the handler publishes the domain events on the event bus. Subscribers run synchronously, in registration order, and a failing subscriber does not stop the others.
6. The handler maps the result to a response. The GraphQL route follows the same path through the same commands and queries.

The OpenAPI document and the GraphQL schema are built from the same route and type definitions that serve traffic, without any adapter, so both can be exported with no environment, database or network ([ADR 0007](adr/0007-api-contracts.md)).

## Error model

Errors have four levels, and each level converts to the next in exactly one place ([ADR 0003](adr/0003-error-model.md)):

- Domain errors are `thiserror` enums per concept and know nothing about HTTP.
- Application errors are one enum per bounded context and are the error type of that context's commands and queries.
- Bus errors wrap the application error, or report a missing handler.
- The problem is the HTTP representation: `application/problem+json` with `type`, `title`, `status` and, where it helps, `detail` and an extension member. Every 5xx problem is created in one function that logs the error chain once and returns a body without internal detail.

One table fixes the status codes (400, 404, 405, 413, 415, 422, 500 and 503) and the two problem types that carry extension members: a validation failure lists its `violations`, and a failed health check lists its `failures`. GraphQL operation errors are not problem documents; they are returned in `errors[]` with a stable `extensions.code`.

## Operational assumptions

The design relies on the following assumptions about how the service is run. They are properties of the template, not options.

- **No session or per-client state.** The service keeps no session and no per-client state between requests. Any instance can answer any request, and a resource created through one instance can be read through another. A test reads a resource through an application instance other than the one that created it.
- **PostgreSQL is the only source of truth.** The in-process cache sits behind a port and is used only by the cache health probe. No endpoint response depends on the content of the cache, so an instance restart or a cold cache changes no answer. A remote cache is an extension through the same port.
- **Domain-event delivery is at most once.** Events are published after the save succeeded and are not part of a database transaction, and no outbox ships. If a subscriber fails after the save, the request still succeeds with `201`, the failure is logged once per subscriber, and the event is not retried. A service that needs guaranteed delivery adds an outbox (see [extension seams](extension-seams.md)).
- **A proxy or load balancer sits in front of the service.** The service speaks plain HTTP. A proxy or load balancer terminates TLS, adds `Strict-Transport-Security` and cross-origin headers where needed, and limits header-read time and the number of connections, because the server has no header-read timeout and no connection limit of its own. Per-request time and body size are limited by the service itself.
- **Shutdown is bounded.** On SIGTERM or SIGINT the service stops accepting connections and drains in-flight requests for at most `SHUTDOWN_GRACE_PERIOD`. It exits with status 0 when all finished and with status 1 when the period ended with a request still open, so a cut request is visible to the platform.
- **Start-up does not wait for dependencies.** The database pool is lazy, so `serve` starts and answers `/ping` while the database is down, and `/api/health` reports the failing dependency. Migrations are a separate step, never run by `serve`.

## Run modes and socket owners

One image runs in two modes ([ADR 0015](adr/0015-iam-is-the-api-gateway-split-planes-one-image-two-run-modes.md)): `service serve` is the control plane (`iam-control`, with PostgreSQL) and `service gateway` is the data plane. The gateway opens four listeners and never a PostgreSQL pool: the public listener on `GATEWAY_LISTEN` (TLS 1.3 and 1.2, ALPN `h2` and `http/1.1`, a certificate that is replaced without a restart; its requests go through the pipeline of Story 10.2: one snapshot load and the freshness check (503 `iam_stale`), the route match on host, method and the normalised path (400 for a path that breaks the path rule, 404 without a route), authentication from the bearer token or the `__Host-auth_token` cookie (401 with `WWW-Authenticate: Bearer`), authorization from the snapshot (403 with a reason code, 503 when it cannot be decided) and the hand-over to the forwarder, which answers 502 until Story 10.3), the internal listener on `GATEWAY_INTERNAL_LISTEN` for `iam-control` and the gateway pods, the decision listener on `GATEWAY_DECISION_LISTEN` for the microservices that check their own internal actions (the contract of `iam-control` for `POST /api/access-validations`, `POST /api/access-validations/batch`, `POST /api/token-resolutions` and `POST /api/graphql` with only `validateAccess`, `validateAccessBatch` and `resolveToken`, decided from the replicated snapshot: a stale snapshot, a `minPolicyVersion` the pod has not applied and a GraphQL document check, for which the snapshot carries no return types yet, are HTTP 200 with `deny` and `unavailable`), and the probe listener on `GATEWAY_PROBE_LISTEN` with `/ping`. `service check-config --mode gateway` and `service healthcheck --mode gateway` work on the gateway; without `--mode` both keep the behaviour of `serve`.

Sockets are opened by a short list of owners, each with an item-level `#[expect(clippy::disallowed_methods, reason = ...)]`; code anywhere else cannot bind or connect (`clippy.toml`). The socket-owner rule list:

| Owner | What it opens |
| --- | --- |
| `crates/service/src/command/serve.rs` | the listening socket of `service serve` |
| `crates/service/src/command/gateway.rs` | the three listening sockets of `service gateway` (`bind`) |
| `crates/service/src/command/healthcheck.rs` | the loopback connection of the liveness probe |
| integration tests (`crates/service/tests/integration/`) | the sockets their subject talks to |

## IAM events on `iam.events.v1`

Every administrative change of IAM writes its domain events into the transactional outbox in the same transaction as the change, and the outbox relay ([ADR 0017](adr/0017-policy-state-topic-transactional-outbox-and-fenced-relay.md)) publishes them to the topic named by `EVENTS_TOPIC` (`iam.events.v1`). The topic is retention-based and has one record per event, keyed by the aggregate id, so the events of one aggregate stay in order. IAM produces to two topics only, the state topic `iam.policy.state.v1` and this one; it writes into no topic of Notification service and never publishes `iam.authorization_cache.flushed`.

The record value is the envelope `{id, type, occurredAt, data}`, at most 64 KiB:

- `id` is a UUID v7, the key that a consumer de-duplicates by, and `type` is a dotted lower-case name that starts with `iam.`.
- `occurredAt` is an RFC 3339 UTC time with microseconds.
- `data` starts with the common fields `aggregateId`, `entityVersion` (null when the aggregate is not versioned), `actor` and `policyVersion` (the version of the committing transaction), followed by the fields of the event.

Notification service tails the topic with its own consumer and selects events by `type`. Four types are meant for it:

| Type | Fields of `data` after the common ones |
| --- | --- |
| `iam.user_role.assigned` | `userRoleId`, `subject {kind, id}`, `userId` (a user subject only), `roleId`, `roleName`, `scope` (`global` or `project:<uuid>`), `expiresAt` |
| `iam.user_role.revoked` | `userRoleId`, `subject {kind, id}`, `userId` (a user subject only), `roleId`, `roleName`, `scope`, `cause` |
| `iam.privileged_role.assigned` | the fields of `iam.user_role.assigned` and `privilegedKeys`, the wildcards and reserved keys of the role |
| `iam.permissions.orphaned` | `specId`, `service`, `orphanedKeys`, `affectedRoleIds` |

The end-to-end suite gives every scenario a topic of its own on the compose broker, because the scenarios run concurrently and one shared topic would mix their events; each scenario points `EVENTS_TOPIC` at it, runs the relay on its own database and reads the topic back.

## Quality gates and the decision records

The architecture is held in place by gates that fail: layer and context isolation, a lint policy with complexity limits, 100% line and function coverage, mutation testing, contract snapshots and a protected-configuration guard. Run them together with `make ci`; the verification section of `AGENTS.md` lists them in order, and [`docs/make-targets.md`](make-targets.md) describes each one. The decisions behind the structure are written down as twelve records, indexed in the [decision record index](adr/README.md).
