# Research: IAM as the VilnaCRM API Gateway

| Field | Value |
| --- | --- |
| Bundle | `specs/8-iam-scaffolding-and-spikes/` |
| Issue | `#8` "Scaffold the IAM context and run the phase-0 spikes" (VilnaCRM-Org/api-gateway-service); one pull request delivers all 16 epics (owner decision, 2026-11-22) |
| Date | 2026-11-22 (derived from the master plan of 2026-11-21) |
| Status | Planning bundle of issue #8 (all 16 epics, one pull request). Master draft: Revised for the gateway design and for the owner decisions of 2026-11-21 (D1, D2, D3, D4, D6 part, D7, D8, D9, D13, D14a, D14b, D15) |
| Inputs | Miro board "C4 Architectural Diagrams" (IAM frames, 2022-02-10); reconnaissance of this checkout; read-only reconnaissance of the VilnaCRM `user-service`, `notification-service`, `core-service`, `api-gateway-infrastructure` and the infrastructure repositories; a review of authorization domain practice (scoped RBAC, token handling, audit logging, OWASP API risks); seven research notes on the gateway redesign (data-plane options, Kafka replication, cache topology, capacity model, Kubernetes, bottlenecks of the earlier draft, organisation reconnaissance), digested in sections 14 to 18; the owner decisions, recorded in section 19; the master plan `specs/0-iam-authorization-service/` (iam-service checkout, 2026-11-21, placeholder issue 0) and the Epic 1 bundle of this directory (2026-11-22) |

This document records what exists today, what the target architecture asks for, what the surrounding services actually do, which options were evaluated and why the gateway design was chosen, which risks remain, and how every open question was resolved or is still open. The product brief, the PRD and the architecture build on it.

## 0. What Changed in This Revision

The first version of this bundle described IAM as a decision service that a separate API gateway calls once per request. The owner replaced that premise. IAM is now the API gateway itself: it authenticates, authorizes and proxies every request, and it also exposes the IAM management API. The consequences for the research are summarised here so that a reader of the older material can see what still holds.

| Topic | Status | Where |
| --- | --- | --- |
| Template analysis (layers, allow-lists, reusable parts, gates) | Still valid, with the new needs added | Sections 1 and 4 |
| Miro board analysis, names adapted to Rust | Still valid | Section 2 |
| Facts about User service, Notification service and the other services | Still valid; the Kafka, platform and gateway-plan facts are added | Section 3 and sections 15 and 18 |
| Choice of PostgreSQL over DynamoDB and DAX | Still valid | Section 5 |
| In-process moka cache filled on a miss, `LISTEN/NOTIFY` invalidation, epoch poll, tombstones and floors, SQS for events, access-decision log in PostgreSQL | **Superseded** by a replicated in-process snapshot fed from one ordered Kafka topic, Kafka for events, and Loki for the access log | Sections 5, 8, 15 and 16 |
| Token validation (offline RS256, no token persistence) | Still valid; the session-liveness call to User service is removed and revocations arrive through Kafka | Section 6 |
| Authorization model (scoped RBAC, key formats, wildcards, guards) | Still valid | Section 7 |
| Latency, throughput and availability proposals for a decision service (p95 3 ms, p99 10 ms, 2,000 checks per second per instance) | **Superseded** by gateway figures, all labelled ESTIMATE or target until measured | Section 17 |
| Allow-list change | Larger: the gateway needs an HTTP stack, a Kafka client, TLS, Valkey and Kubernetes access | Section 9 |
| Placement | A new platform: AWS EKS, Strimzi Kafka, Valkey, Loki; none of them exists in the organisation today | Section 18 |

> Assumption: The issue is #8 of VilnaCRM-Org/api-gateway-service. The owner decided on 2026-11-22 that all sixteen epics ship in one pull request for this issue, so the bundle directory is `specs/8-iam-scaffolding-and-spikes/` and the commit convention in `architecture.md` uses the literal `(#8)`. This file was derived on 2026-11-22 from the master research of `specs/0-iam-authorization-service/` (placeholder issue 0, iam-service checkout), with the target-repository facts of the earlier Epic 1 bundle of this directory in section 1.

> Assumption: The profile `.claude/rust-sdlc.yml` exists in `api-gateway-service` and maps every `make.*` key to the target of the same name with underscores replaced by hyphens; the ten dispatch keys are listed only in `## Constraints` of `architecture.md`. `make.bench_spikes` (added by Story 1.6 in `make/service.mk`) and `make.bats` (the existing template target `bats`) are not profile keys and resolve by the same rule.

> Assumption: Every performance figure in this bundle is an ESTIMATE, a target or a CONFIG value until a measurement replaces it. Nothing in the gateway design has been measured on VilnaCRM code or hardware. A figure tagged SOURCE is a published number carried from the cited note, which is not a measurement of this service either.

> Owner decision (2026-11-22): all 16 epics (127 stories) ship in one pull request for issue #8, replacing the per-epic method under which the earlier bundle of this directory planned Epic 1 only. Story 1.1 runs first and alone; its code is already in the working tree of branch `feat/8-iam-scaffolding-and-spikes`, uncommitted (section 1.6).

## 1. Current State of the Target Repository

### 1.1 What the repository is

`api-gateway-service` (VilnaCRM-Org/api-gateway-service, default branch `main`) is a copy of `VilnaCRM-Org/rust-service-template` with the service identity set to "VilnaCRM API Gateway" (profile `project.description`). It is a Rust 1.99.1 workspace (edition 2024) with one crate per bounded-context layer, named `<context>-{domain,application,infrastructure}` and placed at `crates/<group>/<context>/<layer>`. The rust-backend-sdlc profile `.claude/rust-sdlc.yml` exists (schema version 1) and maps every gate key to the template target of the same name.

The workspace has thirteen members:

| Members | Purpose |
| --- | --- |
| `crates/company-subdomain/some-module/{domain,application,infrastructure}` | The example context (`ExampleApiResource`), the reference for how a context is built |
| `crates/internal/health-check/{domain,application,infrastructure}` | Health service and probes for PostgreSQL, the cache and SQS |
| `crates/shared/{domain,application,infrastructure}` | Shared kernel: buses, ports (`Cache`, `Clock`, `UuidGenerator`), problem documents, extractors, `MokaCache`, the SQS client factory, the migrator |
| `crates/service` | Composition root, library plus the `service` binary |
| `tests/e2e`, `tests/support`, `xtask` | Gherkin end-to-end tests, test fakes and fixtures, architecture and scaffolding tooling |

No IAM code exists on `main` (Story 1.1 is in the working tree, section 1.6). No member path starts with `crates/authorization/iam/`, so the story-1 rule applies: Story 1.1 is "Scaffold authorization/iam" with the checklist C1 to C12. The scaffolder (`make new-context group=<g> context=<c>`, `xtask/src/scaffold/`) accepts names matching `^[a-z][a-z0-9]*(-[a-z0-9]+)*$` and refuses the reserved context names `shared`, `service`, `xtask`, `test-support` and `e2e-tests`; `iam` is not reserved.

### 1.2 Layer rules that shape the plan

`architecture.toml` (protected) defines allow-lists per layer, checked by `make.architecture`:

| Layer | Third-party crates allowed | Consequence for Epic 1 |
| --- | --- | --- |
| domain | `async-trait`, `thiserror`, `uuid` (dev: `proptest`, `rstest`, `tokio`) | The policy-epoch value objects, the port and the error enum need nothing else |
| application | `async-graphql`, `async-trait`, `axum`, `futures-util`, `humantime`, `serde`, `thiserror`, `tokio`, `tracing`, `utoipa`, `utoipa-axum`, `uuid`, `validator` (dev: `http-body-util`, `proptest`, `rstest`, `serde_json`, `tokio`, `tower`) | `IamState`, the router, the GraphQL roots and the query handler fit |
| infrastructure | `async-trait`, `aws-config`, `aws-sdk-sqs`, `moka`, `sqlx`, `thiserror`, `tracing`, `uuid` (dev: `aws-smithy-mocks`, `rstest`, `tokio`) | `PgPolicyEpochRepository` fits; no Kafka, HTTP or JWT crate is allowed yet |
| composition root (`service`) | any (`["*"]`) | The spike dev-dependencies (`krafka`, `jsonwebtoken`, `criterion`, `aws-lc-rs`) need no allow-list change |
| test-support | `async-trait`, `fake`, `rand`, `tracing`, `uuid` | `FakePolicyEpochRepository` fits |

`[contexts]` lists only `shared`. A new context may depend on itself and on `shared` without any rule change.

Other bars every story inherits: 100% line and function coverage (G14); zero surviving mutants (G15); cognitive complexity at most 8, at most 50 lines and 5 arguments per function, nesting at most 5 (G3); clippy pedantic, nursery and restriction lints with `-D warnings`; `#[allow]` banned in favour of `#[expect(..., reason)]`; no `mod.rs`; `SystemTime::now`, `Instant::now`, `Uuid::new_v4`, `Uuid::now_v7`, `std::env::var` and socket binds banned outside the composition root; Spectral with zero findings; OpenAPI and GraphQL breaking-change diffs; secrets and image scans; documentation-drift checks.

### 1.3 What is reusable as shipped

| Template element | Reuse in Epic 1 |
| --- | --- |
| `InMemoryQueryBus` with typed handlers | `GetPolicyEpochQueryHandler` is registered on it |
| `Problem` and its constructors | `IamError` converts into it |
| Extractors `ApiJson`, `ApiPath`, `ValidatedJson`, `ValidatedQuery` | The extractor-check test of `http/handler.rs` |
| PostgreSQL through `sqlx`, `migrations/`, `.sqlx/`, `make.create_migration`, `make.setup_test_db`, `make.sqlx_prepare`, `make.validate_sqlx_metadata` | `iam_policy_epoch` and its repository |
| `utoipa` generation, SDL export, contract snapshots and pinning tests | Regenerated, unchanged (no IAM operation yet) |
| Gherkin e2e world (`tests/e2e/world.rs`, `steps.rs`) | The IAM smoke scenario |

### 1.4 What Epic 1 must build (the first slice of the whole product)

The three IAM crates and their first slice; the composition-root wiring; a compose Kafka broker; the krafka spike tests and the criterion benches in `crates/service`; the seam check; the spike report, ADRs 0013, 0014 and 0026; and the mutation-gate changes of Story 1.8.

### 1.5 Facts re-checked in the target repository (2026-11-22)

| Fact | Value | Bearing |
| --- | --- | --- |
| Make targets | Every target named by the Epic 1 criteria exists in the `Makefile` and in `docs/make-targets.md`, except `bench-spikes`, which Story 1.6 adds to `make/service.mk` | `make.bench_spikes` is service-owned |
| Profile keys | `.claude/rust-sdlc.yml` lists every key Epic 1 names except `make.bench_spikes` (new) and `make.bats` (the target `bats` exists, gate G16; the profile has only `make.ci_cli`, whose stage runs `bats`) | Recorded in `epics.md` and `run-summary.md` |
| `make ci` stages | Seven: `ci-preflight`, `ci-static-analysis`, `ci-tests`, `ci-contracts`, `ci-mutation`, `ci-delivery`, `ci-cli` (Bats) | Story 1.1 C12 runs the first six; Bats runs in CI and in Story 1.8 |
| Backing services for tests | `DEPS ?= database localstack`; `integration-tests`, `tests-with-coverage`, `e2e-tests` and `mutation-tests-diff` depend on `ensure-deps`; the `Makefile` loads `make/service.mk` with `-include` after that default | Story 1.2 can add `kafka` through `make/service.mk` without editing the template `Makefile` |
| `base_ref` | `Makefile` default `origin/main`; profile `ci.base_ref: origin/main` | Stories pass `base_ref=main` as written; both resolve on a clone with a local `main` |
| Protected files | `protected-config.toml` lists `architecture.toml`, `deny.toml`, `clippy.toml`, `.cargo/mutants.toml`, `make/gates.mk`, `scripts/check-invariants.sh`, `scripts/mutation-diff.sh` and others, the directories `xtask/src/arch/`, `xtask/src/config_guard/`, `xtask/tests/`, `tests/CLI/bats/`, and the `workspace.lints` table of `Cargo.toml`; label `approved-config-change` | Epic 1 changes none of them unless the Story 1.8 resize is approved |
| `deny.toml` | `openssl-sys` and `native-tls` banned; `unmaintained = "all"`; licences MIT, Apache-2.0, BSD, ISC, Unicode-3.0, Zlib, CDLA-Permissive-2.0; time-boxed ignores for RUSTSEC-2026-0543 (chrono via aws-smithy test utilities) and RUSTSEC-2026-0542 (humantime), both accepted 2026-11-21 until 2027-02-21; `[bans.workspace-dependencies]` denies duplicate and unused workspace entries | Spike crates must be declared once in `[workspace.dependencies]`; krafka is MIT OR Apache-2.0; criterion's transitive tree must pass `unmaintained = "all"` |
| `aws-lc-rs` | Already in `Cargo.lock` (1.19.0, with `aws-lc-sys` 0.47.0) | The `jsonwebtoken` `aws_lc_rs` backend adds no new TLS stack |
| `.templatesyncignore` | Lists `Cargo.toml`, `Cargo.lock`, `.sqlx/`, `migrations/`, contract snapshots, `workspace.dsl`, `specs/`, `docs/requests.http`, `docs/adr/`, `crates/service/Cargo.toml`, `bootstrap.rs`, `bootstrap/`, `cli.rs`, `config.rs`, `http.rs`, `http/router/tests.rs`, `openapi.rs`, `openapi/`, `graphql/schema.rs`, `graphql/schema/`, `tests/integration/{bootstrap,migrate,serve,panic}.rs`, `tests/support/`, `tests/e2e/` and others; it does not list `docker-compose.yml`, `crates/service/tests/integration/main.rs`, `.github/workflows/tests.yml`, `docs/architecture.md` or `docs/operations.md` | Stories 1.2 and 1.8 add the first three; the two documentation files are a template-sync risk (readiness section 6) |
| Mutation matrix | `scripts/ci/mutation-plan.sh`: `per_shard=150`, `max_shards=8`; `tests.yml` mutation shard job `timeout-minutes: 45`, pull-request step `make mutation-tests-diff`, push step `make mutation-tests` | Story 1.8 premises hold |
| `Adapters { .. }` literals | `bootstrap/tests.rs`, `http/router/tests.rs`, `tests/integration/panic.rs` (plus the definition in `bootstrap.rs`) | Story 1.1 C9 premises hold |
| Local ports | Host ports 8080, 8081 and 18081 are taken on the developer machine; `.env` sets `APP_PORT=8081`, `STRUCTURIZR_PORT=8080`; the `Makefile` sets `LOAD_TEST_APP_PORT ?= 18081` | Local runs set `APP_PORT=28081` and `STRUCTURIZR_PORT=28080`; the isolated load-test stack also needs a free `LOAD_TEST_APP_PORT` |

### 1.6 Story 1.1 in the working tree (2026-11-22)

Story 1.1 ("Scaffold authorization/iam") is implemented in the working tree of branch `feat/8-iam-scaffolding-and-spikes` and not yet committed: `crates/authorization/` (the three IAM crates with the policy-epoch slice), the migration pair `migrations/20261122000224_create_iam_policy_epoch.{up,down}.sql` with its `.sqlx/` query file, ADRs `docs/adr/0013-iam-bounded-context.md` and `docs/adr/0014-postgresql-and-replicated-policy-snapshot.md`, `features/iam.feature` with `tests/e2e/steps/iam.rs`, `tests/support/src/policy_epoch.rs` with its sibling directory, and the wiring in `Cargo.toml`, `crates/service/{Cargo.toml,src/bootstrap.rs,src/http.rs,src/openapi.rs}`, the three `Adapters { .. }` literals, `workspace.dsl`, `docs/architecture.md` and `docs/requests.http`. As Story 1.1 prescribes, `graphql/schema.rs` is unchanged: the merge of `IamQuery` and `IamMutation`, the `.data(iam_state)` call, the `iam` tag and the `bearerAuth` scheme wait for Story 2.8. The bundle text of Epic 1 is kept verbatim so that it keeps matching this code.

### 1.7 What the template offers the whole product

| Template element | Reuse in IAM |
| --- | --- |
| Command and query buses (`InMemoryCommandBus`, `InMemoryQueryBus`) with typed handlers | Every board handler becomes a registered handler; REST and GraphQL dispatch through the same buses, which gives the required interface parity for free |
| `Problem` (`application/problem+json`) and `problem_to_error` for GraphQL | Error model for all IAM endpoints; 401 and 403 mappings must be added (GraphQL codes `UNAUTHENTICATED` and `FORBIDDEN`) |
| Extractors `ApiJson`, `ApiPath`, `ValidatedJson`, `ValidatedQuery` with `deny_unknown_fields` | Request validation for every IAM DTO |
| `utoipa` OpenAPI generation, SDL export, contract snapshots and their pinning tests | Contract artefacts for IAM's REST and GraphQL surfaces |
| PostgreSQL through `sqlx` with compile-time checked queries, `migrations/`, `.sqlx/`, `make.setup_test_db`, `make.sqlx_prepare` | System of record for IAM (section 5) |
| `MokaCache` and moka 0.12 (`future` feature, per-entry expiry) | Per-pod memos only (token resolutions, parsed GraphQL documents). Policy is not held in moka: it lives in a replicated snapshot (section 16) |
| `sqs_client(&SqsSettings)` factory and `SqsProbe` | Not used by IAM: events and revocations travel over Kafka (section 15). The shipped probe stays as the template has it |
| `InMemoryEventBus` with synchronous subscribers | In-process reactions; not used for anything that must survive a crash (it is at most once) |
| Request id, security headers, `TraceLayer`, timeout, panic catcher, body limit | Kept unchanged; the authentication layer is inserted inside them as `docs/extension-seams.md` prescribes |
| `HealthService` with `HealthProbe` ports | Extended with probes for Kafka and the access-log store (control plane); the gateway has its own startup, readiness and liveness probes |
| CLI (`serve`, `migrate`, `check-config`, `openapi-export`, `graphql-export`, `healthcheck`) | Extended with a `gateway` run mode and an `iam-bootstrap` subcommand; `serve` becomes the control plane |
| `tokio` in the application layer | Task loops (timers, channels, back-off) live in `iam-application`, where `tokio` is allowed. `iam-infrastructure` keeps `tokio` as a dev dependency only: hyper-util's executor, krafka and redis need it transitively, and every timer, timeout and breaker runs in the application layer around the port calls (section 9) |

### 1.8 What the whole product must build

- The gateway data plane: TLS termination, an HTTP/1.1 and HTTP/2 proxy with a pooled upstream client, route matching, REST and GraphQL authorization from an in-memory snapshot, WebSocket, SSE and GraphQL subscription handling, rate limiting and body and timeout limits.
- An authentication layer for IAM's own management API and identity propagation into GraphQL context data.
- A Kafka client and the replication pipeline: a transactional outbox, a fenced relay, a group-less tail with bootstrap, digest and freshness proof, and a consumer for User service events.
- A typed policy snapshot with atomic publication (the shared `Cache` port is bytes-only and has no delete, and policy is not a cache).
- A JWT verifier and the revocation state.
- Adapters for Valkey (rate limits), Loki (access-log push and query) and the Kubernetes EndpointSlice watch.
- Reference Kubernetes manifests and platform resources (Strimzi, Valkey, Loki, Grafana Alloy), which no repository of the organisation has today.

## 2. Target Architecture from the Miro Board

The board dates from February 2022. Its technology labels are outdated: IAM is now built in Rust from the service template, not in Go; User service is a PHP/Symfony service on MongoDB, not Go on MariaDB as drawn; Notification service is a Rust service fed by Kafka. The structure and the names on the board remain the owner's target.

### 2.1 System context

A customer uses the public Website and the protected CRM front end. Both call the API Gateway (load balancing, logging, tracing, request limiting), which routes to IAM, User service, Core service (CRM, Project), Payment, Analytics, Notification, Webhook, Integration and IP telephony services. IAM "provides auth cache and authorization management, security and access logs" and links directly to User service. User service stores users, profiles and settings and owns authentication (registration, sign-in, OAuth, 2FA, cookie authentication). IAM does not authenticate users.

### 2.2 IAM container diagram

- The API Gateway calls the IAM service, which "provides authorization for REST API / GraphQL".
- Database (board label DynamoDB): "stores user roles, permissions, openapi specs and graphql docs".
- Cache (board label DAX): "stores authorization data".
- Invalidation cache workers (a separate container): "recalculating and invalidation the cache"; IAM service calls the workers, which use the Cache and the Database.
- Other microservices call IAM synchronously over REST and GraphQL.
- IAM sends asynchronous messages to Notification service through a message broker.

### 2.3 IAM component diagram (one "IAM bounded context")

| Layer | Component | Relationship |
| --- | --- | --- |
| Application | `ValidateAccessQueryHandler` | creates `AccessToken` |
| Application | `LoadGraphQLCommandHandler` | creates `GraphQLSpec` |
| Application | `GraphQLCreatePermissionsCommandHandler` | creates `GraphQLPermission` |
| Application | `GraphQLGetPermissionsQueryHandler` | loads `GraphQLPermission` |
| Application | CRUD handlers | CRUD on `UserRole` and `Role`; read `UserRolePermission` |
| Domain | `AccessToken` (value object), `GraphQLSpec`, `GraphQLPermission`, `UserRole`, `Role` (entities, the last three dispatch change events), `UserRolePermission` (computed read model) | |
| Infrastructure | `TokenRepository` | saves and loads `AccessToken` using the Cache, the Database and `UserAPIClient` |
| Infrastructure | `UserAPIClient` | calls User service |
| Infrastructure | `GraphQLSpecRepository`, `GraphQLPermissionRepository`, `UserRoleRepository`, `RoleRepository` | Database |
| Infrastructure | `InvalidationCacheWorker` | Database, `UserRolePermission`, Message Broker |
| External | Database (DynamoDB): "access tokens, roles, permissions, openapi and graphql spec"; Cache (DAX): "confirmation token, roles and permissions"; Message Broker (AWS SQS): "entity events" | |

### 2.4 Owner decisions layered on the board

- Scope is everything in the system context: REST/OpenAPI specifications and REST permissions symmetric to the GraphQL ones, and security and access logs, neither of which has a component on the board.
- Binding API rule: every IAM capability is exposed over both REST and GraphQL with equivalent behaviour, served by the same command and query handlers; both contract snapshots are regenerated in every story that changes the surface; reviewers flag any capability exposed on one interface only. The board already shows IAM serving both interfaces ("Other microservices -> IAM service: sync/rest api and graphql"); the owner made full capability parity binding, so this is an owner decision, not a deviation from the board.
- The datastore is chosen by evaluation (section 5). The owner later decided that IAM is the API gateway itself (sections 0 and 14 to 20).

### 2.5 Board names adapted to Rust

Rust type names follow the API guidelines, which treat an acronym as one word (`GraphQl`, `OpenApi`, `UserApi`). Three further rules apply: acronyms are cased as one word; handler names are verb-first (`CreateGraphQlPermissionsCommandHandler` for the board's `GraphQLCreatePermissionsCommandHandler`, `GetGraphQlPermissionsQueryHandler` for `GraphQLGetPermissionsQueryHandler`), matching the template's `CreateExampleApiResourceCommandHandler` form; and `LoadGraphQLCommandHandler` gains the `Spec` suffix (`LoadGraphQlSpecCommandHandler`) for symmetry with `LoadOpenApiSpecCommandHandler`. ADR 0013 records these rules. Every other board name is kept as drawn.

| Board name | Rust name | Kind |
| --- | --- | --- |
| `ValidateAccessQueryHandler` | `ValidateAccessQueryHandler` (plus `ValidateAccessBatchQueryHandler`) | query handler |
| `AccessToken` | `AccessToken` | domain value object |
| `LoadGraphQLCommandHandler` | `LoadGraphQlSpecCommandHandler` | command handler |
| `GraphQLCreatePermissionsCommandHandler` | `CreateGraphQlPermissionsCommandHandler` | command handler |
| `GraphQLGetPermissionsQueryHandler` | `GetGraphQlPermissionsQueryHandler` | query handler |
| CRUD handlers for `Role` | `CreateRoleCommandHandler`, `UpdateRoleCommandHandler`, `DeleteRoleCommandHandler`, `SetRolePermissionsCommandHandler`, `GetRoleQueryHandler`, `ListRolesQueryHandler` | handlers |
| CRUD handlers for `UserRole` | `AssignUserRoleCommandHandler`, `UpdateUserRoleCommandHandler`, `RevokeUserRoleCommandHandler`, `GetUserRoleQueryHandler`, `ListUserRolesQueryHandler` | handlers |
| read of `UserRolePermission` | `GetUserRolePermissionsQueryHandler` | query handler |
| `GraphQLSpec`, `GraphQLPermission`, `UserRole`, `Role`, `UserRolePermission` | `GraphQlSpec`, `GraphQlPermission`, `UserRole`, `Role`, `UserRolePermission` | aggregates and read model |
| `TokenRepository` | `TokenRepository` port; `CachingTokenRepository` composing `AccessTokenVerifier`, `TokenMemo` and `RevocationView` (no database and no User service call on the warm path) | port and adapter |
| `UserAPIClient` | Removed in the gateway design: revocations arrive as replicated state (deviation 9) | removed |
| `GraphQLSpecRepository`, `GraphQLPermissionRepository`, `UserRoleRepository`, `RoleRepository` | same names with `GraphQl`; PostgreSQL adapters prefixed `Pg` | ports and adapters |
| `InvalidationCacheWorker` | No cache to invalidate. Its responsibilities become `OutboxRelay`, `UserEventConsumer` and the anti-entropy and republish job in the control plane (deviation 3) | background tasks |

Components added for the owner's scope and for correctness (the board lacks them):

| New component | Purpose |
| --- | --- |
| `OpenApiSpec`, `RestPermission`, `LoadOpenApiSpecCommandHandler`, `CreateRestPermissionsCommandHandler`, `GetRestPermissionsQueryHandler`, `OpenApiSpecRepository`, `RestPermissionRepository` | REST/OpenAPI symmetry with the GraphQL components |
| `AccessLogSink` port with `StdoutAccessLogSink` and `LokiPushAccessLogSink`, `AccessLogQuery` port with `LokiAccessLogQuery`, `GetAccessDecisionsQueryHandler` | Access log in Loki: write and query (the earlier `AccessDecision` entity, buffered writer and partitioned repository are removed) |
| `SecurityAuditEvent`, `SecurityAuditLog` port with `PgSecurityAuditLog`, `BufferedRejectedAttemptLog`, `GetSecurityAuditEventsQueryHandler`, `VerifySecurityAuditChainQueryHandler` | Security audit log: write, query and integrity check |
| `PolicyView` port with `ArcSwapPolicySnapshot`, `RevocationView`, `TokenMemo` and `DocumentCache` ports, `PolicyEpochRepository` | The replicated snapshot, the revocation state and the per-pod memos (the earlier `AuthorizationCache`, `MokaAuthorizationCache` and `RevocationSnapshot` are removed) |
| `IamUnitOfWork` port with `PgIamUnitOfWork`, `OutboxRelay`, `PolicyLogProducer`, `PolicyLogTail`, `PolicyLogProbe` | Reliable delivery of state and events to Kafka, and the group-less tail with the freshness probe |
| `UserEventConsumer`, `RevocationRepository` | Consumption of User service events from Kafka (control plane) and storage of revocation state |
| `UpstreamForwarder`, `EndpointWatch`, `RateLimitStore`, `LocalRateLimiter`, the `Upstream`, `Route` and `RatePolicy` aggregates and their repositories | The gateway data plane: forwarding, endpoint discovery, rate limiting and routing configuration |
| `ResolveTokenQueryHandler`, `ResyncPolicyCommandHandler`, `BootstrapIamCommandHandler` | Token resolution for other services, republishing the full policy state (replaces the cache flush), first-administrator bootstrap |

## 3. Facts About the Surrounding Services

Tags: VERIFIED means read in the named repository file; INFERRED means concluded from code but not confirmed.

### 3.1 User service (`user-service`, PHP/Symfony on MongoDB)

| Fact | Tag |
| --- | --- |
| First-party access tokens are JWTs signed RS256; the validator rejects any other algorithm (`AccessTokenValidator.php`, `AuthTokenFactory.php`) | VERIFIED |
| Claims: `sub` (user UUID v7), `iss`, `aud`, `exp`, `iat`, `nbf`, `jti` (UUID), `sid` (session id), `roles`; end users always get `roles: ["ROLE_USER"]` | VERIFIED |
| Expected `iss` is `vilnacrm-user-service` (`JWT_ISSUER`), expected `aud` is `vilnacrm-api` (`JWT_AUDIENCE`) | VERIFIED |
| A token carrying `roles` must also carry `sid`; a missing `roles` claim defaults to `ROLE_USER` | VERIFIED |
| Access-token lifetime is 900 seconds; refresh tokens are opaque, 32 random bytes, rotated through `POST /api/token`, lifetime one month | VERIFIED |
| Transport is `Authorization: Bearer` or the cookie `__Host-auth_token` | VERIFIED |
| Service tokens use the same JWT shape with `roles: ["ROLE_SERVICE"]` and a non-UUID `sub`; their session is not checked | VERIFIED |
| How production `ROLE_SERVICE` tokens are minted and rotated is not visible; only a load-test script signs them | INFERRED |
| League OAuth2 server tokens are signed with the same key but carry `aud = client_id` and no `iss` or `roles`; no authenticator accepts them on the resource API | VERIFIED (shape), INFERRED (not accepted) |
| There is no JWKS endpoint, no `kid` header, no RFC 7662 introspection endpoint, no `/userinfo` and no OIDC `id_token`; a single PEM key pair signs everything | VERIFIED |
| Signature validity is not sufficient: User service checks the `sid` session in its own database on every request, so sign-out and theft detection invalidate unexpired JWTs only inside User service | VERIFIED |
| Users have no role or permission fields; roles exist only as the hard-coded token claim and inline API Platform expressions | VERIFIED |
| `GET /api/users/{id}` is allowed only for the user's own id; `ROLE_SERVICE` cannot read arbitrary users; no service-readable lookup or introspection endpoint exists | INFERRED |
| Domain events travel over SQS through Symfony Messenger to one shared queue `domain-events`, as `DomainEventEnvelope` JSON with `eventClass` (a PHP class name), `body`, `eventId` and `occurredOn` | VERIFIED |
| Event names are dotted lower case: `user.session.revoked` {userId, sessionId, reason}, `user.all_sessions_revoked` {userId, reason, revokedCount}, `user.deleted` {userId, email}, `user.refresh_token_theft_detected`, `user.signed_in`, `user.updated` | VERIFIED |
| A second consumer on the shared `domain-events` queue would steal messages from User service's own consumers | INFERRED |
| User service has no Kafka transport and publishes none of its events to Kafka; no PHP service of the organisation produces to Kafka | VERIFIED (messenger configuration read in full), search-limited for other repositories |

### 3.2 Other services

| Fact | Tag |
| --- | --- |
| Notification service is a Rust service that reads one Kafka topic and expects `{id (UUID), type, occurredAt (RFC 3339 UTC), data}` with `type` matching `^[a-z][a-z0-9]*([._-][a-z0-9]+)*$`, at most 64 KiB, delivered at least once with de-duplication by `id`; SQS is kept only as an unused probe there | VERIFIED |
| Notification service has no subscriber authorization and plans to use "a token from the user service" later, which makes it a future IAM caller | VERIFIED |
| `api-gateway-infrastructure` is an unmodified Pulumi template; no gateway routes, authorizers or rate limiting exist. The organisation's own plan was AWS API Gateway REST with a WAF and an internal ALB (issues #2 and #30, PR #35), which IAM as the gateway replaces | VERIFIED |
| Core service has no authentication or authorization configuration | VERIFIED |
| The only deployed edge component is a public ALB in front of User service on AWS ECS Fargate in `eu-central-1`; nothing runs on Kubernetes | VERIFIED |

### 3.3 Consequences for the design

1. The gateway can validate user tokens offline (RS256, fixed issuer and audience, configured public keys) but cannot see session revocation offline. User service checks the `sid` session in its database on every request, so a gateway that verifies only the signature is weaker than User service for the same token. Revocations must reach the gateway as replicated state, which needs User service to publish them to Kafka (owner decision D1).
2. The earlier `UserApiClient` liveness call is removed: it would put User service on the request path and grow with the fleet.
3. IAM must not consume the shared `domain-events` queue. It needs the Kafka topic that User service must add.
4. Roles and permissions are owned entirely by IAM; nothing in User service conflicts with that.
5. The gateway is this repository's product, not separate work outside it: IAM replaces the organisation's planned managed gateway. Core service has no authentication, so the gateway is its only enforcement point.
6. Three token lifetimes live in User service's `.env` (900 s first-party, 3,600 s Lexik default, `PT1H` League OAuth2). The gateway treats 900 s as the first-party lifetime (open decision D12).
7. No JWKS and no `kid`: the gateway holds a configured key list and tries each key during a rotation (open decision D11).

## 4. Surface This Plan Touches in the Repository

| Area | Change |
| --- | --- |
| New crates | `crates/authorization/iam/{domain,application,infrastructure}` (packages `iam-domain`, `iam-application`, `iam-infrastructure`), scaffolded with the template's context generator. The gateway code lives as modules inside these crates (section 20, D19 default) |
| Workspace | `[workspace].members`, `[workspace.dependencies]` path entries at first use |
| Run modes | One image, two Deployments: `service gateway` (data plane, `iam-gateway`) and `service serve` (control plane, `iam-control`), plus the `iam-migrate` and `iam-bootstrap` jobs. There is no `worker` subcommand |
| Architecture model | `workspace.dsl` components and relationships for the new crates, the Customer person, the User service, the Notification service, Kafka, Valkey, Loki, the upstream services and the changed Database container |
| Persistence | New reversible migration pairs under `migrations/`; regenerated `.sqlx/` metadata. PostgreSQL is used by the control plane only; gateway pods hold no database connection |
| Composition root | `crates/service`: `Cargo.toml`, `bootstrap.rs` (adapters, handlers, subscribers, state, GraphQL data), `http.rs`, `openapi.rs`, `graphql/schema.rs`, `http/router.rs` and `graphql/handler.rs` (authentication seam), `config.rs` and `cli.rs` (new settings and run modes), new files under `command/` for the gateway and the bootstrap job, new files under `bootstrap/` for task wiring |
| Template sync | `crates/service/src/command/serve.rs`, `command.rs`, `http/router.rs` and `graphql/handler.rs` are added to `.templatesyncignore`, as the extension-seams document requires for the authentication seams; `bootstrap.rs`, `bootstrap/`, `cli.rs`, `config.rs` and `tests/e2e/` are already listed there |
| Health | `Dependency` enum and new probes in `crates/internal/health-check` (template-ignored seam files): `kafka` and `access-log-store` on the control plane; startup, readiness and liveness on the gateway's internal listener |
| Deployment | Reference Kubernetes manifests under `deploy/kubernetes/`, platform resources (Strimzi, Valkey, Loki, Grafana Alloy) under `deploy/platform/`, manifest checks in a Bats suite |
| Tests | `tests/support` fakes and fixtures for every new port; `features/iam-*.feature` and `tests/e2e/steps/iam*.rs`; new k6 scenarios under `tests/Load/` with their own thresholds (the protected health budgets stay untouched); a phase-0 spike report under `docs/spikes/` |
| Contracts | `.github/openapi-spec/spec.yaml` and `.github/graphql-spec/spec` regenerated, never edited by hand; they are generated from the `iam-control` router |
| Documentation | `docs/architecture.md` (context table), `docs/environment.md` (every new variable), `docs/requests.http`, new ADRs, `docs/extension-seams.md` cross-references |

The example context `some-module` and the template's own bundle `specs/rust-service-template-bootstrap/` stay untouched.

> Assumption: The example context `some-module` is kept as it is. Removing it deletes REST operations from the contract, which the OpenAPI diff gate reports as a breaking change needing a separate approval. Its removal is a follow-up issue, not part of this plan.

> Assumption: The authentication layer protects IAM's management routes and IAM's GraphQL fields. `/ping`, `/api/health`, the documentation routes and the example context keep their current behaviour. Applying security requirements to existing operations would be a breaking contract change; adding new secured operations and a `securitySchemes` component is additive. Routes of proxied upstream services are governed by the route table, not by the OpenAPI contract of IAM.

## 5. Datastore, Cache and Invalidation Evaluation (partly superseded)

### 5.1 The question and the status of this section

The board specifies DynamoDB for the database and DAX for the cache. The template ships PostgreSQL through `sqlx` with moka as an in-process cache. The owner asked which is better. The first version of this plan evaluated the options for a decision service. Part of that evaluation still holds; part is superseded.

> **Superseded.** The per-instance moka cache filled from PostgreSQL on a miss, `LISTEN/NOTIFY` invalidation with an epoch poll, per-key tombstones and global floors, the 10-second stale grace with a database fallback, SQS for outbound events and inbound revocations, and the access-decision log in partitioned PostgreSQL tables are replaced. Reasons, in short: IAM now sits on every request, so a database read, a notification session or a network round trip on the warm path is not acceptable (section 16); `LISTEN` needs one session connection per replica and does not scale with the fleet (section 17, limits); one SQS message reaches one consumer and cannot update every replica; the owner decided that Kafka carries IAM updates (D1, section 19) and that the access log lives in Loki (D13); and a gateway writes one access record per request, far above what a primary database should absorb.

> **Still valid.** PostgreSQL 16 through `sqlx` is the system of record, and the reasons against DynamoDB and DAX (sections 5.2 to 5.5) are unchanged. The conclusion about in-process caching is stronger, not weaker: the cache is kept, but as a replicated snapshot that meets the eight conditions of section 16, not as a cache-aside copy.

### 5.2 Capabilities the data store needs

The authorization design (sections 6 and 7) needs a data store that offers: an atomic write of a change with its audit and outbox records; a commit-ordered, gap-free policy version; conditional writes on a version; consistent reverse lookups; uniqueness and referential integrity; storage of specification documents of several MiB; expiry of revocation and idempotency records; point-in-time recovery; and local testing that meets the coverage and mutation gates.

| Capability | PostgreSQL 16 | DynamoDB + DAX |
| --- | --- | --- |
| Atomic write of an administrative change with its outbox and audit records | Yes, one transaction | `TransactWriteItems`, capped at 100 actions; the outbox needs a Streams consumer outside the Rust binary |
| Gap-free, commit-ordered global version | Yes, one counter row locked in the writing transaction | No: Streams order per partition key only |
| Conditional writes on a version | Yes (`UPDATE ... WHERE version = $n`) | Yes (condition expressions) |
| Reverse lookups (role to holders, permission key to granting roles) | Yes, consistent indexes | Global secondary indexes, eventually consistent |
| Uniqueness and referential integrity | Constraints and foreign keys | Application code |
| Immutable specification documents up to several MiB | Yes (`text` column) | No: 400 KB item limit, needs object storage |
| Expiry of revocation and idempotency records | Scheduled deletes | Native TTL |
| Point-in-time recovery | RDS PITR | Native PITR |
| Local and CI testing compatible with the 100% coverage and mutation gates | Already wired (`make.setup_test_db`, integration tests against a real container) | DynamoDB through LocalStack after protected changes; DAX is reachable only inside a VPC, and whether any LocalStack tier emulates it is UNVERIFIED |

### 5.3 Options compared

The scores below were the author's judgement in the first version of this plan, out of 10, weighted 40% runtime correctness and data model, 35% template fit, 25% operations and cost. They are kept for the record. The status column shows what the gateway design changed.

| Option | Template fit | Runtime and data model | Ops and cost | Score | Status |
| --- | --- | --- | --- | --- | --- |
| A: PostgreSQL + per-instance moka + invalidation through SQS | 7 | 4 | 8 | 6.0 | Rejected, still: one SQS message reaches one replica |
| B: PostgreSQL + shared Redis or Valkey for policy | 5 | 6 | 6 | 5.6 | Rejected for policy data, still. Valkey is adopted for rate-limit counters only (D4) |
| C: DynamoDB + DAX, as on the board | 2 | 3 | 3 | 2.6 | Rejected, still |
| C′: DynamoDB + per-process moka + Streams invalidation | 3 | 5 | 4 | 4.0 | Rejected, still |
| D: PostgreSQL + versioned in-process cache + `LISTEN/NOTIFY` + epoch poll + outbox to SQS | 8 | 9 | 9 | 8.6 | **Superseded** by D′ |
| **D′: PostgreSQL as source of truth + outbox to Kafka + in-process replicated snapshot in every gateway pod (sections 15 and 16)** | 7 | 9 | 7 | not scored | **Chosen.** It keeps D's PostgreSQL and in-process reads, and replaces its invalidation path with state replication. Template fit drops because of the larger allow-list (section 9); operations drop because Kafka, Valkey and Loki become platform dependencies (section 18) |

### 5.4 Decision

PostgreSQL 16 through `sqlx` is the system of record, running on RDS for PostgreSQL Multi-AZ in production. It holds roles, grants, user-role assignments, the GraphQL and REST permission catalogue, specification versions, the upstream, route and rate-policy configuration, the policy version counter, the outbox, the revocation tables, bulk-operation records and the hash-chained security audit log. It does **not** hold the access-decision log (Loki, D13) and never holds raw tokens. Only the control plane connects to it.

Every authorization read in a gateway pod comes from an in-process snapshot that is built from the Kafka state topic and replaced with one atomic pointer swap. The cache-aside design is gone: there are no misses on the warm path, so there is no fill and invalidate race, and no tombstones or floors. The R6 test applied by the owner ("cache can be used inside rust if we can do it distributed") is met by the eight conditions of section 16.

Change events leave PostgreSQL through a transactional outbox, drained by one fenced relay in the control plane that publishes to Kafka (section 15). Admin writes return the new policy version; a client may wait for its own write through the read-your-writes header or the Sync-Fence write mode (section 15).

> Assumption: The data-store decision is PostgreSQL as the source of truth and Kafka-fed in-process snapshots for reads. Nothing in the first release uses DynamoDB, DAX or a shared cache for authorization data. The reasons are in section 5.5; the triggers for revisiting are in section 5.7.

### 5.5 Reasons

Why the board's DynamoDB and DAX are not followed:

- DAX cannot be tested here. It is reachable only inside a VPC, so local development and CI could never exercise it, and the coverage and mutation gates could not be met for its adapter. This reason carries the decision.
- DAX semantics work against authorization. Its item cache is write-through only for writes that pass through DAX, but its query cache is not invalidated by writes and expires only by TTL (5 minutes by default); it has no invalidate operation; strongly consistent reads bypass it; replication between its nodes is eventual. A bounded revocation time cannot be guaranteed on top of it. This reason carries the decision too.
- Risk, not a deciding reason: no maintained Rust DAX data-plane client is known to the author (UNVERIFIED; AWS lists DAX clients for Java, Node.js, Go, .NET and Python, and the Rust `aws-sdk-dax` crate manages clusters).
- DynamoDB without DAX (option C′) fits the data model less well: eventually consistent reverse lookups, integrity in application code, a 100-action transaction cap that prevents atomic activation of large specifications or deletion of widely held roles, a 400 KB item limit, no gap-free global version, and an outbox that needs a Streams consumer outside the Rust binary.
- Either DynamoDB option changes protected items of `protected-config.toml` that encode the PostgreSQL stack, at least `architecture.toml` (no `aws-sdk-dynamodb` in any allow-list), `make/gates.mk` (the persistence gate command lines), `make/tool-versions.mk` (LocalStack services and tool pins), `scripts/setup-test-db.sh`, `scripts/check-sqlx-metadata.sh`, `scripts/with-load-test-stack.sh` and the Bats suites under `tests/CLI/bats/` that test those scripts; whether `deny.toml` and `scripts/check-invariants.sh` change too is UNVERIFIED. It also rewrites synchronised compose, Dockerfile and CI files and would conflict with every later template-sync pull request.

Why PostgreSQL stays the source of truth under the gateway design:

- A gap-free policy version needs one serialisable counter row locked inside the writing transaction. PostgreSQL gives that and is already the template stack.
- PostgreSQL remains authoritative, so a snapshot can always be rebuilt (the control plane can republish the whole state, the resync operation).
- The admin write rate is low (assumption in section 5.6), so one counter row is not a bottleneck.
- Gateway pods have no database connection, so the number of pods never loads the database.

Why no shared external cache for policy (option B): one round trip to Valkey costs about 200 µs typical and about 0.5 to 1 ms under load (SOURCE, section 16), while the whole IAM-specific work per request is about 2 to 3.5 µs (ESTIMATE). Valkey replication is asynchronous, so an acknowledged revocation can vanish on failover, and memory eviction can drop a revocation, which is a false allow.

What the board's intent keeps: the Database and Cache remain separate concepts behind ports; the board's invalidation workers keep their responsibility as the outbox relay and the state republisher in the control plane; entity events still reach Notification service through a message broker, which is now Kafka. A later move to DynamoDB would mean new adapters behind unchanged ports, but not unchanged transactional guarantees, so it would be a project with its own ADR.

### 5.6 Consequences and mitigations

| Risk | Mitigation |
| --- | --- |
| A fill racing an invalidation keeps a revoked grant | Gone by design: the snapshot is replaced as a whole from contiguous, digest-checked versions. The version guard makes apply idempotent and ordered |
| A notification is lost or a listener is stuck | Gone by design for policy: there is no listener. A pod that loses Kafka stops allowing after `T_hard` and returns 503 (section 15) |
| PostgreSQL failover (RDS Multi-AZ, typically 60 to 120 seconds, SOURCE order of magnitude) | Gateway pods are unaffected in the default freshness mode, because they read only Kafka. Administrative writes fail during the failover. A change committed but not yet acknowledged on the state topic is not enforced until it is (contract boundary, section 15) |
| Epoch row contention | One counter row per write; admin writes are assumed infrequent (assumption below); revisit trigger 3 |
| Decision-log volume loads the primary | Removed: the access log is in Loki (D13). The security audit log stays in PostgreSQL at administrative-change volume |
| Miss storms on cold start, scale-out or a flush | Removed: no misses. Cold start is a bootstrap from the compacted state topic (about 3 to 20 s, ESTIMATE, section 15), gated by the startup probe |
| Fail-closed coupling | The data plane depends on Kafka freshness, not on PostgreSQL. A fleet-wide Kafka outage beyond `T_hard` is a full API outage, by design (risk 5, section 12) |

> Assumption: Administrative writes, including role assignments made by the CRM during user or project onboarding, stay below 10 per second on average and 50 per second at peak. Every write takes the counter row. The state topic carries at most tens of records per second (ESTIMATE), so one partition suffices. A sustained higher rate is revisit trigger 3.

### 5.7 Triggers for revisiting

1. Move assignments (only) to a two-tier cache with Valkey as L2 when the steady policy snapshot exceeds 12.5% of the pod memory request (section 16).
2. Move the security audit chain out of PostgreSQL only if its volume or lock rate outgrows the primary; the audit chain head lock allows about 10 transactions per second per writer (ESTIMATE from the bottleneck note), which administrative traffic does not approach.
3. Switch to per-scope version counters if administrative-write p99 exceeds 200 ms because of counter-row lock waits.
4. Build the strict freshness mode (a bound counted from the PostgreSQL commit, not from the Kafka acknowledgement) only if the replica-quorum spike or the zombie-leader test T15 fails (section 15).
5. Re-evaluate the data store on a VilnaCRM platform decision to standardise on DynamoDB, or when an officially supported Rust DAX client appears.

### 5.8 Claims the owner should confirm

These were not verified and are recorded as risks: whether a shared VilnaCRM PostgreSQL instance exists; current RDS, MSK, ElastiCache, DynamoDB and DAX prices; that no maintained Rust DAX client exists; whether any LocalStack tier emulates DAX; that adding the seam files to `.templatesyncignore` is acceptable to the template owners; cardinality of users, tenants, assignments and sessions (D6, rest), which sizes memory.

## 6. Token Handling Decision

User service issues RS256 JWTs without `kid` and without a JWKS endpoint, and checks sessions in its own database. The usual recommendation for a central authorization component (offline validation plus an event-fed revocation layer, with resolutions memoised by token digest) is adapted to those facts. The gateway runs this on every request, in every gateway pod.

1. **Offline validation.** The gateway verifies the signature against one or more configured PEM public keys (several so that a key rotation can overlap; with no `kid`, keys are tried newest first, up to three), accepts only RS256, requires `iss = vilnacrm-user-service` and `aud = vilnacrm-api` (both configurable), checks `exp`, `nbf` and `iat` with at most 60 seconds of clock skew, requires `sid` when `roles` is present, and rejects tokens whose header supplies its own key (`jwk`, `jku`, `x5u`, `x5c`). A `ROLE_SERVICE` token is accepted only when its `sub` is a valid service name (`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`, at most 63 characters), which becomes the service principal's identity. League OAuth tokens fail the issuer check and are rejected (deviation 12 in section 10).
2. **No session-liveness call.** The earlier design confirmed session liveness with a call to User service on a cache miss. The gateway design removes it: a call per first-seen token per pod would put User service on the request path and grow with the fleet. Session revocations instead arrive as replicated state (item 4). `UserApiClient` and its HTTP adapter are removed.
3. **Memoisation.** The resolution (subject id, subject kind, session id, `jti`, roles claim, expiry) is memoised per pod for `min(exp − now, 900 s)`, keyed by a SHA-256 digest of the token, never the raw token. Capacity is CONFIG, `max(200k entries, active sessions)`, at about 400 B per entry (ESTIMATE). A bounded negative memo (10k entries, 5 s) limits forged-token floods. The memo is flushed whenever the trusted key set changes. It is safe because the replicated revocation set is checked on every request, including memo hits.
4. **Revocation.** User service publishes `user.session.revoked`, `user.all_sessions_revoked`, `user.refresh_token_theft_detected` and `user.deleted` to Kafka (owner decision D1). The control plane consumes them with a consumer group, writes revocation state to PostgreSQL (a per-session revocation or a per-user `tokens_valid_after` cut-off; `user.deleted` also revokes every assignment of the user) and republishes it as IAM revocation records on the state topic. Gateway pods read one ordered stream, check the revocation set on every request, and never read the User service topic. An operator revocation API remains for administrators.
5. **No persistence of tokens.** Only session ids, `jti` values and timestamps are stored. This deviates from the board, which lists access tokens in the database.

End-to-end revocation. From the Kafka acknowledgement of the User service event to enforcement on every healthy gateway pod, the target is p99 at most 1 s (ESTIMATE 0.2 to 0.5 s: consumer fetch up to 100 ms, commit 5 to 15 ms, relay wake-up and produce about 15 ms, propagation about 40 ms at 10 pods). Once the revocation record is acknowledged on the state topic, no pod allows on older state after `T_hard` (15 s now, 5 s target). A revocation stuck before that point (User service not publishing, the IAM consumer or the relay stalled) is not bounded by `T_hard`; it shows as consumer lag (alerts at 2 s and 10 s), and the access-token lifetime of at most 900 s, enforced by the gateway, is the absolute backstop.

> Assumption: The gateway validates User service access tokens offline with RS256 against configured PEM public keys (`JWT_PUBLIC_KEYS`, up to three, delivered through a Kubernetes Secret), because User service publishes no JWKS and sets no `kid`. A JWKS source can be added behind the same port when User service offers one (open decision D11).

> Assumption: Only first-party tokens with a lifetime of at most 900 s pass the gateway. `.env` in User service also sets 3,600 s (Lexik) and `PT1H` (League OAuth2) lifetimes, which belong to other token families and are rejected unless the owner lists them (open decision D12).

> Assumption: League OAuth2 tokens (`aud = client_id`, no `iss` and no `roles`) are rejected with reason `token_invalid` in release 1, because no VilnaCRM resource server accepts them today. This narrows the owner's "everything in the system context" scope, so it is recorded as deviation 12 and listed as an open owner item in `architecture.md`. Revisit trigger: the first resource server that accepts OAuth tokens; IAM would then add a subject kind `oauth_client` keyed by the client id.

> Assumption: Callers of IAM's management API and of the internal decision API authenticate with a `ROLE_SERVICE` JWT from User service, the only machine credential that exists. The caller's `sub` is its service name. A service caller's token must carry `JWT_CALLER_AUDIENCE` (default `vilnacrm-iam`) in `aud`, and its lifetime (`exp - iat`) must not exceed `JWT_SERVICE_TOKEN_MAX_LIFETIME` (default 900 seconds), because service tokens are not checked for session liveness and cannot be revoked. Minting service tokens with the IAM audience is a User service change and an open owner item; until it exists, the internal listener is reachable only through a private network path and a NetworkPolicy.

> Assumption: User service has no Kafka transport today. Its four revocation events travel over SQS through Symfony Messenger to the shared queue `domain-events`, and IAM never consumes that queue, because a second consumer on it would steal messages from User service's own consumers. User service must add a Kafka publication of the four events to `user.events.v1` (keyed by user id, with an event id, `occurredAt`, `userId` and, for session events, `sessionId`). The topic name, partitioning and payload are to be agreed with the User service team (open decision D25). This is an external prerequisite of the release. Until it is met, the 900 s token lifetime is the revocation bound for upstreams that do not check sessions themselves, and the operator revocation API is the manual path.

> Assumption: The consumer accepts both the Symfony Messenger envelope (mapping the known `eventClass` names to dotted event names) and a neutral `{id, type, occurredAt, data}` envelope, so that either publication style can be used.

## 7. Authorization Model Decisions

The model is scoped role-based access control over a permission catalogue generated from each service's contracts, with the adjustments below.

- Scoped RBAC with allow-only grants and deny by default. Permissions are generated from uploaded specifications; administrators can grant only catalogue keys or one of four structured wildcards.
- GraphQL keys are `gql:{service}:{Type}.{field}`; root operations are keyed by root field; `__typename` is always allowed; introspection maps to the reserved key `gql:{service}:__introspection`.
- REST keys are `rest:{service}:{METHOD} {template}` with parameter names replaced by `{}`; `operationId` is a label only.
- Wildcards: `gql:{service}:{Type}.*`, `gql:{service}:*`, `rest:{service}:{METHOD} *`, `rest:{service}:*`, matched with a fixed number of probes and never expanded; elements flagged sensitive are excluded from wildcard matches; granting a wildcard needs the reserved permission `iam:grant:wildcard`.
- An operation absent from every active specification of the target service is denied with `unknown_operation`.
- IAM returns scopes; object-level checks stay in the owning services.
- IAM's own admin API is protected by the same model, using the keys generated from IAM's own OpenAPI and GraphQL contracts (service name `iam`).

> Assumption: The first release supports two assignment scopes: global and project (a Core service project UUID). There is no tenant identifier in User service tokens or in Core service today, so a tenant level is deferred; the scope type is modelled so that a tenant level can be added without changing existing rows.

> Assumption: GraphQL decisions are all-or-nothing in the first release: if any required coordinate is denied, the request is denied and the denied coordinates are listed. Partial responses are out of scope.

> Assumption: The gateway routes to per-service GraphQL endpoints and is not federated. Each validate request names its target service, and coordinates are resolved against that service's active SDL.

> Assumption: OpenAPI documents are uploaded as JSON (OpenAPI 3.0.x and 3.1.x), which every template-based service already serves at `/api/docs/openapi.json`. YAML uploads are out of scope, which avoids a YAML parser on an untrusted-input path. Only internal `#/` references are resolved; external references are rejected.

> Assumption: Elements are flagged in the specification itself: the OpenAPI extensions `x-iam-sensitive: true` and `x-iam-audit: always` on an operation, and the GraphQL directives `@iamSensitive` and `@iamAuditAlways` on a field definition. Unflagged elements are neither sensitive nor always-audited.

> Assumption: Public routes (sign-in, token refresh, sign-up, password restore, health) are marked `anonymous` on the route in the gateway's route table. The gateway skips authentication for them, which needs the reserved key `iam:route:anonymous` to set. IAM has no anonymous principal in its authorization model. Their behaviour during a Kafka outage beyond `T_hard` is open decision D5 (default: fence).

> Assumption: The right to administer permissions is separate from the right to use them. Granting or revoking a key of service `s`, and assigning a role that holds such keys, needs the reserved key `iam:grant:s` or `iam:grant:*` at global scope; a sensitive key also needs `iam:grant:sensitive`, and a wildcard also needs `iam:grant:wildcard`. Nobody can change their own assignments, and the last active global assignment of `iam-platform-admin` cannot be revoked, expired or removed. The first platform administrator (a user, or a service principal for automated environments) is created by an audited `service iam-bootstrap` command that refuses to run while an active assignment of that role exists.

> Assumption: Specification uploads, activations and retirements are scoped to the target service: they need `iam:spec:s` or `iam:spec:*` for the service named in the request (`iam:spec:*` excludes the reserved service `iam`, whose specifications are written only by IAM's own startup registration). An activation that would remove a sensitive or always-audit flag from a key is a flag downgrade: it is listed in the diff and needs explicit confirmation plus `iam:grant:sensitive`.

> Assumption: Role assignments name a subject `{kind, id}`: kind `user` with a UUID, or kind `service` with a service name. Service principals (the gateway, delivery pipelines and microservices) therefore hold roles exactly like users.

> Assumption: A microservice caller may ask about its own service only (reserved key `iam:validate:{service}`); the gateway holds `iam:validate:*`. This prevents a compromised service from using IAM as an oracle for other services' policies.

## 8. Events, Logs and Background Work

> Assumption: IAM produces change events to the Kafka topic `iam.events.v1` through the transactional outbox, using Notification service's envelope `{id, type, occurredAt, data}` with dotted lower-case types prefixed `iam.`. Notification service tails `iam.events.v1` with its own consumer (owner decision D7). IAM never writes into the `notifications` topic, because every notification consumer forwards its records to browsers. This is a Notification service change and an external prerequisite.

> Assumption: The event types of the earlier catalogue stay: `iam.role.created`, `iam.role.updated`, `iam.role.deleted`, `iam.role_permissions.changed`, `iam.user_role.assigned`, `iam.user_role.updated`, `iam.user_role.revoked`, `iam.graphql_spec.loaded`, `iam.graphql_spec.retired`, `iam.graphql_permissions.created`, `iam.openapi_spec.loaded`, `iam.openapi_spec.retired`, `iam.rest_permissions.created`, `iam.permissions.orphaned`, `iam.privileged_role.assigned` and `iam.security_audit.anchored`. `iam.authorization_cache.flushed` is removed with the cache flush. The gateway adds events for routes, upstreams, rate policies and revocations; `architecture.md` lists them. The notification-relevant events, which carry the affected subject and the actor in `data`, are `iam.user_role.assigned`, `iam.user_role.revoked`, `iam.privileged_role.assigned` and `iam.permissions.orphaned`. Notification service decides whom to notify.

> Assumption: State records and event records are two views. `iam.policy.state.v1` (compacted, one partition) carries the full new state of each changed entity and drives replication; `iam.events.v1` (retention-based) carries domain events for Notification service and other interested consumers. Gateway pods read only the state topic.

> Assumption: The access-decision log is written to Loki, not PostgreSQL (owner decision D13). Gateway pods emit structured access records in two lanes, as `prd.md` FR-50 defines. The ordinary lane holds sampled allows and per-class aggregates; it goes to stdout and Grafana Alloy ships it to Loki, best effort. The audit lane holds every denial, every always-audit or sensitive-key decision and every wildcard allow; the pod pushes it to Loki's push API and a record counts as delivered only once Loki acknowledges it. Audit-or-deny applies to always-audit and sensitive keys only: such a request is refused with 503 `audit_unavailable` when Loki cannot acknowledge within about 2 seconds (ESTIMATE); other audit-lane records are counted as dropped while Loki is unavailable. The access-log query API (REST and GraphQL parity) is served by the control plane from Loki through a port, with a fixed low-cardinality label set, bounded ranges (24 h default, CONFIG), a page cap of 500 and a 30 s timeout. Loki's limits are stated plainly: no secondary index, slow queries over long ranges, retention per stream; filters on high-cardinality fields such as subject id use structured metadata or line filters. The partitioned `iam_access_decisions` table and its maintainer are dropped.

> Assumption: The hash-chained security audit log of administrative changes and rejected attempts stays in PostgreSQL and is written in the same transaction as the change, from control-plane pods only. Retention defaults: in Loki, `lane="access"` 90 days and `lane="audit"` 400 days (open decision D24); the security audit log in PostgreSQL at least 400 days, never deleted automatically in the first release. The lawful basis is security and legitimate interest; compliance retention beyond that is an owner decision recorded in ADR 0019.

> Assumption: The logs hold pseudonymous identifiers only: subject, actor and caller ids, role names and permission keys. Audit summaries never hold a person's name or email (the email in `user.deleted` is never stored). On `user.deleted`, access records are not rewritten; they age out within the Loki retention (90 days for the access lane, 400 days for the audit lane), and the audit chain keeps the pseudonymous UUID. The owner confirms this as an open item.

> Assumption: Background work runs in the control plane, not in the gateway. The control plane (`iam-control`, 2 to 3 pods) runs the outbox relay (a singleton with Kafka-side fencing), the User service event consumer (a consumer-group member), the anti-entropy and republish job, and the Sync-Fence coordinator. Gateway pods run only the tail and apply thread, the freshness probe, the access-log writer and the endpoint watch. Their loops live in `iam-application` and the composition root as pure step functions with branch-free shells, so the mutation gate can kill every loop mutant; `tokio` is not requested for `iam-infrastructure` (section 9). The earlier `service worker` subcommand does not exist.

## 9. Dependencies and Protected Changes

The gateway needs one protected configuration change, recorded in ADR 0023. The owner approved it on 2026-11-21, so the plan schedules it: Story 2.3 applies it to `architecture.toml` on the branch of the single pull request for issue #8, before the first story that uses a new crate, with `ALLOW_PROTECTED_CONFIG_EDIT=1` and the `approved-config-change` label set by a maintainer. The plan schedules no other protected change on its own authority: the Story 1.8 mutation-matrix resize is not approved, and any other protected change a story needs stops for the owner.

| Layer | Add to `external` | Add to `dev_external` |
| --- | --- | --- |
| Domain | none | none |
| Application | none | `criterion` |
| Infrastructure | `arc-swap`, `bytes`, `http`, `http-body-util`, `hyper`, `hyper-rustls`, `hyper-util`, `jsonwebtoken`, `krafka`, `matchit`, `rand`, `redis`, `rustix`, `rustls`, `rustls-pki-types`, `serde`, `serde_json`, `sha2` | `aws-lc-rs`, `criterion`, `krafka` |
| Composition root | already `external = ["*"]`; adds `tokio-rustls`, `ppp`, `tokio-tungstenite` and `prometheus-client` with no allow-list change | – |

Why each group is needed:

| Group | Crates | Purpose |
| --- | --- | --- |
| HTTP data plane | `hyper`, `hyper-util`, `hyper-rustls`, `http`, `http-body-util`, `rustls`, `rustls-pki-types`, `bytes` (infrastructure); `tokio-rustls`, `ppp` (composition root only) | Proxying with a pooled client and the Kubernetes API client in infrastructure; terminating TLS and reading PROXY protocol in the composition root's listeners |
| Routing | `matchit` | Route matching, shared by the snapshot and by route writes; the local rate limiter uses the domain GCRA rule and needs no crate |
| Snapshot | `arc-swap`, `sha2`, `rand` | Atomic snapshot publication; policy digest and credential digests; seeded jitter |
| Tokens | `jsonwebtoken`, `serde`, `serde_json` | RS256 verification, state-record and event encoding |
| Kafka | `krafka` | The only Kafka client (owner decision D14a) |
| Valkey | `redis` | `ValkeyRateLimitStore` |
| Clock | `rustix` | `CLOCK_BOOTTIME` for the freshness proof |
| Runtime | none added | `tokio` stays out of infrastructure: loops, timers, timeouts and breakers live in `iam-application`; a direct dependency is requested only if the spikes show that krafka's or redis's public API exposes `tokio` types |
| Tests and benchmarks | `criterion`, `aws-lc-rs` | Criterion benchmarks; runtime-generated RSA keys for verifier tests through `aws-lc-rs`, already in the graph through `jsonwebtoken`'s `aws_lc_rs` backend (no key is committed, so the secrets scan and the protected `.gitleaksignore` stay untouched). The `rsa` crate is not used: it carries RUSTSEC-2023-0071 with no patched release, which `deny.toml` would refuse |

Rules that stay:

- `reqwest` is not requested; `hyper-util` serves the few outbound calls.
- `openssl-sys` stays banned by `deny.toml`. Every added crate must pass `make.check_security` (licences, advisories, bans).
- Phase-0 spike stories put `krafka`, `jsonwebtoken` and `criterion` only as dev-dependencies of `crates/service`, so the spikes need no approval.
- Pingora is not a deliverable fallback: `pingora-core` depends on crates with RustSec "unmaintained" advisories while `deny.toml` sets `unmaintained = "all"` with no ignores, its only pure-Rust TLS backend is experimental, and 0.9.0 panics with tokio 1.54 or later (section 14). It is usable only if the owner pre-approves time-limited advisory ignores (open decision D21).
- `rdkafka`, the documented Kafka fallback, needs librdkafka (a C library) and a lift of the `openssl-sys` ban or a non-OpenSSL build, which is an owner-approved build change and dependency-policy exception (section 15).

> Owner decision (2026-11-21): the single protected configuration change above is approved and applied in Story 2.3, with `cargo-deny` reviewing the licences and sources through `make.check_security`. If a crate of the delta fails that check, the story stops and reports; the fallback of placing the adapters in the composition-root crate behind the same domain ports changes no protected file but weakens layering and needs its own ADR.

## 10. Deviations from the Miro Board

| # | Board | Plan | Reason |
| --- | --- | --- | --- |
| 1 | Database is DynamoDB | PostgreSQL 16 through `sqlx` | DynamoDB's transaction cap, item limit, eventual reverse lookups, missing gap-free version and an outbox that needs a Streams consumer outside the binary conflict with atomic activation, audit and ordering; the template's gates already cover PostgreSQL; DynamoDB changes the protected items enumerated in section 5.5 |
| 2 | Cache is DAX, "stores authorization data" | An in-process replicated snapshot in every gateway pod, fed by Kafka, behind ports | DAX cannot be tested locally or in CI; its query cache is not invalidated by writes and expires only by TTL; an external cache on the hot path costs more than the whole IAM-specific work and is a shared point of failure (section 16) |
| 3 | Invalidation cache workers are a separate container | There is no cache to invalidate. The outbox relay, the User service event consumer and the anti-entropy job run in the `iam-control` Deployment | Matches the board's separate container more closely than in-binary tasks; gateway pods hold state, not a cache |
| 4 | Database "stores access tokens"; Cache "stores confirmation token" | No token is stored; only session ids, `jti` values and validity timestamps; token resolutions are memoised per pod by digest for at most 900 s | A second store of bearer credentials adds risk with no functional benefit; confirmation tokens belong to User service |
| 5 | No REST/OpenAPI components | `OpenApiSpec`, `RestPermission` and their handlers and repositories, symmetric to GraphQL | Owner scope decision; the board's database already stores OpenAPI specifications |
| 6 | "Security and access logs" named only in the system context | `SecurityAuditEvent` (hash-chained, same transaction, PostgreSQL) and the access-decision log (Loki), each with a query API on both interfaces | Owner scope decision and D13; compliance and incident response need queryable logs |
| 7 | `InvalidationCacheWorker` is linked to the Message Broker; the board does not show the direction | Entity events are written to a transactional outbox and published by `OutboxRelay` to Kafka; the broker link is read as publishing | The template's in-process event bus is at most once; a lost revocation or audit event is a security or compliance defect |
| 8 | `UserRolePermission` is a computed entity per user | Composed at check time from compiled per-role sets and per-subject assignment lists; exposed as a read model | Avoids recomputing every holder's set when a popular role changes |
| 9 | `UserAPIClient` resolves tokens; `ValidateAccessQueryHandler` creates `AccessToken` | Offline RS256 validation in the gateway plus replicated revocation state; no `UserApiClient`, no per-request call to User service | User service has no introspection endpoint and a per-request call does not scale with the fleet; revocations are replicated state (D1) |
| 10 | Technology labels (Go, MariaDB for User service) | Rust for IAM; User service is PHP/Symfony on MongoDB | The board predates the current stack |
| 11 | Role, UserRole and GraphQLPermission dispatch change events; the Message Broker "stores entity events" (SQS); workers use the broker to invalidate | The broker is Kafka on Strimzi. IAM produces `iam.policy.state.v1` and `iam.events.v1` and consumes `user.events.v1`. Replicas converge by applying ordered state records, not by invalidation | Owner decisions R3, R5 (amended by D1), D14b; one SQS message reaches one consumer and cannot update every replica |
| 12 | User service issues OAuth tokens through its OAuth sub-context, and the gateway routes every protected request through IAM | OAuth server tokens (`aud = client_id`, no `iss` or `roles`) are rejected with `token_invalid` in release 1 | No VilnaCRM resource server accepts them today; revisit trigger: the first one that does, through a subject kind `oauth_client` keyed by the client id; the owner confirms the narrowed scope |
| 13 | A separate "API Gateway [DevOps]" box (load balancer, logging, tracing, request limiting) in front of IAM | IAM is the gateway: the NLB balances connections, the gateway balances requests, logs, propagates request ids and limits requests | Owner decision R1 |
| 14 | "Other microservices call IAM: sync REST API and GraphQL" | An optional internal decision API on the gateway pods' internal listener; upstreams normally rely on the headers the gateway adds | Proxied requests are already authorized |
| 15 | IAM sends asynchronous messages to Notification service through a message broker | Notification service tails `iam.events.v1` (D7) | The board does not name the events or the transport |
| 16 | `ValidateAccessQueryHandler` is the entry point | An in-process `DecisionPolicy` in the gateway pipeline, plus the optional decision API | R1 |
| 17 | Cache "stores confirmation token, roles and permissions" (component view) | Roles and permissions in the replicated snapshot; Valkey holds rate-limit counters only | R6; D4 |

## 11. Bounded Context

> Assumption: IAM stays one bounded context, `authorization/iam`, with the packages `iam-domain`, `iam-application` and `iam-infrastructure` at `crates/authorization/iam/`. The board draws one "IAM bounded context". Roles, grants, the permission catalogue, specification activation, the policy version, the outbox and the audit log must change in one transaction (activating a specification orphans grants; deleting a role revokes assignments; every change writes an audit row and takes the version counter), which is the defining property of one context. Splitting the logs or the catalogue into separate contexts would also require context-to-context dependencies, which need a protected `[contexts]` edit in `architecture.toml`. The new group `authorization` avoids the template-synchronised `company-subdomain` group.

> Assumption: The gateway code (routing, forwarding, snapshot, freshness, streams, rate limiting) lives as modules inside the same three crates (open decision D19, changed default). A separate `gateway` context would need a protected `[contexts]` edit and a shared kernel for the decision policy that both planes use. The two planes are two run modes of one image, not two contexts.

## 12. Risks

Risks 1 to 25 come from the gateway design; they are numbered as in that design. Risks 26 to 29 are carried from the first version.

| # | Risk | Effect | Mitigation |
| --- | --- | --- | --- |
| 1 | Every number is an estimate; nothing is measured on VilnaCRM code | Gates may be missed | Phase-0 benchmark replaces every figure; fallback is profiling and optimising the hyper pipeline |
| 2 | krafka maturity (accepted by the owner with a spike first, D14a): pre-1.0, single author, breaking minor releases; no throughput figure; several capabilities unverified (section 15) | Freshness of every pod and User service revocations depend on it | Exact pin, port abstraction, `test-broker` fault injection, 72 h soak before each bump, phase-0 spike stories, `rdkafka` fallback |
| 3 | Zombie leader and watermark validity: an AZ isolated together with the old Kafka leader could produce valid-looking proofs in the default mode | Allow on frozen policy in that AZ for the partition's duration | Replica-quorum epoch check (spike and test T15); peer cross-check; until T15 passes, guarantees G4 and G8 are conditional; liveness ticks (D17) or strict mode if the check cannot be built |
| 4 | Contract boundary in default mode (decided, D3): committed but unpublished changes (relay stall, PostgreSQL failover) and User service events not yet consumed are not enforced until acknowledged on the state topic | Revocations delayed for the outage duration, visible as `202` or as consumer lag | Sync-Fence default for revocation-class writes, lag alerts at 2 s and 10 s, 900 s token lifetime as backstop |
| 5 | Fleet-wide Kafka outage beyond `T_hard`, and every leader-broker crash at `T_hard` 5 s, is a full API outage, by design (fail closed) | Outage of about 6 to 7 s per leader crash at 5 s if failover is not tuned; none at 15 s | `T_hard` 15 s until test T14 (D2); Strimzi broker timings tuned; three AZs, RF 3; optional anonymous-route exemption (D5) |
| 6 | AZ-aware, peer-relative readiness is novel; NLB registration and deregistration timing for IP targets is unmeasured | Wrong behaviour under correlated failure; slow rebalancing | Fault-injection tests T16, T16b, T17 before production; GOAWAY on staleness |
| 7 | Session revocation gap until User service publishes its events to `user.events.v1` (D1 decided, User service change pending) | Gateway weaker than User service's own session check, for upstreams that do not check sessions (core-service), for up to 900 s | Track the User service change as a release prerequisite; operator revocation API; 900 s maximum token lifetime |
| 8 | Digest, framing and derived-state complexity | Determinism bugs fence pods (safe but unavailable); derived-state bugs caught only by the periodic check | Property tests, derived-state check, canary rollout |
| 9 | Edge responsibilities move to the gateway team: TLS rotation (TLS in the pod, D9), HTTP/2 hardening, DoS posture; no WAF unless the open WAF part of D9 adds one | Security exposure | Hardening suite, rate limits, connection caps, optional CloudFront or ALB with WAF |
| 10 | New platform: EKS, Strimzi Kafka, Valkey, Loki and a metrics stack do not exist in the organisation today; running Kafka ourselves makes broker operations our job | Schedule and operations load depend on the platform work | Phase-0 dependency; Strimzi resources with the configuration gates; runbooks |
| 11 | Upstream readiness for h2c and trusted proxies (PHP upstreams) | Connection explosion near 50 pods | Verify in phase 0 (D10) |
| 12 | The image links `sqlx` in release 1 | A gateway compromise could reuse database code, but has no credentials or network path | Credentials, NetworkPolicy; separate binary later (D16) |
| 13 | Strict-mode clock skew (ε = 250 ms, unmeasured) | Strict guarantee weakened if skew exceeds ε | chrony monitoring, alarm above 50 ms; only if strict mode is built |
| 14 | Kafka configuration drift (a Strimzi resource edited to enable unclean election, allow-everyone, fewer replicas or a second partition) | Lost acknowledged revocations; anyone can write the state topic | Startup configuration gates; Strimzi `KafkaUser` ACLs; anti-entropy offset verification |
| 15 | Bulk changes and catalogue activations saturate the single leader's egress | Fleet-wide fence | Commit-time pacing; content-addressed chunks; test T6b; follower fetching later |
| 16 | Scale-out and rollouts are slow (scale-out up to 5 minutes, ESTIMATE) | Overload before capacity arrives | 50% HPA target; pre-scaling for known peaks; emergency rollout mode later |
| 17 | Memory at 1M users with many tenants may exceed 12.5% of 2 GiB | Two-tier assignments with their fill and invalidate race | D6 cardinality; test T13 with multi-tenant data |
| 18 | Pingora fallback blocked by `cargo-deny` | No drop-in data-plane fallback | Profile and optimise hyper; Envoy plus ext_authz only as an out-of-repo baseline; or owner pre-approval of time-limited advisory ignores (D21) |
| 19 | Zone-aware routing depends on the EndpointSlice watch | Without it, p95 misses the gate | Phase-1 requirement; RTT metric per zone |
| 20 | Quantile arithmetic: end-to-end figures sum percentiles | The true end-to-end percentile differs | Gate on the measured residence histogram; report RTT separately |
| 21 | Valkey on the request path of rate-limited routes (D4) | Added latency (one round trip, up to about 0.6 ms cross-AZ, ESTIMATE); stricter limiting in degraded mode; brief over-admission after a failover | Valkey only for routes with a rate policy; 5 ms deadline, breaker, conservative local limiter; test T30 |
| 22 | Loki query limits (no secondary index, slow long ranges, retention per stream) | Access-log queries slow or timing out on busy streams | 24 h default range cap, page cap 500, 30 s timeout with 504, fixed labels plus structured metadata; test T31 measures |
| 23 | Loki outage blocks always-audit operations through audit-or-deny | Always-audit routes return 503 after about 2 s of Loki unavailability | Loki replicated across AZs; alert; the owner may relax audit-or-deny per route class (open D24) |
| 24 | GraphQL subscription frame inspection (D8) adds a WebSocket codec and per-message parsing to the gateway | A bug could let a frame through unauthorized or break subscriptions | Per-operation authorization before forwarding, fail closed on any decode error (close code 4400), message size cap, fuzzing in the parser-differential suite, test T33 |
| 25 | Changes outside IAM: User service must publish to `user.events.v1`; Notification service must tail `iam.events.v1` | Revocation gap (risk 7); no IAM notifications | Release prerequisites tracked in the readiness file |
| 26 | The protected allow-list change (section 9) is not approved | Token, Kafka and gateway epics cannot be implemented as planned | Owner decision recorded as a prerequisite; composition-root fallback with its own ADR |
| 27 | Parser differential between IAM and upstream services | IAM checks one operation, the service executes another | Documented normalisation, rejection of ambiguous paths, literal segments before templates, authorize the same bytes that are forwarded, a parser-differential test suite |
| 28 | Cross-scope cache leaks | One project's permissions served for another | Scope-first keys in the snapshot and property-based tests over key construction |
| 29 | Template-sync conflicts | Sync pull requests overwrite IAM wiring | `.templatesyncignore` entries for the four seam files; new files only elsewhere |

## 13. Open Questions Resolved

Every open question from the domain review, the reconnaissance and the evaluations is resolved above as an assumption or listed in section 20 with the default it keeps. For convenience, the general ones are collected here.

> Assumption: The latency, throughput, availability and freshness figures in the PRD come from the capacity model (section 17) and the freshness design (section 15). They are ESTIMATE, target or CONFIG values. They become gates through new k6 scenarios with their own thresholds, or through integration benchmarks for the figures k6 cannot observe (propagation latency, bootstrap time, logging overhead); availability targets are operational objectives documented in `docs/operations.md`; the protected health budgets in `tests/Load/config.json.dist` are not changed.

> Assumption: Administrative writes accept an `Idempotency-Key` header (REST) or an `idempotencyKey` input field (GraphQL), replayed for 24 hours, and use optimistic concurrency through `ETag` and `If-Match` (REST) or an `expectedVersion` input field (GraphQL). GraphQL has no headers, so these inputs are its equivalent. Every write accepts a write-mode modifier (REST `Prefer: wait=propagated`, GraphQL input `consistency`), and every write response carries the policy version.

> Assumption: The decision API (validate, batch, resolve token) always returns HTTP 200 with a decision body when the caller is authenticated and the input is valid, including when IAM cannot decide (`deny` with reason `unavailable`). Non-200 statuses describe the caller's request (401, 403, 413, 415, 422), never the subject's decision. On the proxy path the gateway maps decisions to the client: 401 for a missing or invalid token, 403 for a denial, 503 `iam_stale` when the freshness proof is too old.

> Assumption: Batch validation accepts 1 to 100 checks per request, evaluates them independently and returns results in request order, resolving each distinct credential once.

> Assumption: Gateway pods report health through three probes on their probe listener (startup, readiness, liveness), as `architecture.md` sections 17.5 and 17.6 define. Startup requires a completed bootstrap with a verified `__head` digest, passed configuration gates, a freshness proof attached to a published snapshot and parsed JWT keys. Readiness uses local state plus the peers' freshness read over HTTP, and never the broker or PostgreSQL. Liveness is process-level only and never depends on Kafka or an upstream, so a broker outage cannot restart every pod. The control plane's `/api/health` reports PostgreSQL, Kafka and the access-log store. User service reachability is not part of any probe.

> Assumption: The existing template bundle `specs/rust-service-template-bootstrap/` stays in place; replacing it as `docs/new-service.md` suggests is a separate housekeeping change.

## 14. Research: Gateway Data-Plane Options

Number tags: SOURCE (a published figure; the note holds the link), ESTIMATE (reasoning, not measured), CONFIG (a value this design chooses). Versions were read from crates.io on 2026-11-21.

### 14.1 Finding

No published benchmark gives added latency and requests per second per core for any Rust stack under an authenticate-plus-proxy workload. The only first-party numbers are Cloudflare's production figures for Pingora (70% less CPU and 67% less memory than its NGINX-based predecessor on the same traffic, SOURCE), which are not a gateway-added-latency figure. Every other number is blog-grade. The figures this bundle needs must therefore come from a benchmark that we run (an open-loop generator, below the saturation knee).

### 14.2 Options

| Option | Fit | Verdict |
| --- | --- | --- |
| **axum 0.8 + hyper 1.12 + hyper-util legacy client** | Reuses crates already in `Cargo.lock` (hyper 1.12.0, hyper-util 0.1.21, h2 0.4.20, rustls 0.23.46, tower 0.5.3, tower-http 0.7.1); same runtime and framework as the management API, so REST and GraphQL parity needs no second stack; rustls is already the workspace standard; in-process decision with no extra hop; Kubernetes supplies load balancing and health. Weaknesses: `hyper-util` is 0.1.x, so its client API is formally unstable; pooling, retries and circuit breaking are ours to build | **Chosen** |
| Pingora 0.9.1 (Cloudflare) | Built-in pooling, load balancing and health checks; production-proven at scale. Weaknesses: still 0.x with breaking changes between minors (about one minor every two to three months) and a security-fix cadence driven by HTTP smuggling and HTTP/2 exhaustion issues; its own runtime and server model; a large dependency tree; the pure-Rust TLS backend is experimental; 0.9.0 panics with tokio 1.54 or later (this workspace pins 1.54.1, so only 0.9.1 or later is usable); `cargo-deny` blocks it (section 9). Its fd-passing graceful upgrade does not apply on Kubernetes, and Kubernetes supplies the load balancing it sells | Recorded alternative, blocked by policy |
| tower layers only | Middleware, not a proxy | Used inside the chosen stack |
| Envoy or NGINX in front, IAM as `ext_authz` | Battle-tested data plane. An `ext_authz` round trip adds the IAM decision time plus about 0.3 to 1 ms (ESTIMATE, from hop count). Contradicts the owner's decision that IAM is the gateway, and GraphQL coordinate authorization needs body buffering in the edge | Rejected as the design; kept as the benchmark baseline |

### 14.3 GraphQL proxying

The gateway parses the request document, resolves the operation (by `operationName` when the document has several), walks the selection set with fragments and `@skip` or `@include` to collect field coordinates (`Type.field`), authorizes them, and forwards the original bytes unchanged.

- Parser: `async-graphql-parser` 7.2.1 is already a transitive dependency of `async-graphql`, and `async_graphql::parser` re-exports it, so it is the lowest-governance choice (re-export to be verified). `apollo-parser` 0.8.7 and `apollo-compiler` 1.33.1 are heavier and add new crates. No parse-latency benchmark is published for either; the cost is an ESTIMATE (single-digit to low tens of microseconds for 0.3 to 2 KB) and a criterion benchmark on the real operation corpus replaces it.
- Cache: key is a hash of the document plus the operation name, compared in full on a hit so that a hash collision cannot bypass authorization; value is the resolved coordinate list and the depth and complexity, not the AST. It is a pure function of the document and the catalogue version, so it never creates a false allow across users, and a catalogue change produces new keys. The decision itself is never cached with the coordinates: it is computed per request from the principal's grants and the cached coordinates.
- Conservative variables: authorize the union of coordinates reachable under any variable value (fail closed) rather than evaluating directives with the supplied variables.
- Fail closed: a parse error is rejected with 400, never forwarded; an oversized body with 413; an unknown operation or unresolved fragment is rejected. The gateway authorizes the same bytes it forwards and rejects duplicate JSON keys and non-standard content types on which parsers disagree.
- Subscriptions: the document arrives in a WebSocket message after the handshake, so authorizing on the handshake alone is insufficient. The owner decided to carry subscriptions in phase 1 (D8): authorize per subscribe message, re-evaluate on change, cap lifetimes, drain on shutdown.
- Persisted queries and an allow-list mode are the strongest posture but are a later-phase item.

### 14.4 What the benchmark must answer (phase 0)

Open-loop load, 4 CPUs per pod, three paths: (a) hello-world upstream with no authentication; (b) authentication, cached decision, forward; (c) GraphQL with a cached document and a cold parse. Record p50, p99 and p99.9 added latency against the direct-to-upstream baseline at about 50% of the saturation rate, and the maximum rate per core. Run the same against Envoy `ext_authz` in HTTP mode as the baseline. Decision rule: if the hyper pipeline misses the gate, profile and optimise it; Pingora is evaluated only if the owner approves the `cargo-deny` exceptions.

## 15. Research: Kafka Replication and the krafka Risk

### 15.1 How VilnaCRM uses Kafka today

Only `notification-service` uses Kafka (VERIFIED by reading its ADRs and code; code search outside that repository is index-limited, so "none elsewhere" is high but not absolute confidence).

- Client: `krafka =0.32.0` pinned, `default-features = false`, `rustls-aws-lc-rs`, behind three domain ports. Rationale in its ADR 0016: `deny.toml` bans OpenSSL and the builder image has no C toolchain, so `rdkafka` was rejected. The same ADR names krafka's weakness: one author, pre-1.0, 16 releases in 14 weeks with breaking changes in minor releases.
- One topic with exactly one partition, no consumer group, no committed offsets, position in memory, `read_committed`, every node tails the topic itself. Readiness fails when the last watermark read or last catch-up is older than 10 s; watermarks are read at least once per second on a dedicated connection because krafka's long poll does not report a broker outage.
- Recommended broker settings in its operations guide: RF 3, `min.insync.replicas=2`, `acks=all` with idempotence, `auto.create.topics.enable=false`. They are recommendations, not provisioned reality.
- No Kafka producer exists in any PHP service, and no infrastructure repository provisions a broker (no MSK, Strimzi, topic or ACL resource). The only broker definition is a single-node KRaft compose file. IAM's relay and User service's publisher would be the first producers in the organisation.
- User service publishes its domain events over SQS only, through Symfony Messenger to one shared queue `domain-events`; its Messenger configuration has no Kafka transport.

The gateway reuses the same client, pin, port style, environment variable names and readiness philosophy. It must not copy the tolerance for staleness: Notification service serves a stale node and only flips readiness, while the gateway must fail closed.

### 15.2 Rust Kafka clients (crates.io, 2026-11-21)

| Client | State | Reading |
| --- | --- | --- |
| `krafka` 0.32.0 (pure Rust) | Published 2026-11-14, crate created 2026-02-08, 52.7K downloads, MIT OR Apache-2.0. README: pre-1.0, a minor release may carry breaking changes. Has a group-less consumer, an idempotent and transactional producer (per its README), rustls TLS and mTLS, SASL | **Chosen (D14a)**, with a phase-0 spike first |
| `rdkafka` 0.40.0 (C librdkafka) | Most mature, widest coverage, 45.3M downloads. Needs a C library and OpenSSL by default, which `deny.toml` bans | Documented fallback; needs an owner-approved build change and dependency-policy exception |
| `rskafka` 0.6.0 | No consumer groups, offsets or transactions; last release 20 months ago | Not recommended |
| `kafka` 0.10.0, `samsa` 0.1.8 | Stale or too young | Not recommended |

The choice is driven by the build and licence constraints, not by raw client quality: `rdkafka` is the more battle-tested client. Risk acceptance for krafka: exact pin `=x.y.z`, a port abstraction, the in-memory fake broker (`krafka` test feature, dev-dependency only) for fault injection, and a 72-hour soak against a real broker before each version bump.

### 15.3 Capabilities to verify in the spike

Phase-0 spike stories verify through krafka's public API, against its test broker and a real KRaft broker, every capability the freshness guarantee relies on, before the guarantee is declared unconditional: headers on null-value (tombstone) records; group-less partition assignment with `read_committed`, the last stable offset, out-of-range detection and reseek after reconnect; metadata requests addressed to a chosen broker and the leader epoch in the response; `ListOffsets` with `current_leader_epoch` (KIP-320); transactions and the relay fencing; consumer groups for the control plane's User service consumer; custom-root TLS; and throughput. The spike report is recorded in `docs/spikes/phase-0.md` and ADR 0026. If a capability is missing and a value-framing fallback also fails, the fallback is another Kafka client (`rdkafka`), not an external cache, because the replication conditions do not depend on where the cache lives.

### 15.4 Replication pattern

| Element | Choice (CONFIG unless noted) |
| --- | --- |
| Source of truth and order | PostgreSQL commit order defines a gap-free `policy_version` (one counter row in the writing transaction). A transactional outbox holds the state records |
| State topic | `iam.policy.state.v1`: exactly one partition, RF 3 (one replica per AZ), `min.insync.replicas=2`, `cleanup.policy=compact`, `unclean.leader.election.enable=false`, `min.compaction.lag.ms` 1 h, `max.compaction.lag.ms` 1 day, `segment.bytes` 64 MiB, `message.timestamp.type=LogAppendTime`, write ACL for the control plane only. Records are the full new state of each changed entity, keyed by entity id, with tombstones for deletion |
| Relay | One singleton in the control plane, an idempotent or transactional producer with `acks=all`, publishing in version order, with fencing against a zombie relay (transactional producer if krafka supports it, otherwise a relay-epoch header plus anti-entropy repair). Bulk changes are paced at commit time so that the single leader's egress never outruns the fleet |
| Consumer | Every gateway pod reads the whole topic, no consumer group, no committed offsets, manual partition assignment, `read_committed`, `client.id` set to the pod name; checks version contiguity and a per-version state digest; applies each version on a dedicated thread to a copy-on-write snapshot and publishes it with one atomic pointer swap |
| Bootstrap | Read the compacted topic from the beginning to the end offset recorded at start, then tail. The data plane depends only on Kafka: no PostgreSQL credentials and no database load from N pods at autoscale time. The control plane can republish the whole state on demand (resync) to heal a corrupted topic |
| Why not a PostgreSQL snapshot plus tail | N gateway pods would hit PostgreSQL at autoscale and rollout time (thundering herd), the data plane would need a database credential or a snapshot API, and the snapshot offset is not exactly knowable because the relay is asynchronous. The version-compare rule is kept anyway, because it makes apply idempotent |
| Size and bootstrap time | One million keys at 200 B is 200 MB (ESTIMATE). Bootstrap to fresh: 3 to 20 s expected for a single joiner (ESTIMATE, krafka throughput unmeasured); with k concurrent joiners the time grows with the shared bootstrap quota |

### 15.5 What "synchronous" can and cannot mean

The owner wants the cache updated "synchronously" from Kafka. Kafka delivery to N independent consumers is asynchronous by construction. The design therefore offers the following, stated precisely:

| Guarantee | Meaning | Status |
| --- | --- | --- |
| G1 durability (numbering as in `architecture.md` section 9.6) | The change and its outbox row commit atomically; the relay publishes with `acks=all` and `min.insync.replicas=2`, so an acknowledged record survives loss of any one broker | Conditional on the broker configuration gates |
| G2 order | One partition plus gap-free versions give every replica the same sequence; duplicates are ignored; gaps are detected | Holds |
| G3 convergence | A connected replica reaches the same state as every other; a restart rebuilds the same state | Holds |
| G4 bounded staleness | A pod allows a request only while its snapshot carries a freshness proof younger than `T_hard` on the pod's own `CLOCK_BOOTTIME`: the snapshot contains every complete IAM version that Kafka had acknowledged when the probe was sent, and at least 2 of the 3 partition replicas confirmed the leader epoch the watermark came from. Otherwise 503. No cross-host clock comparison and no NTP are needed | **Conditional** on the broker gates, relay fencing, and the replica-quorum epoch check passing its spike and test T15 |
| G5 typical propagation | Kafka acknowledgement to every healthy pod p99 about 40 ms at 10 pods; PostgreSQL commit to every healthy pod p99 about 150 to 300 ms; target p99 at most 500 ms on the first-release fleet | ESTIMATE, steady state |
| G6 read-your-writes | A write returns the policy version V; a follow-up request carrying `X-IAM-Min-Policy-Version: V` (or the `__Host-iam_pv` cookie) is held until the serving pod has applied V or refused (503 `iam_propagating`); the version, not the Kafka offset, is used because the offset does not exist at commit time | Holds |
| G7 monotonic reads | A pod never moves backwards | Holds |
| G8 Sync-Fence | A write sent in `propagated` mode returns `complete` when every gateway pod has applied it and finished re-evaluating open streams, or `bounded` after `T_hard` + 0.5 s. After either answer no pod makes a new decision, or keeps an open stream, on older state; requests already authorized may complete. Revocation-class writes use this mode by default (D3b) | Same conditions as G4 |
| G9 fail closed | Unknown state, a gap, an incomplete bootstrap or a stale proof means 503 or deny, never allow | Holds |

What is not guaranteed: an instantaneous global effect, and linearizability across replicas (after pod A returns deny, pod B may still allow for a short time). The only cure would be a single authority per request, which defeats the latency target.

Default mode (decided, D3): the bound counts from the Kafka acknowledgement of the state topic. A change committed in PostgreSQL but not yet acknowledged (relay stalled, PostgreSQL failover) is not covered by `T_hard`; it appears as `202` on the write and as consumer lag. The strict mode, which counts from the PostgreSQL commit, is a later-phase option that is built only if the replica-quorum spike or T15 fails.

`T_hard` is 15 s now and 5 s after the broker-failover test T14 shows a proof gap of at most 2 s (D2). Because Strimzi runs Kafka in the cluster, broker session and failover timings are ours to tune, which makes 5 s reachable. A leader crash can then cost about 6 to 7 s of fleet 503 if failover is not tuned (ESTIMATE), which is why the initial value is 15 s.

### 15.6 Propagation latency (ESTIMATE, to be replaced by the spike)

Published anchors are generic: the Apache Kafka design document gives about 10 ms for an `acks`-all write (not a benchmark); a Confluent benchmark gives p99 end-to-end 5 ms at 200 MB/s on three NVMe brokers with unstated `acks` for the latency test, so it is not quoted as an `acks=all` figure; Redpanda's vendor benchmark shows fsync on network disks can dominate p99. None is measured on our topology (small messages, low rate, cross-AZ replication, relay in Kubernetes).

| Stage | p50 | p99 |
| --- | --- | --- |
| PostgreSQL commit | 1 to 5 ms | 10 to 20 ms |
| Relay wake-up | 1 to 5 ms (`LISTEN`, polling fallback) | 100 to 500 ms if only polling |
| Produce `acks=all`, RF 3, cross-AZ | 5 to 10 ms | 20 to 50 ms |
| Broker to consumer | 1 to 5 ms | 10 to 20 ms |
| Decode and apply | under 1 ms | under 5 ms |
| Total, commit to applied on every pod | 15 to 40 ms | 100 to 300 ms |

From the Kafka acknowledgement to every healthy pod, p99 is 40 ms at 10 pods, 70 ms at 50 and 150 ms at 200 (ESTIMATE, steady state, no bulk in flight). The target is p99 of at most 500 ms from commit to every healthy pod on the first-release fleet (6 to 9 pods); the 50-pod and 200-pod figures above are later-phase estimates. The request path never touches Kafka: a read is one atomic pointer load plus a few hash probes.

### 15.7 Kafka scope (R5, amended by D1)

IAM produces only IAM topics (`iam.policy.state.v1`, `iam.events.v1`) and consumes its own state topic (gateway pods) and, in the control plane only, `user.events.v1`. Request traffic, access logs, rate-limit counters, acknowledgements and freshness probes never travel on Kafka. The control plane republishes consumed revocations onto the state topic instead of letting pods read `user.events.v1`, because the state topic is the version clock: a second topic would have no common order with the first, and a pod could not prove that it applied every change acknowledged before `t − T_hard` across both. Notification service tails `iam.events.v1` (D7); IAM never writes into the `notifications` topic.

## 16. Research: Cache Topology per Data Kind

### 16.1 The R6 test and the options

The owner's rule: a cache may be used inside the Rust process if it can be made distributed; otherwise use a separate cache. The options for policy data were evaluated against read latency, consistency under failure, cold start, memory, operations and effect on scaling.

| Option | Hot-path cost per request | Consistency under failure | Verdict |
| --- | --- | --- | --- |
| **A. In-process replicated snapshot fed by Kafka** | One `ArcSwap` load plus about 5 hash probes, at most 2.5 µs (ESTIMATE) | Prefix-consistent, contiguous, digest-verified, bounded staleness that fails closed; unaffected by PostgreSQL failover in default mode | **Chosen** for roles, grants, assignments, catalogues, routes, revocations and rate policies |
| B. Embedded distributed cache (gossip, Raft, CRDT, groupcache-style peers) | About 1 µs local; a peer miss is a network hop | Gossip broadcast is best effort with no bound under partition; a CRDT merge of grant and revoke can resurrect a grant (a false allow); Raft turns the gateway into a StatefulSet with a quorum, and openraft 0.10 is alpha | Rejected: each variant manufactures an order the system already has |
| C. External cache (Valkey, Redis, Dragonfly, KeyDB, Memcached) on the hot path | About 200 µs typical per round trip, p99 0.93 ms at 256 connections (SOURCE); at least two dependent round trips (assignments, then roles), so about 0.4 to 1 ms p50 and 2 ms or more at p99 (ESTIMATE) | Replication is asynchronous, so acknowledged writes can be lost on failover and a revocation can vanish; `maxmemory` eviction can drop revocations; a cache outage is a fleet-wide outage | Rejected for policy |
| D. Two tiers (L1 in process, L2 external) | L1 hit as A; miss as C | Weakest tier plus the fill and invalidate race; per-user L1 hit ratio falls as pods are added | Fallback for assignments only |

In-process reads cost tens to hundreds of nanoseconds each; an external cache costs hundreds of microseconds to about a millisecond each. That is three to four orders of magnitude, on a path that does four to six lookups per request.

### 16.2 Why option A counts as distributed

It is state-machine replication: one writer (PostgreSQL commit order exported through the outbox), one totally ordered log (a single-partition compacted topic) and N deterministic replicas. It meets eight conditions.

| Condition | Mechanism |
| --- | --- |
| C1 total order | Locked counter row, one relay, one partition |
| C2 contiguous versions with gap detection | Contiguity check on the tail, `__head` resolved by highest version, per-version digest |
| C3 every pod reads every record | No consumer group |
| C4 readiness gated on catch-up | Startup and readiness probes |
| C5 silence is detectable | Watermark probe with replica-quorum epoch confirmation (conditional on T15); heartbeats only in the later-phase strict mode |
| C6 hard staleness bound that fails closed | The `T_hard` decision rule (G4) |
| C7 idempotent, deterministic apply | Version guard; no clock or randomness in apply; pruning only by log tombstones |
| C8 divergence detection | Record-set divergence by per-version digests, with `(version, digest)` metrics and relay anti-entropy; derived-state divergence by a periodic rebuild-and-compare and property tests. The digest alone does not cover derived structures |

### 16.3 Placement per data kind

| Data kind | Placement | Reason |
| --- | --- | --- |
| Roles, grants, compiled role sets | Replicated snapshot | About 6 MB (ESTIMATE); a stale grant is a false allow |
| Assignments | Replicated snapshot while the steady snapshot is at most 12.5% of the memory request; otherwise a two-tier option D for assignments only (L1 moka version-stamped, Valkey L2 filled by an IAM projector, fail closed when both miss) | 25 to 40 MB interned at 1M users with few tenants; 360 to 480 MB with many tenants, when interning collapses (ESTIMATE). Cardinality is unknown (D6) |
| Catalogues, routes, upstream names, rate policies | Replicated snapshot | A route must share one version with its catalogue |
| Revocations, per-user and global cut-offs | Replicated snapshot, never evictable | An evicted revocation is a false allow |
| Token resolutions | Per-pod memo, TTL at most `exp` and 900 s, flushed on key-set change | A pure function of the token; revocation is checked on every hit; a miss costs about 25 to 35 µs CPU (ESTIMATE), less than one networked cache round trip |
| Negative token results | Per-pod memo, 10k entries, 5 s | Bounds forged-token floods |
| Parsed GraphQL documents, matched routes | Per-pod memo keyed by catalogue version | Pure functions; nothing to converge |
| Rate-limit counters | Valkey, exact global quotas, phase 1 (D4), only for routes with a rate policy | The only genuinely shared mutable state. Never on Kafka. Never authorization data |

### 16.4 Valkey for rate limits (D4)

Each pod keeps a local token bucket per key as a first line of defence and a per-IP guard that is always on. Exact global quotas use Valkey behind the `RateLimitStore` port, on rate-limited routes only. The call has a bounded deadline (5 ms, CONFIG) and a circuit breaker; when Valkey is slow or down the pod falls back to a conservative per-pod limiter (global limit divided by ready replicas) and never blocks authorization. Valkey loss weakens rate limiting only; it never relaxes authorization, and Valkey holds no authorization data. One round trip costs about 0.2 ms same-AZ and up to about 0.6 ms cross-AZ (ESTIMATE). Strict billing-grade quotas would need a synchronous call per request and are reserved for the routes that need them. Product choice: Valkey (BSD-3, operators and managed services); Redis adds licence terms with no technical gain; Dragonfly is BSL 1.1; KeyDB shows no release since October 2023; Memcached has no replication. Deployment on Kubernetes (in-cluster primary and two replicas with Sentinel, or Amazon ElastiCache for Valkey) is open decision D23; the port keeps either a configuration change.

### 16.5 Sizing the snapshot

| Component | Formula | Example (ESTIMATE) |
| --- | --- | --- |
| Compiled role sets | roles × keys per role × about 40 B | 500 roles × 300 keys, about 6 MB |
| Catalogues and routing | services × operations × about 300 B | 8 × 3,000, about 7 MB |
| Assignments, naive | subjects × assignments × about 120 B | 1M users × 2, about 240 MB |
| Assignments, interned | subjects × about 24 B plus distinct role-set and scope combinations | 1M users, 5,000 combinations, about 25 to 40 MB |
| Revocations | revocations per second × maximum token lifetime × about 40 B | 10 per second × 3,600 s, about 1.5 MB |

Rule of thumb (CONFIG): keep the snapshot plus build headroom under about 12.5% of the pod memory request, which is 256 MB of a 2 GiB request. Beyond that, move assignments only to option D.

## 17. Research: Capacity Model

### 17.1 Method and caveats

The model prices each pipeline step of a warm request (accept, TLS record, token digest, memo lookup, revocation check, route match, decision, proxy, response, log) and adds queueing and tail events. Nothing has been measured on our code or hardware. A number is SOURCE only when a link in the note follows it. Each headline figure has a conservative (C), expected (E) and optimistic (O) value. Utilisation assumptions: at most 60% CPU on the hottest pod and no CFS throttling. A phase-0 benchmark replaces every figure.

### 17.2 Sourced building blocks and comparable systems

| System | Published figure | Comparability |
| --- | --- | --- |
| Pingora (Cloudflare) | 70% less CPU and 67% less memory than the NGINX-based predecessor; median TTFB 5 ms lower | Production edge; not a gateway-added-latency figure |
| Pingap (Pingora-based) | Proxy hop on loopback: 63.4k rps, average 158.7 µs, p99 233 µs, against NGINX direct at p99 84 µs | Closed-loop wrk (coordinated omission), no TLS or auth |
| Kong 3.16 | No plugins 144k rps on 16 vCPU (9.0k per vCPU); key-auth plus rate limiting 102k rps (6.4k per vCPU) | The closest gateway-with-auth figure; our conservative case matches it |
| Istio 1.24 Envoy sidecar | About 0.20 vCPU per 1,000 rps (1 KB, mTLS, 2 workers) | Includes mTLS on both legs and telemetry; the anchor of the conservative case |
| RSA-2048 verify | 13.1 µs measured on a fast laptop CPU (graviola); 17 to 24 µs scaled to cloud vCPUs (ESTIMATE) | Cold-token cost |
| OPA RBAC | About 45 µs per decision, a budget "of the order of 1 ms"; memory about 20 times the raw JSON | An interpreted engine; a compiled bitset is far cheaper |
| Same-AZ round trip | 52 µs (ENA Express sockperf) to 300 µs (AWS worked example); cross-AZ p50 0.39 to 0.60 ms, p99 0.52 to 0.68 ms | The extra hop to an upstream |
| Valkey or Redis lookup | About 200 µs typical, 0.93 ms p99 at 256 connections | A lower bound for an external lookup |

The in-process authorization step (about 2 to 5 µs, ESTIMATE) is about ten times cheaper than OPA's interpreted RBAC and about a thousand times cheaper than a networked decision service. The claim that total proxy CPU lands between Kong's and Pingora-class efficiency is what the load test must prove.

### 17.3 Headline figures (all ESTIMATE; same AZ, at most 60% CPU, no throttling)

Gateway residence time is the time a request spends inside the gateway, measured server side (accept to upstream write, plus upstream first byte to last client byte). It excludes the network round trip to the upstream, which is reported separately.

| Metric | Conservative | Expected | Optimistic |
| --- | --- | --- | --- |
| Residence, warm REST p50 / p95 / p99 | 0.25 / 0.6 / 1.2 ms | 0.09 / 0.20 / 0.45 ms | 0.06 / 0.12 / 0.25 ms |
| Round trip to a same-AZ upstream p50 / p99 | 0.3 / 0.5 ms | 0.1 / 0.25 ms | 0.05 / 0.1 ms |
| End-to-end added, warm REST p50 / p95 / p99, zone-local upstream | 0.55 / 1.0 / 1.7 ms | 0.19 / 0.4 / 0.7 ms | 0.11 / 0.2 / 0.35 ms |
| End-to-end added without zone-aware routing | 0.65 / 1.2 / 2.5 ms | 0.45 / 0.8 / 1.2 ms | not estimated |
| Extra for warm GraphQL, document-cache hit, p50 / p95 / p99 | +0.03 / +0.08 / +0.2 ms | +0.01 / +0.03 / +0.08 ms | +0.005 / +0.02 / +0.04 ms |
| GraphQL document-cache miss (1 to 5 KB), extra p50 / p99 | +0.15 / +1.0 ms | +0.05 to 0.15 / +0.3 to 1.0 ms | +0.02 / +0.2 ms |
| First request of a token on a pod, extra residence p50 / p99 | +0.08 / +0.3 ms | +0.03 / +0.1 ms | +0.015 / +0.05 ms |
| CPU per warm REST request (1 to 4 KB response) | 200 µs | 80 µs | 60 µs |
| Authorization share of that CPU | 5.5 µs | 1.9 µs | 0.85 µs |
| RPS per worker vCPU, saturation / planned at 50% | 5k / 2.5k | 12.5k / 6.25k | 16.7k / 8.3k |
| RPS per 4-worker pod, saturation / planned | 18k / 9k | 47k / 24k | 67k / 33k |
| Memory per pod, snapshot at 100k / 1M users | 80 / 480 MB | 30 to 60 / 170 to 220 MB | 20 / 100 MB |
| Pod memory request and limit | 3 GiB | 2 GiB | 1.5 GiB |

Without zone-aware routing about two thirds of upstream calls cross AZs and the p95 misses the 1 ms gate, so zone-aware routing over the EndpointSlice watch is a phase-1 requirement. A larger response adds about 0.5 to 0.7 µs of CPU per KB (ESTIMATE). End-to-end figures add percentiles, which does not combine exactly; the gate is on the measured residence histogram.

Proposed gates, replacing the decision-service figures of the first version (p95 3 ms, p99 10 ms, 2,000 checks per second per instance), all targets until measured:

- Residence, warm REST, hottest pod at most 60% CPU: p95 at most 0.5 ms and p99 at most 1 ms. End-to-end added p99 at most 2 ms with zone-aware routing. Warm GraphQL with a document-cache hit adds at most 0.1 ms over REST. First-seen token: residence p99 at most 1.2 ms.
- At least 5k planned rps per worker vCPU at 50% CPU on the production mix, and a knee at least 1.6 times the planned rate.
- Propagation, commit to every healthy pod, p99 at most 500 ms on the first-release fleet (6 to 9 pods); larger fleets are a later-phase estimate. During change bursts, request p99.9 within 20% of baseline.
- Zero CFS-throttled periods in the reference configuration.

The conservative case would miss these gates. That is deliberate: if the benchmark lands there, the response is to profile and optimise the hyper pipeline, not to relax the gates.

### 17.4 First-release sizing (owner decision D6, part)

The first release is sized and load-tested for a peak of 1,000 rps. Six pods with two worker threads each (12 worker vCPUs) give about 75k planned rps of gateway CPU at the expected figures and about 30k at the conservative figures (ESTIMATE). The fleet size is therefore set by zone availability, not load: two pods per zone across three zones (`minReplicas` 6, `maxReplicas` 9, CONFIG), about 170 rps per pod at peak. Each pod requests 1 CPU with no CPU limit and `TOKIO_WORKER_THREADS=2`; without a limit the apply and log threads use idle node CPU above the request; memory request equals limit at 2 GiB. The earlier request of 3 CPU bought availability, not capacity; the plan now requests 1 CPU (ADR 0031), and open decision D20 asks whether to raise it if test T2 misses NFR-33. Per-pod gates stay as designed.

Mechanisms needed only at tens or hundreds of pods are later-phase items, documented but not built: upstream subsetting, peer snapshot bootstrap, bulk-egress pacing beyond a simple record-rate cap, token-memo dilution work, follower fetching, per-AZ HPA, several h2c connections per endpoint, and 200-pod rollout targets. The design stays horizontally scalable.

For reference, a peak of 100k rps would need 5 pods at the expected figure, 12 at the conservative figure or 4 at the optimistic figure (ESTIMATE), plus zone headroom and a floor of two per zone.

### 17.5 What limits linear scaling

| Limit | Mechanism | When it binds (ESTIMATE) | Mitigation |
| --- | --- | --- | --- |
| Policy replication egress | Every pod reads every record; leader egress is event rate × size × pods | 100 events/s × 1 KB × 200 pods is 20 MB/s, fine; a bulk change of 100k events × 200 pods is 20 GB | Compaction, coarse bulk records, commit-time pacing |
| Sync-Fence fan-out | Admin write latency is the slowest pod | Above about 100 pods | Bounded wait, then fence stragglers (`T_hard` + 0.5 s) |
| Shared rate-limit state | A global quota needs a shared counter | Any route with a rate policy | Valkey with a deadline and a local fallback |
| Upstream connection pools | In-flight = rps × upstream latency | 760 connections per pod at 38k rps and 20 ms | h2c with several connections per endpoint; subsetting above about 50 pods |
| Upstream capacity | The gateway scales faster than upstreams | Always the real system limit | Per-upstream concurrency limits and load shedding |
| Access-log sink | 400 B per request is about 15 MB/s per pod at 38k rps | Sink ingest and log-path CPU (about 4 µs per request, 7% of CPU at full logging) | Denials, always-audit records and sampled allows only |
| Bootstrap thundering herd | N new pods each load a full snapshot | Burst of 50 pods × 1 GB | Bootstrap from the compacted topic with a separate quota; capped scale-up |
| NIC baseline bandwidth | About 5 KB in and out per request | About 70k rps per node on instances with a low baseline | Smaller nodes; size for baseline, not burst |

Nothing on the request path is shared between pods: no database, no Kafka call, no lock across pods. Throughput scales linearly with pods until upstream capacity, broker egress for bulk changes or the write barrier binds.

### 17.6 Load-test method

Latency gates use an open-loop, coordinated-omission-corrected generator (wrk2 or oha with latency correction); scenario gates use k6 with the constant-arrival-rate executor, failing a run if `dropped_iterations` is above zero. Microbenchmarks (digest, memo get, route match, decision, GraphQL parse and extract, RS256, ES256 and EdDSA verify) use criterion on the target instance type. Topology, as `architecture.md` section 20.5 fixes it: generators, the gateway and a stub upstream on dedicated EKS nodes across 3 AZs, with the first-release pod (1 CPU request, no CPU limit, 2 workers); a CFS-limit A/B, the 5-CPU reference pod and an Envoy baseline are later-phase characterisation. Added latency is the difference between the via-gateway and direct histograms per percentile, cross-checked with a server-side histogram. Procedure: find the knee; run open loop at 25, 50, 60 and 75% of it (2 minutes warm-up, 10 minutes measured, 3 repetitions); scenarios for warm REST, warm and cold GraphQL, cold tokens, policy changes at 100 per second plus bursts, scale-out mid-run, a forged-token flood and large GraphQL documents. Memory is measured at 100k and 1M subjects; 10M is a later-phase measurement. Test ids T1 to T33 are defined in the design and carried into `epics.md`.

## 18. Research: Kubernetes, EKS, Strimzi and the Platform

### 18.1 What exists today

Nothing in the organisation runs on Kubernetes. The current runtime is AWS ECS on Fargate behind a public HTTPS ALB, provisioned by Pulumi (Python) in `eu-central-1`, two AZs, CloudWatch for logs and alarms. There is no EKS cluster, Helm chart, manifest, operator, Strimzi resource, Prometheus, OpenTelemetry or Loki anywhere (VERIFIED by search and tree reads; search is index-limited). Rust services log JSON to stdout with `tracing_subscriber` and emit no OTLP. The organisation's own gateway plan was AWS API Gateway REST with a WAF and an internal ALB (issues #2 and #30, PR #35); IAM as the gateway replaces it (open decision D18). `api-gateway-infrastructure` is an unmodified Pulumi template. Core service has no authentication, so the gateway is its only enforcement point. Cross-service path collisions exist (`/api/health`, `/api/graphql`, `/api/docs`), and Notification service needs long-lived SSE and WebSocket connections. The platform is therefore a new decision, recorded as owner decisions D14b and D15 (section 19), and a phase-0 dependency.

### 18.2 Placement and edge

The gateway is the ingress data plane: AWS Network Load Balancer (L4, IP target mode, cross-zone off, provisioned by the AWS Load Balancer Controller) to gateway pods to upstream Services. TLS 1.3 terminates in the pod (D9) with an ECDSA P-256 certificate and session resumption; the NLB is a pure TCP listener. One L7 hop is the lowest latency and the fewest moving parts. Rejected: an L7 ingress controller in front (two hops; ingress-nginx maintenance halted in March 2026), a Gateway API implementation with IAM as `ext_authz` (contradicts the owner's decision), and an ALB on the hot path (adds a full HTTP hop). Because the gateway is the edge, the gateway team owns TLS certificate rotation, HTTP/2 hardening, slowloris and header-size limits and DoS posture; whether a WAF is required in front of the NLB is open (D9, WAF part). NLB facts (SOURCE, AWS documentation): TCP idle timeout default 350 s; health-check defaults give about 150 s to a healthy target and about 60 s to cut a failed one; a target that becomes unhealthy receives TCP RST on its connections, so long-lived connections are reset, not drained; when all targets are unhealthy the NLB fails open.

### 18.3 Workloads, probes and scaling

- Two Deployments from one image: `iam-gateway` (data plane) and `iam-control` (2 to 3 pods), plus `iam-migrate` and `iam-bootstrap` jobs. Reference manifests live under `deploy/kubernetes/`.
- Probes (as `architecture.md` sections 17.5 and 17.6): the startup probe passes only after a completed bootstrap with a verified `__head` digest, passed configuration gates, a freshness proof attached to a published snapshot and parsed JWT keys; the readiness probe passes only while the pod is fresh by the AZ-aware peer-relative rule, which uses local state plus the peers' freshness over HTTP and never the broker or PostgreSQL; the liveness probe is process-level only and never depends on Kafka or upstream health, so a broker outage does not restart every pod. A dead tail task exits the process. Readiness is AZ-aware and peer-relative, because a broker outage that hits every pod would otherwise fail every readiness probe at once; a pod that goes unready for staleness also sends GOAWAY or `Connection: close`, because the NLB resets connections to unhealthy targets.
- Scaling: HPA on CPU (target 50%, CONFIG) plus gateway-local saturation signals; never upstream in-flight and never Kafka lag, because lag measures policy freshness, not load, and a no-group consumer commits nothing for KEDA to read. Scale-up capped, scale-down slow (every scale-in ends long-lived connections). HPA sync period 15 s; scale-out reaction about 90 to 120 s with a spare node, up to 5 minutes (ESTIMATE).
- CPU: requests equal to steady-state need with no CPU limit (CFS throttling degrades tail latency: one published study saw about 5 times worse end-to-end tail latency from a limit on one pod, on a different workload, SOURCE), `TOKIO_WORKER_THREADS` set explicitly, large GraphQL documents (above 8 KB) parsed on a bounded 2-thread pool; RS256 verify stays inline on the workers, because it costs about 17 to 24 µs and runs only on a memo miss (`architecture.md` section 17.3; option rejected: moving RSA verify off the workers). Memory request equals limit.
- Topology: spread constraints across zones and hosts, a PodDisruptionBudget, rolling updates with `maxUnavailable 0` and a small absolute `maxSurge`, a preStop `exec` of `service drain` that flips readiness and waits `DRAIN_PROPAGATION_DELAY` (45 s, ESTIMATE) because endpoint removal and NLB deregistration are asynchronous (option rejected: a `sleep` hook, which cannot signal the process; `architecture.md` section 17.9), and connection draining on SIGTERM. Keep-alive lifetime is capped so that connections rebalance after scale-out.
- Upstream discovery: a read-only EndpointSlice watch through a plain hyper client (`architecture.md` section 6.5; option rejected: the `kube` crate, which is not on the allow-list) with zone-aware power-of-two-choices, so the upstream hop stays in the pod's AZ. kube-proxy balances per connection, not per request, and HTTP/2 keep-alive would pin a client to one pod; headless DNS alone does not give zone affinity. Pools are capped per endpoint and their idle timeout is shorter than the upstream's keep-alive and the NLB's 350 s.
- Per-pod Kafka identity: group-less manual assignment with `client.id` set to the pod name; ACLs `Read`, `Describe` and `DescribeConfigs` on the state topic only, no group ACL (`architecture.md` section 17.11; `DescribeConfigs` is needed by the configuration gates).
- Network policy and secrets: NetworkPolicy limits gateway egress to Kafka, the upstreams, Valkey, Loki, gateway pods' internal port and the Kubernetes API, and admits each gateway listener only from its own callers (`architecture.md` section 16.8); JWT public keys and Kafka credentials come from Secrets.

### 18.4 Strimzi (D14b, D15)

Strimzi is a CNCF project (incubating since 2024-02-08) and the standard path for Kafka on Kubernetes (KRaft-only in recent releases; which versions are currently supported is UNVERIFIED because no support-policy page was read). Kafka configuration gates are expressed as `Kafka`, `KafkaNodePool`, `KafkaTopic` and `KafkaUser` resources: RF 3 across zones (`broker.rack`), `min.insync.replicas` 2, unclean leader election off, ACLs through `KafkaUser` (principals `iam-control`, `iam-gateway`, `iam-gateway-bootstrap`, `notification-service`), topics reconciled by the Topic Operator and never created by the service. The gateway reuses the notification service's variable names (`KAFKA_BOOTSTRAP_SERVERS`, `KAFKA_SASL_MECHANISM`, `KAFKA_SASL_USERNAME`, `KAFKA_SASL_PASSWORD`, `KAFKA_SECURITY_PROTOCOL`). Running Kafka ourselves adds storage, disk sizing and rolling broker upgrades to our operations; for a team without Kafka experience a managed service lowers risk, which is why this is flagged, but the owner decided on Strimzi. Broker session and failover timings are under our control, which helps the 5 s target.

### 18.5 Loki and the access log (D13)

Loki runs in simple scalable mode on EKS with S3 object storage and replication factor 3 across zones, with a Grafana Alloy DaemonSet as the collector (assumption D26). Retention defaults: `lane="access"` 90 days and `lane="audit"` 400 days (D24). Limits to state plainly: no secondary index, slow queries over long ranges, retention per stream. The API is bounded accordingly (section 8). The security audit chain stays in PostgreSQL.

### 18.6 Other platform items

- Observability: Rust services emit no metrics endpoint today. The gateway exposes a Prometheus-compatible endpoint on the internal port; the metrics stack (Prometheus or an OpenTelemetry collector, HPA custom metrics adapter) is open decision D15 (rest).
- Valkey: in-cluster primary plus two replicas with Sentinel, one node per zone (assumption D23), or ElastiCache for Valkey; the port makes either a configuration change.
- IaC: Pulumi is the organisation's IaC; reference manifests live in this repository under `deploy/`, production copies in the platform repository.

## 19. Owner Decisions

Decided on 2026-11-21 (`gw-owner-decisions.md`), binding, overriding the design's defaults where they differ. The rationale column gives the owner's reason or the reason the design records.

| Id | Topic | Decision | Rationale |
| --- | --- | --- | --- |
| D1 | Session revocations from User service | IAM consumes the User service events (session revoked, all sessions revoked, refresh-token theft, user deleted) from Kafka, the common message bus. R5 is amended: IAM produces only IAM topics and additionally consumes the User service topic. The control plane consumes with a consumer group, writes revocation state to PostgreSQL and republishes it on the state topic. No REST call from User service; the revocation API stays for operators | Owner: "We will have message bus for all microservices, so iam should read the event from user service." Keeps one ordered stream for gateway pods |
| D14a | Kafka client | krafka, with a spike first; rdkafka stays the fallback | Matches the org precedent and the `deny.toml` and builder-image constraints; the spike removes the maturity risk before the guarantee is declared unconditional |
| D2, D3 | Freshness | `T_hard` 15 s now, 5 s target. Default mode: the bound counts from the Kafka acknowledgement. Revocation-class writes use Sync-Fence by default (D3b) | Kafka failover timings are tuned first; strict mode is built only if the quorum spike or T15 fails |
| D4 | Rate limits | Valkey for exact global quotas in phase 1, behind a port; bounded timeout, then a conservative per-pod limiter; never blocks authorization; holds no authorization data; runs on Kubernetes | Owner: "We should use some distributed storage for rate limits." Counters are the only genuinely shared mutable state |
| D9 | TLS | Terminates in the gateway pod, behind an L4 NLB | One L7 hop and the lowest latency; the gateway team owns the edge |
| D7 | Notification service | Reads `iam.events.v1` from Kafka; IAM does not write into its topic | Notification consumers forward every record to browsers |
| D13 | Access log | Dedicated log store, Loki; the security audit log stays in PostgreSQL; the partitioned table and its maintainer are dropped | Gateway traffic makes one record per request, far above what the primary should absorb |
| D8 | Streams | WebSocket, SSE and GraphQL subscriptions in phase 1 with per-coordinate authorization at subscribe time, re-evaluation on change, lifetime caps and drain | Notification service needs long-lived connections |
| D14b, D15 | Platform | AWS EKS, Kafka in-cluster with Strimzi, NLB with IP targets through the AWS Load Balancer Controller | Owner platform choice; broker timings under our control |
| D6 (part) | First-release peak | Up to 1,000 rps; a small fleet sized for zone availability; large-fleet mechanisms deferred | Avoids building machinery for tens of pods now |
| ADR 0023 | Protected allow-list change | Approved (2026-11-21); applied in Story 2.3 with the `approved-config-change` label | Lets the gateway crates live in `iam-infrastructure` behind domain ports |
| Story 1.8 | Mutation gate | Push step of the mutation shard job runs `make mutation-tests-diff` (agreed 2026-11-22); the protected matrix resize is NOT approved and is recorded as a request only | Keeps shards within 45 minutes without a protected change |
| Delivery | Pull requests | All 16 epics in one pull request for issue #8 (2026-11-22) | Owner: "we don't need one pr for each epic, you can work on the all epic in one pr" |
| Working rule | Questions | Standing instruction: do not stop to ask; take the recommended option, record it, continue (protected changes excepted) | Owner instruction |

Earlier binding decisions still hold: IAM's management API has REST and GraphQL parity; scope includes REST/OpenAPI permissions and the security and access logs; authentication stays in User service; decisions fail closed; the plan, first a local draft with placeholder issue `0`, ships for issue #8 in one pull request. The owner's requirements R1 to R7, numbered as in the gateway design, also bind: IAM is the gateway in the request path (R1); the lowest latency (R2); the policy cache is fed from Kafka (R3); REST and GraphQL parity for every IAM management capability (R4); Kafka is used for updates about IAM (R5, amended by D1); an in-process cache only if it can be made distributed (R6); Kubernetes for the gateway and Notification service (R7). "Authentication stays in User service" is an earlier binding decision, listed above, not one of R1 to R7.

## 20. Open Decisions

Each keeps the stated default until the owner answers. None blocks planning; the readiness file tracks them.

| Id | Decision | Default proposed here |
| --- | --- | --- |
| D5 | Anonymous routes (sign-in, token refresh) during a Kafka outage or leader loss beyond `T_hard`: fence, or keep serving on route-table age only? | Fence |
| D6 (rest) | Cardinality: users, tenants, distinct scopes, assignments per user, roles, active sessions, session request-rate distribution, requests per connection, average rps, response-size distribution | Needed to size memory (12.5% rule) and the token memo; the first release uses 2 GiB pods and a 200k memo |
| D9 (WAF) | A WAF or DDoS layer in front of the NLB (CloudFront or ALB hop)? | No WAF in the first release; revisit with the security review |
| D10 | One public host with prefix routing, or one host per service? Will PHP upstreams accept h2c? | One host per service; HTTP/1.1 to PHP upstreams; verify h2c later |
| D11 | Will User service add `kid` and a JWKS endpoint? | Ask; until then a Secret with up to three keys, tried newest first |
| D12 | Which token families must pass the gateway (900 s first-party, 3,600 s Lexik, `PT1H` League OAuth2)? | 900 s only; others rejected unless listed |
| D15 (rest) | Metrics stack for HPA custom metrics; production home of the Kubernetes manifests | Prometheus-compatible endpoint on the internal port; reference manifests under `deploy/`, production copies in the platform repository |
| D16 | A separate gateway binary with a build-time no-`sqlx` rule now, or later as hardening? | Later; credentials and NetworkPolicy in release 1 |
| D17 | Are routes, upstream names and rate policies "updates about IAM" for R5? May `iam-control` publish a liveness record every second if the replica-quorum check cannot be built? | Yes to both; the liveness record is used only if the quorum check fails |
| D18 | Retire the AWS API Gateway plan (issues #2 and #30, PR #35) | Yes, after the gateway enforces in the test environment |
| D19 | Crate placement for the gateway code | Gateway modules inside the `authorization/iam` crates; alternatives: a shared-domain kernel with duplicated application code, or a `[contexts]` edit |
| D20 | Capacity cost: each first-release pod requests 1 CPU with no limit for 2 workers (cut from 3 CPU) | Keep 1 CPU; raise it only if test T2 shows hot-pod latency above NFR-33 |
| D21 | Pingora as a fallback needs time-limited `deny.toml` advisory ignores and an experimental rustls backend | Do not pre-approve; the fallback is profiling hyper |
| D22 | Fleet rollout times at 200 pods and peer snapshot bootstrap | Not relevant to the first release |
| D23 | Valkey on Kubernetes: in-cluster with Sentinel, or ElastiCache for Valkey | In-cluster with Sentinel, one node per zone (assumption) |
| D24 | Loki retention per lane and the scope of audit-or-deny | `lane="access"` 90 days, `lane="audit"` 400 days; audit-or-deny for always-audit and sensitive keys only |
| D25 | Name, partitioning and payload of the User service topic | `user.events.v1`, keyed by user id, neutral envelope with event id, `occurredAt`, `userId`, `sessionId`; to agree with the User service team |
| D26 | Loki deployment mode and storage | Simple scalable mode on EKS with S3, replication factor 3 across zones; Grafana Alloy DaemonSet |
| D27 | Should the first release drop AZ-aware peer-relative readiness, the peer cross-check of the freshness proof and zone-aware upstream selection (EndpointSlice watch) in favour of local readiness and ClusterIP Services with topology-aware routing, as D6 might allow? | Keep them: they address correlated failures (one pod or one zone cut off from Kafka while the NLB fails open) that exist at 6 pods |
| D28 | Calls between services: through the gateway's east-west listener, or direct with mTLS or a signed principal header? | Through the gateway's east-west listener (FR-90); upstreams admit ingress only from gateway pods |

> Assumption: D9 (WAF): no WAF in the first release, because AWS WAF cannot attach to an NLB and a CloudFront or ALB hop would add an L7 hop to every request; the security review may require one later.

> Assumption: D17: routes, upstreams and rate policies are "updates about IAM" under R5 and are published on the state topic, because the route table is authorization state that must share the version clock; Epic 8 relies on this. Control-plane liveness ticks are built only if the replica-quorum check fails its spike or T15.

> Assumption: D18: the earlier AWS API Gateway plan is retired once the gateway enforces in the test environment, because two edges would duplicate routing and rate limits.

> Assumption: D20: each first-release pod requests 1 CPU with no limit for 2 workers, because zone availability, not load, sets the fleet size and 3 CPU per pod would leave the fleet about 30 times oversized; it is revisited after the first production month.

> Assumption: D21: the Pingora dependency-policy exceptions are not pre-approved, because they need advisory ignores in the protected `deny.toml`; the data-plane fallback is profiling the hyper pipeline.

> Assumption: D22: fleet rollout targets at 200 pods and peer snapshot bootstrap are not relevant to the first release, by D6; they stay later-phase items with triggers.

> Assumption: D27: peer-relative readiness, the peer cross-check and zone-aware selection stay in the first release until the owner answers, because removing them later is cheaper than adding them under incident pressure.

> Assumption: D28: east-west calls go through the gateway's east-west listener, because it reuses the pipeline, the route table and service tokens and needs no mesh or new credential type.

Later-phase items, deferred by D6 or kept only as fallbacks, each with the trigger that would start it: upstream subsetting (fleet above about 50 pods); several h2c connections per endpoint (about 50 pods or D10 answered); peer snapshot bootstrap (rollouts limited by leader egress); `N`-aware bulk pacing (about 20 pods or bulk changes above about 50 MB); follower fetching (leader egress binds); token-memo dilution work (about 20 pods or a memo hit ratio below 90%); per-AZ HPA and a KEDA saturation scaler (about 20 pods or skew above 1.2); a 200-pod rollout target (about 50 pods); strict freshness mode (the quorum spike or T15 fails); control-plane liveness ticks (the quorum check cannot be built and D17 allows it); persisted queries and an allow-list mode (owner request); a two-tier cache for assignments (snapshot above 12.5% of the memory request); a separate gateway binary without `sqlx` (D16).
