# Architecture: IAM API Gateway and Authorization Service

| Field | Value |
| --- | --- |
| Bundle | `specs/8-iam-scaffolding-and-spikes/` |
| Issue | `#8` "Scaffold the IAM context and run the phase-0 spikes" (VilnaCRM-Org/api-gateway-service); one pull request delivers all 16 epics (owner decision, 2026-11-22) |
| Date | 2026-11-22 (derived from the master plan of 2026-11-21) |
| Inputs | `research.md`, `product-brief.md`, `prd.md`, the Miro C4 board (IAM frames), the datastore decision (PostgreSQL as system of record), the gateway design (IAM as the API gateway with a control plane and a data plane, revised for the owner decisions of 2026-11-21); the master plan `specs/0-iam-authorization-service/` (iam-service checkout, 2026-11-21, placeholder issue 0) and the Epic 1 bundle of this directory (2026-11-22) |
| Bounded context | `authorization/iam` (absent from `[workspace].members`; Story 1.1 scaffolds it) |

This document places every component that the PRD requires into the layers of one bounded context and into the template's composition root. IAM is the API gateway: one image runs as `iam-gateway`, the data plane that authenticates, authorizes and proxies every request, and as `iam-control`, the control plane that owns PostgreSQL and serves IAM's management API. Policy reaches every gateway pod through one ordered Kafka topic and is held in an in-process snapshot that carries a freshness proof. The document keeps the Miro board's names (adapted to Rust naming, see `research.md` section 2.5), adds the components the board lacks, and records every deviation in an ADR (section 22). Requirements are cited by their PRD identifiers (`FR-n`, `NFR-n`); gates are cited by their `make.*` key or by their repository gate name. Every performance figure is labelled **ESTIMATE** (reasoning, not measured), **target** (a goal a benchmark story must prove) or **CONFIG** (a chosen value). Nothing in this document has been measured.

## Tech Stack

- Rust toolchain 1.99.1 (channel from `rust-toolchain.toml`), edition 2024
- Workspace crates used: `shared-domain`, `shared-application`, `shared-infrastructure`, `health-check-domain`, `service`, `test-support`
- Workspace crates added: `iam-domain`, `iam-application`, `iam-infrastructure`
- Runtime crates used: `axum`, `tokio`, `tower`, `tower-http`, `async-graphql` (including its `parser` re-export), `utoipa`, `utoipa-axum`, `serde`, `serde_json`, `validator`, `sqlx` (postgres, macros, migrate, uuid, plus the added `time` feature), `moka`, `rand`, `async-trait`, `thiserror`, `tracing`, `tracing-subscriber`, `uuid`, `futures-util`, `humantime`, `clap`
- Runtime crates added: `hyper`, `hyper-util`, `hyper-rustls`, `rustls`, `rustls-pki-types`, `tokio-rustls`, `http`, `http-body-util`, `bytes`, `arc-swap`, `matchit`, `ppp`, `jsonwebtoken` (feature `aws_lc_rs`), `sha2`, `krafka`, `redis` (Valkey client), `rustix`, `tokio-tungstenite`, `prometheus-client`
- Test crates used: `rstest`, `proptest`, `fake`, `cucumber`, `http-body-util`
- Test crates added: `aws-lc-rs` (runtime RSA test keys), `krafka` with the `test-broker` feature, `criterion`

## Constraints

(a) Commit convention: commit each story with the hooks active as `<type>(#8): story N.M <title>` (type one of feat, fix, refactor, build, chore, ci, docs, style, perf, test). Stay on the branch the plugin checked out and never commit on `main`; never push, the plugin command pushes; never bypass a hook.

(b) Story dispatch: a story whose `Depends on:` stories are done is independent.
When the rust-backend-sdlc:rust-implementer agent is available, independent stories may run as parallel subagents under the DB rule; otherwise implement stories sequentially under the same DB rule.
DB rule: parallel agents run only the DB-free targets `make.format` (make format), `make.lint_code` (make lint-code), `make.unit_tests` (make unit-tests), `make.architecture` (make architecture) and `make.complexity` (make complexity); one serialized verify step at a time runs the DB-backed targets `make.setup_test_db` (make setup-test-db), `make.integration_tests` (make integration-tests), `make.tests_with_coverage` (make tests-with-coverage), `make.e2e_tests` (make e2e-tests) and `make.sqlx_prepare` (make sqlx-prepare). A target that reads not available is skipped and reported.

- Scope: all 16 epics (127 stories) in one pull request for issue #8 (owner, 2026-11-22). Story 1.1 runs first and alone; spike stories 1.2 to 1.6 add tests, never production code that uses krafka.
- Protected files (protected-config.toml): the ADR 0023 allow-list delta (section 3.1) is owner-approved (2026-11-21) and applied only in Story 2.3, with the approved-config-change label set by a maintainer. The Story 1.8 mutation-matrix resize is NOT approved: record the request only. Any other protected change a story needs is not approved: stop and report to the owner.
- Kafka client: krafka. If Story 1.7 records a failed must-pass capability, stop before Epic 7 for the owner; the rdkafka fallback needs an owner-approved build change and openssl-sys exception. openssl-sys stays banned; never the rsa crate. Spike crates (krafka, jsonwebtoken aws_lc_rs, criterion, aws-lc-rs) are dev-dependencies of crates/service, each version declared once in [workspace.dependencies]; the spike modules leave in Story 1.7.
- Every API story ships REST and GraphQL through one handler, regenerates both snapshots (make generate-openapi-spec, make generate-graphql-spec) and its pinning tests; the API Surface Summary of prd.md is the parity checklist.
- Decisions fail closed; raw credentials, documents and concrete paths are never stored, logged or returned. Versioned transactions bump iam_policy_epoch under its row lock; the gateway never reads PostgreSQL.
- One image, two run modes: service gateway (iam-gateway) and service serve (iam-control). IAM produces only iam.policy.state.v1 and iam.events.v1; only iam-control consumes user.events.v1; Valkey holds rate-limit counters only.
- Time only through Clock and BootClock, ids through UuidGenerator, randomness through Rng; no mod.rs; no unwrap, expect, panic or indexing on production paths; never #[allow], #[mutants::skip], #[coverage(off)] or a coverage exclusion.
- Migrations: reversible pair via make create-migration, reviewed down migration, rollback round trip only when an operator allows it (else not run (ask rule)), make validate-sqlx-metadata passing, .sqlx/ committed in the same story.
- Performance figures are targets or host measurements, never make ci gates; each crate integration suite stays within 15 s on CI (section 19).
- Leave some-module and the template Makefile untouched (service targets in make/service.mk); never change lib.rs; add a synchronised file to .templatesyncignore in the story that first changes it and extend the seam check.
- Local runs: host ports 8080, 8081 and 18081 are taken; set APP_PORT=28081, STRUCTURIZR_PORT=28080 and a free LOAD_TEST_APP_PORT.

## 1. Context Map and System Context

### 1.1 Systems around IAM

| System | Relationship to IAM | Direction and protocol | Status today |
| --- | --- | --- | --- |
| Clients: CRM SPA, Website, partners, internal callers | Send every API request to VilnaCRM's public hosts; IAM authenticates, authorizes and proxies them | Client to the AWS Network Load Balancer, then to `iam-gateway` over TLS (HTTP/1.1, HTTP/2, WebSocket, SSE) | Exist; no gateway authorizes them today |
| Customers (the board's Customer person) | The subjects whose requests IAM authorizes | Their User service token travels in `Authorization: Bearer` or the `__Host-auth_token` cookie | Exist |
| Administrators (through the CRM frontend) | Manage roles, assignments, specifications, permissions, upstreams, routes, rate policies and revocations, and read the logs | Through `iam-gateway` to `iam-control`'s management API, REST or GraphQL, with a user token | New |
| AWS Network Load Balancer | L4 entry point; balances connections, not requests | TCP 443 to gateway pod IPs (IP targets, cross-zone off, Proxy Protocol v2), provisioned by the AWS Load Balancer Controller | New (prerequisite, `research.md`) |
| `iam-gateway` (this plan, data plane) | Terminates TLS, verifies tokens offline, authorizes from the in-process policy snapshot, rate-limits, proxies, logs | Reads `iam.policy.state.v1`; calls upstreams, Valkey, Loki and the Kubernetes API | New |
| `iam-control` (this plan, control plane) | Owns PostgreSQL; serves the management API and the decision API from PostgreSQL; publishes state and events; consumes User service events; coordinates Sync-Fence | Reached only through the gateway (management API) and from gateway pods' Sync-Fence answers | New |
| User service | Upstream identity provider (customer/supplier: IAM conforms). Issues the RS256 tokens IAM verifies; publishes session and user events | Publishes `user.events.v1` to Kafka; proxied by the gateway like any upstream; IAM never calls it | Tokens exist; it publishes its events to SQS only today and must add Kafka publication (external prerequisite) |
| Notification service | Downstream consumer of IAM change events (published language: the envelope `{id, type, occurredAt, data}`) | Tails `iam.events.v1` with its own no-group consumer; its SSE and WebSocket endpoints are proxied by the gateway | Reads Kafka already; the `iam.events.v1` tail is a Notification service change (external prerequisite) |
| Upstream services (Core, Payment, Analytics, Webhook, Integration, IP telephony, User, Notification, `iam-control`) | Receive authorized requests with principal headers; supply OpenAPI and GraphQL specifications through their delivery pipelines; may call the internal decision API for their own checks | Gateway to upstream over HTTP/1.1 or h2c inside the cluster; NetworkPolicy admits only gateway pods | Exist; core-service has no own authentication |
| PostgreSQL 16 (RDS Multi-AZ with synchronous replication) | IAM's own system of record; used by `iam-control` only | `sqlx` over TCP from `iam-control`; one `LISTEN` session for the relay leader's wake-up | Template-provided |
| Kafka on Strimzi (3 brokers, one per AZ) | Common message bus. Carries IAM's state topic and events topic, and User service's event topic | `krafka` over SASL SCRAM-SHA-512 and TLS | New in the org (prerequisite) |
| Valkey (primary and 2 replicas with Sentinel) | Exact global rate-limit counters for routes that carry a rate policy | `redis` crate from gateway pods; never on the authorization path | New (prerequisite, assumption D23) |
| Loki with Grafana Alloy | Access-decision log store | Gateway: stdout lane shipped by Alloy, audit lane pushed to the Loki push API; `iam-control` queries with LogQL | New (prerequisite, assumption D26) |
| Kubernetes API | EndpointSlices for upstream discovery; pod list for Sync-Fence | Read-only RBAC from both planes | EKS (prerequisite) |

### 1.2 Context map

- **IAM (this plan)** is the authorization context and VilnaCRM's API gateway. It owns roles, grants, user-role assignments, the permission catalogue generated from specifications, upstreams, routes, rate policies, revocation state, decisions, the policy state topic, and the security and access logs.
- **User service to IAM** is a conformist relationship with an anticorruption layer inside IAM: `JwtAccessTokenVerifier` translates User service's token claims into IAM's `AccessToken`, and `KrafkaUserEventSource` translates User service's Kafka events (neutral envelope or Symfony Messenger `DomainEventEnvelope`) into IAM's `UserRevocationEvent`. Nothing of User service's wire format leaks past `iam-infrastructure`, and gateway pods never read `user.events.v1`.
- **IAM to Notification service and other consumers** is an open-host relationship with a published language: the `iam.*` event catalogue of section 15 on `iam.events.v1`, in Notification service's envelope.
- **IAM to upstream services** is an open-host relationship through principal headers (`X-IAM-Subject`, `X-IAM-Subject-Kind`, `X-IAM-Session`, `X-IAM-Policy-Version`, `X-Request-Id`, `X-Forwarded-For`). Upstreams trust them because a NetworkPolicy admits only gateway pods.
- **Microservices to IAM** is an open-host relationship: the decision API (validate access, batch, resolve token) on the gateway's decision listener and on `iam-control`, and the specification-upload contract, versioned through IAM's OpenAPI and GraphQL snapshots.
- **IAM to the platform** (Kafka, Valkey, Loki, Kubernetes API) runs through IAM-owned ports with infrastructure adapters, so the domain and application layers name no platform product.

## 2. Topology and Deployables

### 2.1 Diagram

```
 Clients (CRM SPA, Website, partners, internal callers)
        | TLS: HTTP/1.1, HTTP/2, WebSocket, SSE (TLS terminates in the gateway pod)
        v
 AWS NLB (L4, IP targets, cross-zone off, Proxy Protocol v2, health check /internal/ready)
        | TCP 443 -> 8443
 +----------------------------------- AWS EKS cluster -----------------------------------+
 |  Deployment iam-gateway (service gateway)   first release 6..9 pods, 2 per AZ          |
 |    public :8443     TLS -> limits -> read-your-writes -> snapshot + freshness -> route |
 |                     -> rate limit -> authenticate -> authorize -> rewrite -> forward   |
 |    east-west :8444  service-to-service calls through the same pipeline (FR-90)         |
 |    internal :9090   /internal/freshness, /internal/policy/applied                      |
 |                     (iam-control and gateway pods only)                                |
 |    decision :9091   validate, validate batch, resolve token (iam-gateway-decision)     |
 |    probe :9092      /ping, /internal/startup, /internal/ready, /metrics,               |
 |                     loopback-only /internal/drain                                      |
 |    threads: 2 tokio workers | 1 apply thread | 1 log writer                            |
 |    no PostgreSQL credentials, no Kafka producer, no admin handlers                     |
 |      |              |                 |                 |                 |            |
 |   Valkey      Kafka (Strimzi)       Loki           upstream Services  Kubernetes API   |
 |  (counters)   iam.policy.state.v1   (audit lane    (EndpointSlices)   (EndpointSlices) |
 |               read by every pod,    push; Alloy                                        |
 |               no consumer group     ships stdout)                                      |
 |                     ^  iam.events.v1 --> Notification service (tails it)               |
 |                     |  user.events.v1 <-- User service (publishes)                     |
 |                     | produce (p0, acks=all, 1 in flight, fenced relay)                |
 |                     | consume user.events.v1 (group iam-control-user-events)           |
 |  Deployment iam-control (service serve)   2..3 pods                                    |
 |    management API (REST + GraphQL, parity), decision API from PostgreSQL,              |
 |    outbox relay, User service event consumer, anti-entropy, tombstone emitter,         |
 |    maintenance, Sync-Fence coordinator (pod list), audit chain, Loki queries           |
 |                     | SQL                                                              |
 |  PostgreSQL 16 (system of record, synchronous replication)                             |
 +---------------------------------------------------------------------------------------+
```

### 2.2 Deployables

| Name | Kind | Command | Runs | Scales by |
| --- | --- | --- | --- | --- |
| `iam-gateway` | Kubernetes Deployment, data plane | `service gateway` | Public TLS listener, east-west listener (calls between services), decision listener (decision API), internal listener (Sync-Fence answers, peer freshness), probe listener (probes, metrics, loopback-only drain), Kafka tail and freshness probe, apply thread, EndpointSlice watch, stream and subscription registry, access-log writer (stdout lane and Loki audit lane), local guard and Valkey client | CPU at 50 % (CONFIG) with a scale-up cap; first release 6 to 9 pods |
| `iam-control` | Kubernetes Deployment, control plane | `service serve` | Management API (REST and GraphQL), decision API from PostgreSQL, relay, User service event consumer, anti-entropy, tombstone emitter, maintenance, bulk runner, Sync-Fence coordinator, rejected-attempt writer, access-log queries to Loki | Administrative load; 2 to 3 pods for availability |
| `iam-migrate` | Job | `service migrate` | Migrations | – |
| `iam-bootstrap` | Job | `service iam-bootstrap --admin-user <uuid>` or `--admin-service <service-name>` | First administrator and seeding of IAM's own upstream and routes | – |
| one image | the service image, built by the existing Dockerfile | – | Both Deployments and both Jobs | – |

### 2.3 One image, two run modes, isolation

- One composition root (`crates/service`) links every crate, so the image links `sqlx` in both modes. The run mode decides what starts: `service gateway` builds its own tokio runtime in `command/gateway.rs` and never opens a database pool; `service serve` keeps the template's server and adds the control tasks.
- Isolation in the first release is by **credentials and network** (FR-45, NFR-14): gateway pods mount no database Secret; they hold two Kafka principals (`iam-gateway` for the tail and probe, `iam-gateway-bootstrap` for the quota-limited bootstrap read), each with `Read`, `Describe` and `DescribeConfigs` on `iam.policy.state.v1` only; a NetworkPolicy denies gateway egress to PostgreSQL. The Valkey password and, when enabled, the Loki tenant credentials are the only other Secrets a gateway pod mounts.
- A second composition root with a build-time "no `sqlx` in the gateway binary" rule is a later hardening option (owner item D16), because every crate must match exactly one layer pattern in `architecture.toml` and a per-crate transitive ban needs a new layer pattern, which is a protected change.

### 2.4 Alternatives considered

| Topology | Verdict | Reason |
| --- | --- | --- |
| Single binary, every pod runs everything | Rejected | PostgreSQL and Kafka write credentials in every internet-facing pod; administrative bursts share tokio workers with proxied traffic; the database pool grows with the gateway fleet |
| Two binaries, two images | Deferred as hardening (D16) | Best blast radius, but a second composition-root crate and a new protected layer pattern; credentials and NetworkPolicy give most of the benefit now |
| Envoy or NGINX edge with IAM as `ext_authz` | Rejected | Contradicts the owner's decision that IAM is the gateway; two hops; GraphQL coordinates need body buffering in the edge. Kept as an out-of-repository benchmark baseline |
| Pingora data plane | Blocked under the current dependency policy | `pingora-core` pulls crates with "unmaintained" advisories while `deny.toml` admits none; the rustls backend is experimental. Usable only with an owner pre-approval of time-limited ignores (D21); the real fallback is profiling the hyper pipeline |
| L7 ingress controller in front | Rejected for latency | Two L7 hops; needed only if a WAF is mandated (D9 WAF part, open) |
| TLS at an NLB TLS listener with ACM | Rejected by the owner (D9) | TLS terminates in the gateway pod; the NLB stays a plain TCP listener |
| Decision API on the control plane only | Rejected as the hot path | Would not scale with load. Microservices call the gateway pods' decision listener, which decides from the snapshot; `iam-control` serves the same contract from PostgreSQL so the published contract, e2e scenarios and Schemathesis run against one router |

## 3. Bounded Context and Crates

> Assumption: IAM is one bounded context, `authorization/iam`, with the gateway code as modules inside its three crates (owner item D19, default). Roles, grants, the catalogue, specification activation, the policy version, state rows, the outbox and the audit log change in one transaction, and both planes need the same decision kernel and the same GraphQL coordinate extraction. A separate `gateway` context could not depend on `iam`, because the architecture gate accepts only the `shared` key under `[contexts]`; moving the kernel into `shared-domain` would leave GraphQL extraction (which needs `async-graphql`, an application crate) duplicated or force edits to the template-synchronised `shared-application`. The group `authorization` keeps the context out of the template-synchronised `company-subdomain` group. A separate gateway binary with its own crates stays the later hardening path (D16).

| Crate (package) | Path | Layer | Modules (new or changed) |
| --- | --- | --- | --- |
| `iam-domain` | `crates/authorization/iam/domain` | domain | Aggregates and the `policy/` kernel (`PermissionKey`, `WildcardMatcher`, `DecisionPolicy`, `CompiledRoleSet`, `PathNormalizer`, `RestOperationMatcher`, `EffectivePermissionComposer`, guards); new `gateway/` (`Upstream`, `Route`, `RatePolicy`, their value objects, `RouteConflictGuard`, `AnonymousRouteGuard`, `RouteScopeGuard`, `CorsRule`, `CsrfRule`, `RateDecisionRule`), `replication/` (`StateKey`, `StateRecord`, `PolicyVersion`, `LogEpoch`, `RelayEpoch`, `VersionAssembly`, `FreshnessRule`, `PropagationOutcome`, `WriteMode`), `revocation/` (`SessionRevocation`, `UserTokenCutoff`, `GlobalTokenCutoff`, `RevocationRule`, `TokenLifetimeRule`), `bulk/` (`BulkOperation`), `port/` (all ports of section 4.4) |
| `iam-application` | `crates/authorization/iam/application` | application | Existing `command/`, `query/`, `http/`, `graphql/`, `error.rs`; the handlers of section 14; `gateway/` use cases (`RequestAuthorizer`, `GraphQlRequestAnalyzer`, `SubscriptionAuthorizer`, `StreamReauthorizer`, `ReadYourWritesBarrier`); `task/` loops of section 5.6 |
| `iam-infrastructure` | `crates/authorization/iam/infrastructure` | infrastructure | `persistence/` (PostgreSQL), `kafka/`, `snapshot/`, `token/`, `upstream/`, `kubernetes/`, `rate_limit/`, `access_log/`, `clock/` adapters of section 6 |
| `service` | `crates/service` | composition root | `command/gateway.rs` (own tokio runtime builder: `TOKIO_WORKER_THREADS`, `max_blocking_threads` 16), `bootstrap/gateway/` (`listener.rs` TLS and Proxy Protocol accept for the public and east-west listeners, `pipeline.rs`, `internal.rs` internal router, `probe.rs` probe router, `decision.rs` decision API listener, `streams.rs` splice and registry wiring, `graphql_ws.rs` frame codec with `tokio-tungstenite`, `apply_thread.rs`, `drain.rs`, `metrics.rs` Prometheus rendering), `bootstrap/tasks.rs` (control tasks) |
| `health-check-domain` | `crates/internal/health-check/domain` | domain | `Dependency` enum (template-ignored seam) gains `Kafka` and `AccessLogStore`; `PolicyListener` is not added |
| `test-support`, `e2e-tests` | `tests/support`, `tests/e2e` | test layers | Fakes per port with `new()` and `failing()`; the e2e world starts `iam-control` and an in-process gateway against the compose Kafka, a fake upstream and static pod and endpoint lists |

Dependency edges (each one becomes a `workspace.dsl` relationship, section 18):

- `iam-domain` depends on `shared-domain`.
- `iam-application` depends on `iam-domain`, `shared-domain` and `shared-application`.
- `iam-infrastructure` depends on `iam-domain`, `shared-domain` and `shared-infrastructure`.
- `service` depends on all three IAM crates and on `health-check-domain` (already present).
- `test-support` depends on `iam-domain` (dev-only for the IAM application and infrastructure crates).

Application and infrastructure never depend on each other. No `[contexts]` change and no change to the `shared-*` crates. The `[workspace.dependencies]` path entries for the three crates are added at first use, as the unused-dependency gate requires. Module layout follows the template: one file plus a sibling directory per module (no `mod.rs`), unit tests in a sibling `tests.rs`, integration tests in `tests/integration/{main,...}.rs` of the crate.

### 3.1 Allow-list delta (ADR 0023, owner-approved 2026-11-21, applied in Story 2.3)

The owner approved this protected change on 2026-11-21. Story 2.3 applies it to `architecture.toml` in its first commit, in the single pull request of issue #8, with the `approved-config-change` label set by a maintainer (NFR-6). Stories that use its crates depend on Story 2.3 directly or transitively:

- Domain `external`: unchanged (`async-trait`, `thiserror`, `uuid`).
- Application `external`: unchanged (`async-graphql` and `tokio` are already allowed; `moka` stays forbidden transitively). Application `dev_external`: add `criterion`.
- Infrastructure `external`: add `arc-swap`, `bytes`, `http`, `http-body-util`, `hyper`, `hyper-rustls`, `hyper-util`, `jsonwebtoken`, `krafka`, `matchit`, `rand`, `redis`, `rustix`, `rustls`, `rustls-pki-types`, `serde`, `serde_json`, `sha2`.
- Infrastructure `dev_external`: add `aws-lc-rs` (runtime RSA test keys; it is already in the graph through the `aws_lc_rs` backend of `jsonwebtoken`), `criterion`, `krafka`. The `rsa` crate is not requested: it carries RUSTSEC-2023-0071 with no patched release, and `deny.toml` fails on every open advisory, dev-dependencies included; Story 1.6 confirms that `aws-lc-rs` passes `make.check_security`.
- Not requested for infrastructure: `tokio` (task loops, timers, timeouts and breakers live in `iam-application`, where `tokio` is already allowed; hyper-util's executor, krafka and redis need it only transitively), `governor` (the local limiter applies the domain `RateDecisionRule` over `BootClock` instants, so tests pause it with `FakeBootClock`), and `ppp` and `tokio-rustls` (the listeners live in the composition root). A direct `tokio` dependency is requested only if spike Stories 1.2 to 1.5 show that krafka's or redis's public API exposes `tokio` types; ADR 0026 and ADR 0023 then record it. `rustix` (`LinuxBootClock`) and `rand` (`SeededRng`) stay in infrastructure because adapters of domain ports belong there under the template's layering, and each is a single small adapter.
- `reqwest` is not requested. The composition root (`external = ["*"]`) adds `tokio-rustls`, `ppp`, `tokio-tungstenite` and `prometheus-client` without an allow-list change. Phase-0 spike Stories 1.2 to 1.6 put `krafka`, `jsonwebtoken` and `criterion` only as dev-dependencies of `crates/service`, so they need no approval.
- Every added crate passes `make.check_security` (licences, advisories, bans). `openssl-sys` stays banned, which rules out `rdkafka` with TLS unless the owner grants the fallback exception (ADR 0026). Persistent-map crates under MPL-2.0 would not pass the licence check, hence the hand-written sharded copy-on-write snapshot.
- If the change is refused, the adapters that need these crates move into the composition root behind the same ports, as ADR 0023 records. `HyperUpstreamForwarder` takes that path in every case (section 4.4), so `tokio` stays out of the infrastructure delta.
- Crates that need this change, in `iam-infrastructure`: the `external` and `dev_external` lists above; `criterion` as a dev-only crate of `iam-application`. `tokio-rustls`, `ppp`, `tokio-tungstenite` and `prometheus-client` are used only in `service` and need no allow-list change.

## 4. Domain Layer (`iam-domain`)

Allowed dependencies: `async-trait`, `thiserror`, `uuid`, `shared-domain` (NFR-5). No `serde`, no clock, no crypto, no async runtime. Every rule that decides access, freshness, rate admission or revocation is here, so it is unit- and property-testable without I/O, and both planes run the same code.

### 4.1 Aggregates and entities

| Component | Kind | Board name | Holds | Domain events it records |
| --- | --- | --- | --- | --- |
| `Role` | aggregate root | `Role` | `RoleId`, `RoleName`, `RoleDescription`, `RoleKind` (`System` or `Custom`), `PermissionGrantSet`, `EntityVersion`, timestamps | `RoleCreated`, `RoleUpdated`, `RoleDeleted`, `RolePermissionsChanged` |
| `UserRole` | aggregate root | `UserRole` | `UserRoleId`, `SubjectRef` (a user or a service principal), `RoleId`, `AssignmentScope`, `AssignmentExpiry`, `EntityVersion`, revocation state | `UserRoleAssigned`, `UserRoleUpdated`, `UserRoleRevoked`, `PrivilegedRoleAssigned` |
| `GraphQlSpec` | aggregate root | `GraphQLSpec` | `SpecId`, `ServiceName`, `ContentHash`, `SpecStatus` (`Draft`, `Active`, `Retired`), `GraphQlTypeGraph` (types, fields, return types, possible types, flags) | `GraphQlSpecLoaded`, `GraphQlSpecRetired` (activation is recorded by the catalogue as `GraphQlPermissionsCreated`) |
| `GraphQlPermission` | entity (catalogue entry) | `GraphQLPermission` | `PermissionId`, `PermissionKey` (`gql:{service}:{Type}.{field}`), `PermissionFlags` (sensitive, audit-always; the most restrictive value across active versions), active state | `GraphQlPermissionsCreated` (created keys, renames and `flagChanges`), `PermissionsOrphaned` |
| `OpenApiSpec` | aggregate root | added (REST symmetry) | `SpecId`, `ServiceName`, `ContentHash`, `SpecStatus`, the `RestOperation` set (method, `PathTemplate`, `operationId` label, flags) | `OpenApiSpecLoaded`, `OpenApiSpecRetired` (activation is recorded as `RestPermissionsCreated`) |
| `RestPermission` | entity (catalogue entry) | added (REST symmetry) | `PermissionId`, `PermissionKey` (`rest:{service}:{METHOD} {template}`), `PermissionFlags`, active state | `RestPermissionsCreated` (created keys, renames and `flagChanges`), `PermissionsOrphaned` |
| `UserRolePermission` | read model | `UserRolePermission` | per subject: `EffectivePermission` entries (key or wildcard, granting roles, `ScopeSet`, shortest expiry) and the `PolicyVersion` | none |
| `Upstream` | aggregate root | added (gateway) | `UpstreamId`, `UpstreamName` (service-name pattern), Kubernetes namespace and Service name, the catalogue `ServiceName` it serves (`catalogService`), port, `UpstreamProtocol` (`Http1`, `H2c`), connect and response timeouts, concurrency limit, retry budget percent, outlier threshold, `forwardCredentials`, `system` flag, `EntityVersion` | `UpstreamCreated`, `UpstreamUpdated`, `UpstreamDeleted` |
| `Route` | aggregate root | added (gateway) | `RouteId`, `RouteHost`, `HttpMethod` set, `PathPattern`, catalogue `ServiceName` used for authorization, `UpstreamId`, `RouteFlags` (`graphql`, `streaming`, `anonymous`), `EnforcementMode` (`Enforce`, `Audit`), `BodyLimit`, `RouteTimeouts`, `RetryPolicy` (`None`, `Idempotent`), ordered `RatePolicyId` list, optional `CorsPolicy`, `system` flag, `EntityVersion`; its `ServiceName` must equal its upstream's `catalogService` | `RouteCreated`, `RouteUpdated`, `RouteDeleted`, `RouteConfigurationApplied` (per host) |
| `RatePolicy` | aggregate root | added (gateway) | `RatePolicyId`, name, `RateKeyKind` (`Ip`, `Subject`, `SubjectRoute`, `Route`), limit, period, burst, `RateFallback` (`Divided`, `Full`), `EntityVersion` | `RatePolicyCreated`, `RatePolicyUpdated`, `RatePolicyDeleted` |
| `SessionRevocation` | entity (append-only record) | added | `SessionRevocationId`, `SessionId`, `UserId`, `RevocationSource` (`UserService`, `Operator`), revoked by, revoked at, prune-after instant | `SessionRevoked` |
| `UserTokenCutoff` | entity | added | `UserId`, tokens valid after, `RevocationSource`, prune-after instant | `UserTokensCutOff` |
| `GlobalTokenCutoff` | entity (single record) | added | tokens valid after, set by, set at | `GlobalTokensCutOff` |
| `BulkOperation` | aggregate root | added | `BulkOperationId`, `BulkKind` (`RoleDeletion`, `Catalogue`, `Resync`, `Other`), propagation outcome of the last fenced chunk for revocation-class bulk changes, `BulkStatus` (`Pending`, `Running`, `Completed`, `Failed`), total and applied records, first and last `PolicyVersion`, requester, error | `BulkOperationCompleted` |
| `SecurityAuditEvent` | entity (append-only record) | added (logs) | event id, `ActorRef`, caller service, `AuditAction`, target, scope, before and after summaries, `IdempotencyKey`, `AuditOutcome`, reason, `PolicyVersion`, `RequestId` | none |
| `AccessRecord` | value record (not persisted in PostgreSQL) | added (logs) | the fields of section 12.1, built by the gateway per decision and handed to `AccessLogSink` | none |
| `ChangeReceipt` | value record | added | change id, actor, target type and id, resulting `EntityVersion` (the source of the `ETag`), resulting `PolicyVersion`, outcome; stored in `iam_change_receipts` by the unit of work; lets REST and GraphQL read the result of a command that returns `()`, and lets replays return the original result | none |

The `AccessDecision` entity and the `CacheTier` value object of the superseded plan are removed: access records are not stored in PostgreSQL, and policy has no cache tiers.

Aggregates follow the template's `ExampleApiResource` pattern: a `create(...)` constructor that validates through value objects and records the creation event, a `restore(...)` constructor without events for reconstitution, behaviour methods that check `EntityVersion` and record events, and the `AggregateRoot` implementation from `shared-domain` (`recorded_events`, `pull_domain_events`). Every event struct carries `event_id`, `aggregate_id`, `occurred_at` (from the `Clock` port) and implements `shared_domain::DomainEvent` with a `NAME` equal to its `iam.*` type in section 15.

### 4.2 Value objects

- Identity and versioning: `RoleId`, `UserRoleId`, `SpecId`, `PermissionId`, `DecisionId`, `ChangeId`, `UpstreamId`, `RouteId`, `RatePolicyId`, `SessionRevocationId`, `BulkOperationId`, `SubjectId` (a UUID for users, a `ServiceName` for service principals), `SubjectKind` (`User`, `Service`), `SubjectRef`, `ProjectId`, `EntityVersion`, `PolicyVersion` (gap-free, commit-ordered), `PolicyEpoch` (policy version, digest, log epoch, relay epoch, catalogue epoch), `RequestId`, `IdempotencyKey`.
- Replication: `StateKey` (the keys of section 9.2, parsed and printed), `StateRecord` (key, full state with `schemaVersion` or tombstone, version, sequence, count, digest after, operation, schema, log epoch, relay epoch), `LogEpoch`, `RelayEpoch`, `PolicyDigestValue` (16 bytes), `WriteMode` (`Published`, `Propagated`), `PropagationOutcome` (`Published`, `CommittedPending`, `Complete`, `Bounded`, with pods acknowledged and timed out).
- Names: `RoleName` (1 to 100 characters, no control characters, case-insensitive comparison form), `RoleDescription` (at most 1,000), `ServiceName` (`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`, at most 63), `UpstreamName` (service-name pattern), `RouteHost` (a DNS host name, lower case).
- Scope and time: `AssignmentScope` (`Global` or `Project(ProjectId)`), `AssignmentExpiry`, `ScopeSet` (`All` or a set of project ids), `BootInstant` (an instant on the `BootClock`; never compared across hosts).
- Permission model: `PermissionKey` (parsed `Rest`, `Gql` or `Reserved` form, with the service segment), `WildcardPattern` (exactly the four structured forms of FR-10), `PermissionGrant`, `PermissionGrantSet` (at most 5,000), `PermissionFlags`, `ReservedPermission` (exactly the keys of section 16.3; `iam:cache:flush` is removed).
- REST matching: `HttpMethod`, `NormalizedPath`, `CanonicalPath` (the re-encoded form that the gateway forwards), `PathTemplate`, `PathPattern` (a route pattern for `matchit`), `RestOperation`.
- GraphQL matching: `GraphQlCoordinate` (`{Type}.{field}`, including `Subscription` roots), `GraphQlTypeGraph`, `CoordinateSet`, `DocumentKey` (128-bit hash plus operation name plus catalogue version; a hit is confirmed by a full-text comparison), `DocumentLimits` (64 KiB at the decision API, depth 15, 500 coordinates, 50 aliases, 100 fragments).
- Gateway: `RouteFlags`, `EnforcementMode`, `BodyLimit`, `RouteTimeouts`, `RetryPolicy`, `UpstreamProtocol`, `RateKeyKind`, `RateFallback`, `RateDecision` (`Admit`, `Reject { retry_after }`).
- Tokens: `AccessToken` (subject id, subject kind, session id, `TokenId` for `jti`, roles claim, issued-at, expiry), `TokenIdentity` (the memo value: subject, kind, session, `iat`, `exp`, `jti`; never permissions), `Credential` (opaque wrapper whose `Debug` prints nothing), `CredentialDigest` (SHA-256 bytes computed in infrastructure; `Debug` prints only the 8-character prefix), `SessionId`, `TokenRejection` (`Missing`, `Invalid`, `Expired`, `Revoked`, `Unavailable`).
- Decisions: `AccessCheck` (target service, one of `RestTarget`, `GraphQlTarget`, `PermissionsTarget`, optional project, optional `min_policy_version`), `Decision` (`Allow`, `Deny`), `DecisionReason` (the twelve codes of FR-6 plus `audit_mode_would_deny` for access records of FR-69), `DecisionOutcome` (decision, reason, denied list, scopes, subject, decision id, policy version).
- Audit: `ActorRef` (`User(SubjectId)`, `Service(SubjectId)`, `System(component)` such as `system:bootstrap`, `system:user-service`, `system:startup`), `AuditAction`, `AuditOutcome` (`Committed`, `Rejected`).

### 4.3 Domain services (pure functions over value objects)

| Component | Responsibility | FR |
| --- | --- | --- |
| `PathNormalizer` | Single leading slash, no trailing slash, no empty segments, query ignored, percent-decode exactly once; rejects a residual `%`, `\`, NUL, a `.` or `..` segment, an encoded `/` and paths over 2,048 bytes; produces the `CanonicalPath` that is forwarded | FR-7 |
| `RestOperationMatcher` | Matches a `NormalizedPath` against the active `PathTemplate`s of a service, literal segments before templated ones | FR-7 |
| `WildcardMatcher` | Fixed-probe matching of a key against the four wildcard forms, never covering sensitive keys | FR-10 |
| `DecisionPolicy` | The decision rule: required keys against compiled role sets of the subject's active assignments in scope; produces `DecisionOutcome` with `permission_missing` or `scope_missing`. The same code runs in `iam-control` (inputs from PostgreSQL) and in `iam-gateway` (inputs from the snapshot) | FR-10, FR-39 |
| `CompiledRoleSet` | Per-role exact-key set plus wildcard list, built from active grants | FR-39, FR-71 |
| `EffectivePermissionComposer` | Builds `UserRolePermission` from the same compiled sets and assignment lists that `DecisionPolicy` uses, so both always agree | FR-39 |
| `EscalationGuard` | Grant or revoke a key of service `s` only with `iam:grant:s` or `iam:grant:*` at global scope, plus `iam:grant:sensitive` for a sensitive key and `iam:grant:wildcard` for a wildcard; create, change or revoke an assignment only with those grant keys for every key of the role; never act on an assignment whose subject is the actor | FR-24, FR-25 |
| `SpecScopeGuard` | Load, activate or retire a specification of service `s` only with `iam:spec:s` or `iam:spec:*` (`iam:spec:*` excludes `iam`; versions of `iam` are loaded and activated only by `system:startup`); a flag downgrade needs `iam:grant:sensitive` | FR-30, FR-32, FR-34, FR-36, FR-38 |
| `LastAdministratorGuard` | Refuses a revocation, expiry or change that would leave no active, non-expiring global assignment of `iam-platform-admin` | FR-5, FR-28, FR-29 |
| `SpecDiff` | Added and removed keys between a candidate version and the active versions; removed keys that have grants; wildcard grants that gain new elements; flag downgrades in the union of active versions | FR-31, FR-35 |
| `OrphanPolicy` | Which grants become inactive on activation or retirement; orphaned grants never reactivate | FR-38 |
| `RouteConflictGuard` | Refuses a route whose host and pattern equal another live route's with intersecting methods (409), and an anonymous route whose pattern is broader than a protected route on the same host; validates a full host configuration as a set; the matcher-level check (for example `/users/{id}` beside `/users/{name}`) is delegated to `RouteTableCompiler` | FR-57, FR-58 |
| `RouteScopeGuard` | A write on a route or upstream of catalogue service S needs `iam:route:{S}` or `iam:route:*` at global scope (`iam:route:*` never covers `iam`); a route's service must equal its upstream's `catalogService`; entries of service `iam` and `system` entries are refused (409 `system_entry`) | FR-4, FR-56, FR-57, FR-58 |
| `CorsRule`, `CsrfRule` | Preflight and response decisions over a route's `CorsPolicy`; the origin check for cookie-authenticated unsafe methods and WebSocket upgrades | FR-89 |
| `AnonymousRouteGuard` | Requires `iam:route:anonymous` to set `anonymous = true` or `enforcement = audit`, or to change either flag | FR-57, FR-63, FR-69 |
| `RateDecisionRule` | GCRA arithmetic over a theoretical arrival time, used by the local limiter and mirrored by the Valkey script; the conservative divisor `limit / N_ready` for `fallback = divided` | FR-65 |
| `VersionAssembly` | Collects the records of one policy version by sequence, drops duplicates, reports complete, incomplete, duplicate (same `digest-after`) or conflicting content, gaps, lower log epochs and lower relay epochs | FR-71 |
| `FreshnessRule` | Allow only while `now_boot − last_proof ≤ T_hard` and the watchdog shows no gap above `T_ready` since that proof; the local, AZ-shaped and fleet-wide readiness verdicts with hysteresis and the AZ floor | FR-73, FR-85 |
| `RevocationRule` | Reject when the session is revoked, `iat <=` the user cut-off or `iat <=` the global cut-off; a cut-off computed by IAM is the commit time plus 2 s, and a cut-off from a User service event is `occurredAt` plus `JWT_CLOCK_SKEW`; the pruning instant `max(revoked_at, cut-off instant) + longest MAX_TOKEN_LIFETIME ever configured + 2 × max JWT_CLOCK_SKEW (120 s) + 60 s`, where the cut-off instant is `tokens_valid_after` for a user cut-off and `occurredAt + JWT_CLOCK_SKEW` for a session revocation from a User service event; a property test shows that no token accepted by `TokenLifetimeRule` and refused by the record is accepted after its tombstone | FR-17, FR-79 |
| `TokenLifetimeRule` | `exp − iat > MAX_TOKEN_LIFETIME` is `token_invalid`; time checks with `JWT_CLOCK_SKEW` against injected instants | FR-15 |
| `BulkChunker` (part of `bulk/`) | Splits a change above `BULK_CHUNK_ENTITIES` into versions with revoke-type chunks before grant-type chunks | FR-84 |

### 4.4 Ports (traits, all `Debug + Send + Sync`, `#[async_trait]` where I/O is involved)

The status labels in this section and in section 13.1 (KEEP, AMEND, NEW, REMOVE) compare with the superseded plan only. In the repository every IAM crate, port, adapter and table is new: nothing exists before Story 1.1, and no story writes a drop or rename migration for these labels.

| Port | Status | Adapter (layer) |
| --- | --- | --- |
| `RoleRepository`, `UserRoleRepository`, `GraphQlSpecRepository`, `GraphQlPermissionRepository`, `OpenApiSpecRepository`, `RestPermissionRepository`, `IdempotencyRepository`, `ChangeReceiptRepository`, `SecurityAuditLog`, `SingletonLeadership`, `PolicyEpochRepository`, `PolicyReadRepository`, `IamUnitOfWork`, `OutboxStore` | KEEP | `Pg*` repositories, `PgSecurityAuditLog`, `AdvisoryLockLeadership`, `PgIamUnitOfWork`, `PgOutboxStore` (infrastructure) |
| `AccessTokenVerifier` | KEEP | `JwtAccessTokenVerifier` (infrastructure) |
| `GraphQlSchemaParser`, `GraphQlDocumentAnalyzer`, `OpenApiDocumentParser` | KEEP | `AsyncGraphQlSchemaParser`, `AsyncGraphQlDocumentAnalyzer`, `JsonOpenApiDocumentParser` (application; `async-graphql` is allowed only there) |
| `Clock`, `UuidGenerator` (from `shared-domain`) | KEEP | `SystemClock`, `UuidV7Generator` (shared-infrastructure); fakes in `tests/support` |
| `TokenRepository` | AMEND | `CachingTokenRepository` composing `AccessTokenVerifier`, `TokenMemo` and `RevocationView` |
| `RevocationRepository` | AMEND | `PgRevocationRepository` (sessions, user and global cut-offs, inbound events) |
| `UserEventSource` | AMEND | `KrafkaUserEventSource` (consumer group member) |
| `TokenMemo` | NEW | `MokaTokenMemo` (positive and negative) |
| `RevocationView` | NEW | `SnapshotRevocationView` (gateway), `PgRevocationView` (control) |
| `DocumentCache` | NEW | `MokaDocumentCache` |
| `PolicyView` | NEW | `ArcSwapPolicySnapshot` (synchronous reads of the published snapshot) |
| `PolicyDigest` | NEW | `Sha256PolicyDigest` (128-bit XOR set hash over SHA-256 entity hashes) |
| `StateRecordCodec` | NEW | `JsonStateRecordCodec` |
| `PolicyLogProducer` | NEW | `KrafkaPolicyLogProducer` (state and events topics; transactional or relay epoch) |
| `PolicyLogTail` | NEW | `KrafkaPolicyLogTail` |
| `PolicyLogProbe` | NEW | `KrafkaPolicyLogProbe` (replica-quorum metadata, `ListOffsets`) |
| `KafkaTopicInspector` | NEW | `KrafkaTopicInspector` (`DescribeConfigs`, `DescribeAcls`) |
| `UpstreamForwarder` | NEW | `HyperUpstreamForwarder` (composition root, under the ADR 0023 fallback for this one adapter; see below) |
| `RouteTableCompiler` | NEW | `MatchitRouteTableCompiler` (the one builder used by the snapshot and by route writes) |
| `EndpointWatch` | NEW | `KubernetesEndpointWatch`, `StaticEndpointWatch` |
| `PodLister` | NEW | `KubernetesPodLister`, `StaticPodLister` |
| `PeerFreshnessClient` | NEW | `HyperPeerFreshnessClient` |
| `RateLimitStore` | NEW | `ValkeyRateLimitStore` |
| `LocalRateLimiter` | NEW | `BucketLocalRateLimiter` (standard collections, `RateDecisionRule` over `BootClock`) |
| `AccessLogSink` | NEW | `StdoutAccessLogSink`, `LokiPushAccessLogSink` |
| `AccessLogQuery` | NEW | `LokiAccessLogQuery` |
| `UpstreamRepository`, `RouteRepository`, `RatePolicyRepository`, `BulkOperationRepository` | NEW | `PgUpstreamRepository`, `PgRouteRepository`, `PgRatePolicyRepository`, `PgBulkOperationRepository` |
| `BootClock` | NEW | `LinuxBootClock` (`CLOCK_BOOTTIME` through `rustix`) |
| `Rng` | NEW | `SeededRng` (`rand`) |
| `AuthorizationCache`, `PolicyNotificationSource`, `RevocationSnapshot`, `UserApiClient`, `EventPublisher`, `AccessDecisionLog`, `AccessDecisionRepository` | REMOVE | – |

`Clock` supplies every wall-clock timestamp (event `occurred_at`, expiry checks, token `exp`/`nbf`/`iat` checks, retention cut-offs). `BootClock` supplies every elapsed-time measurement that decides freshness, watchdog gaps, breakers and timers; it counts suspend time and is never compared across hosts. `UuidGenerator` supplies every identifier (aggregate ids generated in the REST or GraphQL layer as the template does, event ids, decision ids as UUID v7, change ids, outbox ids). `Rng` supplies every random draw (power-of-two-choices, jitter, peer sampling, log sampling), seeded in tests. No domain or application code reads the system time or generates ids or random numbers directly (NFR-4).

**`UpstreamForwarder` signature.** The domain may name only `async-trait`, `thiserror` and `uuid`, so the port carries no HTTP type. It uses associated types:

```rust
#[async_trait]
pub trait UpstreamForwarder: Debug + Send + Sync {
    type Request: Send;
    type Response: Send;
    async fn forward(&self, target: UpstreamTarget, req: Self::Request)
        -> Result<Self::Response, ForwardError>;
}
```

`UpstreamTarget` (domain) names the upstream, the route id, the retry policy, the timeouts and whether the request body is buffered. `ForwardError` distinguishes `NotSent`, `ConnectTimeout`, `ResponseTimeout`, `Overloaded`, `NoEndpoint` and `Upstream`. The implementation binds `Request` and `Response` to hyper's types and lives in the composition root (`bootstrap/gateway/upstream.rs`), which may use `tokio` and `hyper` directly; the composition-root pipeline calls it. The retry, budget and outlier decisions are pure domain rules (`RetryRule`, `RetryBudget`, `OutlierRule`) that the forwarder calls and that are unit-tested on their own. This places timers in one owner, the forwarder, and keeps the streamed request body and the request that hyper hands back on a "not sent" error in the same place as the retry.

### 4.5 Domain errors

One `thiserror` enum per aggregate family, each with `property_path()` and `code()` for violations, following `InvalidExampleApiResource`: `InvalidIamValue` (shared identity and version value objects), `InvalidRole`, `InvalidUserRole`, `InvalidSpec` (with a JSON pointer or a line and column), `InvalidPermissionKey`, `InvalidAccessCheck`, `InvalidUpstream`, `InvalidRoute`, `InvalidRatePolicy`, `InvalidStateRecord`, `EscalationDenied`, `SpecScopeDenied`, `LastAdministrator`, `RouteConflict`, `RouteScopeDenied`, `SystemEntry`, `ReferencedByRoute` (an upstream or rate policy still in use), `VersionConflict` (`Missing`, `Stale`), plus the port errors `RepositoryError { AlreadyExists, NotFound, Conflict, Unavailable(BoxError) }`, `LogError { Unavailable, Fenced, OutOfRange, Misconfigured }`, `StoreError { Timeout, Unavailable }` and `QueryError { RangeTooLong, Timeout, Unavailable }`.

## 5. Application Layer (`iam-application`)

Allowed crates: `async-graphql`, `async-trait`, `axum`, `futures-util`, `humantime`, `serde`, `thiserror`, `tokio`, `tracing`, `utoipa`, `utoipa-axum`, `uuid`, `validator`; dev-only `criterion` after ADR 0023. Each capability has one handler; REST handlers and GraphQL resolvers both dispatch to it through the template's `CommandBus` and `QueryBus` (FR-1). The gateway use cases are synchronous functions over `PolicyView` wherever possible, so the request path takes no lock and awaits nothing between the snapshot load and the decision.

### 5.1 Commands and command handlers

Commands return `()`, as the template's bus requires. Each command carries a `ChangeId` generated by the interface layer through `UuidGenerator`; after dispatch, the interface layer reads the `ChangeReceipt` (new version, `policyVersion`, target id, propagation outcome) through `GetChangeReceiptQuery`. The same receipt serves idempotent replays.

| Command handler | Board name | FR |
| --- | --- | --- |
| `CreateRoleCommandHandler` | CRUD handlers | FR-20 |
| `UpdateRoleCommandHandler` | CRUD handlers | FR-22 |
| `DeleteRoleCommandHandler` | CRUD handlers | FR-23 (revocation-class) |
| `SetRolePermissionsCommandHandler` | CRUD handlers | FR-24, FR-25 (revocation-class when a key is removed) |
| `AssignUserRoleCommandHandler` | CRUD handlers | FR-26, FR-25 |
| `UpdateUserRoleCommandHandler` | CRUD handlers | FR-28, FR-25, FR-5 |
| `RevokeUserRoleCommandHandler` | CRUD handlers | FR-29, FR-25, FR-5 (revocation-class) |
| `LoadGraphQlSpecCommandHandler` | `LoadGraphQLCommandHandler` | FR-30 |
| `CreateGraphQlPermissionsCommandHandler` | `GraphQLCreatePermissionsCommandHandler` | FR-32 |
| `RetireGraphQlSpecCommandHandler` | added | FR-38 |
| `LoadOpenApiSpecCommandHandler` | added | FR-34 |
| `CreateRestPermissionsCommandHandler` | added | FR-36 |
| `RetireOpenApiSpecCommandHandler` | added | FR-38 |
| `CreateUpstreamCommandHandler`, `UpdateUpstreamCommandHandler`, `DeleteUpstreamCommandHandler` | added (gateway) | FR-56 |
| `CreateRouteCommandHandler`, `UpdateRouteCommandHandler`, `DeleteRouteCommandHandler` | added (gateway) | FR-57, FR-63, FR-69 |
| `ApplyRouteConfigurationCommandHandler` | added (gateway) | FR-58, FR-84 |
| `CreateRatePolicyCommandHandler`, `UpdateRatePolicyCommandHandler`, `DeleteRatePolicyCommandHandler` | added (gateway) | FR-64 |
| `RevokeSessionsCommandHandler` | added | FR-80 |
| `SetGlobalTokenCutoffCommandHandler` | added | FR-80 |
| `ResyncPolicyCommandHandler` | added (replaces the cache flush) | FR-78, FR-84 |
| `BootstrapIamCommandHandler` | added | FR-5 (also seeds IAM's own upstream and routes, Story 8.7) |
| `RegisterOwnSpecsCommandHandler` | added | FR-4 |
| `ApplyUserRevocationEventCommandHandler` | added | FR-18 |
| `RecordRejectedAttemptCommandHandler` | added; offers the attempt to `BufferedRejectedAttemptLog` without awaiting | FR-4, FR-12, FR-25, FR-49 |
| `RunMaintenanceCommandHandler` | added (the board's worker, reduced to purges and anchoring) | FR-43, FR-38, FR-52 |

Removed: `FlushAuthorizationCacheCommandHandler`, `MaintainAccessDecisionPartitionsCommandHandler`, `ReconcilePolicyCommandHandler` (its purge and anchor duties move to `RunMaintenanceCommandHandler`; drift detection is the anti-entropy task of FR-77).

Each write handler validates through value objects, loads the aggregate, checks the version (FR-2), applies `EscalationGuard`, `SpecScopeGuard`, `LastAdministratorGuard`, `RouteConflictGuard` and `AnonymousRouteGuard` where relevant, against PostgreSQL inside the write transaction (the authoritative state, never the snapshot), then calls `IamUnitOfWork::commit(change, write_mode)`. The unit of work persists the aggregate, the state records of every changed entity, the pulled domain events as outbox event rows, the audit record, the change receipt and the idempotency record, and bumps the policy version, atomically (section 9.2). After the commit the handler waits for the write mode (section 9.8): `published` waits for the Kafka acknowledgement of the version; `propagated` also waits for Sync-Fence. The resulting `PropagationOutcome` is stored on the change receipt so a replay returns it. The template's at-most-once `InMemoryEventBus` is not used for IAM events.

### 5.2 Queries and query handlers

| Query handler | Board name | FR |
| --- | --- | --- |
| `ValidateAccessQueryHandler` | `ValidateAccessQueryHandler` (here the token comes from `TokenRepository`; deviation in section 22.1) | FR-6 to FR-10, FR-12 to FR-14 |
| `ValidateAccessBatchQueryHandler` | added | FR-11 |
| `ResolveTokenQueryHandler` | added | FR-19 |
| `GetRoleQueryHandler`, `ListRolesQueryHandler` | CRUD handlers | FR-21, FR-24 |
| `GetUserRoleQueryHandler`, `ListUserRolesQueryHandler` | CRUD handlers | FR-27 |
| `GetUserRolePermissionsQueryHandler` | read of `UserRolePermission` | FR-39 |
| `GetGraphQlSpecsQueryHandler`, `GetGraphQlPermissionsQueryHandler` | added, `GraphQLGetPermissionsQueryHandler` | FR-31, FR-33 |
| `GetOpenApiSpecsQueryHandler`, `GetRestPermissionsQueryHandler` | added | FR-35, FR-37 |
| `GetUpstreamQueryHandler`, `ListUpstreamsQueryHandler` | added (gateway) | FR-56 |
| `GetRouteQueryHandler`, `ListRoutesQueryHandler`, `GetRouteConfigurationQueryHandler` | added (gateway) | FR-57, FR-58 |
| `GetRatePolicyQueryHandler`, `ListRatePoliciesQueryHandler` | added (gateway) | FR-64 |
| `GetSessionRevocationQueryHandler`, `ListSessionRevocationsQueryHandler`, `GetUserTokenCutoffQueryHandler`, `GetGlobalTokenCutoffQueryHandler` | added | FR-81 |
| `GetPolicyStatusQueryHandler`, `GetPolicyVersionPropagationQueryHandler` | added | FR-82, FR-83 |
| `GetBulkOperationQueryHandler`, `ListBulkOperationsQueryHandler` | added | FR-84 |
| `GetAccessDecisionsQueryHandler` | added (now from Loki) | FR-51 |
| `GetSecurityAuditEventsQueryHandler`, `VerifySecurityAuditChainQueryHandler` | added | FR-52 |
| `GetChangeReceiptQueryHandler` | added | FR-2 |
| `GetPolicyEpochQueryHandler` | added (used by the `minPolicyVersion` check in `iam-control` and by the status query) | FR-14, FR-82 |

The three decision handlers run on both planes. In `iam-control` their inputs come from `PolicyReadRepository` and `PgRevocationView`; on the gateway's decision listener they come from `PolicyView` and `SnapshotRevocationView`. Both feed the same `DecisionPolicy`, so the outcome is identical for the same policy version (FR-6, NFR-16).

### 5.3 Gateway use cases (`gateway/`)

| Use case | Responsibility | FR |
| --- | --- | --- |
| `RequestAuthorizer` | Given one loaded snapshot, a matched route and the authenticated principal: resolve the required keys (REST template key, GraphQL coordinates, or none for `anonymous`), run `DecisionPolicy`, apply the enforcement mode, return the outcome and the access-record fields | FR-4, FR-13, FR-59, FR-63, FR-69 |
| `GraphQlRequestAnalyzer` | Envelope decode with duplicate-key rejection, batch split (at most 10), `DocumentCache` lookup with full-text confirmation, parse budget, coordinate extraction through `GraphQlDocumentAnalyzer`, introspection rule | FR-8, FR-60 |
| `SubscriptionAuthorizer` | Per-operation decisions for `subscribe` and `start` messages (and queries or mutations sent over the socket), the per-connection operation cap, the `connection_init` token rule | FR-62 |
| `StreamReauthorizer` | Given an applied version's touched subjects, sessions, roles, catalogue services, routes and cut-offs, decide which open streams and operations to close; completes before the version is reported applied | FR-61, FR-62, FR-76 |
| `ReadYourWritesBarrier` | The barrier of section 9.9 over the published version and the highest version seen in the log | FR-14 |

### 5.4 Application services

- `AccessDecisionService`: the decision path shared by `ValidateAccessQueryHandler`, `ValidateAccessBatchQueryHandler`, `RequestAuthorizer` and `IamAccessGuard`, so IAM's own API, the decision API and proxied traffic are decided by exactly one piece of code.
- `RequiredKeyResolver`: turns an `AccessCheck` into the set of required keys using `RestOperationMatcher`, `GraphQlDocumentAnalyzer` or the permission-key parser, against the service catalogue of the same snapshot or read.
- `IamAccessGuard`: given the authenticated `Principal` and the IAM operation (REST: `rest:iam:{METHOD} {matched template}`; GraphQL: every IAM coordinate the document selects), applies the rule of FR-4 in `iam-control` against PostgreSQL; a denial becomes `IamError::Forbidden` and dispatches `RecordRejectedAttemptCommand`. The gateway applies the same rule first from the snapshot (section 16.2).
- `Principal`: the authenticated caller (`SubjectRef`, session id, roles claim), put into request extensions and GraphQL context data by the composition root.
- `BufferedRejectedAttemptLog`: a bounded `tokio` channel with non-awaiting `offer`; it summarises identical rejected attempts per actor, action and reason within 60 seconds (FR-49).
- `AccessRecordBuilder`: builds the access record of section 12.1 from the decision outcome and route data, applies the lane rule (audit lane for denials, always-audit, sensitive-key and wildcard allows; ordinary lane otherwise), the sampling draw through `Rng` and the per-class budgets (FR-50).
- `WriteOutcomeMapper`: maps one handler result (`ChangeReceipt` with `PropagationOutcome`, or a pending bulk operation) to the REST status and headers (`201`/`200`, `202` `committed_pending_propagation`, `202` with the bulk operation's `Location`, `Iam-Policy-Version`, `Iam-Policy-Offset`, `Iam-Propagation`) and to the GraphQL `propagation` payload and the nullable `bulkOperationId` payload field, so parity holds for write modes and bulk operations (FR-75, FR-84).
- Parser adapters: `AsyncGraphQlSchemaParser` (SDL to `GraphQlTypeGraph`, with the type and field limits of FR-30 and the `@iamSensitive`/`@iamAuditAlways` directives), `AsyncGraphQlDocumentAnalyzer` (document to `CoordinateSet` with the limits of FR-8, fragments, inline fragments, interfaces, introspection and `Subscription` roots, through the `async_graphql::parser` re-export), `JsonOpenApiDocumentParser` (OpenAPI 3.0/3.1 JSON to the `RestOperation` set, internal `#/` references only, `x-iam-sensitive` and `x-iam-audit`).

> Assumption: Specification documents arrive as a string field (`sdl` for GraphQL, `document` for OpenAPI) on both interfaces, so the stored text is exactly what was uploaded and its content hash is stable. OpenAPI JSON is decoded in the application layer through the JSON decoding that `axum`'s `Json` type exposes, into local `serde` types, which needs no allow-list change; if that API is unsuitable at implementation time, the parser moves behind the same port into `iam-infrastructure`, where `serde_json` is allowed after ADR 0023.

### 5.5 Application error enum

One enum, `IamError`, for the whole context, with `impl From<IamError> for Problem` in `error.rs` and an IAM-specific `iam_problem_to_graphql_error` (the shared `problem_to_error` maps only 422 and 500 and is a synchronised file, so IAM does not change it):

| Variant | HTTP | GraphQL `extensions.code` |
| --- | --- | --- |
| `Invalid(violations)` | 422 | `VALIDATION_FAILED` |
| `Unauthenticated(TokenRejection)` | 401 with `WWW-Authenticate: Bearer` | `UNAUTHENTICATED` |
| `Forbidden` | 403 | `FORBIDDEN` |
| `NotFound` | 404 (GraphQL single-entity queries return `null`) | `NOT_FOUND` |
| `Conflict` (duplicate name or assignment, overlapping route, upstream or rate policy still referenced) | 409 | `CONFLICT` |
| `OrphanConfirmationRequired(grants)` | 409 with the grant list | `ORPHAN_CONFIRMATION_REQUIRED` |
| `FlagDowngradeConfirmationRequired(keys)` | 409 with the key list | `FLAG_DOWNGRADE_CONFIRMATION_REQUIRED` |
| `LastAdministrator` | 409 | `LAST_ADMINISTRATOR` |
| `IdempotencyMismatch` | 422 | `VALIDATION_FAILED` |
| `PreconditionRequired` | 428 | `PRECONDITION_REQUIRED` |
| `PreconditionFailed` | 412 | `PRECONDITION_FAILED` |
| `QueryTimeout` (Loki) | 504 | `QUERY_TIMEOUT` |
| `DependencyUnavailable` (Loki, Kafka metadata for status reads) | 503 | `SERVICE_UNAVAILABLE` |
| `Storage(BoxError)` | 500 through `Problem::internal` (logs the chain once) | `INTERNAL_SERVER_ERROR` |

`Problem` instances are built with the public `Problem::new(status)` and `with_detail` of `shared-application`; no synchronised shared file changes. A write whose Kafka acknowledgement does not arrive within `PUBLISH_WAIT_TIMEOUT` is not an error: it returns `202` with `committed_pending_propagation` through `WriteOutcomeMapper`. Validate-access never returns these errors for the subject's decision: an internal failure becomes `deny` with reason `unavailable` (FR-13); in `iam-control` a `minPolicyVersion` above the current version is the caller's error and returns 422 (FR-14).

### 5.6 Background task loops (`iam-application`, module `task/`)

Every loop is an `async fn run(self, shutdown)` over ports (the apply-thread and log-writer loops are plain functions that the composition root runs on dedicated OS threads). The composition root's `TaskSupervisor` (`bootstrap::start_tasks(&adapters, mode, shutdown)`) starts them per run mode and stops them within `SHUTDOWN_GRACE_PERIOD` (FR-45).

**Mutation rule for loops (NFR-2).** cargo-mutants counts a timed-out mutant as surviving, and `exclude_re` is protected. Every loop is therefore a pure step function `(state, input) -> (state, actions)` in the domain or application layer, unit-tested directly; the async task or OS-thread shell only receives inputs, calls the step and performs its actions, with no branching of its own; every test that drives a shell waits with a bound (`recv_timeout`, `tokio::time::timeout`), so a mutant that would hang fails instead. Timeouts around port calls (`RATE_LIMIT_STORE_TIMEOUT`, Loki pushes) and breakers are applied here with `tokio::time`, not inside adapters. Upstream timeouts, retries, outlier ejection and the concurrency limit are the exception: they live in the composition-root `HyperUpstreamForwarder` (section 4.4), because only there are the streamed request body and the request that hyper returns on a "not sent" error available.

| Task | Plane | Kind | Loop | FR |
| --- | --- | --- | --- | --- |
| `OutboxRelay` | control | singleton | Wake on `LISTEN` or every 100 ms; claim unpublished rows in `(policy_version, seq)` order inside a fenced batch; produce; store offsets; mark published; delete published rows after 7 days | FR-46 |
| `UserEventConsumer` | control | consumer group member | Fetch from `user.events.v1`; decode; dispatch `ApplyUserRevocationEventCommand`; commit the offset after the PostgreSQL commit | FR-18 |
| `AntiEntropyChecker` | control | singleton | Head check every `ANTI_ENTROPY_HEAD_INTERVAL`, full check and shadow bootstrap every `ANTI_ENTROPY_FULL_INTERVAL`; republish lost records | FR-77 |
| `RevocationTombstoneEmitter` | control | singleton | Commit tombstones for revocation records past their prune-after instant | FR-79 |
| `PolicyMaintenance` | control | singleton | Every `MAINTENANCE_INTERVAL` dispatch `RunMaintenanceCommand` inside a fenced batch | FR-43 |
| `SyncFenceCoordinator` | control | per request batch | List gateway pods, long-poll their applied version, batch concurrent writes, report `complete` or `bounded` | FR-76 |
| `BulkOperationRunner` | control | singleton per operation (fenced) | Commit the chunks of a pending bulk operation at most `BULK_MAX_RECORDS_PER_SECOND`, revokes before grants, letting revocation-class writes interleave | FR-84 |
| `RejectedAttemptWriter` | control | per replica | Drain `BufferedRejectedAttemptLog` at most every second into `SecurityAuditLog::append_batch` | FR-49 |
| `PolicyTail` | gateway | per pod | Bootstrap, then tail; hand raw record batches to the apply thread over a bounded channel; reseek after reconnect | FR-71 |
| `FreshnessProber` | gateway | per pod | Every `FRESHNESS_PROBE_INTERVAL` take a replica-quorum proof and hand it to the apply thread; watchdog tick every 1 s | FR-73 |
| `DerivedStateChecker` | gateway | per pod, on the apply thread | Every `DERIVED_STATE_CHECK_INTERVAL` rebuild 1/16 of the shards' derived structures and compare | FR-74 |
| `PeerReadinessChecker` | gateway | per pod | Every 2 s compare own freshness with peers; drive readiness and connection shedding | FR-85 |
| `EndpointWatcher` | gateway | per pod | Keep the zone-annotated endpoint sets of every upstream current | FR-87 |
| `AccessLogWriter` | gateway | per pod, dedicated thread | Drain the access-record channel; ordinary lane to `StdoutAccessLogSink`, audit lane to `LokiPushAccessLogSink` with acknowledgement tracking | FR-50 |

Removed: `PolicyListener`, `PolicyEpochPoller`, `PolicyReconciler`, `AccessDecisionWriter`, `PartitionMaintainer`. Singletons run in every `iam-control` replica, but each batch runs in a transaction that first takes the task's transaction-level advisory lock (`AdvisoryLockLeadership`); a replica without the lock skips the batch and retries at its next interval, so leadership moves as soon as a holder stops, and a replica that lost its connection can never keep working as leader. Kafka-side fencing of the relay is section 9.3.

### 5.7 Interface modules

- `http.rs` with `IamState` (`command_bus`, `query_bus`, `uuid_generator`, `clock`), exposed through `FromRef`, and `router<S>() -> OpenApiRouter<S>` with one `routes!` group per resource; sub-modules `http/{access_validation,token_resolution,role,user_role,graphql_spec,graphql_permission,openapi_spec,rest_permission,effective_permission,upstream,route,route_configuration,rate_policy,session_revocation,token_cutoff,policy_status,policy_resync,bulk_operation,access_decision,security_audit}.rs`, each with `dto.rs` and `handler.rs` (DTOs derive `serde`, `utoipa::ToSchema`, `IntoParams`, `validator::Validate`, `#[serde(deny_unknown_fields)]`). Every operation documents 400, 401, 403, 413, 415, 422 and default problem responses, carries the `bearerAuth` security requirement and the tag `iam`, and uses `operation_id` values in the template's form (`api_roles_post` and so on).
- Header handling: an `IdempotencyKeyHeader`, an `IfMatchHeader` and a `PreferWaitHeader` (`Prefer: wait=propagated`) extractor in IAM's `http/extract.rs`, rejecting with problems; responses set `ETag`, `Location`, `Iam-Policy-Version`, `Iam-Policy-Offset` and, in `propagated` mode, `Iam-Propagation`.
- `graphql.rs` with `IamQuery` and `IamMutation` (`#[Object]`), `SimpleObject` and `InputObject` types (every write input carries `consistency: PUBLISHED | PROPAGATED`; every write payload carries `propagation {status, policyVersion, podsAcknowledged, podsTimedOut}`), state from `ctx.data::<IamState>()`, the principal from `ctx.data::<Option<Principal>>()`, and `IamAuthorizationExtension` (an `async-graphql` extension that, when a document selects any IAM-owned field, requires a principal and runs `IamAccessGuard` over the IAM coordinates before execution). Resolvers reuse the REST helper functions, as the example context does.
- `subscriber/` holds no IAM subscriber on the in-process bus: durable reactions go through the outbox (section 9.2).

## 6. Infrastructure Layer (`iam-infrastructure`)

Allowed crates today: `async-trait`, `aws-config`, `aws-sdk-sqs`, `moka`, `sqlx`, `thiserror`, `tracing`, `uuid` (dev-only: `aws-smithy-mocks`, `rstest`, `tokio`). The change of ADR 0023 (section 3.1), approved by the owner on 2026-11-21 and applied in Story 2.3, adds the gateway crates; `tokio` is not added, because hyper-util's executor, krafka and the Valkey client need it only transitively. IAM uses neither `aws-config` nor `aws-sdk-sqs`. Task loops stay in the application layer; adapters here are one-shot operations or long-lived clients that a loop drives.

### 6.1 Repositories and the unit of work (PostgreSQL through `sqlx`)

`PgPolicyEpochRepository`, `PgRoleRepository`, `PgUserRoleRepository`, `PgGraphQlSpecRepository`, `PgGraphQlPermissionRepository`, `PgOpenApiSpecRepository`, `PgRestPermissionRepository`, `PgUpstreamRepository`, `PgRouteRepository`, `PgRatePolicyRepository`, `PgBulkOperationRepository`, `PgRevocationRepository`, `PgPolicyReadRepository`, `PgIdempotencyRepository`, `PgChangeReceiptRepository`, `PgSecurityAuditLog`, `PgOutboxStore` and `PgIamUnitOfWork` follow `PgExampleApiResourceRepository`: compile-time checked `sqlx::query!`/`query_as!`, private `Row` structs, a `translate(sqlx::Error)` that maps unique violations to `AlreadyExists` and everything else to `Unavailable`, and `restore(row)` through the value objects. Timestamps are `timestamptz` columns mapped through `sqlx::types::time::OffsetDateTime` (the `time` feature of the workspace `sqlx` dependency) and converted to and from the `SystemTime` of the `Clock` port inside the adapters.

`PgIamUnitOfWork::commit` runs, in one transaction (FR-2, FR-70):

1. `SELECT ... FROM iam_policy_epoch FOR UPDATE`, then `version = version + 1` when the change affects decisions (gap-free and commit-ordered under the row lock).
2. The aggregate statements with `WHERE version = $expected`, and the guards that read PostgreSQL.
3. For every changed entity: the canonical state bytes through `JsonStateRecordCodec`, the entity hash `first 16 bytes of SHA-256(key ‖ canonical_state)` through `Sha256PolicyDigest`, and `digest ^= h_old ^ h_new`. The digest is computed in Rust and written back to `iam_policy_epoch`; no bit arithmetic in SQL.
4. Outbox state rows (one per changed entity, framed with version, sequence, count and `digest_after`; null payload for a tombstone) plus one `__head` row `{version, digest}`; catalogue changes as content-addressed chunks of at most 1 MiB plus a manifest.
5. Outbox event rows for `iam.events.v1` (payload JSON encoded with `serde_json` from private DTOs mapped from domain events).
6. The audit insert chained under the lock of `iam_security_audit_chain_head`; the change receipt; the idempotency record.
7. `SELECT pg_notify('iam_outbox', '')` as a wake-up for the relay leader only (added by Story 7.4; it carries no keys, no replica depends on it, and the 100 ms poll fallback bounds a lost notification).

Transactions that do not change decisions (loading a draft specification, for example) write event rows only and do not bump the version. `PgPolicyReadRepository` loads compiled role sets, assignment lists, service catalogues, routes and the current `PolicyEpoch` in one `REPEATABLE READ READ ONLY` transaction, so data and version come from one snapshot; it feeds the decision API in `iam-control` and the shadow bootstrap of anti-entropy.

### 6.2 Kafka adapters (`kafka/`, `krafka` pinned exactly)

- `KrafkaPolicyLogProducer`: produces state rows to `POLICY_TOPIC` partition 0 and event rows to `EVENTS_TOPIC`, `acks=all`, idempotent, `max.in.flight.requests.per.connection = 1`, `linger.ms` 1, lz4, headers of section 9.2. Transactional producer with `transactional.id` `iam-relay` when spike Story 1.4 passes; otherwise the `iam-relay-epoch` header from `iam_policy_epoch.relay_epoch`, incremented on every relay takeover. Returns the stored offsets. Refuses to produce when metadata shows more than one partition (FR-46).
- `KrafkaPolicyLogTail`: no consumer group; `assign` partition 0; `read_committed`; never auto-reset (an out-of-range position means rebootstrap); `fetch.min.bytes` 1 and `KAFKA_FETCH_MAX_WAIT` 100 ms; separate bootstrap connection under principal `iam-gateway-bootstrap`; returns raw batches, never decoded records (FR-71).
- `KrafkaPolicyLogProbe`: addresses Metadata requests to at least 2 of the 3 replica brokers and compares leader and leader epoch; sends `ListOffsets` with `current_leader_epoch` for every partition; maps `OFFSET_NOT_AVAILABLE`, `FENCED_LEADER_EPOCH`, `UNKNOWN_LEADER_EPOCH`, a watermark regression or a nonzero watermark on another partition to "no proof" (FR-73).
- `KrafkaTopicInspector`: `DescribeConfigs` for the topic and broker, `DescribeAcls`; returns a configuration verdict that the gateway (readiness) and `iam-control` (publishing) evaluate under `KAFKA_CONFIG_GATES` (FR-72).
- `KrafkaUserEventSource`: consumer group `USER_EVENTS_CONSUMER_GROUP` on `USER_EVENTS_TOPIC`, manual commit after processing, rebalance handling; decodes the neutral envelope or the Symfony Messenger `DomainEventEnvelope` (mapping known `eventClass` values) into `UserRevocationEvent`; reports undecodable records as dead letters without blocking the partition (FR-18).
- All Kafka adapters authenticate with SASL SCRAM-SHA-512 over TLS, trusting the Strimzi cluster CA from `KAFKA_CA_FILE` (`KAFKA_SECURITY_PROTOCOL` `PLAINTEXT` only in `dev` and `test`).

> Assumption: krafka passes the phase-0 capabilities of section 20.4. If a must-pass capability fails, Story 1.7 records it and the run stops for an owner decision before Epic 7; `rdkafka` is the documented fallback and needs an owner-approved build change and an `openssl-sys` exception (ADR 0026). If the consumer-group capability fails, `iam-control` consumes `user.events.v1` by manual assignment under the relay's advisory lock and stores offsets in PostgreSQL in the revocation transaction.

### 6.3 Snapshot adapter (`snapshot/`)

`ArcSwapPolicySnapshot` implements `PolicyView`. It holds the published `PolicySnapshot` behind an `ArcSwap` and exposes a synchronous `load()` that returns one `Arc` per request. A snapshot contains 4,096 copy-on-write shards of raw entity state keyed by `StateKey` with per-key version guards; the derived structures decisions read (compiled role sets, the role-to-subject reverse index, interned assignment lists, per-host `matchit` routers, upstream table, revocation sets and cut-offs, rate policies, service catalogues and type graphs); the published version, digest, derived hash and log epoch; and the freshness proof (`last_proof` on the `BootClock`). The builder runs only on the apply thread: it applies complete versions in order, clones each touched shard at most once per published snapshot, publishes at most once per 5 ms (CONFIG, measured on `BootClock`, never on the wall clock) at a version boundary, builds each host's router through `MatchitRouteTableCompiler` (the same code route writes use to refuse a table the gateway could not build), checks the digest after each version, and keeps retired snapshots in a queue until their strong count reaches 1 (deferred reclamation), so a tokio worker never runs the destructor of a replaced generation. `SnapshotRevocationView` reads the revocation sets of the same loaded snapshot.

### 6.4 Token adapters (`token/`)

- `JwtAccessTokenVerifier` (`jsonwebtoken` with the `aws_lc_rs` backend): RS256 only; keys from `JWT_PUBLIC_KEYS_FILE` (1 to 3 PEM keys, newest last in the file, tried newest first, hot-reloaded through a file watch; the last valid set is kept when a reload fails); `iss`, `aud`; `validate_exp` and `validate_nbf` off, because `exp`, `nbf` and `iat` are checked through the `Clock` port with `JWT_CLOCK_SKEW` by `TokenLifetimeRule`; required `sub` and `jti`, `sid` for user tokens, a service-name `sub` for `ROLE_SERVICE` tokens; the header is decoded strictly and rejected when it names any other algorithm or carries `jwk`, `jku`, `x5u`, `x5c` or `crit` (FR-15). For caller authentication it also checks `JWT_CALLER_AUDIENCE` and `JWT_SERVICE_TOKEN_MAX_LIFETIME` on service tokens (FR-3). Its integration tests sign tokens with RSA keys generated at test time through the dev-only `aws-lc-rs`.
- `MokaTokenMemo`: a positive memo of `TokenIdentity` keyed by `CredentialDigest`, TTL `min(exp − now, TOKEN_MEMO_MAX_TTL)`, capacity `TOKEN_MEMO_CAPACITY`; a negative memo of 10,000 entries for 5 s; both flushed when the trusted key set changes (FR-17).
- `CachingTokenRepository` (board `TokenRepository`): digests the credential with `sha2`; consults the negative and positive memos; on a miss verifies; on every call, memo hits included, checks the `RevocationView` (FR-17). There is no session-liveness call to User service (FR-16 is retired).
- `PgRevocationView`: reads session revocations and user and global cut-offs from PostgreSQL for `iam-control`.

### 6.5 Upstream, Kubernetes, rate-limit, access-log and clock adapters

- `HyperUpstreamForwarder` lives in the composition root (`crates/service/src/bootstrap/gateway/upstream.rs`), not in `iam-infrastructure`, under the ADR 0023 fallback for this adapter: it needs `tokio` timers, hyper request and upgrade types, and the request hyper returns for a "not sent" retry, none of which may cross the domain port or enter infrastructure without a direct `tokio` dependency. It is a hyper-util client per upstream with HTTP/1.1 keep-alive pools or one h2c connection per endpoint (first release), connect timeout 250 ms, per-route response and whole-request timeouts, at most one safe retry to another endpoint under a 10 % budget, passive outlier ejection, a per-upstream in-flight limit with fail-fast `upstream_overloaded`, zone-aware power-of-two-choices over the endpoints from `EndpointWatch` with the seeded `Rng`, and an RTT histogram per zone (FR-66, FR-87). The same forwarder performs the upstream WebSocket upgrade (`forward_upgrade`), so endpoint selection is never duplicated (Story 11.1). A retry after "not sent" reuses the request hyper hands back; an idempotent retry is allowed only for a request without a body or with a body buffered under 64 KiB (CONFIG), because a streamed body is consumed by the first attempt.
- `KubernetesEndpointWatch` and `StaticEndpointWatch` (`kubernetes/`): watch EndpointSlices (`ready`, `serving`, `terminating`, zone) with read-only RBAC through a plain hyper client using the ServiceAccount token and the in-cluster CA; the static adapter reads `UPSTREAM_STATIC_ENDPOINTS_FILE` for compose and e2e. DNS with fully qualified names is the fallback.
- `KubernetesPodLister` and `StaticPodLister`: list pods by `GATEWAY_FLEET_LABEL` in `GATEWAY_NAMESPACE` as a consistent read (`resourceVersion` unset), including Pending and Terminating pods with container states; the static adapter reads `SYNC_FENCE_STATIC_PODS` (FR-76).
- `HyperPeerFreshnessClient`: `GET /internal/freshness` on peers from the `iam-gateway-peers` headless Service (FR-85).
- `ValkeyRateLimitStore` (`rate_limit/`): `redis` crate with Sentinel support at `RATE_LIMIT_STORE_URL`; one `EVALSHA` of the GCRA Lua script per policy and request on key `rl:{policyId}:{keyHash}` (key parts hashed, TTL of one period); each call is bounded by `RATE_LIMIT_STORE_TIMEOUT`, applied by the application around the port call. `BucketLocalRateLimiter`: the per-IP guard and the conservative per-pod fallback buckets, built from standard collections and `RateDecisionRule` over `BootClock` instants (FR-65).
- `StdoutAccessLogSink` and `LokiPushAccessLogSink` (`access_log/`): JSON lines to stdout for the ordinary lane; batched pushes to `LOKI_PUSH_URL` (`/loki/api/v1/push`, header `X-Scope-OrgID` from `LOKI_TENANT_ID`) with labels and structured metadata of section 12.1 for the audit lane, reporting acknowledged batches. `LokiAccessLogQuery`: LogQL against `LOKI_QUERY_URL` with a fixed label selector and structured-metadata filters, bounded range, page size and timeout (FR-50, FR-51).
- `LinuxBootClock` (`clock/`): `CLOCK_BOOTTIME` through `rustix`. `SeededRng`: `rand` seeded from the operating system in production and from a fixed seed in tests.

### 6.6 Removed adapters

The moka authorization cache, the `LISTEN` notification source for replicas, the in-memory revocation snapshot, `HttpUserApiClient`, `SqsEventPublisher`, `SqsUserEventSource`, `PgAccessDecisionRepository` and the partition functions are not built.

## 7. Composition Root and Run Modes

### 7.1 Wiring

| File | Change | First story |
| --- | --- | --- |
| `Cargo.toml` | `iam-domain`, `iam-application`, `iam-infrastructure`; `tokio-tungstenite`, `prometheus-client`; dev-dependencies `krafka` (`test-broker`), `jsonwebtoken`, `criterion` for the spikes | 1.1, 1.2, 1.6 |
| `bootstrap.rs` | `Adapters` gains IAM fields for the control plane (repositories, unit of work, token repository, Kafka producer and consumer, pod lister, Loki query); `connect` builds them; handlers registered on the buses; `IamState` built; GraphQL schema gets `.data(iam_state)` and `IamAuthorizationExtension`; the three `Adapters { .. }` literals in `bootstrap/tests.rs`, `http/router/tests.rs` and `tests/integration/panic.rs` are updated; `register_iam_specs(&adapters)` (FR-4, under a transaction-level advisory lock) and `start_tasks(&adapters, mode, shutdown) -> TaskSupervisor` are reusable by `command/serve.rs`, `command/gateway.rs` and the e2e world | 1.1, then 2.3 onward and 6.9 |
| `http.rs`, `http/authentication.rs` (new) | `AppState` gains `IamState`; `authenticate` middleware reads `Authorization: Bearer`, or the `__Host-auth_token` cookie when that header is absent, resolves it through `ResolveTokenQuery`, inserts `Principal`; on IAM REST routes a missing or rejected token returns the 401 problem | 2.7 |
| `http/router.rs` (seam) | Nests IAM routes under `/api` with the authentication layer and the `IamAccessGuard` layer applied as `route_layer` to the IAM router only, inside request id, security headers and `TraceLayer` | 2.7 |
| `graphql/handler.rs` (seam), `graphql/schema.rs` | Passes `Option<Principal>`; merges `IamQuery` and `IamMutation` with `MergedObject`; `EXPECTED_SDL` updated | 2.7 (`handler.rs`, added to `.templatesyncignore`), 2.8 (schema merge) |
| `openapi.rs` | Nests the IAM router, adds the `iam` tag and the `bearerAuth` security scheme; `openapi/tests.rs` updated | 2.8 |
| `cli.rs`, `config.rs` | The variables of section 7.3 per mode, with `env` and hidden values, ranges and cross-field rules; `GatewayConfig` without database settings; subcommands `gateway`, `drain` and `iam-bootstrap` (`--admin-user` or `--admin-service`, optional `--iam-host`, `--repair-routes`); `check-config --mode gateway\|control`; `healthcheck --mode gateway\|control` (gateway mode probes `/ping` on `GATEWAY_PROBE_LISTEN`) | per story, 9.2, 15.2, 16.1 |
| `command.rs` (seam) | `pub mod gateway; pub mod iam_bootstrap; pub mod drain;` and the dispatch arms; added to `.templatesyncignore` in the first story that changes it | 6.10 (`iam_bootstrap`), 9.2 (`gateway`), 15.2 (`drain`) |
| `command/check_config.rs`, `command/healthcheck.rs` (seams) and `tests/integration/{main,support,check_config,healthcheck}.rs` | `--mode gateway\|control` for both commands; new integration modules; each added to `.templatesyncignore` with its sibling tests in the story that changes it | 1.2 (`tests/integration/main.rs`), 9.2 |
| `command/serve.rs` (seam) | After `Adapters::connect`: `register_iam_specs`, configuration gates, `start_tasks(&adapters, Mode::Control, shutdown)`; on shutdown stops tasks within `SHUTDOWN_GRACE_PERIOD` | 6.9 |
| `command/gateway.rs` (new) | `service gateway`: own tokio runtime builder (`new_multi_thread()` honouring `TOKIO_WORKER_THREADS`, `max_blocking_threads` 16), builds gateway adapters without a database pool, starts the listeners (their binds carry `#[expect(clippy::disallowed_methods, reason = ...)]` like the template's socket owners, listed in `docs/architecture.md`), the apply and log threads and the gateway tasks | 9.2 |
| `command/drain.rs` (new) | `service drain`: the preStop `exec` that calls `/internal/drain` over loopback and returns after `DRAIN_PROPAGATION_DELAY` | 15.2 |
| `command/iam_bootstrap.rs` (new) | `service iam-bootstrap --admin-user <uuid>` or `--admin-service <service-name>`, optional `--iam-host <host>` (seeding), `--repair-routes --iam-host <host>` (repair), exit codes 0, 1, 2 (FR-5) | 6.10, 8.7 |
| `bootstrap/tasks.rs` (new, template-ignored `bootstrap/`) | `TaskSupervisor` for the control tasks and the gateway tasks with a shared cancellation signal | 6.9 |
| `bootstrap/gateway/listener.rs` | rustls acceptor (TLS 1.3 and 1.2, ALPN `h2` and `http/1.1`, certificate resolver hot-reloaded from `GATEWAY_TLS_CERT_FILE`/`GATEWAY_TLS_KEY_FILE`), Proxy Protocol v2 through `ppp` when `GATEWAY_PROXY_PROTOCOL` is true on the public listener, the east-west listener on `GATEWAY_MESH_LISTEN` without Proxy Protocol (FR-90), hyper server with the limits of FR-67, connection-age cap with GOAWAY | 9.2, 10.9, 10.13 |
| `bootstrap/gateway/pipeline.rs` | The request pipeline of section 8.1 as a tower service over the application use cases | 10.2 onward |
| `bootstrap/gateway/upstream.rs` | `HyperUpstreamForwarder`, the `UpstreamForwarder` adapter placed here under the ADR 0023 fallback: pooled clients, `tokio` timeouts, "not sent" and idempotent retries, retry budget, outlier ejection, concurrency limit and `forward_upgrade` for WebSockets (section 4.4) | 10.3, 10.5, 11.1 |
| `bootstrap/gateway/internal.rs` | Internal router on `GATEWAY_INTERNAL_LISTEN` (port 9090, admitted from `iam-control` and gateway pods only): `/internal/freshness`, `/internal/policy/applied` | 9.2, 9.5, 13.3 |
| `bootstrap/gateway/probe.rs` | Probe router on `GATEWAY_PROBE_LISTEN` (port 9092, admitted from the kubelet, the NLB subnets and monitoring): `/ping`, `/internal/startup`, `/internal/ready`, `/metrics`, and `/internal/drain`, answered only to loopback peers | 9.2, 9.7, 15.2, 16.2 |
| `bootstrap/gateway/decision.rs` | Decision API on `GATEWAY_DECISION_LISTEN` (port 9091, admitted from decision-API caller namespaces only), section 8.9 | 10.11 |
| `bootstrap/gateway/streams.rs`, `graphql_ws.rs` | WebSocket and SSE splice, stream and subscription registry, the `graphql-transport-ws` and `graphql-ws` frame codec | 11.1, 11.3 |
| `bootstrap/gateway/apply_thread.rs`, `drain.rs`, `metrics.rs` | Apply-thread spawn and its bounded channel; drain and SIGTERM sequence; Prometheus text rendering of the `metrics` target | 9.3, 15.2, 16.2 |
| health probes under `bootstrap/` | Two `HealthProbe` implementations for the `kafka` and `access-log-store` dependencies of `/api/health` in `iam-control` (they live in the composition root because an IAM crate may not depend on the health-check context without a protected `[contexts]` edit) | 7.3, 14.3 |
| `docker-compose.yml` (seam) | `kafka` (single-node `apache/kafka` KRaft broker), later `valkey` and `loki` services; gateway e2e wiring | 1.2, 12.2, 14.2 |
| `Dockerfile`, compose health checks (seam) | The gateway health check runs `service healthcheck --mode gateway` against the probe listener, because the gateway has no serve port | 9.2 |
| `.github/workflows/*` (seam) | The mutation workflow starts the compose `kafka`, `valkey` and `loki` services on every shard; gateway e2e and smoke jobs; service targets in `make/service.mk` | 1.2, 12.2, 14.2, 16.6 |
| `lib.rs` | Unchanged: new modules sit under `command/` and `bootstrap/` | – |

### 7.2 Run modes

| Command | Runs |
| --- | --- |
| `service gateway` | `iam-gateway`: public, east-west, decision, internal and probe listeners; the gateway tasks of section 5.6 (tail, prober, apply thread with the derived-state check, peer readiness, endpoint watch, access-log writer); no database pool |
| `service serve` | `iam-control`: HTTP server with the management API and the decision API; the control tasks of section 5.6 (relay, User service event consumer when `USER_EVENTS_TOPIC` is set, anti-entropy, tombstone emitter, maintenance, bulk runner, Sync-Fence coordinator, rejected-attempt writer) |
| `service iam-bootstrap --admin-user <uuid>` or `--admin-service <service-name>`, optional `--iam-host <host>` | Registers IAM's own specifications, creates `iam-platform-admin` and its first assignment, and with `--iam-host` seeds the upstream `iam-control` and the routes that expose the management API through the gateway as `system` entries, audited as `system:bootstrap` |
| `service iam-bootstrap --repair-routes --iam-host <host>` | Restores the seeded upstream and routes whether or not an administrator exists, as an audited revocation-class change |
| `service drain` | The gateway's preStop hook: calls `/internal/drain` over loopback and returns after `DRAIN_PROPAGATION_DELAY` |
| `service migrate [revert]` | Template behaviour |
| `service check-config [--mode gateway\|control]` | Validates the configuration of one mode; refuses `KAFKA_CONFIG_GATES=relaxed` outside `APP_ENV` `dev` and `test` |
| `service healthcheck [--mode gateway\|control]` | Template behaviour by default (control); gateway mode probes `/ping` on `GATEWAY_PROBE_LISTEN` |
| `service openapi-export`, `service graphql-export` | Template behaviour; the snapshots are generated from the `iam-control` router |

`service worker` does not exist: the `iam-control` Deployment is the isolation for background work.

### 7.3 Configuration

The variables are fixed in the PRD (FR-55) with their defaults and rules; this table groups them by mode (G gateway, C control, B both). Every default is CONFIG.

| Group | Variables |
| --- | --- |
| Tokens (B) | `JWT_PUBLIC_KEYS_FILE`, `JWT_ISSUER`, `JWT_AUDIENCE`, `JWT_CALLER_AUDIENCE`, `JWT_SERVICE_TOKEN_MAX_LIFETIME`, `JWT_CLOCK_SKEW`, `MAX_TOKEN_LIFETIME` (900 s), `TOKEN_MEMO_CAPACITY` (200,000), `TOKEN_MEMO_MAX_TTL` (900 s) |
| Kafka (B unless marked) | `KAFKA_BOOTSTRAP_SERVERS`, `KAFKA_SECURITY_PROTOCOL`, `KAFKA_SASL_MECHANISM`, `KAFKA_SASL_USERNAME`, `KAFKA_SASL_PASSWORD`, `KAFKA_BOOTSTRAP_SASL_USERNAME` and `KAFKA_BOOTSTRAP_SASL_PASSWORD` (G), `KAFKA_CA_FILE`, `KAFKA_CLIENT_ID`, `KAFKA_CONNECT_TIMEOUT`, `KAFKA_REQUEST_TIMEOUT`, `KAFKA_RETRY_DELAY`, `KAFKA_FETCH_MAX_WAIT`, `KAFKA_CONFIG_GATES`, `KAFKA_TRANSACTION_TIMEOUT` (C, 10 s), `POLICY_TOPIC`, `EVENTS_TOPIC` (C), `USER_EVENTS_TOPIC` (C), `USER_EVENTS_CONSUMER_GROUP` (C) |
| Control plane (C) | `DATABASE_LISTEN_URL`, `PUBLISH_WAIT_TIMEOUT` (2 s), `SYNC_FENCE_MARGIN` (500 ms), `SYNC_FENCE_POD_DISCOVERY`, `SYNC_FENCE_STATIC_PODS`, `GATEWAY_NAMESPACE`, `BULK_CHUNK_ENTITIES` (1,000), `BULK_MAX_RECORDS_PER_SECOND` (2,000), `ROUTE_CONFIGURATION_MAX_ROUTES` (1,000), `ANTI_ENTROPY_HEAD_INTERVAL` (10 s), `ANTI_ENTROPY_FULL_INTERVAL` (5 min), `MAINTENANCE_INTERVAL` (10 min), `ORPHANED_GRANT_RETENTION` (90 days), `LOKI_QUERY_URL`, `ACCESS_LOG_QUERY_MAX_RANGE` (24 h), `ACCESS_LOG_QUERY_TIMEOUT` (30 s) |
| Fleet (B) | `GATEWAY_FLEET_LABEL`, `FRESHNESS_HARD_BOUND` (`T_hard`, 15 s, range 3 to 30 s; both Deployments read it from one ConfigMap key), `LOKI_TENANT_ID`, `SHUTDOWN_GRACE_PERIOD` (template; 20 s for the gateway) |
| Gateway listeners and freshness (G) | `GATEWAY_LISTEN` (`0.0.0.0:8443`), `GATEWAY_MESH_LISTEN` (`0.0.0.0:8444`), `GATEWAY_INTERNAL_LISTEN` (`0.0.0.0:9090`), `GATEWAY_DECISION_LISTEN` (`0.0.0.0:9091`), `GATEWAY_PROBE_LISTEN` (`0.0.0.0:9092`), `APPLIED_POLL_MAX_CONCURRENT` (256), `GATEWAY_TLS_CERT_FILE`, `GATEWAY_TLS_KEY_FILE`, `GATEWAY_PROXY_PROTOCOL`, `GATEWAY_ZONE`, `POD_NAME`, `POD_NAMESPACE`, `FRESHNESS_PROBE_INTERVAL` (500 ms), `FRESHNESS_READY_BOUND` (`T_ready`, 2 s), `DERIVED_STATE_CHECK_INTERVAL` (60 s), `RYW_MAX_WAIT` (1 s), `READINESS_AZ_FLOOR` (1), `DRAIN_PROPAGATION_DELAY` (45 s), `TOKIO_WORKER_THREADS` (2) |
| Upstreams (G) | `UPSTREAM_DISCOVERY`, `UPSTREAM_STATIC_ENDPOINTS_FILE`, `UPSTREAM_ZONE_AWARE` |
| Rate limiting (G) | `RATE_LIMIT_STORE_URL`, `RATE_LIMIT_STORE_TIMEOUT` (5 ms), `RATE_LIMIT_BREAKER_OPEN_DURATION` (5 s) |
| Access log (G) | `LOKI_PUSH_URL`, `LOG_ALLOW_SAMPLE_RATE` (0.01), `LOG_CLASS_BUDGETS`, `LOG_CHANNEL_CAPACITY` (65,536), `ACCESS_LOG_AUDIT_FLUSH_INTERVAL` (250 ms), `ACCESS_LOG_AUDIT_MAX_PENDING` (2 s) |
| Streams (G) | `STREAM_MAX_LIFETIME` (1 h), `STREAM_IDLE_TIMEOUT` (60 s), `GRAPHQL_WS_MAX_SUBSCRIPTIONS` (100), `GRAPHQL_WS_INIT_TIMEOUT` (5 s) |

Removed variables: `USER_SERVICE_BASE_URL`, `USER_SERVICE_TIMEOUT`, `JWT_PUBLIC_KEYS`, `TOKEN_CACHE_TTL`, `AUTHZ_CACHE_TTL`, `AUTHZ_CACHE_MAX_ENTRIES`, `POLICY_EPOCH_POLL_INTERVAL`, `POLICY_STALE_GRACE`, `RECONCILIATION_INTERVAL`, `IAM_EVENTS_QUEUE_URL`, `USER_EVENTS_QUEUE_URL`, `ACCESS_LOG_RETENTION`, `ACCESS_LOG_ALLOW_SAMPLE_RATE`, `ACCESS_LOG_BUFFER`. Template variables (`APP_ENV`, `APP_HOST`, `APP_PORT`, `DATABASE_*`, `LOG_LEVEL`, `HTTP_*`, `HEALTH_PROBE_TIMEOUT`) stay; the template's AWS and SQS variables are not used by IAM and stay untouched in the template's own configuration.

### 7.4 Routes and resolvers in `iam-control`

REST under `/api` (section 14) is protected by authentication and `IamAccessGuard`; `/ping`, `/api/health`, `/api/docs`, `/api/docs/openapi.json` and the example context's routes keep their template behaviour. GraphQL stays at `POST /api/graphql`; IAM fields are protected by `IamAuthorizationExtension`, other fields are unaffected. In production `iam-control` is reached only through the gateway, on the routes that `iam-bootstrap` seeds; its ClusterIP Service admits only gateway pods and Jobs.

### 7.5 Epic 1 wiring in `api-gateway-service`

The Epic 1 stories change these files of the target repository; later epics extend the same files as section 7.1 states. Story 1.1's part of this table is already in the working tree, uncommitted.

| File | Change | Story |
| --- | --- | --- |
| `Cargo.toml` (workspace, not protected except `workspace.lints`) | Path entries for the three IAM crates; exact-version entries for `krafka`, `jsonwebtoken`, `criterion`, `aws-lc-rs` in `[workspace.dependencies]` | 1.1, 1.2, 1.6 |
| `crates/service/Cargo.toml` (template-ignored) | The three IAM crates; dev-dependencies `krafka` (`test-broker`), `jsonwebtoken` (`aws_lc_rs`), `criterion`, `aws-lc-rs`; the `[[bench]]` entries | 1.1, 1.2, 1.6 |
| `bootstrap.rs` (template-ignored) | `Adapters` gains the policy-epoch adapter; `Adapters::connect` builds it; `GetPolicyEpochQueryHandler` registered on the query bus; `IamState` built | 1.1 |
| `bootstrap/tests.rs`, `http/router/tests.rs`, `tests/integration/panic.rs` (template-ignored) | The three `Adapters { .. }` literals use `FakePolicyEpochRepository` | 1.1 |
| `http.rs` (template-ignored) | `AppState` gains `IamState` | 1.1 |
| `openapi.rs` (template-ignored) | Nests the IAM router under `/api`; snapshots unchanged; the `iam` tag and `bearerAuth` scheme wait for the first operation | 1.1 |
| `graphql/schema.rs` | Unchanged in this feature | – |
| `lib.rs`, template `Makefile` | Unchanged | – |
| `docker-compose.yml` (seam, added to `.templatesyncignore`) | Service `kafka`: single-node `apache/kafka` KRaft broker, exact image version, PLAINTEXT listener for `dev` and `test`; Story 1.3 adds the `simple` authorizer settings and Story 1.5 a SASL_SSL listener whose CA and certificates a fixture script generates at test time; a separate 3-broker profile outside `make ci` | 1.2, 1.3, 1.5 |
| `crates/service/tests/integration/main.rs` (seam, added to `.templatesyncignore`) | Module lines for `kafka_spike` (removed in 1.7) and `template_seams` | 1.2, 1.7 |
| `.github/workflows/tests.yml` (seam, added to `.templatesyncignore`) | Every mutation shard starts the compose `kafka` service; the push step runs `make mutation-tests-diff` (Story 1.8, with owner agreement) | 1.2, 1.8 |
| `make/service.mk`, `docs/make-targets-service.md` (new, service-owned) | Target `bench-spikes` (key `make.bench_spikes`) running the criterion benches outside `make ci` | 1.6 |

> Assumption: `make.integration_tests` reaches the compose `kafka` service through the service-owned seam `make/service.mk`, which the template `Makefile` loads with `-include` after its `DEPS ?= database localstack` default, so a `DEPS` assignment there adds `kafka` to the services that `ensure-deps` starts locally and in the CI test jobs. Story 1.2 must choose and document this (or an equivalent seam) because the template `Makefile` is not edited.

## 8. Request Path

### 8.1 Pipeline for REST and GraphQL (FR-59)

1. **Accept and read headers** (FR-67). TLS in the pod; header block at most 16 KiB; header read timeout 10 s; HTTP/2 `max_concurrent_streams` 128 and `max_header_list_size` 16 KiB; buffered bytes at most 256 KiB per connection and 256 MB per pod; at most 64 connections per client IP and 32 per subject; keep-alive idle 120 s (below the NLB idle timeout of 350 s); connection age cap 10 min ± 20 % with GOAWAY; heavy connections (above 2,000 requests/s) get GOAWAY early. Client IP from Proxy Protocol v2. Conflicting `Content-Length`/`Transfer-Encoding` rejected; hop-by-hop headers stripped; HTTP/2 `:path` validated; a header block above 16 KiB gets 431. All CONFIG.
2. **Read-your-writes barrier**, only when `X-IAM-Min-Policy-Version` or the `__Host-iam_pv` cookie is present (FR-14, section 9.9). Evaluated before the snapshot load.
3. **Load the snapshot once** and check freshness (FR-73): `now_boot − last_proof ≤ T_hard` and no watchdog gap above `T_ready` since that proof. Not fresh: 503 `iam_stale` with `Retry-After: 1`. Steps 4 to 7 use only this snapshot, so a decision never mixes versions (FR-13).
4. **Route.** Match `(host, method, normalized path)` against the per-host `matchit` routers of the snapshot; the path rule of section 8.2 applies first (400 on rejection). The match gives the upstream, the catalogue service, the route flags, body limit, timeouts, retry policy, enforcement mode, rate policies and CORS policy. No match: 404. A CORS preflight is answered here, before authentication (FR-89): 204 with the CORS headers when the route's policy allows the origin and method, otherwise 403 `cors_rejected`.
5. **Rate limit** (FR-65, section 11). The local per-IP guard always runs; routes with rate policies are checked in Valkey (per-IP and per-route keys here, per-subject keys after step 6). Over limit: 429 `rate_limited` with `Retry-After`. This step never returns 503 and never changes an authorization decision.
6. **Authenticate** (skipped for `anonymous` routes, FR-63). Token from `Authorization: Bearer` or the `__Host-auth_token` cookie; key = SHA-256 of the token; memo, then negative memo; on a miss strict header, RS256 against up to 3 keys newest first, claims, maximum lifetime; on every request, memo hits included, the revocation rule against the snapshot's revocation sets (FR-15, FR-17). Failure: 401 with `WWW-Authenticate: Bearer`. A cookie-authenticated unsafe method or WebSocket upgrade then needs an allowed `Origin` or `Referer`, otherwise 403 `csrf_rejected` (FR-89).
7. **Authorize** (FR-4, FR-10). REST: the matched operation template yields `rest:{service}:{METHOD} {template}`. GraphQL: section 8.3. `DecisionPolicy` over the subject's assignment list and the compiled role sets of the snapshot, with scope and expiry evaluated at decision time. Deny: 403 with a reason code that never discloses another service. A route in `enforcement = audit` logs `audit_mode_would_deny` and forwards (FR-69).
8. **Release the snapshot.** Copy out the fine-grained `Arc`s the rest of the request needs and drop the snapshot `Arc` before any await on the upstream.
9. **Rewrite headers** (FR-68). Strip hop-by-hop headers, every client `X-IAM-*`, `Forwarded` and `X-Forwarded-*`; set `X-IAM-Subject`, `X-IAM-Subject-Kind`, `X-IAM-Session`, `X-IAM-Policy-Version`, `X-Request-Id`, `X-Forwarded-For`; forward `Authorization` and the `__Host-auth_token` cookie only to upstreams with `forwardCredentials = true` (User service, which re-checks sessions on its own routes, and `iam-control`) and strip both elsewhere, so an upstream that is compromised or logs headers never holds a replayable token. No per-request internal token signing; upstream trust comes from the NetworkPolicy, which admits upstream ingress only from gateway pods, and calls between services also go through the gateway (FR-90, section 16.8).
10. **Forward** (FR-66, FR-87). Zone-aware power-of-two-choices over the upstream's endpoints, the canonical re-encoded path, the per-route body limit (REST streamed), timeouts, at most one safe retry, outlier ejection, per-upstream concurrency limit (fail-fast 503 `upstream_overloaded`). Upstream failure: 502; timeout: 504.
11. **Relay the response** unbuffered; strip hop-by-hop headers; add `X-IAM-Policy-Version`; on management write responses set `__Host-iam_pv`.
12. **Log** (FR-50): `try_send` of the access record to the bounded channel; the decision is never delayed except by audit-or-deny (section 12.2).

Statuses produced by the gateway itself: 400, 401, 403, 404, 405 (non-`POST` GraphQL, `graphql-sse` reservation), 413, 415 (multipart or non-JSON GraphQL body), 429, 431 (header block above 16 KiB), 502, 503, 504, and 500 for a caught panic. Gateway error codes: 403 `cors_rejected`, 403 `csrf_rejected`, 503 `iam_stale`, 503 `iam_propagating`, 503 `audit_unavailable`, 503 `upstream_overloaded`, 429 `rate_limited`; WebSocket close codes 1001 (drain), 1008 (revoked), 1013 (fenced), 4400 (malformed frame), 4401 (unauthenticated), 4403 (forbidden); GraphQL `extensions.code` `FORBIDDEN`.

### 8.2 REST path rule and latency budget

**Path rule** (FR-7): decode percent-encoding exactly once; reject with 400 (or `malformed_operation` at the decision API) a decoded path that contains `%`, `\`, NUL, a `.` or `..` segment, an encoded `/` in the raw form, or exceeds 2,048 bytes; forward the canonical re-encoded form of the decoded path, so the upstream's single decode yields exactly the bytes that were authorized. A request such as `%252e%252e` never reaches an upstream that could decode it a second time.

Per-step CPU budget for a warm REST request with a 1 to 4 KB response (all figures ESTIMATE; nothing measured):

| Step | CPU, HTTP/1.1 on both legs | CPU, production mix (HTTP/2 down, h2c up) |
| --- | --- | --- |
| Kernel, TLS records, HTTP parse (downstream) | 11.5 µs | 17 µs |
| Snapshot load and freshness check | < 0.1 µs | < 0.1 µs |
| Route match and normalisation | 0.3 µs | 0.3 µs |
| Token digest, memo hit, revocation checks | 1.1 µs | 2.6 µs (includes 5 % cold tokens) |
| Decision (compiled role sets, 1 to 5 probes) | 0.5 µs | 0.5 µs |
| Header rewrite | 1.5 µs | 2.5 µs |
| Upstream hop (pool, write, read, parse) | 10.8 µs | 15 µs |
| Response relay | 1 µs | 2 µs (plus 0.5 to 0.7 µs per further KB) |
| Access record and metrics | 6 µs | 4 µs (sampled allows; serialisation on the log thread) |
| Scheduling, allocator, cache misses | about 27 µs | about 35 µs |
| **Total** | **about 60 µs** | **about 80 µs**; conservative 200 µs (anchored on a published sidecar proxy cost) |

A Valkey quota check (rate-limited routes only) adds one network round trip of about 0.1 to 0.6 ms (ESTIMATE, same or other AZ) and is reported separately. IAM-specific work (digest to decision) is about 2 to 3.5 µs (ESTIMATE); proxying, framing and logging dominate.

Latency targets (NFR-33, unmeasured): gateway residence time for warm REST on the hottest pod at ≤ 60 % CPU p95 ≤ 0.5 ms and p99 ≤ 1 ms; warm GraphQL with a document-cache hit ≤ +0.1 ms; first-seen token p99 ≤ 1.2 ms; routes with a Valkey rate policy p99 ≤ 2 ms; end-to-end added p99 ≤ 2 ms with zone-aware routing. Expected residence for warm REST is p50 / p95 / p99 ≈ 0.09 / 0.20 / 0.45 ms (ESTIMATE; conservative 0.25 / 0.6 / 1.2 ms, which would miss the targets and trigger the fallback of section 20.4). The gateway-to-upstream round trip is reported separately (same AZ about 0.05 to 0.3 ms p50, cross AZ about 0.4 to 0.6 ms p50, ESTIMATE from published figures), which is why zone-aware routing is a first-release requirement (NFR-43).

### 8.3 GraphQL specifics (FR-8, FR-60)

1. Accept `POST` only (405 with `Allow: POST` otherwise, so an operation never travels in a URL). Buffer the body up to the route limit (64 KiB default, 6 MiB on IAM's own GraphQL route so specification uploads keep parity); larger: 413. Accept `application/json` only (multipart and other types: 415); reject duplicate JSON keys so the gateway and the upstream cannot read different `query` members; accept only the members `query`, `operationName`, `variables` and `extensions`, require a non-empty `query` string, and reject `extensions.persistedQuery` and any document-id member (`documentId`, `queryId`, `id`) with 400, because an upstream could execute a cached operation the gateway never saw; a JSON array is a batch of at most 10, each element authorized.
2. Document cache (`MokaDocumentCache`): key = 128-bit non-cryptographic hash of the query text plus `operationName` and the catalogue version; on a hit the full text is compared, so a collision can never become a bypass. The value is the coordinate set plus depth, alias and fragment counts, never a decision.
3. On a miss: charge the subject's parse budget (20 misses/s and 1 MB/s, CONFIG; over budget 429); parse with `async-graphql-parser` on the request's worker up to 8 KB and through `spawn_blocking` on the bounded blocking pool (`max_blocking_threads` 16) above that, so a large document never holds a request worker; collect `gql:{service}:{Type}.{field}` coordinates against the service type graph in the snapshot, including fragments, interfaces, unions and both branches of `@skip`/`@include`; enforce depth 15, 500 coordinates, 50 aliases, 100 fragments. Introspection only with `gql:{service}:__introspection`.
4. Decide over all coordinates, all or nothing; an empty coordinate set is `malformed_operation`, a denial.
5. Forward the original buffered bytes unchanged.

### 8.4 Anonymous routes (FR-63)

Routes flagged `anonymous` skip authentication and authorization but keep the local guard, rate limits, body limits and freshness fencing, because the flag and the route table are policy and a stale pod must not keep serving a route that has since become protected. The reference route configuration flags User service's public endpoints (`/api/signin`, `/api/signin/2fa`, `/api/token`, `/api/oauth/*`, `/api/reset-password*`, `POST /api/users`, `/api/users/confirm`, `/api/health`). Consequence: a Kafka outage longer than `T_hard` also blocks sign-in and token refresh (owner item D5, default "fence").

### 8.5 WebSocket and SSE streams (FR-61)

- `streaming` routes authorize the opening request (WebSocket upgrade or SSE `GET`); after `101` or the first SSE bytes the gateway splices and registers `(subject, session, required keys, scope, token exp, earliest expiry of the authorizing assignments, authorizing version)` in the stream registry, indexed by subject and session. The decision composer already computes the shortest expiry of the assignments that contributed to the allow; the registry keeps it because an assignment expiry produces no policy version. No compression and no response timeout on stream routes; idle timeout `STREAM_IDLE_TIMEOUT` (60 s, above Notification service's 15 s keep-alive).
- **Re-authorization by subject index.** When a version is applied, `StreamReauthorizer` re-evaluates only streams of subjects, sessions or roles that version touched (a role change maps to its subjects through the snapshot's reverse index); a global cut-off or a route change re-evaluates every stream of the affected scope. Revoked streams close (WebSocket 1008, SSE end). The pod reports the version applied on `/internal/policy/applied` only after this finishes, so a Sync-Fence `complete` covers open streams too (G8).
- **Registration race.** A stream whose authorizing version is below the published version, or below the finished-re-evaluation mark, is re-checked right after insertion; the mark for V advances only when no stream registered below V remains unevaluated. A stream opened while V is applied is therefore evaluated against V before V is reported applied.
- **Staleness closes streams.** When the published snapshot's proof age exceeds `T_hard`, or the pod fences or goes unready for staleness, the gateway closes every registered stream and subscription (WebSocket 1013, SSE end). GOAWAY never reaches upgraded connections and a stale pod never answers a Sync-Fence poll, so without this rule a `bounded` answer would not cover open streams.
- **Assignment expiry.** At the earliest expiry of its authorizing assignments a stream is decided again on the current snapshot and closed (WebSocket 1008, SSE end) when denied; when another assignment still grants it, it stays open with the new earliest expiry. Without this rule a stream would outlive its assignment until token expiry (up to 900 s) or `STREAM_MAX_LIFETIME`.
- **Lifetime cap.** Every stream closes at `min(token exp, STREAM_MAX_LIFETIME)` (1 h), and is re-checked earlier at its assignment expiry as above; fencing closes with 1013; drain closes with 1001. Per-subject stream count follows the per-subject connection cap (32).

### 8.6 GraphQL subscriptions (FR-62)

- Routes flagged both `graphql` and `streaming` accept WebSocket subprotocols `graphql-transport-ws` and the legacy `graphql-ws` only; any other subprotocol is refused with 400 before the upgrade.
- The composition root decodes WebSocket frames in both directions with `tokio-tungstenite`; client messages are inspected, server messages pass through.
- Authentication before any upstream connection: the gateway completes the client-side handshake itself and holds the upstream. It reads `connection_init` within `GRAPHQL_WS_INIT_TIMEOUT` (5 s, CONFIG; a client that sends nothing is closed with 4408), takes the token from the upgrade request or, if absent there, from `connection_init.payload.authorization` (`Bearer <token>`), verifies it (missing or invalid closes with 4401), and authorizes the route on the authenticated principal (a denial closes with 4403). Only then does it open the upstream WebSocket and send a `connection_init` whose payload has `authorization` removed unless the upstream has `forwardCredentials = true` (FR-68); it relays the upstream's `connection_ack` and registers the connection in the stream registry. No upstream socket exists for an unauthenticated client, and sockets waiting for `connection_init` count against the edge connection limits (FR-67). A token is never forwarded inside any message, the first one included, to an upstream without `forwardCredentials`.
- Per operation: on `subscribe` or `start` (and queries or mutations over the socket) `SubscriptionAuthorizer` parses with the analyzer and limits of section 8.3, collects coordinates including the `Subscription` root field, and decides all or nothing. A denial answers that operation id with an `error` message carrying `FORBIDDEN` and does not forward the frame; the socket stays open. At most `GRAPHQL_WS_MAX_SUBSCRIPTIONS` (100) operations per connection; messages at most 64 KiB; malformed frames close with 4400.
- Re-evaluation: when an applied version touches the subject, a session, a role it holds or the service catalogue, and at the earliest expiry of the assignments that authorized it (stored per operation), each open operation is decided again; a denied operation gets `complete` towards the upstream and `error` with `FORBIDDEN` towards the client; a revoked session or cut-off closes the socket with 4403.
- A `subscribe` or `start` payload follows the envelope rules of section 8.3: one with `extensions.persistedQuery`, a document-id member or no non-empty `query` gets an `error` for its id and is not forwarded.
- GraphQL over SSE: distinct-connections mode only; the operation travels in the opening request, so it is authorized like any GraphQL request and registered like an SSE stream. The single-connection mode's `PUT` reservation is refused with 405, because its operations would arrive as separate requests that the registry cannot re-evaluate.

### 8.7 Timeouts, retries, circuit breaking and body limits (FR-66)

| Concern | Design (CONFIG) |
| --- | --- |
| Timeouts | Upstream connect 250 ms; response headers 10 s REST and 30 s GraphQL; whole request 60 s, none for streams; downstream header read 10 s; upstream pool idle 60 s |
| Retries | Only when the request provably was not sent (refused, closed before write, HTTP/2 `REFUSED_STREAM`, GOAWAY above the last stream id; the forwarder resends the request hyper hands back), or for idempotent methods on routes with `retryPolicy = idempotent` when the request has no body or a body buffered under 64 KiB; at most one retry to another endpoint; budget 10 % per upstream; GraphQL mutations never retried; all decided in the composition-root forwarder |
| Outlier ejection | After 5 consecutive connect errors or 5xx, for 10 s, at most 50 % of an upstream's endpoints |
| Concurrency | Per-upstream in-flight limit sized to the upstream's worker count, fail-fast 503 `upstream_overloaded`; this, not the connection count, is the binding upstream limit |
| Body limits | REST streamed, 10 MiB default per route; GraphQL buffered, 64 KiB default, 6 MiB on IAM's GraphQL route; HTTP/2 windows 1 MiB per stream and 4 MiB per connection, bounded by the per-connection buffer cap |

### 8.8 Logging step

The access record is built by `AccessRecordBuilder` and sent with `try_send`; section 12 describes the lanes, budgets, audit-or-deny and the Loki layout.

### 8.9 Internal decision API (replaces the validate-access sequence)

Microservices that check their own internal actions call the decision API on the gateway's decision listener (`GATEWAY_DECISION_LISTEN`, Service `iam-gateway-decision`, port 9091) at the same paths as `iam-control`; that listener serves nothing else, so a decision-API caller cannot reach the internal or probe endpoints: `POST /api/access-validations`, `POST /api/access-validations/batch`, `POST /api/token-resolutions`, and `POST /api/graphql` exposing only `validateAccess`, `validateAccessBatch` and `resolveToken` (FR-6, FR-11, FR-19). The sequence is: caller authentication with `JWT_CALLER_AUDIENCE` and `JWT_SERVICE_TOKEN_MAX_LIFETIME` (FR-3); caller authorization with `iam:validate:{service}` or `iam:validate:*` (FR-12); input limits; the read-your-writes wait for `minPolicyVersion` (FR-14); one snapshot load and freshness check; subject token resolution with the memo and the revocation rule; required keys; `DecisionPolicy`; an access record; HTTP 200 with the decision body. A stale snapshot or any internal error yields `deny` with reason `unavailable` (FR-13). `iam-control` serves the same contract from PostgreSQL through `PolicyReadRepository`, so the published contract, Schemathesis and e2e scenarios run against one router and agree for the same policy version (NFR-7, NFR-16).

## 9. Policy Replication and Freshness

### 9.1 Topics

| Topic | Purpose | Partitions and replication | Cleanup and settings (CONFIG) | Key | Value | Readers |
| --- | --- | --- | --- | --- | --- | --- |
| `iam.policy.state.v1` (`POLICY_TOPIC`) | Replicates authorization state; bootstrap source | Exactly 1; RF 3, one replica per AZ; `min.insync.replicas` 2 | `compact`; `min.compaction.lag.ms` 1 h; `max.compaction.lag.ms` 1 day; `delete.retention.ms` 7 days; `max.message.bytes` 1 MiB; `segment.bytes` 64 MiB; `segment.ms` 1 h; `min.cleanable.dirty.ratio` 0.1; `message.timestamp.type=LogAppendTime`; `unclean.leader.election.enable=false`; `Write` ACL for `iam-control` only | The state keys of section 9.2 | Full new entity state (JSON with `schemaVersion`) or null (tombstone) | Every gateway pod (all records); `iam-control` anti-entropy |
| `iam.events.v1` (`EVENTS_TOPIC`) | IAM domain events | 1; RF 3 | `delete`, 7 days | Aggregate id | Envelope `{id, type, occurredAt, data}` ≤ 64 KiB | Notification service, audit and analytics pipelines |
| `user.events.v1` (`USER_EVENTS_TOPIC`, owned by User service) | User service session and user events | Set by User service, keyed by user id | User service's choice | User id | Neutral envelope, or the Symfony Messenger `DomainEventEnvelope` | `iam-control` only, group `iam-control-user-events` |

- One partition gives one total order and a scalar cursor (the org precedent). Growth path above about 500 policy writes/s (ESTIMATE): partitions keyed by tenant with per-partition cursors; not in this plan.
- With the segment and dirty-ratio settings above, a bootstrap reads about `live × 1.1 + 64 MiB` instead of up to `2 × live + 1 GiB` at broker defaults (ESTIMATE).
- Topics are Strimzi `KafkaTopic` resources reconciled by the Topic Operator, never created by the service (section 17.11).
- **Configuration gates** (FR-72): gateway pods (readiness) and `iam-control` (publishing) read the topic configuration with `DescribeConfigs` and refuse unless cleanup policy, unclean election off, `min.insync.replicas` 2, replication factor 3, exactly one partition and `LogAppendTime` match; `iam-control` also checks the topic ACLs and `allow.everyone.if.no.acl.found=false` (through `DescribeConfigs` on the cluster, or the fallback recorded by spike Story 1.3 when the broker does not return that authorizer property). `KAFKA_CONFIG_GATES=relaxed` accepts RF 1 and a 1-of-1 replica quorum and logs a warning on every probe; it is refused outside `APP_ENV` `dev` and `test`, because docker compose runs a single broker.

### 9.2 Unit of work, state records and framing (FR-70)

- Every versioned transaction increments the gap-free `iam_policy_epoch.version` under the counter-row lock, writes one state row per changed entity and one `__head` row `{version, digest}`, and updates the 128-bit XOR digest (section 6.1). Guards run against PostgreSQL inside that transaction.
- State keys: `role/<uuid>`, `subject/<kind>/<id>` (the subject's full assignment list), `catalog/<service>/manifest`, `catalog/<service>/<catVer>/<chunk>` (content-addressed chunks of at most 1 MiB), `route/<id>`, `upstream/<name>`, `ratepolicy/<id>`, `revocation/session/<sid>`, `revocation/user/<uid>`, `revocation/global`, `__head`. Later phase only: `pq/<hash>` (persisted queries) and `hb/<control-pod>` (strict-mode heartbeats).
- Record headers (a null tombstone keeps its headers, so deletes stay framed): `iam-version`, `iam-seq`, `iam-count`, `iam-digest-after`, `iam-op`, `iam-schema`, `iam-log-epoch`, `iam-relay-epoch`. Spike Story 1.2 must prove that krafka writes and reads headers on null-value records; the fallback (framing in the value with soft-delete markers) needs its own design pass and is an owner decision.
- A catalogue version activates in the snapshot only when its manifest and all its chunks are present; unchanged chunks are not republished.
- PostgreSQL replication must be synchronous (RDS Multi-AZ, CONFIG precondition). An asynchronous failover could roll the version back below versions already in Kafka; the relay then detects "topic ahead" and stops, and the runbook resyncs as a new log epoch (FR-78, NFR-28).

### 9.3 Relay, fencing, anti-entropy and bulk changes

- **Relay** (`OutboxRelay`, one active per fleet, FR-46): a transaction-level advisory lock per batch; wake-up on `LISTEN iam_outbox` held by the current leader only, with a 100 ms poll fallback; reads unpublished rows in `(policy_version, seq)` order; produces state rows to partition 0 and event rows to `iam.events.v1` with `acks=all`, idempotence, one request in flight and lz4; stores the returned offsets and marks rows published; checks on every metadata refresh that the state topic still has exactly one partition and stops otherwise; releases the lock on SIGTERM; deletes published rows after 7 days.
- **Zombie-relay fencing.** An advisory lock does not fence Kafka writes: a relay that lost its PostgreSQL session can still deliver a late batch. Layer 1 (when spike Story 1.4 passes): a transactional producer with `transactional.id` `iam-relay`, so the broker rejects an old producer epoch; consumers read with `read_committed` and the probe sends `ListOffsets` with isolation `READ_COMMITTED`, so both stop at the last stable offset (LSO). In this mode a row is published, and its offset stored, only when the transaction that contains it has committed; the produce acknowledgement alone is not visibility, and rows of an aborted transaction stay unpublished and are sent again. `KAFKA_TRANSACTION_TIMEOUT` (`transaction.timeout.ms`, default 10 s, CONFIG) must stay below `FRESHNESS_HARD_BOUND`, so a hanging zombie transaction cannot pin the LSO past the staleness bound; with `KAFKA_CONFIG_GATES=enforce` the relay refuses to start transactional mode otherwise, and the runbook lowers it before `T_hard` drops to 5 s. Layer 2 (always on): the `iam-relay-epoch` header from a PostgreSQL counter incremented on every takeover; every key and `__head` resolve by highest version, never by offset; pods ignore records with a lower relay epoch than one already seen; the new relay republishes the current state of every key in the takeover range; a bootstrap that finds a record above the highest `__head.version` fails closed and alerts.
- **Anti-entropy** (`AntiEntropyChecker`, FR-77): every `ANTI_ENTROPY_HEAD_INTERVAL` (10 s) compare the topic's newest `__head` with PostgreSQL; verify that stored published offsets still hold the expected versions and republish lost records; for each key written since the previous check, compare the version of the key's last record by offset (read from the tail) with the newest PostgreSQL version and republish the current state when it is lower, well inside `min.compaction.lag.ms` (1 h). This is layer 2's repair for a zombie relay batch that lands after the takeover republish: without it, compaction would keep the stale record as the key's last value and every later bootstrap would fail its digest check; every `ANTI_ENTROPY_FULL_INTERVAL` (5 min) run a shadow bootstrap that rebuilds state from the topic and compares the full digest with PostgreSQL. Alert within 10 s.
- **Resync** (FR-78): `ResyncPolicyCommandHandler` republishes the full current state as a new log epoch with versions continuing above the topic maximum, as a bulk operation, audited, with `iam.policy.resynced`. It replaces the operator cache flush.
- **Bulk changes** (FR-84): above `BULK_CHUNK_ENTITIES` (1,000) a change is split into versions with revoke-type chunks committed before grant-type chunks, so no intermediate version is more permissive than both its predecessor and the final state. The first release caps the commit rate at `BULK_MAX_RECORDS_PER_SECOND` (2,000 records/s), about 12 to 48 MB/s of leader egress at 9 pods (ESTIMATE). The request returns 202 with the `Location` of the bulk operation (GraphQL `bulkOperationId`); other revocation-class writes interleave between chunks and take the next version. A bulk change that is itself revocation-class (for example deleting a role with 2,500 assignments, kind `role_deletion`) fences each revoke-type chunk with Sync-Fence before the next chunk commits, and the bulk operation reports `propagation` for its last fenced version. Pacing happens at commit, so the outbox never holds a large backlog in front of a revocation. Fleet-size-aware pacing (`r_bulk ≤ 0.5 × B_egress / N_ready`) is a later-phase item (section 20.6).

### 9.4 Consumer, bootstrap and apply in the gateway (FR-71, FR-74)

**Consumer.** No consumer group: `assign` partition 0, position in memory, `read_committed`, never auto-reset. Tail and probe use principal `iam-gateway` with `client.id` `iam-gateway-<pod-name>`; the bootstrap read uses principal `iam-gateway-bootstrap` with `client.id` `iam-gateway-bootstrap`, which alone carries a fetch quota. Metadata refresh every 2 s with the partition-count and replica-quorum checks. After a reconnect, or when the probe sees the watermark move while the tail is idle, the tail reseeks to its in-memory position (krafka's long poll does not report a broker outage). Decoding runs on the apply thread, never on a tokio worker.

**Bootstrap** (PostgreSQL never participates):

1. Read `HW0` with `ListOffsets` with isolation `READ_COMMITTED` (the last stable offset, which equals the high watermark when no transaction is open); seek to offset 0.
2. Decode into a plain builder, per-key version guard (`v > current(K)`, highest version wins, tombstones delete); ignore records of a lower relay epoch than one already seen.
3. At position ≥ `HW0`: finish the version straddling `HW0` if complete; if incomplete, publish at V − 1 and continue in tail mode. Set `applied` to the highest complete `__head.version`; a record above it fails closed and alerts. The computed digest must equal that `__head.digest`; otherwise retry once, then stay not started and alert.
4. Freeze into a `PolicySnapshot`, publish through `ArcSwap`, switch to tail mode.
5. Once a freshness proof taken after step 4 is attached to a published snapshot, the pod is fresh and its startup probe passes. `/internal/policy/applied` is served from process start, so Sync-Fence can count a bootstrapping pod as complete when its `HW0` is beyond the write's offset.

Bootstrap targets: single joiner ≤ 30 s at the first-release data size and at 1M users (NFR-37, ESTIMATE 3 to 20 s); startup probe budget 300 s (CONFIG). No krafka throughput figure exists; spike Story 1.5 records a read rate on the compose host only.

**Tail and apply.**

- `VersionAssembly` collects the records of one version by `iam-seq`; a version is applied only when complete (`iam-count` records) and equal to `applied + 1`.
- Duplicates are normal: a record whose version is ≤ `applied` is ignored when its `iam-digest-after` equals the one recorded for that version (a ring of the last 100,000 versions, about 2.4 MB, ESTIMATE). Conflicting content for the same version, a lower `iam-log-epoch`, a gap, a broker append time older than 1 h in tail mode, or a watermark regression fences the pod.
- Apply runs on a dedicated OS thread into 4,096 copy-on-write shards; each touched shard is cloned at most once per published snapshot; publication at most once per 5 ms measured on `BootClock`, always at a version boundary; deferred reclamation of retired snapshots on the apply thread.
- After each version the incremental digest must equal `iam-digest-after`, and the apply thread checks it before it publishes the version: a version whose digest does not match is never published, so the serving snapshot stays the last verified one and the mismatch is a log-level fence. Pods export `applied_version`, `digest` and `derived_hash`; an alert fires when pods disagree.
- **Derived-state check** (FR-74): every `DERIVED_STATE_CHECK_INTERVAL` (60 s) the apply thread rebuilds the derived structures of a rotating 1/16 of the shards from the raw map and compares a hash of the decision-relevant outputs (each subject's sorted effective-key set, the route table) with the incremental structures. A mismatch means the published, serving snapshot is wrong, so the pod stops allowing at once: it clears `last_proof`, every request gets 503 `iam_stale` (decision API `deny`/`unavailable`) and the pod fails readiness until a rebootstrap has published a verified snapshot.
- Apply uses no wall clock and no randomness; assignment and revocation expiry are evaluated at decision time, and open streams and subscription operations are decided again at the earliest expiry of their authorizing assignments (sections 8.5 and 8.6), because an expiry produces no version; pruning happens only through control-plane tombstones (FR-79).
- **Fence without a thundering herd.** Two fence classes exist. A log-level fault (a gap, conflicting duplicate content, a lower log or relay epoch, a watermark regression, an append time older than 1 h, an out-of-range position, a digest mismatch caught before publication) leaves the published snapshot verified, so the pod keeps serving it while its proof is younger than `T_hard` (the proof stops advancing, so this ends by itself). A derived-state mismatch on the published snapshot stops allows at once, as above. Both classes start the rebootstrap after a random delay of 0 to `T_ready`.

### 9.5 Freshness proof (FR-73)

What cannot be built: an atomic update of PostgreSQL and every replica; an unconditional "every replica applied" answer while the replica set changes; linearizable decisions without a per-request round trip; and a partition-proof freshness signal from the watermark alone, because an isolated partition leader keeps answering with its frozen high watermark. The design therefore proves freshness per pod with a quorum-backed signal.

- **Clock.** All elapsed-time rules use `CLOCK_BOOTTIME` through `BootClock`. A 1 s watchdog tick that observes a gap larger than `T_ready` invalidates the current proof.
- **Probe** every `FRESHNESS_PROBE_INTERVAL` (500 ms) on its own connection: (1) record `t_s` before sending anything; (2) ask at least 2 of the 3 replica brokers for partition 0's metadata and accept only if at least 2 report the same leader and leader epoch, that epoch is at least the highest seen, and the topic has exactly one partition; (3) `ListOffsets` with isolation `READ_COMMITTED` for every partition to that leader with the confirmed `current_leader_epoch`; any of `OFFSET_NOT_AVAILABLE`, `FENCED_LEADER_EPOCH`, `UNKNOWN_LEADER_EPOCH`, a lower watermark than one observed, or a nonzero watermark on another partition means no proof; (4) the result is `HW(t_s)`, the last stable offset at `t_s`. With the transactional relay an open transaction holds `HW(t_s)` at its first record, so no proof covers a version before its commit; without transactions the LSO equals the high watermark.
- **Why the quorum step closes the zombie-leader case.** An acknowledged write needs 2 in-sync replicas (`min.insync.replicas` 2, RF 3, unclean election off). Two replicas that confirm epoch e and two that acknowledged a write under a newer epoch share one broker, which knows the newer epoch; so once a newer-epoch write is acknowledged no pod can confirm the old epoch, and a pod that reaches only the old leader gets no proof. This rests on one unverified point (a broker's Metadata response is never older than the leader epoch its own replica fetcher uses), checked by spike Story 1.3 and test T15.
- **Proof attached to the published snapshot.** When the apply thread has published a snapshot containing every complete version whose last record lies below `HW(t_s)`, it sets that snapshot's `last_proof = max(last_proof, t_s)`. The proof never claims more than the snapshot that serves requests contains.
- **Peer cross-check.** If a peer reports an applied version above this pod's published version for more than 1 s while this pod's proof says fresh, the pod treats its proof as invalid and alerts.
- **Decision rule:** allow only if `now_boot − last_proof ≤ T_hard` and the watchdog shows no gap above `T_ready` since that proof; otherwise 503 `iam_stale` with `Retry-After: 1` (decision API: `deny`/`unavailable`).
- No record is written to Kafka for freshness in the default mode. If the quorum check cannot be built, the options are a sequenced liveness record from `iam-control` (needs an owner ruling, D17) or the later-phase strict mode.

### 9.6 Guarantees

| Id | Guarantee | Conditions |
| --- | --- | --- |
| G1 | Durability: an acknowledged change survives the loss of any one broker and a PostgreSQL failover | `acks=all`, `min.insync.replicas` 2, RF 3, unclean election off (gated), synchronous PostgreSQL replication; anti-entropy republishes a lost record |
| G2 | Total order and idempotent apply: every pod passes through the same sequence of states | Exactly one partition (checked every 2 s); relay fencing |
| G3 | Convergence: every connected pod reaches the same `(version, digest, derived_hash)`; restarted pods rebuild it from the topic | Keys resolve by highest version |
| G4 | Bounded staleness, enforced: no allow based on a state missing a change acknowledged more than `T_hard` earlier | Conditional on the configuration gates, relay fencing and the replica-quorum check passing spike Story 1.3 and T15 (Story 16.8) |
| G5 | Typical propagation: Kafka acknowledgement to every healthy pod p99 about 40 ms at 10 pods; PostgreSQL commit to every healthy pod p99 about 150 to 300 ms | ESTIMATE; steady state; target p99 ≤ 500 ms (NFR-35) |
| G6 | Read-your-writes on any pod: a request carrying minimum version V is authorized on a published snapshot ≥ V, or refused with 503 | Barrier before the snapshot load |
| G7 | Monotonic reads per pod | Regression detection |
| G8 | Sync-Fence: after a write returns `complete` or `bounded`, no gateway pod makes a new decision, or keeps an open stream, on state older than that write; requests authorized earlier may complete | Every gateway pod carries the fleet label; consistent pod list; the coordinator waits for the highest hard bound any pod reports; streams are re-checked on registration and closed when the proof ages past `T_hard` (section 8.5); same conditions as G4 |
| G9 | Fail closed: unknown, partial, gapped, diverged or stale state gives 503 or deny, never allow | – |

The default mode (owner decision D3) counts the bound from the Kafka acknowledgement. Committed but unacknowledged changes (relay stall, PostgreSQL failover) are not enforced until published; this contract boundary is made visible by `202 committed_pending_propagation`, `outbox_oldest_unpublished_seconds` (alert above 2 s, page above 10 s) and Sync-Fence. The strict mode with heartbeats, which counts from the commit at an availability cost, is built only if spike Story 1.3 or T15 fails (section 20.6).

### 9.7 Choosing `T_hard`

`T_hard` (`FRESHNESS_HARD_BOUND`) is both the maximum staleness of an allow and the tolerance for losing the partition leader. A hard leader crash gives about 11 to 12 s with no valid proof (ESTIMATE: broker session timeout, election, metadata refresh, probe). The initial production value is **15 s** (owner decision D2), which rides out a leader crash; the **5 s target** applies once T14 (Story 16.8) measures a proof gap of at most 2 s, with Strimzi broker session and heartbeat timings tuned in the `Kafka` resource. Sync-Fence's `bounded` answer takes `T_hard + SYNC_FENCE_MARGIN`, so it shortens with `T_hard`. NFR-36: no allow on a snapshot whose proof is older than `FRESHNESS_HARD_BOUND`.

### 9.8 Write modes and Sync-Fence (FR-75, FR-76)

| Mode | Returns when | Added latency (ESTIMATE) | REST response | GraphQL payload |
| --- | --- | --- | --- | --- |
| `published` (default for ordinary writes) | PostgreSQL commit and visibility of the version's `__head` row to `read_committed` readers: its `acks=all` acknowledgement with the idempotent relay, the completed commit of its transaction with the transactional relay (the handler waits for the relay's stored offset of that row, stored only at that point) | 5 / 15 / 50 ms (optimistic / expected / conservative) | `200`/`201` with `Iam-Policy-Version` and `Iam-Policy-Offset`; `202` with `committed_pending_propagation` after `PUBLISH_WAIT_TIMEOUT` (2 s) | `propagation { status: PUBLISHED \| COMMITTED_PENDING, policyVersion }` |
| `propagated` (`Prefer: wait=propagated` or `consistency: PROPAGATED`; default for revocation-class writes) | `published`, and every gateway pod has applied the version and finished stream re-evaluation, or the bound has passed | p99 about 300 ms with no pod in transition; `T_hard` + 0.5 s when a running pod does not answer | `200` with `Iam-Propagation: complete` or `bounded` and pod counts | `propagation { status: COMPLETE \| BOUNDED \| COMMITTED_PENDING, policyVersion, podsAcknowledged, podsTimedOut }` |

Revocation-class writes (default `propagated`): delete role (FR-23); replace role grants removing at least one key (FR-24); revoke assignment (FR-29); an assignment expiry shortened or newly set (FR-28); an activation that orphans grants (FR-32, FR-36); a retirement that orphans grants (FR-38); a route update that clears `anonymous`, moves `enforcement` from `audit` to `enforce`, or deletes the route (FR-57); an applied route configuration whose diff does any of these (FR-58); revoke sessions and set cut-offs (FR-80). The class depends on the effect, not on the API path. A revocation-class change above `BULK_CHUNK_ENTITIES` is a bulk operation whose revoke-type chunks are each fenced (section 9.3). Revocations consumed from `user.events.v1` are fenced asynchronously (FR-18).

**Sync-Fence coordinator** (`SyncFenceCoordinator` in `iam-control`):

1. At `t_ack` (control-plane boot-time clock): the instant the version's `__head` row became visible to `read_committed` readers, which is the Kafka acknowledgement with the idempotent relay and the completed transaction commit with the transactional relay. Then list gateway pods by `GATEWAY_FLEET_LABEL` through `PodLister` as a consistent read, including Running, Pending and Terminating pods. A ready-only list (headless-Service DNS) would miss terminating pods that still serve keep-alive traffic.
2. Count as complete without polling: pods with no started container (their bootstrap watermark is read after `t_ack`) and pods whose gateway container has terminated.
3. Long-poll every other pod on its internal listener: `GET /internal/policy/applied?atLeast=V&offset=O&wait=T`. A pod answers when it has published V and no stream registered below V remains unevaluated; a bootstrapping pod answers at once if its `HW0` is beyond the write's offset O; when the wait (capped at `T_hard` + 1 s) ends it answers 204 without an acknowledgement; at most `APPLIED_POLL_MAX_CONCURRENT` polls wait per pod and a further one gets 503. Every answer, like `/internal/freshness`, carries the pod's configured `T_hard` as `hardBoundMs`. Concurrent writes are batched: one long poll per pod serves the highest pending V.
4. Return `complete` when every polled pod has answered; otherwise `bounded` once `max(own T_hard, the highest hardBoundMs any gateway pod reported in the last 24 h) + SYNC_FENCE_MARGIN` (0.5 s) has elapsed since `t_ack`. The maximum covers a fleet in the middle of a `T_hard` change: both Deployments read the value from one ConfigMap key, and the runbook raises it on `iam-control` first and lowers it on the gateways first. A pod that has not answered cannot allow on older state by then: an allow needs a proof whose probe was sent after `t_ack`, so its snapshot contains V. This step inherits G4's conditions.
5. Acknowledgements travel over HTTP, never Kafka. RBAC: `get` and `list` on pods in `GATEWAY_NAMESPACE` only.

Targets: commit to every healthy pod p99 ≤ 500 ms on the first-release fleet; Sync-Fence p99 ≤ 1 s with no pod in transition (NFR-35). `GET /api/policy-versions/{version}/propagation` runs the same wait for an already published version (FR-83); `GET /api/policy-status` reports committed and published versions, offset, log epoch, oldest unpublished outbox age, User service consumer lag and each pod's applied version and proof age (FR-82).

### 9.9 Read-your-writes (FR-14)

Every management write response carries `Iam-Policy-Version: V`; because the management API is proxied by the gateway, the gateway also sets the cookie `__Host-iam_pv=V` (`Max-Age` 60 s, `Secure`, `HttpOnly`, `SameSite=Strict`), so the CRM SPA gets the barrier without code changes. API clients may send `X-IAM-Min-Policy-Version: V`. `ReadYourWritesBarrier` runs before the snapshot load and compares V with the published snapshot's version: a V above the highest version this pod has seen in the log gives 503 `iam_propagating` with `Retry-After: 1` at once (no task held); otherwise the request waits on a watch channel up to `RYW_MAX_WAIT` (1 s), then continues on a snapshot ≥ V, or gives the same 503. Without the header or cookie the cost is one atomic load. At the decision API `minPolicyVersion` uses the same wait on the gateway; on `iam-control` a version above the current one returns 422.

### 9.10 Failure behaviour

| Failure | Gateway behaviour | Client sees | Allow beyond G4? |
| --- | --- | --- | --- |
| Kafka unreachable from one pod | Peers fresh, so after 2 local verdicts the pod goes unready and sends GOAWAY or `Connection: close`; denies after `T_hard`; open streams and subscriptions closed with 1013 at `T_hard` | Connections move to other pods; 503 on remaining requests after `T_hard`; streams reconnect to fresh pods | No |
| One AZ partitioned from Kafka or from 2 of 3 replicas | Pods in that AZ lose their proof; the last `READINESS_AZ_FLOOR` pods stay registered and fail closed per request | 503 in that AZ; other AZs unaffected | No |
| One AZ isolated with the old partition leader | Probe reaches one replica only; no proof | 503 in that AZ | No, conditional on spike Story 1.3 and T15 |
| Kafka down fleet-wide | Peers stale too, so pods stay ready and return 503 `iam_stale` after `T_hard` | Deterministic 503 with `Retry-After` | No |
| Partition leader crash | No valid proof for about 11 to 12 s (ESTIMATE) | Nothing at `T_hard` 15 s; about 6 to 7 s of 503 at 5 s | No |
| Topic misconfiguration or unclean election | Configuration gate fails, or anti-entropy republishes; conflicts fence pods | Pods unready or 503 | No |
| Relay restart republishes versions | Duplicates ignored | Nothing | No |
| Zombie relay batch | Transactional fencing or relay epoch; anti-entropy repairs | New pods may wait for repair | No |
| Relay stuck or PostgreSQL failing over | Gateway serves the acknowledged state; writes return `202`; alert | Administrators see "not yet in force" | Contract boundary (section 9.6) |
| `iam-control` down | Data plane unaffected; Sync-Fence, bulk runs and management API unavailable | Management 503 | No |
| Gap, digest or derived-state mismatch, conflicting duplicate, regression, lower epoch | Pod fences, keeps its last verified snapshot until `T_hard`, rebootstraps after a random delay | That pod unready | No |
| CPU starvation, blocked apply thread, VM pause | Proof ages or the watchdog invalidates it | 503 at `T_hard` | No |
| JWT key file missing at startup / reload fails at runtime | Startup fails / last valid set kept, alert | – | No |
| User service down | Nothing changes at the gateway; its own routes return their errors | Errors on User service routes only | No |
| User service stops publishing, or the consumer stalls | Replicated revocations stay enforced; new ones wait; lag alert at 2 s, page at 10 s | Logged-out sessions keep working on upstreams without their own session check until the consumer catches up or the token expires (≤ 900 s) | Revocation-delay window (section 10.3) |
| Poison record on `user.events.v1` | `dead_letter`, counted, alerted, skipped | Nothing | No |
| Valkey slow or down | Limiter degrades (section 11) | Possibly stricter limiting; never 503 from the limiter | Authorization unaffected |
| Loki down or slow | Ordinary lane buffers on the node; audit lane fills, then 503 `audit_unavailable` on audit-required operations; queries 503 or 504 | Always-audit operations and log queries unavailable | No |
| Upstream down or slow | Breaker, timeouts, concurrency limit, at most one safe retry | 502, 503, 504 | – |
| Panic in a request task / in tail or apply / OOM | 500, counted / process exits and rebootstraps / restart | – | No |

### 9.11 Why an in-process snapshot is "correctly distributed"

The owner allowed an in-process cache only if it can be distributed correctly, otherwise a separate cache solution. The snapshot meets the eight conditions of the cache research: C1 total order (locked counter row, one relay, one partition); C2 contiguous versions with gap detection (contiguity under the 1 h compaction lag, `__head` by highest version, digest, duplicate recognition); C3 every pod reads every record (no consumer group); C4 readiness gated on catch-up (section 17.5); C5 silence is detectable (watermark probe with replica-quorum epoch confirmation); C6 a hard staleness bound that fails closed (G4); C7 idempotent, deterministic apply; C8 divergence detection (per-version digest, metrics, anti-entropy with shadow bootstrap, derived-state check, property tests). An external cache on the hot path was rejected: two dependent round trips (about 0.4 to 1 ms p50, ESTIMATE) exceed the whole residence budget, and asynchronous replication can lose an acknowledged revocation on failover. Token resolutions and parsed GraphQL documents are per-pod memos, safe because they are pure functions and revocation is checked on every request. A two-tier cache for assignments is a later-phase option if the steady snapshot exceeds 12.5 % of the pod memory request (NFR-38).

## 10. Kafka Scope and Inbound User Service Events

### 10.1 Amended scope rule (R5, owner decision D1)

IAM **produces** only IAM topics (`iam.policy.state.v1`, `iam.events.v1`). IAM **consumes** its own state topic (gateway pods and anti-entropy) and, in the control plane only, `user.events.v1` for session and user events. The owner's words: "We will have message bus for all microservices, so iam should read the event from user service."

| Data | On Kafka? | How it moves |
| --- | --- | --- |
| Policy, catalogues, routes, upstreams, rate policies, revocations, `__head` | Yes, `iam.policy.state.v1` | Produced by the relay |
| IAM domain events | Yes, `iam.events.v1` | Produced by the relay; Notification service tails it (D7) |
| User service session and user events | Yes, `user.events.v1`, produced by User service | Consumed by `iam-control`, written to PostgreSQL, republished as IAM revocation records on the state topic |
| Request traffic | No | HTTP proxy |
| Access-decision log | No | stdout and Grafana Alloy, or direct push, to Loki (D13) |
| Rate-limit counters | No | Valkey (D4) |
| Sync-Fence acknowledgements, freshness, peer readiness | No | HTTP to pods' internal port; broker metadata reads |
| Upstream endpoints | No | Kubernetes EndpointSlice watch |
| JWT public keys | No | Kubernetes Secret mounted as a file |

**Why republish instead of letting pods read `user.events.v1`.** The state topic is the version clock (C1): one partition, gap-free versions, a digest per version. A second topic read by pods would share no order with the first, so a pod could not prove it has applied every change acknowledged before *t* − `T_hard` across both. Republishing keeps G1 to G9 unchanged and keeps User service's wire format out of the data plane.

### 10.2 Consumer rules (FR-18)

- `UserEventConsumer` in `iam-control`, group `iam-control-user-events`, client id `iam-control-user-events-<pod-name>`; not started when `USER_EVENTS_TOPIC` is unset.
- At-least-once consumption; idempotent by event id in `iam_inbound_events`; the offset is committed only after the PostgreSQL commit; one user's events stay ordered because the topic is keyed by user id.
- Applied events: `user.session.revoked` {userId, sessionId} records the session as revoked; `user.all_sessions_revoked` and `user.refresh_token_theft_detected` {userId} set the user's cut-off to the event's `occurredAt` plus `JWT_CLOCK_SKEW`, so a token minted just before the event on a User service pod whose clock runs ahead is still refused (a user who signs in again within that margin is refused once); `user.deleted` {userId} sets the cut-off and revokes every assignment of the user with actor `system:user-service`.
- Each applied event commits a policy version with revocation state records, an audit record (actor `system:user-service`) and the events `iam.session.revoked`, `iam.user_tokens.cut_off` or `iam.user_role.revoked`.
- Unknown types are recorded as `ignored`, undecodable records as `dead_letter` (counted and alerted); both are skipped, so one bad record never blocks the partition. Neutral and Symfony Messenger envelopes are accepted.
- The consumer does not wait for Sync-Fence. The coordinator fences consumed revocations asynchronously in batches and records `revocation_propagation_seconds`, so a slow pod never stalls consumption.

### 10.3 End-to-end revocation bound

Path: User service logout, password change or theft detection → User service publishes to `user.events.v1` → `iam-control` consumer → PostgreSQL commit (version, audit, state row) → relay → `iam.policy.state.v1` → every gateway pod.

- **Typical time** from the User service event's Kafka acknowledgement to enforcement on every healthy pod: consumer fetch wait ≤ 100 ms + commit 5 to 15 ms + relay wake-up and produce about 15 ms + propagation about 40 ms at 10 pods ≈ 0.2 to 0.5 s p99 (ESTIMATE). Target p99 ≤ 1 s (NFR-19), measured by T32 (Story 16.8). Consumer lag alert at 2 s, page at 10 s.
- **Hard bound for allows:** once the revocation record is acknowledged on the state topic, no pod allows on older state after `T_hard` (G4, conditional).
- **Not bounded by `T_hard`:** time before the state-topic acknowledgement (User service not publishing, the consumer stalled, PostgreSQL failing over, the relay stalled). Each stage is visible through `user_events_consumer_lag_seconds` and `outbox_oldest_unpublished_seconds`.
- **Absolute backstop:** the gateway rejects tokens with `exp − iat > MAX_TOKEN_LIFETIME` (900 s), so a revoked session's access token stops working at its expiry whatever happens upstream.

### 10.4 Dependency on User service

User service publishes `SessionRevokedEvent`, `AllSessionsRevokedEvent`, `RefreshTokenTheftDetectedEvent` and `UserDeletedEvent` today over SQS only, and its Messenger configuration has no Kafka transport. It must publish these four events to `user.events.v1`, keyed by user id, with an event id, `occurredAt`, `userId` and, for session events, `sessionId` (external prerequisite; topic name and payload to agree, assumption D25). Until it does, the 900 s token lifetime is the revocation bound for upstreams that do not check sessions themselves, such as core-service. No REST call from User service to IAM is required; the operator revocation API (FR-80) stays for administrators.

## 11. Rate Limiting with Valkey

### 11.1 Policies and enforcement (FR-64, FR-65)

- Rate policies are IAM state (`ratepolicy/<id>`), managed through the management API (section 14) and replicated in the snapshot. A policy names its key kind (`ip`, `subject`, `subject_route`, `route`), its limit and period, its burst and its fallback (`divided` or `full`). A route lists the policies that apply to it.
- The local per-IP guard (`GovernorLocalRateLimiter`, a token bucket sized well above any policy, CONFIG) always runs first, together with the per-IP (64) and per-subject (32) connection caps. It protects Valkey and the pod from floods; it is not the quota.
- Routes with rate policies are checked **exactly and globally** in Valkey: one `EVALSHA` of a GCRA Lua script per policy and request, key `rl:{policyId}:{keyHash}` (key parts hashed, TTL of one period), through `ValkeyRateLimitStore`. Over limit: 429 `rate_limited` with `Retry-After`. Routes without a rate policy never touch Valkey.
- Valkey holds counters only: no authorization data, no tokens, no revocations.

### 11.2 Degradation

- Every call is bounded by `RATE_LIMIT_STORE_TIMEOUT` (5 ms). After 5 consecutive failures or timeouts the breaker opens for `RATE_LIMIT_BREAKER_OPEN_DURATION` (5 s), then lets one probe through.
- While the breaker is open, or for a single timed-out call, the **conservative local limiter** decides: a per-pod bucket with `limit / N_ready` (`N_ready` = ready gateway pods from the peer list, at least 1), which may under-admit sticky clients and never over-admits fleet-wide; a policy with `fallback = full` uses the full limit per pod (over-admission bounded by the connection caps).
- The limiter never returns 503 and never blocks or changes an authorization decision. Degraded mode raises `rate_limit_store_degraded` and an alert.
- NFR-42 target: with Valkey slow (≥ 20 ms), paused or down, rate-limited routes stay within the NFR-33 latency plus `RATE_LIMIT_STORE_TIMEOUT`, with no limiter 503, unchanged authorization, and the breaker open within 5 failures (T30, Story 16.7).

### 11.3 Accuracy and deployment

- Exact while the Valkey primary is healthy. Replication is asynchronous, so a failover can lose recent increments and briefly over-admit; this is stated and accepted.
- One Valkey primary handles well over the first-release load (at most 1,000 `EVALSHA` per second at peak, ESTIMATE). Valkey Cluster or key sharding is needed only at much larger rates.
- Cross-AZ calls to the primary add about 0.4 to 0.6 ms p50 for pods in two of the three AZs (ESTIMATE); this is why the NFR-33 target for rate-limited routes is p99 ≤ 2 ms.

> Assumption: Valkey runs in the EKS cluster as one primary and two replicas, one per AZ, with Sentinel, from a maintained Helm chart or operator (owner item D23, default). Amazon ElastiCache for Valkey is a configuration change behind the same port. The client is the `redis` crate with Sentinel support.

## 12. Access-Decision Log in Loki and Security Audit Log

### 12.1 Access records (FR-50)

Every gateway decision produces one access record with the fields `decision_id` (UUID v7), `occurred_at`, `method`, `host`, `route_id`, `route_template`, `status`, `upstream`, `latency_us`, `bytes_in`, `bytes_out`, `request_id`, `subject_id`, `subject_kind`, `decision`, `reason`, `permission_key` or `denied`, `project_id`, `policy_version`, `credential_digest_prefix` (8 hex). Never a raw token, cookie, document or concrete path (NFR-20).

Loki layout: labels `app` (`iam-gateway`), `env`, `lane` (`access`, `audit`), `decision` (`allow`, `deny`, `error`), `upstream` (registered names only), all low-cardinality; structured metadata `subject_id`, `decision_id`, `request_id`, `route_id`, `status`, `reason`, `policy_version`, `subject_kind` (Loki 3.x); the rest is the JSON line.

### 12.2 Two lanes and their guarantees

| Lane | Content | Transport | Guarantee |
| --- | --- | --- | --- |
| Ordinary (`lane="access"`) | Allows sampled at `LOG_ALLOW_SAMPLE_RATE` (0.01), per-second aggregates beyond the per-class budgets | JSON lines to stdout (`StdoutAccessLogSink`), tailed by a Grafana Alloy DaemonSet that parses the JSON, sets the fixed labels and forwards to Loki; `containerLogMaxSize` raised on the gateway node pool | Best effort: lines can be lost on rotation under incident volume or when a node dies; losses counted by Alloy and by the budget counters |
| Audit (`lane="audit"`) | All denials, always-audit allows, sensitive-key and wildcard allows | Batches pushed by the writer thread to the Loki push API (`LokiPushAccessLogSink`) every `ACCESS_LOG_AUDIT_FLUSH_INTERVAL` (250 ms) or at 1 MiB | Delivered once Loki acknowledged the push (HTTP 204 after the ingesters' replicated write); records still in the pod buffer when the pod crashes are lost, bounded by the flush interval and the pending bound |

- Each record goes to exactly one lane, so Loki holds no duplicates. Why direct push for the audit lane: only the push API returns an acknowledgement the pod can wait on, so audit-or-deny can be honest; stdout gives none.
- Per-class budgets (`LOG_CLASS_BUDGETS`, for example 1,000 error records/s and 2,000 audit records/s per pod) bound volume during incidents; beyond a budget the writer emits one aggregate record per second per (route, status, reason) with a count. RED metrics cover 100 % of requests.
- **Audit or deny** for always-audit and sensitive keys: if the audit lane's buffer is full, or its oldest unacknowledged record is older than `ACCESS_LOG_AUDIT_MAX_PENDING` (2 s), requests that need an audit record get 503 `audit_unavailable`. A Loki outage longer than about 2 s therefore makes always-audit operations unavailable; other routes keep working and their audit-lane denials are counted as dropped. Otherwise the decision is never delayed (NFR-24: channel send p99 ≤ 1 ms with a full channel, target).
- Retention per stream in the reference Loki configuration (FR-53, NFR-25): `lane="access"` 90 days, `lane="audit"` 400 days (assumption D24).

### 12.3 Access-log query API (FR-51)

`iam-control` serves `GET /api/access-decisions`, `GET /api/access-decisions/{id}` and GraphQL `accessDecisions`, `accessDecision` through `GetAccessDecisionsQueryHandler` and the `AccessLogQuery` port (`LokiAccessLogQuery`). The adapter builds LogQL from a fixed label selector and filters high-cardinality fields with structured-metadata filters, for example `{app="iam-gateway", env="prod", lane=~"access|audit", decision="deny"} | subject_id="<uuid>"`. Loki's limits are stated and bounded:

- Loki has no secondary index: a subject or request filter scans every chunk of the selected streams in the range. A time range is required and capped at `ACCESS_LOG_QUERY_MAX_RANGE` (24 h, at most 7 days); longer ranges return 422.
- Long ranges are slow: queries time out after `ACCESS_LOG_QUERY_TIMEOUT` (30 s) with 504 (GraphQL `QUERY_TIMEOUT`), never a partial page. Loki unavailable gives 503.
- Filters: subject id, subject kind, decision, reason, upstream, route id, status. Pages of at most 500 entries, newest first, opaque cursor (the last entry's nanosecond timestamp plus the count already returned at that timestamp).
- Get by id derives the millisecond timestamp from the UUID v7 and queries a ±2 s window with a `decision_id` filter; ids older than retention return 404.
- Results are eventually consistent (a record is queryable a few seconds after ingestion, ESTIMATE); sampled allows appear only at the sample rate. Each query requires `iam:audit:read` and is audited in the security audit log.
- NFR-44 targets at first-release volume: p95 ≤ 5 s for a 1 h range and ≤ 30 s for a 24 h range (T31, Story 16.7).

> Assumption: Loki runs in simple scalable mode on EKS with S3 object storage and replication factor 3 across AZs, with a Grafana Alloy DaemonSet (owner item D26, default). Retention is configured in Loki's compactor per stream, not by IAM.

### 12.4 Security audit log (FR-49, FR-52, unchanged)

| Aspect | Security audit log (`SecurityAuditEvent`) |
| --- | --- |
| Content | Every committed administrative change and every rejected administrative attempt (403, escalation, caller not allowed to validate), the latter summarised per actor, action and reason within 60 seconds; every revocation applied from User service; every access-log and audit query |
| Write path | Same transaction as the change (`PgIamUnitOfWork`), the only synchronous user of the chain-head lock; rejected attempts are offered without awaiting to `BufferedRejectedAttemptLog` and appended by `RejectedAttemptWriter` in one chained transaction at most every second |
| Integrity | Hash chain (`sha256(prev_hash || canonical_form)` computed in SQL under the chain-head lock); trigger rejects `UPDATE` and `DELETE`; the chain head is anchored outside the database by `iam.security_audit.anchored` events from every maintenance run, and chain verification accepts those anchors |
| Storage | One PostgreSQL table, at least 400 days, never deleted by IAM; written only by `iam-control` |
| Query | `GetSecurityAuditEventsQueryHandler`, `VerifySecurityAuditChainQueryHandler`; requires `iam:audit:read`; each query is audited |
| `tracing` target | `audit` (the template's existing target) |
| Never stored | Tokens, specification bodies |

The partitioned `iam_access_decisions` table, its partition functions and the partition maintainer are dropped (owner decision D13).

> Assumption: `ChangeReceipt` rows live in their own table, `iam_change_receipts`, written by `PgIamUnitOfWork` in the change's transaction (one row per command, keyed by change id, with the resulting entity version, policy version and propagation outcome). Commands keep the template's `()` return type, and idempotent replays return the original `ETag`, `Iam-Policy-Version` and propagation outcome without storing response bodies. The audit log is not used for this, because one change can write several audit rows and the audit table has no change id.

> Assumption: The threat model of the audit chain (ADR 0019) is: the in-database chain detects accidental corruption and tampering by anyone who cannot also rewrite the external anchors. Production runs migrations under a database owner role and the service under a runtime role that holds only `INSERT` and `SELECT` on the audit tables (no `UPDATE`, `DELETE`, `TRUNCATE`, `ALTER` or trigger rights). Setting up these two roles is an operational prerequisite documented in `docs/operations.md` and an open owner item.

> Assumption: The logs hold pseudonymous identifiers only. Audit summaries hold identifiers, role names and permission keys, never a person's name or email. On `user.deleted`, access records in Loki are not rewritten; they age out with the lane retention. ADR 0019 records the retention basis (security and legitimate interest) and periods.

## 13. Data Model and Migrations

All tables live in PostgreSQL 16, prefixed `iam_`, and are used only by `iam-control`. Timestamps are `timestamptz`. Identifiers are UUID v7 from `UuidGenerator`. Every table that holds an aggregate has a `version bigint` for optimistic concurrency. The access-decision log is not stored in PostgreSQL (section 12).

### 13.1 Tables

| Table | Status | Key columns | Constraints and indexes | Purpose | Story |
| --- | --- | --- | --- | --- | --- |
| `iam_policy_epoch` | AMEND | `id smallint` (always 1), `version bigint`, `digest bytea` (16 bytes, initial zeros), `log_epoch bigint`, `relay_epoch bigint`, `catalog_epoch bigint`, `updated_at` | `CHECK (id = 1)`; one seeded row; created with exactly these columns by Story 1.1 | Gap-free policy version, state digest, log and relay epochs; its row lock serialises versioned writes | 1.1 |
| `iam_security_audit_events` | KEEP | `seq bigint` (identity), `id uuid`, `occurred_at`, `actor text`, `caller_service text`, `action text`, `target_type text`, `target_id text`, `scope text`, `before_summary text`, `after_summary text`, `idempotency_key text`, `outcome text`, `reason text`, `policy_version bigint`, `request_id text`, `prev_hash bytea`, `hash bytea` | primary key (`seq`); unique (`id`); indexes on (`occurred_at`), (`actor`, `occurred_at`), (`target_type`, `target_id`); trigger rejecting `UPDATE` and `DELETE` | Hash-chained security audit log | 2.2 |
| `iam_security_audit_chain_head` | KEEP | `id smallint` (always 1), `seq bigint`, `hash bytea` | `CHECK (id = 1)` | Chain head locked `FOR UPDATE` by every audit insert | 2.2 |
| `iam_outbox` | AMEND | `id uuid`, `position bigint` (identity), `kind text` (`state`, `event`), `topic text`, `record_key text`, `payload text` (null = tombstone), `policy_version bigint`, `seq int`, `count int`, `digest_after bytea`, `log_epoch bigint`, `event_type text`, `aggregate_id text`, `occurred_at`, `published_at`, `published_offset bigint`, `relay_epoch bigint` | primary key (`id`); unique (`position`); partial index on (`position`) where `published_at IS NULL`; index on (`policy_version`, `seq`) | Transactional outbox for state and event rows | 2.3 (state rows written from 7.2) |
| `iam_idempotency_keys` | KEEP | `actor text`, `idempotency_key text`, `request_digest bytea`, `change_id uuid`, `created_at` | primary key (`actor`, `idempotency_key`); index on (`created_at`) | 24-hour replay (FR-2) | 2.3 |
| `iam_change_receipts` | KEEP (propagation outcome added as a column in Story 7.6) | `change_id uuid`, `actor text`, `target_type text`, `target_id text`, `entity_version bigint`, `policy_version bigint` (null when decisions were not affected), `outcome text`, `created_at` | primary key (`change_id`); index on (`created_at`) | `ChangeReceipt`; purged with the idempotency records after 24 hours | 2.3 |
| `iam_revoked_sessions` | AMEND | `id uuid` (API id), `session_id text`, `user_id uuid`, `source text` (`user-service`, `operator`), `revoked_by text`, `revoked_at`, `prune_after` | primary key (`session_id`); unique (`id`); indexes on (`user_id`, `revoked_at`) and (`prune_after`) | Session revocations, kept until the pruning rule allows a tombstone | 2.6 |
| `iam_user_token_validity` | AMEND | `user_id uuid`, `tokens_valid_after`, `source text`, `updated_at`, `prune_after` | primary key (`user_id`); index on (`prune_after`) | Per-user cut-off for `iat` | 2.6 |
| `iam_global_token_cutoff` | NEW | `id smallint` (always 1), `tokens_valid_after`, `set_by text`, `set_at` | `CHECK (id = 1)` | Global cut-off for emergency key compromise | 2.6 |
| `iam_inbound_events` | NEW (replaces `iam_processed_events`) | `event_id uuid`, `topic text`, `partition int`, `offset bigint`, `event_type text`, `outcome text` (`applied`, `ignored`, `dead_letter`), `error text`, `processed_at` | primary key (`event_id`); index on (`processed_at`) | Idempotent consumption of User service events, with dead letters | 2.6 |
| `iam_roles` | KEEP | `id uuid`, `name text`, `description text`, `kind text` (`system`, `custom`), `grant_count int`, `version bigint`, `created_at`, `updated_at`, `deleted_at` | unique index on `lower(name)` where `deleted_at IS NULL`; length checks | `Role` | 3.2 |
| `iam_role_permissions` | KEEP | `role_id uuid`, `permission_key text`, `key_kind text` (`rest`, `gql`, `iam`), `service text`, `is_wildcard bool`, `active bool`, `orphaned_at`, `granted_by text`, `granted_at` | primary key (`role_id`, `permission_key`); foreign key to `iam_roles`; indexes on (`permission_key`) and (`service`, `active`) | Grants of a role | 3.2 |
| `iam_user_roles` | KEEP | `id uuid`, `subject_kind text`, `subject_id text`, `role_id uuid`, `scope_kind text`, `project_id uuid`, `expires_at`, `version bigint`, `created_by text`, `created_at`, `updated_at`, `revoked_at` | subject checks; unique index on (`subject_kind`, `subject_id`, `role_id`, `scope_kind`, `coalesce(project_id, nil uuid)`) where `revoked_at IS NULL`; index on (`subject_kind`, `subject_id`) where `revoked_at IS NULL`; index on (`role_id`) | `UserRole` | 3.5 |
| `iam_graphql_specs`, `iam_graphql_spec_fields`, `iam_graphql_spec_possible_types`, `iam_graphql_permissions` | KEEP | as in the PRD's specification model: versions with `content_hash` computed in SQL, fields with flags, possible types, catalogue entries | unique (`service`, `content_hash`); unique (`permission_key`); index on (`service`, `active`) | GraphQL specifications and catalogue | 4.3 |
| `iam_openapi_specs`, `iam_openapi_spec_operations`, `iam_rest_permissions` | KEEP | as for GraphQL with `document text`, operations (`method`, `path_template`, `operation_id`, flags) and REST catalogue entries | unique (`service`, `content_hash`); unique (`permission_key`); index on (`service`, `active`) | OpenAPI specifications and catalogue | 4.7 |
| `iam_task_state` | KEEP | `task text`, `last_run_at`, `last_epoch bigint` | primary key (`task`) | Maintenance and anti-entropy bookkeeping | 7.1 |
| `iam_token_lifetime_floor` | NEW | `id smallint` (always 1), `max_token_lifetime_seconds bigint`, `updated_at` | `CHECK (id = 1)`; one seeded row | The longest `MAX_TOKEN_LIFETIME` ever configured, raised at startup, read by the tombstone rule (FR-79) | 13.1 |
| `iam_bulk_operations` | NEW | `id uuid`, `kind text` (`role_deletion`, `catalogue`, `resync`, `other`), `propagation_status text`, `pods_acknowledged int`, `pods_timed_out int`, `status text` (`pending`, `running`, `completed`, `failed`), `total_records int`, `applied_records int`, `first_version bigint`, `last_version bigint`, `requested_by text`, `created_at`, `completed_at`, `error text` | primary key (`id`); index on (`status`, `created_at`) | Bulk operations and their progress | 7.9 |
| `iam_upstreams` | NEW | `id uuid`, `name text`, `namespace text`, `service text`, `catalog_service text`, `forward_credentials bool`, `system bool`, `port int`, `protocol text`, `connect_timeout_ms int`, `response_timeout_ms int`, `concurrency_limit int`, `retry_budget_percent int`, `outlier_consecutive_errors int`, `version bigint`, timestamps, `deleted_at` | unique `name` where `deleted_at IS NULL` | `Upstream` | 8.2 |
| `iam_rate_policies` | NEW | `id uuid`, `name text`, `key_kind text`, `limit_count int`, `period_ms int`, `burst int`, `fallback text`, `version bigint`, timestamps, `deleted_at` | unique `name` where `deleted_at IS NULL` | `RatePolicy` | 8.2 |
| `iam_routes` | NEW | `id uuid`, `host text`, `methods text[]`, `path_pattern text`, `service text`, `upstream_id uuid`, `graphql bool`, `streaming bool`, `anonymous bool`, `enforcement text`, `body_limit_bytes bigint`, `connect_timeout_ms int`, `response_timeout_ms int`, `request_timeout_ms int`, `retry_policy text`, `cors jsonb`, `system bool`, `version bigint`, timestamps, `deleted_at` | foreign key to `iam_upstreams`; index on (`host`, `path_pattern`) | `Route` | 8.2 |
| `iam_route_rate_policies` | NEW | `route_id uuid`, `rate_policy_id uuid`, `position int` | primary key (`route_id`, `rate_policy_id`); foreign keys to both tables | Ordered rate policies of a route | 8.2 |
| `iam_access_decisions` and its partition functions | REMOVE | – | – | Replaced by Loki | – |

### 13.2 Migrations (reversible pairs, created with the template's migration target; timestamps assigned at creation)

The order is the story order of `epics.md`; no foreign key points from an earlier table to a later one.

| Order | Name | Creates | Story |
| --- | --- | --- | --- |
| 1 | `create_iam_policy_epoch` | `iam_policy_epoch` (seeded row with zero digest) | 1.1 |
| 2 | `create_iam_security_audit_log` | `iam_security_audit_events`, `iam_security_audit_chain_head`, the append-only trigger | 2.2 |
| 3 | `create_iam_outbox` | `iam_outbox` | 2.3 |
| 4 | `create_iam_idempotency_keys` | `iam_idempotency_keys` | 2.3 |
| 5 | `create_iam_change_receipts` | `iam_change_receipts` | 2.3 |
| 6 | `create_iam_token_revocations` | `iam_revoked_sessions`, `iam_user_token_validity`, `iam_global_token_cutoff`, `iam_inbound_events` | 2.6 |
| 7 | `create_iam_roles_and_permissions` | `iam_roles`, `iam_role_permissions` | 3.2 |
| 8 | `create_iam_user_roles` | `iam_user_roles` | 3.5 |
| 9 | `create_iam_graphql_specs_and_permissions` | the four GraphQL tables | 4.3 |
| 10 | `create_iam_openapi_specs_and_permissions` | the three OpenAPI tables | 4.7 |
| 11 | `create_iam_task_state` | `iam_task_state` | 7.1 |
| 12 | `create_iam_bulk_operations` | `iam_bulk_operations` | 7.9 |
| 13 | `create_iam_gateway_configuration` | `iam_upstreams`, `iam_rate_policies`, `iam_routes`, `iam_route_rate_policies` | 8.2 |
| 14 | `create_iam_token_lifetime_floor` | `iam_token_lifetime_floor` (seeded row) | 13.1 |

A column added to an existing table by a later story (for example the propagation outcome on `iam_change_receipts` in Story 7.6) is its own reversible pair in that story; an applied migration is never edited. Each pair has a reviewed down migration and is proven by one rollback round trip in its story when an operator allows the ask-ruled rollback target; otherwise the round trip is recorded as not run and the story still closes on `make.sqlx_prepare` and the query-metadata gate. `.sqlx/` is regenerated by `make.sqlx_prepare` in the story that adds or changes a query. The example table `example_api_resources` and its migration stay untouched.

## 14. API Surface and Contract Impact

### 14.1 Conventions

- All REST paths are under `/api` on `iam-control`, reached through the gateway on IAM's host; GraphQL at `POST /api/graphql`. Every operation needs a bearer token (FR-3) and the rule of FR-4.
- The decision API rows (validate, batch, resolve token) are also served by `iam-gateway` on its decision listener (`GATEWAY_DECISION_LISTEN`, port 9091) at the same paths, including a GraphQL endpoint at `/api/graphql` that exposes only those three queries. The published contract snapshots are generated from the `iam-control` router.
- Every write accepts the write-mode modifier of FR-75: REST header `Prefer: wait=propagated`, GraphQL input field `consistency: PUBLISHED | PROPAGATED`; every write response carries `Iam-Policy-Version` (REST) or `propagation` (GraphQL payload).
- Each row is one handler and two interfaces (FR-1). Proxied upstream traffic is not an IAM capability.

### 14.2 Table

| Capability | REST operation | GraphQL operation | Handler | FR | Delivering story |
| --- | --- | --- | --- | --- | --- |
| Validate access | `POST /api/access-validations` | query `validateAccess` | `ValidateAccessQueryHandler` | FR-6 | 6.5, 6.7; gateway listener 10.11 |
| Validate access, batch | `POST /api/access-validations/batch` | query `validateAccessBatch` | `ValidateAccessBatchQueryHandler` | FR-11 | 6.8; gateway listener 10.11 |
| Resolve token | `POST /api/token-resolutions` | query `resolveToken` | `ResolveTokenQueryHandler` | FR-19 | 2.8; gateway listener 10.11 |
| Create role | `POST /api/roles` | mutation `createRole` | `CreateRoleCommandHandler` | FR-20 | 3.3 |
| Get role / list roles | `GET /api/roles/{id}`, `GET /api/roles` | query `role`, `roles` | `GetRoleQueryHandler`, `ListRolesQueryHandler` | FR-21 | 3.3 |
| Update role | `PATCH /api/roles/{id}` | mutation `updateRole` | `UpdateRoleCommandHandler` | FR-22 | 3.4 |
| Delete role | `DELETE /api/roles/{id}` | mutation `deleteRole` | `DeleteRoleCommandHandler` | FR-23 | 3.8; revocation-class default 13.4 |
| Get / set role grants | `GET /api/roles/{id}/permissions`, `PUT /api/roles/{id}/permissions` | field `Role.permissions`, mutation `setRolePermissions` | `GetRoleQueryHandler`, `SetRolePermissionsCommandHandler` | FR-24 | 5.7; revocation-class default 13.8 |
| Assign role | `POST /api/user-roles` | mutation `assignUserRole` | `AssignUserRoleCommandHandler` | FR-26 | 3.6 |
| Get / list assignments | `GET /api/user-roles/{id}`, `GET /api/user-roles` | query `userRole`, `userRoles` | `GetUserRoleQueryHandler`, `ListUserRolesQueryHandler` | FR-27 | 3.6 |
| Update assignment | `PATCH /api/user-roles/{id}` | mutation `updateUserRole` | `UpdateUserRoleCommandHandler` | FR-28 | 3.7 |
| Revoke assignment | `DELETE /api/user-roles/{id}` | mutation `revokeUserRole` | `RevokeUserRoleCommandHandler` | FR-29 | 3.7; revocation-class default 13.8 |
| Load GraphQL spec | `POST /api/graphql-specs` | mutation `loadGraphqlSpec` | `LoadGraphQlSpecCommandHandler` | FR-30 | 4.4 |
| Get GraphQL specs and diff | `GET /api/graphql-specs`, `GET /api/graphql-specs/{id}`, `GET /api/graphql-specs/{id}/diff` | query `graphqlSpecs`, `graphqlSpec`, field `GraphQlSpec.diff` | `GetGraphQlSpecsQueryHandler` | FR-31 | 4.5 |
| Create GraphQL permissions | `POST /api/graphql-specs/{id}/permissions` | mutation `createGraphqlPermissions` | `CreateGraphQlPermissionsCommandHandler` | FR-32 | 5.3 |
| Get GraphQL permissions | `GET /api/graphql-permissions`, `GET /api/graphql-permissions/{id}` | query `graphqlPermissions`, `graphqlPermission` | `GetGraphQlPermissionsQueryHandler` | FR-33 | 5.4 |
| Load OpenAPI spec | `POST /api/openapi-specs` | mutation `loadOpenapiSpec` | `LoadOpenApiSpecCommandHandler` | FR-34 | 4.8 |
| Get OpenAPI specs and diff | `GET /api/openapi-specs`, `GET /api/openapi-specs/{id}`, `GET /api/openapi-specs/{id}/diff` | query `openapiSpecs`, `openapiSpec`, field `OpenApiSpec.diff` | `GetOpenApiSpecsQueryHandler` | FR-35 | 4.9 |
| Create REST permissions | `POST /api/openapi-specs/{id}/permissions` | mutation `createRestPermissions` | `CreateRestPermissionsCommandHandler` | FR-36 | 5.5 |
| Get REST permissions | `GET /api/rest-permissions`, `GET /api/rest-permissions/{id}` | query `restPermissions`, `restPermission` | `GetRestPermissionsQueryHandler` | FR-37 | 5.6 |
| Retire spec version | `POST /api/graphql-specs/{id}/retirement`, `POST /api/openapi-specs/{id}/retirement` | mutation `retireGraphqlSpec`, `retireOpenapiSpec` | `RetireGraphQlSpecCommandHandler`, `RetireOpenApiSpecCommandHandler` | FR-38 | 5.8 |
| Effective permissions | `GET /api/users/{userId}/role-permissions` | query `userRolePermissions` | `GetUserRolePermissionsQueryHandler` | FR-39 | 6.15 |
| Create upstream | `POST /api/upstreams` | mutation `createUpstream` | `CreateUpstreamCommandHandler` | FR-56 | 8.3 |
| Get / list upstreams | `GET /api/upstreams/{id}`, `GET /api/upstreams` | query `upstream`, `upstreams` | `GetUpstreamQueryHandler`, `ListUpstreamsQueryHandler` | FR-56 | 8.3 |
| Update upstream | `PATCH /api/upstreams/{id}` | mutation `updateUpstream` | `UpdateUpstreamCommandHandler` | FR-56 | 8.3 |
| Delete upstream | `DELETE /api/upstreams/{id}` | mutation `deleteUpstream` | `DeleteUpstreamCommandHandler` | FR-56 | 8.3 |
| Create route | `POST /api/routes` | mutation `createRoute` | `CreateRouteCommandHandler` | FR-57 | 8.4 |
| Get / list routes | `GET /api/routes/{id}`, `GET /api/routes` (filters host, upstream, service) | query `route`, `routes` | `GetRouteQueryHandler`, `ListRoutesQueryHandler` | FR-57 | 8.4 |
| Update route | `PATCH /api/routes/{id}` | mutation `updateRoute` | `UpdateRouteCommandHandler` | FR-57, FR-69 | 8.4 |
| Delete route | `DELETE /api/routes/{id}` | mutation `deleteRoute` | `DeleteRouteCommandHandler` | FR-57 | 8.4 |
| Get route configuration | `GET /api/route-configurations/{host}` | query `routeConfiguration(host)` | `GetRouteConfigurationQueryHandler` | FR-58 | 8.6 |
| Apply route configuration | `PUT /api/route-configurations/{host}` (query `dryRun`) | mutation `applyRouteConfiguration` | `ApplyRouteConfigurationCommandHandler` | FR-58, FR-84 | 8.6 |
| Create rate policy | `POST /api/rate-policies` | mutation `createRatePolicy` | `CreateRatePolicyCommandHandler` | FR-64 | 8.5 |
| Get / list rate policies | `GET /api/rate-policies/{id}`, `GET /api/rate-policies` | query `ratePolicy`, `ratePolicies` | `GetRatePolicyQueryHandler`, `ListRatePoliciesQueryHandler` | FR-64 | 8.5 |
| Update rate policy | `PATCH /api/rate-policies/{id}` | mutation `updateRatePolicy` | `UpdateRatePolicyCommandHandler` | FR-64 | 8.5 |
| Delete rate policy | `DELETE /api/rate-policies/{id}` | mutation `deleteRatePolicy` | `DeleteRatePolicyCommandHandler` | FR-64 | 8.5 |
| Revoke sessions | `POST /api/session-revocations` | mutation `revokeSessions` | `RevokeSessionsCommandHandler` | FR-80 | 13.1 |
| Set global token cut-off | `POST /api/global-token-cutoffs` | mutation `setGlobalTokenCutoff` | `SetGlobalTokenCutoffCommandHandler` | FR-80 | 13.1 |
| Get / list session revocations | `GET /api/session-revocations/{id}`, `GET /api/session-revocations` | query `sessionRevocation`, `sessionRevocations` | `GetSessionRevocationQueryHandler`, `ListSessionRevocationsQueryHandler` | FR-81 | 13.2 |
| Get user token cut-off | `GET /api/users/{userId}/token-cutoff` | query `userTokenCutoff(userId)` | `GetUserTokenCutoffQueryHandler` | FR-81 | 13.2 |
| Get global token cut-off | `GET /api/global-token-cutoffs/current` | query `globalTokenCutoff` | `GetGlobalTokenCutoffQueryHandler` | FR-81 | 13.2 |
| Policy propagation status | `GET /api/policy-status` | query `policyStatus` | `GetPolicyStatusQueryHandler` | FR-82 | 13.7 |
| Wait for a policy version to propagate (fence) | `GET /api/policy-versions/{version}/propagation` | query `policyVersionPropagation(policyVersion)` | `GetPolicyVersionPropagationQueryHandler` | FR-83 | 13.7 |
| Resync policy state (replaces the cache flush) | `POST /api/policy-resyncs` | mutation `resyncPolicy` | `ResyncPolicyCommandHandler` | FR-78 | 7.10 |
| Get / list bulk operations | `GET /api/bulk-operations/{id}`, `GET /api/bulk-operations` | query `bulkOperation`, `bulkOperations` | `GetBulkOperationQueryHandler`, `ListBulkOperationsQueryHandler` | FR-84 | 7.9 |
| Query access decisions (from Loki) | `GET /api/access-decisions`, `GET /api/access-decisions/{id}` | query `accessDecisions`, `accessDecision` | `GetAccessDecisionsQueryHandler` | FR-51 | 14.3 |
| Query security audit | `GET /api/security-audit-events`, `GET /api/security-audit-events/{id}` | query `securityAuditEvents`, `securityAuditEvent` | `GetSecurityAuditEventsQueryHandler` | FR-52 | 14.4 |
| Verify audit chain | `GET /api/security-audit-events/chain-verification` | query `securityAuditChainVerification` | `VerifySecurityAuditChainQueryHandler` | FR-52 | 14.5 |
| Flush authorization cache | removed (`POST /api/authorization-cache/flushes`) | removed (`flushAuthorizationCache`) | removed | FR-44 (retired) | – |

Total: 48 capability rows, each with both interfaces, plus one removed row listed for the record. The write-mode modifier is delivered by Story 7.6 (`published`) and Story 13.4 (`propagated`) for every write row above; Story 13.8 makes `propagated` the default for the revocation-class writes.

### 14.3 Contract-snapshot impact

- `.github/openapi-spec/spec.yaml` gains the operations above, the `iam` tag, the `bearerAuth` security scheme, the IAM schemas, the `Prefer` request header, the `Iam-Policy-Version`, `Iam-Policy-Offset` and `Iam-Propagation` response headers, `202` responses on writes, and the documented 400, 401, 403, 404, 409, 412, 413, 415, 422, 428, 503, 504 and default problem responses where they apply. Existing operations are unchanged, so the OpenAPI diff gate reports additions only. Specification routes declare a body limit of 6 MiB.
- `.github/graphql-spec/spec` gains `IamQuery` and `IamMutation` fields merged into `Query` and `Mutation`, the IAM object and input types, the `consistency` input field on writes and the `propagation` payload type. Existing fields are unchanged, so the GraphQL diff gate reports additions only.
- The pinning tests `openapi/tests.rs` and `graphql/schema/tests.rs` (`EXPECTED_SDL`) are updated in the same story as the snapshots. Spectral must report zero findings at any severity; Schemathesis runs against `iam-control` with ephemeral credentials and covers every operation, the decision API included (NFR-7, Story 16.5).
- The internal decision API on the gateway's listener is not a separate contract: it serves the same three operations, and Story 10.11 proves both listeners return the same outcome with a parity e2e scenario.
- `docs/requests.http` gains one REST and one GraphQL sample per operation (NFR-30).

## 15. Events

### 15.1 Envelope and transport

Envelope (FR-47): `{id (UUID v7), type, occurredAt (RFC 3339 UTC), data}`, at most 64 KiB, `type` matching `^[a-z][a-z0-9]*([._-][a-z0-9]+)*$`. `data` always carries the aggregate id, the entity version, `actor` and the resulting `policyVersion`, never a token or a specification body. Events are produced by command handlers through `IamUnitOfWork` as outbox event rows and published by `OutboxRelay` to `iam.events.v1`, with Kafka record key = aggregate id and value = envelope. Delivery is at least once with a total order on the single partition; consumers de-duplicate by `id`. Notification service tails the topic with its own no-group consumer and selects the four notification events by `type` (FR-48, D7); IAM never writes into Notification service's `notifications` topic.

### 15.2 Catalogue (`iam.events.v1`)

| Type | Domain event | Producer (handler) | `data` beyond the common fields | Status | Notification event |
| --- | --- | --- | --- | --- | --- |
| `iam.role.created` | `RoleCreated` | `CreateRoleCommandHandler` | `roleId`, `name`, `kind` | KEEP | no |
| `iam.role.updated` | `RoleUpdated` | `UpdateRoleCommandHandler` | `roleId`, changed fields | KEEP | no |
| `iam.role.deleted` | `RoleDeleted` | `DeleteRoleCommandHandler` | `roleId`, `name`, `revokedAssignments` | KEEP | no |
| `iam.role_permissions.changed` | `RolePermissionsChanged` | `SetRolePermissionsCommandHandler` | `roleId`, `addedKeys`, `removedKeys`, `wildcards` | KEEP | no |
| `iam.user_role.assigned` | `UserRoleAssigned` | `AssignUserRoleCommandHandler` | `userRoleId`, `subject {kind, id}`, `userId` (user subjects only), `roleId`, `roleName`, `scope`, `expiresAt` | KEEP | yes |
| `iam.user_role.updated` | `UserRoleUpdated` | `UpdateUserRoleCommandHandler` | `userRoleId`, `subject`, `expiresAt` | KEEP | no |
| `iam.user_role.revoked` | `UserRoleRevoked` | `RevokeUserRoleCommandHandler`, `DeleteRoleCommandHandler`, `ApplyUserRevocationEventCommandHandler` | `userRoleId`, `subject`, `userId` (user subjects only), `roleId`, `roleName`, `scope`, `cause` | KEEP | yes |
| `iam.privileged_role.assigned` | `PrivilegedRoleAssigned` | `AssignUserRoleCommandHandler` | as `iam.user_role.assigned` plus `privilegedKeys` | KEEP | yes (security alert) |
| `iam.graphql_spec.loaded` | `GraphQlSpecLoaded` | `LoadGraphQlSpecCommandHandler` | `specId`, `service`, `contentHash`, `coordinateCount` | KEEP | no |
| `iam.graphql_spec.retired` | `GraphQlSpecRetired` | `RetireGraphQlSpecCommandHandler` | `specId`, `service` | KEEP | no |
| `iam.graphql_permissions.created` | `GraphQlPermissionsCreated` | `CreateGraphQlPermissionsCommandHandler` | `specId`, `service`, `createdKeys`, `renamed`, `flagChanges` | KEEP | no |
| `iam.openapi_spec.loaded` | `OpenApiSpecLoaded` | `LoadOpenApiSpecCommandHandler` | `specId`, `service`, `contentHash`, `operationCount` | KEEP | no |
| `iam.openapi_spec.retired` | `OpenApiSpecRetired` | `RetireOpenApiSpecCommandHandler` | `specId`, `service` | KEEP | no |
| `iam.rest_permissions.created` | `RestPermissionsCreated` | `CreateRestPermissionsCommandHandler` | `specId`, `service`, `createdKeys`, `renamed`, `flagChanges` | KEEP | no |
| `iam.permissions.orphaned` | `PermissionsOrphaned` | `CreateGraphQlPermissionsCommandHandler`, `CreateRestPermissionsCommandHandler`, the retire handlers | `service`, `specId`, `orphanedKeys`, `affectedRoleIds` | KEEP | yes |
| `iam.security_audit.anchored` | `SecurityAuditAnchored` | `RunMaintenanceCommandHandler` | `seq`, `hash` of the current audit chain head | KEEP | no |
| `iam.upstream.created`, `iam.upstream.updated`, `iam.upstream.deleted` | `UpstreamCreated`, `UpstreamUpdated`, `UpstreamDeleted` | the upstream command handlers | `upstreamId`, `name`, changed fields | NEW | no |
| `iam.route.created`, `iam.route.updated`, `iam.route.deleted` | `RouteCreated`, `RouteUpdated`, `RouteDeleted` | the route command handlers | `routeId`, `host`, `pathPattern`, `methods`, changed flags | NEW | no |
| `iam.route_configuration.applied` | `RouteConfigurationApplied` | `ApplyRouteConfigurationCommandHandler` | `host`, `created`, `updated`, `deleted` route ids, `bulkOperationId` when chunked | NEW | no |
| `iam.rate_policy.created`, `iam.rate_policy.updated`, `iam.rate_policy.deleted` | `RatePolicyCreated`, `RatePolicyUpdated`, `RatePolicyDeleted` | the rate-policy command handlers | `ratePolicyId`, `name`, changed fields | NEW | no |
| `iam.session.revoked` | `SessionRevoked` | `RevokeSessionsCommandHandler`, `ApplyUserRevocationEventCommandHandler` | `userId`, `sessionIds`, `source` | NEW (FR-18, FR-80) | no |
| `iam.user_tokens.cut_off` | `UserTokensCutOff` | `RevokeSessionsCommandHandler` (empty session list), `ApplyUserRevocationEventCommandHandler` | `userId`, `tokensValidAfter`, `source` | NEW (FR-18, FR-80) | no |
| `iam.global_tokens.cut_off` | `GlobalTokensCutOff` | `SetGlobalTokenCutoffCommandHandler` | `tokensValidAfter`, `reason` | NEW (FR-80) | no |
| `iam.policy.resynced` | `PolicyResynced` | `ResyncPolicyCommandHandler` | `logEpoch`, `fromVersion`, `toVersion`, `reason`, `bulkOperationId` | NEW (FR-78) | no |
| `iam.bulk_operation.completed` | `BulkOperationCompleted` | `BulkOperationRunner` (on completion or failure) | `bulkOperationId`, `kind`, `status`, `firstVersion`, `lastVersion`, `appliedRecords` | NEW (FR-84) | no |

Removed: `iam.authorization_cache.flushed`.

### 15.3 Inbound events (consumed by `UserEventConsumer` from `user.events.v1`, produced by User service)

`user.session.revoked` {userId, sessionId}, `user.all_sessions_revoked` {userId}, `user.refresh_token_theft_detected` {userId}, `user.deleted` {userId}. Other types are recorded as `ignored`; undecodable records as `dead_letter` (section 10.2).

## 16. Security Design

### 16.1 Service-to-service authentication of callers

Callers of the decision API and of IAM's management API present `Authorization: Bearer` with a User service JWT. Service callers use a `ROLE_SERVICE` JWT, the only machine credential in VilnaCRM today. It is validated with the same pipeline as subject tokens (RS256, issuer, audience, time claims through `Clock`, header rules, maximum lifetime). Because service tokens cannot be revoked by session, a service caller's token must also carry `JWT_CALLER_AUDIENCE` (default `vilnacrm-iam`) in `aud`, so a token issued for calls between other services cannot be replayed to IAM, and its lifetime must not exceed `JWT_SERVICE_TOKEN_MAX_LIFETIME`. The caller's `sub` is its service name and must match the service-name pattern. User tokens are checked against revocation state through `RevocationView` on every request (FR-3, FR-17); no liveness call is made. The caller identity is always distinct from the subject identity of a `credential`; caller authorization (`iam:validate:{service}`) prevents a compromised service from using IAM as an oracle for another service's policy. Authentication headers are never recorded in spans or logs. Minting service tokens with the IAM audience needs a User service change (an open owner item). Calls between services use the same service tokens on the gateway's east-west listener (FR-90), never a direct connection to another service.

### 16.2 Authorization of IAM's own management API, enforced twice

At `iam-control` startup, under a transaction-level advisory lock, `RegisterOwnSpecsCommandHandler` registers IAM's own OpenAPI operations (filtered by the `iam` tag) and IAM's own GraphQL coordinates as specifications of service `iam`, idempotently by content hash, with actor `system:startup`. Every IAM operation therefore has catalogue keys such as `rest:iam:POST /api/roles` and `gql:iam:Mutation.createRole`, and these keys reach the snapshot like every other catalogue. The rule of FR-4 is enforced twice: first by the gateway from the snapshot (the route to `iam-control` names service `iam`), then by `iam-control` from PostgreSQL through `IamAccessGuard` (REST, from the matched route) and `IamAuthorizationExtension` (GraphQL, from the IAM coordinates the document selects). Operation rules: the decision API needs `iam:validate:*` or `iam:validate:{service}`; revoking sessions and user cut-offs need `iam:revoke:sessions`; the global cut-off needs `iam:revoke:global`; resync needs `iam:policy:resync`; setting `anonymous = true` or `enforcement = audit` on a route needs `iam:route:anonymous`; a write on a route or upstream of catalogue service S needs `iam:route:{S}` or `iam:route:*` (`RouteScopeGuard`), and entries of service `iam` and `system` entries are refused, so no principal can map another service's paths to keys it holds or point IAM's routes at a Service it controls; access-log, audit and revocation reads need `iam:audit:read`; every other operation needs its catalogue key plus the reserved keys of FR-25 and FR-30 where they apply. Denials return 403 (`FORBIDDEN`) and are audited. `EscalationGuard`, `SpecScopeGuard` and `LastAdministratorGuard` additionally restrict grants, assignments and specifications (FR-5, FR-25, FR-30).

> Assumption: Startup registration is additive. A new IAM version is activated beside the older active IAM versions and nothing is orphaned automatically, so a rolling deployment or a rollback, in which old and new binaries register alternately, never loses a grant on IAM's own operations. An older IAM version is retired only by an explicit, audited retirement that requires `iam:spec:iam` (not covered by `iam:spec:*`), which then follows the normal orphan confirmation.

### 16.3 Bootstrap of the first administrator and reserved keys

Reserved permission keys: `iam:validate:{service}`, `iam:validate:*`, `iam:grant:{service}`, `iam:grant:*`, `iam:grant:sensitive`, `iam:grant:wildcard`, `iam:spec:{service}`, `iam:spec:*`, `iam:audit:read`, `iam:revoke:sessions`, `iam:revoke:global`, `iam:policy:resync`, `iam:route:anonymous`, `iam:route:{service}`, `iam:route:*` (every service except `iam`). `iam:cache:flush` is removed.

`service iam-bootstrap --admin-user <uuid>` (or `--admin-service <service-name>`) runs as the `iam-bootstrap` Job and dispatches `BootstrapIamCommand` under a transaction-level advisory lock: it registers IAM's own specifications; creates the system role `iam-platform-admin` with `rest:iam:*`, `gql:iam:*` and every reserved key; assigns it globally to the given subject; with `--iam-host` idempotently seeds the upstream `iam-control` and the routes that expose IAM's management API through the gateway as `system` entries the API cannot change (Story 8.7); audits with actor `system:bootstrap`; and refuses (exit 1, no change) while an active assignment of that role exists. Exit codes 0, 1 and 2 (FR-5). The Job talks to PostgreSQL directly, so it works before any route exists. System roles cannot be renamed or deleted through the API, and `LastAdministratorGuard` refuses any change that would leave no active, non-expiring global assignment of `iam-platform-admin` (409, audited). If the last administrator is lost anyway, the break-glass procedure in `docs/operations.md` is an audited re-run of the bootstrap by an operator with database access. If the seeded routes are damaged, `service iam-bootstrap --repair-routes --iam-host <host>` restores them whether or not an administrator exists. Service principals hold roles like users: each microservice receives `iam:validate:{its service}`; each delivery pipeline receives `iam:spec:{its service}`.

### 16.4 Credential and input safety

- Raw credentials exist only in request memory; memos key on SHA-256 digests; access records hold an 8-character digest prefix at most; Valkey keys hold hashed key parts; Kafka records and metric labels hold no credential (NFR-20).
- RFC 8725 rules: RS256 allow-list, issuer and audience required, header-supplied keys rejected.
- Limits are enforced before expensive work (FR-7, FR-8, FR-11, FR-24, FR-30, FR-34, FR-60, FR-62, FR-67); DTOs deny unknown fields; external `$ref` values are rejected, never fetched; reason codes never disclose whether an operation exists in another service (NFR-21).
- OWASP API Security Top 10 (2023) and the IAM-specific risks (parser differential, request smuggling, confused deputy, reason-code disclosure, bootstrap, frame smuggling in GraphQL subscriptions) are mapped to requirements and tests in the security ADR 0022 (NFR-22).

### 16.5 Edge hardening and the path rule

- TLS 1.3 and 1.2 in the pod with an ECDSA P-256 certificate from a cert-manager Secret mounted as files, hot-reloaded; ALPN `h2` and `http/1.1`; the NLB listener is plain TCP (D9). Client IP only from Proxy Protocol v2 when `GATEWAY_PROXY_PROTOCOL` is true (FR-67).
- Header, buffer and connection limits of section 8.1; conflicting `Content-Length`/`Transfer-Encoding` rejected; hop-by-hop headers stripped; `:path` validated; duplicate JSON keys rejected in GraphQL bodies; malformed WebSocket frames close the connection.
- The single-decode path rule of section 8.2 makes the gateway authorize exactly the bytes the upstream decodes. A smuggling and parser-differential corpus (`%252e`, CL/TE conflicts, duplicate JSON keys, malformed WebSocket frames) runs in `make.integration_tests` with zero differentials as the gate (NFR-40, Story 16.4).
- Principal headers are always stripped from client requests and set freshly (FR-68); credentials reach only upstreams with `forwardCredentials = true`.
- CORS preflights are answered from the route's policy before authentication, and cookie-authenticated unsafe requests and WebSocket upgrades need an allowed `Origin` or `Referer` (FR-89).

### 16.6 Token lifetime, key rotation and the emergency cut-off

- `MAX_TOKEN_LIFETIME` (900 s, the first-party access-token TTL) rejects any token with `exp − iat` above it, so revocation retention and the absolute revocation backstop follow from one value. Raising it (owner item D12) never shortens retention of existing records (FR-79).
- Planned key rotation: add the new key to the Secret, wait until every pod reports the new key-set hash, User service switches, wait 900 s, remove the old key; the memo flush on key-set change makes removal immediate.
- Emergency: an administrator holding `iam:revoke:global` sets the global cut-off (`POST /api/global-token-cutoffs` or `setGlobalTokenCutoff`), revocation-class, effective on every pod when the write returns `complete` or `bounded`, without waiting for Secret propagation (FR-80).

### 16.7 Anonymous routes and enforcement mode

Only holders of `iam:route:anonymous` may make a route anonymous or switch it to `audit` mode (`AnonymousRouteGuard`, FR-57, FR-69); every such change is audited, and the reverse changes are revocation-class. Anonymous routes keep freshness fencing (section 8.4). `audit` mode exists for rollout only: it forwards would-deny requests and logs `audit_mode_would_deny`.

### 16.8 Network policy and secrets

- NetworkPolicy default deny in the `iam` namespace and in upstream namespaces. Upstream namespaces admit ingress only from gateway pods on service ports; this is mandatory for core-service, which has no own authentication. Services never call each other directly: east-west calls go through the gateway's east-west listener (FR-90), so `X-IAM-*` headers can reach an upstream only from a gateway pod. With the EKS VPC CNI gateway pods take addresses from the shared node subnets, so no gateway-only pod CIDR exists; the NetworkPolicy is the control, and PHP upstreams set `trusted_proxies` to the VPC range (a dedicated gateway pod subnet through custom networking is a later hardening option).
- `iam-control` admits ingress only from gateway pods and Jobs. Gateway ports: 9090 (internal: `/internal/freshness`, `/internal/policy/applied`) admits only `iam-control` and gateway pods (peer checks of FR-73 and FR-85); 9091 (decision API) admits only the namespaces of decision-API callers; 9092 (probes and `/metrics`) admits only the kubelet, the NLB subnet CIDRs (the NLB health check) and monitoring; 8444 (east-west) admits only microservice namespaces; 8443 (public) admits the NLB. `/internal/drain` answers only loopback peers. Gateway egress to PostgreSQL is denied.
- Gateway egress allowed: Kafka brokers, Valkey, the Loki distributor, upstream namespaces, gateway pods on 9090, the Kubernetes API. `iam-control` egress: PostgreSQL, Kafka, the Loki query frontend, the Kubernetes API, gateway pods' internal port (Sync-Fence). The gateway's EndpointSlice Role covers the upstream namespaces and namespace `iam` (for `iam-gateway-peers`).
- Secrets mounted as files and watched: JWT public keys (`JWT_PUBLIC_KEYS_FILE`), Kafka SCRAM credentials from the Strimzi `KafkaUser` Secrets and the Strimzi cluster CA (`KAFKA_CA_FILE`), the TLS certificate, the Valkey password, Loki tenant credentials when enabled. Gateway pods mount no database Secret.

### 16.9 Kafka ACLs and configuration gates

- Strimzi `KafkaUser` ACLs (section 17.11): only `iam-control` may write the IAM topics; `iam-control` may also read the state topic (assign only, no group ACL) for anti-entropy, shadow bootstrap and resync, and holds `DescribeConfigs` on the cluster for the broker-configuration check; the gateway principals may only read and describe the state topic; only `iam-control` reads `user.events.v1`; the broker runs the `simple` authorizer with `allow.everyone.if.no.acl.found=false`.
- The configuration gates of FR-72 detect drift of a Strimzi resource (unclean election enabled, allow-everyone, fewer replicas, a second partition) at gateway readiness and before every publication by `iam-control`; anti-entropy verifies stored offsets.

### 16.10 Credentials in automated checks

> Assumption: Schemathesis and the e2e suite need valid tokens. The e2e world signs tokens at run time with an ephemeral RSA key pair (the `e2e-tests` crate may use any crate, including `jsonwebtoken`), writes the public key to a per-scenario `JWT_PUBLIC_KEYS_FILE`, and produces User service events to the compose broker where a scenario needs them; no stub User service is needed, because IAM never calls User service. From Story 2.8 on, a service target in `make/service.mk` produces a short-lived `ROLE_SERVICE` token with the IAM caller audience from an ephemeral key for Schemathesis through `SCHEMATHESIS_FLAGS`; from Story 6.10 on, when IAM keys are enforced, the target first bootstraps that service principal in the test database with `service iam-bootstrap --admin-service`. No key or token is committed, so the secrets-scan gate stays clean and no protected file changes.

## 17. Kubernetes Deployment on EKS

The reference manifests live in this repository under `deploy/kubernetes/` and `deploy/platform/` (`strimzi/`, `valkey/`, `loki/`, `alloy/`) as plain, already-rendered YAML with no Kustomize overlays, because no renderer (`kustomize`, `kubectl`, `yq`) is in the protected `make/tool-versions.mk` and pinning one would be a second protected change. Two new Bats files, `tests/CLI/bats/deploy-manifests.bats` (Story 15.3) and `tests/CLI/bats/deploy-platform.bats` (Story 15.4), both with `# bats file_tags=repository` (`make.bats`), check their invariants with `grep` and `awk`, and the repository's strict `yamllint` run covers them (FR-88, Stories 15.3 and 15.4). An environment-specific variant is a copy reviewed by the platform team, not an overlay. Every value below is CONFIG unless tagged.

### 17.1 Placement and workload kinds

- Both planes are Deployments in namespace `iam`. Gateway pods hold no persistent identity, PVC or committed offset; the only per-pod Kafka identity is `client.id`. Gateway pods run on a dedicated gateway node pool (taint plus toleration).
- The gateway is the ingress data plane. No ingress controller and no ALB sit on the hot path; Gateway API objects may be published later for organisation-wide consistency, but routing never depends on them, because the route table is IAM state.
- Kafka (Strimzi), Valkey, Loki and Grafana Alloy run in the same EKS cluster (sections 17.11 and 17.12).

### 17.2 NLB, TLS and Services

- `iam-gateway` Service of `type: LoadBalancer`, port 443 to container port 8443, handled by the AWS Load Balancer Controller: `service.beta.kubernetes.io/aws-load-balancer-type: external`, `...-nlb-target-type: ip`, `...-scheme: internet-facing`, Proxy Protocol v2 on all targets, cross-zone load balancing off, health check on the probe port 9092 path `/internal/ready` every 5 s with healthy and unhealthy thresholds 2, deregistration delay 120 s with connection termination on deregistration. At least one target per AZ at all times.
- TLS terminates in the pod (D9); the certificate comes from a cert-manager Secret mounted as files and is hot-reloaded.
- `iam-gateway-decision` (ClusterIP, port 9091): the decision API only. `iam-gateway-internal` (ClusterIP, port 9090): `/internal/freshness` and `/internal/policy/applied` for `iam-control`. `iam-gateway-mesh` (ClusterIP, port 8444): east-west calls between services (FR-90). `iam-gateway-peers` (headless, port 9090, `publishNotReadyAddresses: false`): peer checks, ready-pod counts and the gateway's own zone. Probes and `/metrics` use port 9092 on the pod. `iam-control` (ClusterIP, port 80 to `APP_PORT`): reachable from gateway pods and Jobs only.
- WAF: none in the first release (owner item D9 WAF part, open); AWS WAF does not attach to an NLB, so a WAF would need CloudFront or an ALB in front.

### 17.3 Resources and runtime

| Setting | First release | Reason |
| --- | --- | --- |
| Gateway CPU | Request 1, **no limit**, `TOKIO_WORKER_THREADS=2`; without a limit the workers, the apply thread and the log writer use idle node CPU above the request; at 1,000 rps a pod needs a few percent of one CPU (ESTIMATE) | CPU limits cause CFS throttling, which multiplies tail latency (published measurements); NFR-39 requires zero throttled periods |
| Gateway memory | Request = limit = 2 GiB (ESTIMATE; conservative 3 GiB) | No overcommit; an OOM restart is also a bootstrap |
| Blocking threads | `max_blocking_threads` 16 in `command/gateway.rs` | Bounded helper threads; RS256 verify stays inline on workers |
| Allocator | glibc (the template sets none); jemalloc and mimalloc compared in Story 16.7 | Each alternative needs an allow-list entry and a licence check |
| `iam-control` | 1 CPU and 512 MiB request (ESTIMATE), 2 to 3 pods | Administrative traffic, relay, shadow bootstrap every 5 minutes |
| Reference benchmark pod | Request 5 CPU, no limit, `TOKIO_WORKER_THREADS=4` | Later-phase characterisation for larger fleets (section 20.6); not part of Story 16.7 |

At 1,000 rps peak each of 6 pods carries about 170 rps, a few percent of one worker (ESTIMATE). Six pods requesting 1 CPU each (6 requested vCPU) leave large headroom; availability, not load, sets the fleet size. The earlier plan of 3 CPU per pod (18 requested vCPU) was cut in ADR 0031; owner item D20 asks whether to raise the request again if test T2 shows hot-pod latency above NFR-33.

### 17.4 Memory per pod (ESTIMATE)

| Component | 100k users | 1M users |
| --- | --- | --- |
| Policy snapshot, steady (roles, catalogues and routes, interned assignment lists, keys and entries, version guards, reverse index, revocations, digest state) | 30 to 60 MB (conservative 80) | 170 to 220 MB (conservative 480 with many tenants) |
| Retained generations | < 10 MB | 13 to 30 MB per in-flight generation |
| Rebuild transient | 2 × snapshot | 2 × snapshot |
| Token memo (200,000 entries at about 400 B) | 80 MB | 80 MB at the first-release capacity |
| Negative memo and GraphQL document cache | 15 to 45 MB | 15 to 45 MB |
| Downstream connection buffers (capped at 256 MB per pod) | up to 256 MB | up to 256 MB |
| Working set with 1.3 × fragmentation | about 0.75 GB | about 1.4 GB |

Decision rule (NFR-38): keep the steady snapshot at or below 12.5 % of the memory request (256 MB at 2 GiB), so the rebuild transient stays inside 25 %. The conservative many-tenant case would exceed it and moves assignments alone to a two-tier cache (later phase). Real cardinality is owner item D6.

### 17.5 Probes gated on policy freshness

| Probe | Endpoint (probe port 9092) | Passes when | Settings |
| --- | --- | --- | --- |
| startupProbe | `/internal/startup` | Bootstrap complete, `__head` digest verified, configuration gates passed, first freshness proof attached to a published snapshot, JWT keys parsed | period 2 s, failureThreshold 150 (300 s) |
| readinessProbe | `/internal/ready` | Started; no rebootstrap; digest and derived-state checks OK; not draining; AZ-aware peer-relative freshness (section 17.6) | period 2 s, failureThreshold 1 (hysteresis inside the check) |
| livenessProbe | `/ping` | A tokio watchdog ticks every 1 s and is less than 10 s old; a dead tail or apply thread exits the process | period 5 s, failureThreshold 3 |

Liveness never depends on Kafka, PostgreSQL, upstreams, Valkey or Loki; otherwise an outage becomes a restart storm of pods that then cannot bootstrap. `iam-control` keeps the template's `/api/health` with the dependencies `database`, `kafka` (producer metadata reachable and configuration gates passed) and `access-log-store` (Loki ready endpoint) (FR-54).

### 17.6 AZ-aware peer-relative readiness (FR-85)

Every 2 s `PeerReadinessChecker` asks peers for `/internal/freshness` (published version, proof age, digest): every peer while the fleet has fewer than 10 pods (first release: 5 peers, 1 in its own AZ), otherwise at least 5 peers with at least 3 in its own AZ. Zones come from the EndpointSlice watch.

- **Local problem** (own proof older than `T_ready` while most peers in its AZ and other AZs are fresh): after 2 consecutive verdicts the pod fails readiness and at once sends HTTP/2 GOAWAY and `Connection: close` on the next HTTP/1.1 response, because NLB deregistration never moves established connections. Ready again after 3 consecutive fresh verdicts.
- **AZ-shaped problem** (own AZ stale, other AZs fresh): as above, except that the last `READINESS_AZ_FLOOR` (1 in the first release) ready pods of the AZ never go unready for staleness; they stay registered and fail closed per request, so the NLB never sees an AZ without a healthy target.
- **Fleet-wide problem** (most peers in every AZ stale): the pod stays ready and fails closed per request with 503 and `Retry-After`, so clients get deterministic 503s instead of connection failures from an empty target group.
- This rule has no external precedent; T16, T16b and T17 (Story 16.8) prove it before production.

### 17.7 Autoscaling

- First release: HPA v2 on CPU at 50 % of the request (fleet average), `minReplicas` 6 (2 per AZ across 3 AZs, because cross-zone is off and one pod per AZ would empty an AZ's target group on any restart), `maxReplicas` 9, scale-up at most 3 pods per 60 s, scale-down at most 1 pod per 2 minutes with a 600 s stabilisation window.
- 50 % rather than 60 %: the fleet average hides hot pods, and scale-out takes about 90 to 120 s, up to 5 minutes (ESTIMATE).
- Never scale on upstream in-flight requests (a slow upstream would scale the gateway out while its CPU idles) and never on Kafka lag (IAM change volume is unrelated to request load; the no-group consumer has no group lag).
- Gateway-local saturation metrics (worker busy ratio, accepted rps per pod) are exported and alerted only in the first release. A bootstrap-budget-derived scale-up cap, per-AZ Deployments and HPAs, and a KEDA saturation scaler are later-phase items (section 20.6).

### 17.8 PodDisruptionBudget, topology spread and rolling updates

- Gateway PDB `maxUnavailable: 1`; `iam-control` PDB `minAvailable: 1`.
- Topology spread: `topology.kubernetes.io/zone` maxSkew 1, `DoNotSchedule`, `minDomains: 3`; `kubernetes.io/hostname` maxSkew 1, `ScheduleAnyway`; `matchLabelKeys: [pod-template-hash]`.
- Rolling update `maxSurge: 3` (one per AZ), `maxUnavailable: 0`, `minReadySeconds: 15`; AWS Load Balancer Controller pod readiness gates hold old pods until new targets are healthy in the NLB. At 6 pods a rollout is two waves of about 1 to 3 minutes each (ESTIMATE).
- Every gateway Deployment and ReplicaSet carries the fleet label `app.kubernetes.io/part-of=iam-gateway` (canary and blue/green included), which Sync-Fence lists.

### 17.9 Graceful shutdown and connection draining (FR-86)

1. preStop `exec` of `service drain`, which calls `/internal/drain` on the probe listener over loopback (the endpoint refuses every non-loopback peer, so no other pod can drain the gateway): the drain flips readiness to false, sends GOAWAY and `Connection: close` on existing connections, keeps serving new connections that arrive while deregistration propagates, and returns after `DRAIN_PROPAGATION_DELAY` (45 s, ESTIMATE of NLB deregistration propagation, measured in T16). The `exec` runs the service binary itself, so it works in the distroless image; a `sleep` hook could not signal the process, and an `httpGet` hook would come from the node, which the loopback rule refuses.
2. SIGTERM: stop accepting; GOAWAY again; in-flight requests finish within `SHUTDOWN_GRACE_PERIOD` (20 s).
3. WebSockets close with 1001, SSE streams end and subscriptions complete, jittered over 5 s; the gateway's own registry handles them, because hyper does not track upgraded connections.
4. Stop the Kafka tail (no offsets to commit), flush both log lanes, exit.

`terminationGracePeriodSeconds: 90` covers 45 + 20 + 5 s plus margin. The pod exits before the NLB's 120 s deregistration delay ends, so the pod, not the NLB, decides when connections close. NFR-41: rolling update, pod kill and scale-out at 1,000 rps with zero failed requests; streams closed with 1001 and resumable.

### 17.10 Upstream discovery and connections (FR-87)

- EndpointSlice watch with read-only RBAC (`get`, `list`, `watch` on `endpointslices` in upstream namespaces), using the `ready`, `serving` and `terminating` conditions and each endpoint's zone. Headless-Service DNS carries no zone, so DNS-based selection would send about two thirds of calls across AZs with 3 AZs (ESTIMATE).
- Zone-aware power-of-two-choices by in-flight count within the pod's own zone; spill to other zones only when the zone has no healthy endpoint, its endpoints are ejected, or its in-flight load per endpoint exceeds a threshold. NFR-43 target: at most 5 % of upstream requests cross AZs while the own zone has healthy endpoints.
- First release: each upstream declares `http1` (pooled keep-alive, default) or `h2c` (one connection per endpoint). At 1,000 rps and 20 ms upstream latency about 3 to 4 requests are in flight per pod (ESTIMATE), so connection and stream limits do not bind. Several h2c connections per endpoint, h2c to PHP upstreams and subsetting are later-phase items.
- `UPSTREAM_DISCOVERY=static` with `UPSTREAM_STATIC_ENDPOINTS_FILE` serves docker compose and e2e; DNS with fully qualified names is the fallback.

### 17.11 Kafka on Strimzi and per-pod identities

| Resource | Settings |
| --- | --- |
| `Kafka` with `KafkaNodePool`s (KRaft) | 3 broker nodes, one per AZ, rack awareness on `topology.kubernetes.io/zone`; 3 controllers in a separate pool; `default.replication.factor: 3`, `min.insync.replicas: 2`, `unclean.leader.election.enable: false`, `auto.create.topics.enable: false`; `broker.session.timeout.ms` and `broker.heartbeat.interval.ms` tuned in T14; internal listener with TLS and `scram-sha-512`; `authorization.type: simple` with `allow.everyone.if.no.acl.found: false`; persistent gp3 volumes |
| `KafkaTopic` `iam.policy.state.v1` | `partitions: 1`, `replicas: 3`, the configuration of section 9.1 |
| `KafkaTopic` `iam.events.v1` | `partitions: 1`, `replicas: 3`, `cleanup.policy: delete`, `retention.ms: 604800000` |
| `KafkaTopic` `user.events.v1` | Owned by User service's manifests; listed only as IAM's dependency |
| `KafkaUser` `iam-control` | `scram-sha-512`; `Write`, `Describe`, `DescribeConfigs` on both IAM topics; `Read` on `iam.policy.state.v1` (assign only, no group ACL) for anti-entropy, the shadow bootstrap, the stored-offset check and resync; `Write` and `Describe` on transactional id `iam-relay`; `IdempotentWrite` on the cluster; `Read`, `Describe` on `user.events.v1`; `Read` on group `iam-control-user-events`; `Describe` and `DescribeConfigs` on the cluster for the ACL and broker-configuration checks |
| `KafkaUser` `iam-gateway` | `Read`, `Describe`, `DescribeConfigs` on `iam.policy.state.v1`; no quota, so tail and probe fetches are never throttled |
| `KafkaUser` `iam-gateway-bootstrap` | Same ACLs; `quotas.consumerByteRate` = a third of the leader egress budget, so concurrent bootstraps cannot starve serving pods' fetches |
| `KafkaUser` `notification-service` | `Read`, `Describe` on `iam.events.v1` and `notifications` |

Strimzi `KafkaUser` quotas apply per user, which is why the bootstrap read uses a separate principal. Clients trust the Strimzi cluster CA from `KAFKA_CA_FILE`; krafka support for a custom root is checked by spike Story 1.5. Strimzi rolling restarts move partition leadership in a controlled way; T14 measures the proof gap for a controlled restart and for a hard broker kill. Bats checks in Story 15.4 assert RF 3, `min.insync.replicas` 2, unclean election off, every topic setting of section 9.1, the ACLs (including `iam-control`'s read of the state topic) and the quotas. Compose runs PLAINTEXT without ACLs, so only these checks and the EKS stories exercise the ACLs.

### 17.12 Valkey, Loki and Grafana Alloy

- Valkey: primary and 2 replicas with Sentinel, one per AZ (assumption D23); password Secret; NetworkPolicy admits gateway pods only.
- Loki: simple scalable mode with S3 object storage and replication factor 3 across AZs (assumption D26); compactor retention per stream `lane="access"` 90 days and `lane="audit"` 400 days (D24); the push API admits gateway pods, the query frontend admits `iam-control` and operators.
- Grafana Alloy: DaemonSet tailing container stdout, parsing the gateway's JSON lines, setting the fixed labels and structured metadata, forwarding to Loki; `containerLogMaxSize` raised (for example 200 MiB) on the gateway node pool.

### 17.13 Metrics and alerts (NFR-27)

Metrics are emitted as `tracing` events with target `metrics` and rendered as Prometheus text by `prometheus-client` on the gateway's probe listener (`/metrics`) and on the control plane.

- Gateway: `gateway_residence_seconds`, `gateway_decisions_total` (by reason), `policy_applied_version`, `policy_digest_info`, `policy_derived_hash_info`, `policy_proof_age_seconds`, `policy_fresh`, `policy_bootstrap_seconds`, `token_memo_hit_ratio`, `graphql_document_cache_hit_ratio`, `streams_open`, `graphql_subscriptions_open`, `rate_limit_store_degraded`, `rate_limit_store_latency_seconds`, `access_log_audit_pending`, `access_log_dropped_total` (by lane and class), `upstream_rtt_seconds` (by zone), `upstream_cross_zone_ratio`.
- Control: `outbox_oldest_unpublished_seconds`, `relay_published_offset`, `user_events_consumer_lag_seconds`, `user_events_dead_letters_total`, `revocation_propagation_seconds`, `anti_entropy_repairs_total`, `sync_fence_outcomes_total` (by outcome), `access_log_query_seconds`.
- Alerts: `outbox_oldest_unpublished_seconds` and `user_events_consumer_lag_seconds` above 2 s (page above 10 s); pods disagreeing on `(applied_version, digest, derived_hash)`; any CFS-throttled period on gateway pods; hottest-pod CPU above 70 %; `rate_limit_store_degraded`; `access_log_audit_pending` near its bound; anti-entropy repairs.
- The metrics stack (Prometheus-compatible scraper or OpenTelemetry collector) does not exist in the org today (owner item D15 rest); the endpoint is Prometheus-compatible so either works.

## 18. Architecture Model (`workspace.dsl`) Changes

- System: rename `system` from "Service" to "IAM API gateway" with the description "VilnaCRM's API gateway and authorization service: authenticates, authorizes and proxies REST, GraphQL and streaming traffic; manages roles, permissions and routes; keeps security and access logs."
- People and external systems: `customer` (person, the subject of authorization), `administrator` (person), `userService` ("User service", External), `notificationService` ("Notification service", External), `upstreamServices` ("Upstream services", External, "Core, Payment, Analytics, Webhook, Integration, IP telephony"); remove `apiGateway` as an external system.
- Containers: `gateway` ("iam-gateway", data plane), `control` ("iam-control", control plane), `database` ("PostgreSQL 16", "Stores roles, assignments, the permission catalogue, specifications, upstreams, routes, rate policies, revocations, the outbox and the security audit log."), `kafka` ("Kafka on Strimzi"), `valkey` ("Valkey", rate-limit counters), `loki` ("Loki", access-decision log), `loadBalancer` ("AWS NLB"), `kubernetesApi` (External). No DynamoDB, DAX or separate worker container appears.
- Components: group `Authorization/Iam` with `Authorization/Iam/Domain`, `/Application` and `/Infrastructure`, holding `iamDomain` ("iam-domain"), `iamApplication` ("iam-application") and `iamInfrastructure` ("iam-infrastructure"), tagged by layer, plus the existing `compositionRoot`.
- Internal relationships (one per workspace dependency edge, unchanged): `iamDomain -> sharedDomain`; `iamApplication -> iamDomain`, `iamApplication -> sharedDomain`, `iamApplication -> sharedApplication`; `iamInfrastructure -> iamDomain`, `iamInfrastructure -> sharedDomain`, `iamInfrastructure -> sharedInfrastructure`; `compositionRoot -> iamDomain`, `compositionRoot -> iamApplication`, `compositionRoot -> iamInfrastructure`.
- External relationships: `customer -> loadBalancer -> gateway` ("Uses VilnaCRM", "HTTPS"); `administrator -> loadBalancer`; `gateway -> kafka` ("Reads iam.policy.state.v1", "Kafka, SASL SCRAM over TLS"); `control -> kafka` ("Produces iam.policy.state.v1 and iam.events.v1; consumes user.events.v1"); `userService -> kafka` ("Produces user.events.v1"); `kafka -> notificationService` ("iam.events.v1"); `control -> database` ("Reads and writes iam_* tables", "SQL over TCP"); `gateway -> valkey` ("Rate-limit counters", "RESP"); `gateway -> loki` ("Pushes the audit lane; Alloy ships stdout", "HTTPS"); `control -> loki` ("Queries access decisions", "LogQL over HTTP"); `gateway -> upstreamServices`, `gateway -> userService`, `gateway -> notificationService`, `gateway -> control` ("Proxies authorized requests", "HTTP/1.1 or h2c"); `gateway -> kubernetesApi` ("Watches EndpointSlices"); `control -> kubernetesApi` ("Lists gateway pods"); `control -> gateway` ("Sync-Fence long polls", "HTTP").
- The architecture-model gate checks one component per crate and one relationship per internal dependency edge. Story 16.9 applies these changes.

## 19. Test Strategy

| Layer or surface | What is tested | How | Key |
| --- | --- | --- | --- |
| `iam-domain` | Value objects; `PathNormalizer` (residual `%`, canonical re-encoding), `RestOperationMatcher`, `WildcardMatcher`, `DecisionPolicy`, `EffectivePermissionComposer`, guards, `SpecDiff`, `OrphanPolicy`, `RouteConflictGuard`, `AnonymousRouteGuard`, `RateDecisionRule`, `VersionAssembly`, `FreshnessRule` (every timer and hysteresis rule over injected instants), `RevocationRule`, `TokenLifetimeRule`, `BulkChunker`; aggregate behaviour and events | Table-driven `rstest` cases; `proptest` properties (normalisation idempotent; adding a grant never turns allow into deny; removing one never turns deny into allow; read model equals decision rule; version assembly is order-independent within a version; revokes-before-grants never yields an intermediate state more permissive than both ends); the maintained decision corpus | `make.unit_tests` |
| `iam-application` | Handlers with `tests/support` fakes (`new()` and `failing()`) for every port; gateway use cases over a fake `PolicyView`; parser adapters; `IamError` mapping; `WriteOutcomeMapper` for both interfaces; extractors; `AccessDecisionService` fail-closed paths; task loops over fakes (relay partial failure and fencing, consumer commit-after-processing and dead letters, anti-entropy repair, Sync-Fence counting rules for pending, terminating and bootstrapping pods, bulk chunk ordering, tombstone timing); `AccessRecordBuilder` lanes, sampling with a seeded `Rng` and budgets | Unit tests in sibling `tests.rs`; tokio paused time for every timer; REST handlers through `tower::ServiceExt` with `http-body-util` | `make.unit_tests` |
| `iam-infrastructure` | Every `Pg*` repository and `PgIamUnitOfWork` (atomicity, version conflicts, digest and `__head`, state rows, audit chain and trigger, change receipts, idempotency); `PgPolicyReadRepository` with a commit between two reads; `AdvisoryLockLeadership` fencing; Kafka adapters against krafka's `test-broker` (fault injection: `FENCED_LEADER_EPOCH`, `OFFSET_NOT_AVAILABLE`, partition-count change, per-broker metadata) and the compose broker (headers on tombstones, transactions, consumer-group rebalance, poison records); `ArcSwapPolicySnapshot` (apply, coalescing, deferred reclamation, derived structures); `JwtAccessTokenVerifier` with RSA keys generated at test time; `MokaTokenMemo` and `MokaDocumentCache`; Kubernetes adapters against a fake API server (Terminating pods, zone changes); `ValkeyRateLimitStore` against a Valkey container with a fault proxy or paused container; Loki adapters against a Loki container (LogQL correctness) and a local HTTP stub (errors, timeouts); `LinuxBootClock` | Integration tests in `tests/integration/` against real PostgreSQL, the compose Kafka, Valkey and Loki containers; migrations proven by a rollback round trip when an operator allows it; no LocalStack SQS (NFR-9) | `make.setup_test_db`, `make.integration_tests`, `make.sqlx_prepare` |
| `crates/service` | Wiring, the three `Adapters` literals, authentication middleware, guard, configuration rules and `check-config --mode` exit codes, `iam-bootstrap` exit codes and seeding, `register_iam_specs`, task supervision and shutdown, the gateway listener (TLS reload, Proxy Protocol, limits, connection-age cap), the pipeline end to end over a fake upstream, `HyperUpstreamForwarder` against a hyper fake upstream (GOAWAY, `REFUSED_STREAM`, resets, slow bodies, streamed and buffered retries), the stream registry and the `graphql-transport-ws`/`graphql-ws` codec, apply-thread hand-off, drain sequence, internal endpoints, Prometheus rendering, contract pinning tests, the smuggling and parser-differential corpus (NFR-40), the compose-reproducible fault suite (NFR-15) | Unit and integration tests of the composition root; manual clock instead of auto-advance where paused time meets real sockets | `make.unit_tests`, `make.integration_tests` |
| End to end | Every management capability over REST and over GraphQL with equivalent assertions, write modes included; the decision API on both listeners with the same outcome; proxied REST, GraphQL, WebSocket, SSE and subscriptions through an in-process gateway against the compose Kafka, a fake upstream and static pod and endpoint lists; every reason code; 401, 403, 429 and 503 cases; events visible on `iam.events.v1`; User service events produced to the compose broker; audit chain verified at the end of the run | Gherkin `features/iam_*.feature` with steps in `tests/e2e/steps/iam*.rs` and `world.rs` (runtime-signed tokens, per-scenario database and topics) | `make.e2e_tests` |
| Coverage and mutation | 100 % lines and functions; zero surviving and zero timed-out mutants on changed code, including `crates/service` (only `main.rs` is excluded); loops as pure step functions with branch-free shells and bounded waits (section 5.6); the mutation workflow starts the compose Kafka, Valkey and Loki services because each mutant reruns its crate's whole test suite; the runtime budget below keeps every shard inside 45 minutes | Template gates, no exclusions | `make.tests_with_coverage`, the mutation gate |
| Static gates | Formatting, clippy and rustdoc, layer rules, complexity, crate isolation, unused dependencies, dependency policy | Template gates | `make.format`, `make.lint_code`, `make.architecture`, `make.complexity`, `make.check_security` |
| Contracts | Snapshots, Spectral, OpenAPI and GraphQL diffs, Schemathesis with ephemeral credentials against `iam-control` | Template gates | contract gates |
| Deployment artefacts | Manifest invariants (no CPU limit on the gateway, probes, preStop hook, fleet label, RBAC scope, NetworkPolicies, Strimzi topic and user settings, Loki retention per lane) | Bats suite `tests/CLI/bats/deploy-manifests.bats` | `make.bats` |
| Load (smoke, in CI) | k6 scenarios `gateway-proxy` and `iam-management` under `tests/Load/` with smoke variants; protected health budgets unchanged | `constant-arrival-rate` (open model); a run fails if `dropped_iterations > 0` | `make.smoke_load_tests` |
| Benchmarks and EKS fault tests (outside `make ci`) | Latency, capacity, propagation, bootstrap, memory, Valkey and Loki behaviour, Kafka failover, zombie leader, readiness under partitions | Section 20; Stories 16.7 and 16.8 on dedicated EKS nodes with stored HDR artefacts | – |

**Mutation runtime budget (NFR-2).** The template caps the matrix in `scripts/ci/mutation-plan.sh` at 8 shards of 150 mutants, each shard has `timeout-minutes: 45`, and the protected `scripts/check-invariants.sh` rule (a) forbids a longer timeout. Every mutant reruns its crate's whole test suite, and every non-pull-request push runs `make mutation-tests` over the whole workspace. With one infrastructure crate holding every adapter, 150 mutants per shard fit in 45 minutes only if one mutant, build and crate suite together, takes about 18 s. The plan therefore sets these rules:

- Budget: the integration suite of `iam-infrastructure` and of `crates/service` each finishes in at most 15 s on the CI runner while the matrix stays at 150 mutants per shard, and in at most 30 s once the owner approves the resize below (targets, measured from Story 1.2 on and printed by `make.integration_tests`). Every story that adds integration tests to either crate keeps its suite inside the budget before it closes.
- Most broker tests run against krafka's in-process `test-broker`; the compose broker is kept for the few tests that need real log semantics (transactions, compaction, consumer-group rebalance). The Kafka spike modules leave `crates/service/tests` in Story 1.7, once their results are recorded.
- Story 1.8 changes the non-pull-request step of the mutation shard job in `tests.yml` from `make mutation-tests` over the whole workspace to `make mutation-tests-diff` against the previous commit of the pushed branch; `scripts/ci/mutation-plan.sh` is unchanged, so its shard count for a push stays an over-estimate capped at 8 and each shard runs its part of the diff. The owner agreed to this on 2026-11-22; it changes no protected file. Resizing the matrix to 16 shards of 60 mutants in `scripts/ci/mutation-plan.sh` (not protected itself, template-synchronised) breaks the assertions of the protected `tests/CLI/bats/ci_scripts.bats`, so it is a second protected change, which the owner has NOT approved (2026-11-22): Story 1.8 records the request only; with it, about 960 mutants per diff run at roughly 30 s each fit (ESTIMATE).
- Fallback when a story still exceeds the budget: split the story so that its changed code fits the matrix (8 × 150 mutants at 18 s, or 16 × 60 at 30 s after the resize), move further tests to `test-broker`, and, if that is not enough, stop and report to the owner. The plan never raises a shard timeout above 45 minutes, never adds an exclusion and never deletes tests to fit.

Testability rules (NFR-4): every timing and randomness rule is a pure domain function over injected instants and a seeded `Rng`, so comparison mutants are killed; `jsonwebtoken` runs with `validate_exp` and `validate_nbf` off and time claims go through `Clock`; `clippy.toml` already disallows `Instant::now` and `SystemTime::now`; property tests compare the PostgreSQL-side digest with the pod-side digest and incremental apply with a full rebuild on random histories that include duplicates and relay takeovers (NFR-16, NFR-28).

## 20. Performance Targets and Proof Plan

Every figure in this section is an ESTIMATE, a target or CONFIG. Nothing has been measured on VilnaCRM code or hardware. Benchmarks and EKS fault tests run outside `make ci` (Stories 16.7 and 16.8); their results replace the estimates in `docs/operations.md`.

### 20.1 Headline estimates

| Metric | Conservative | Expected | Optimistic | Basis |
| --- | --- | --- | --- | --- |
| Gateway residence time, warm REST, p50 / p95 / p99 (hottest pod at ≤ 60 % CPU, network excluded) | 0.25 / 0.6 / 1.2 ms | 0.09 / 0.20 / 0.45 ms | 0.06 / 0.12 / 0.25 ms | ESTIMATE: on-path CPU plus queueing at 60 % utilisation and a tail factor |
| Gateway-to-upstream round trip, p50 / p99 | same AZ 0.3 / 0.5 ms | same AZ 0.1 / 0.25 ms | same AZ 0.05 / 0.1 ms | ESTIMATE between published intra-AZ and cross-AZ measurements |
| End-to-end added latency, warm REST, zone-local, p50 / p95 / p99 | 0.55 / 1.0 / 1.7 ms | 0.19 / 0.4 / 0.7 ms | 0.11 / 0.2 / 0.35 ms | ESTIMATE, approximate sum of the two rows above |
| Extra for warm GraphQL with a document-cache hit, p99 | +0.2 ms | +0.08 ms | +0.04 ms | ESTIMATE |
| Extra for a GraphQL document-cache miss (1 to 5 KB), p99 | +1.0 ms | +0.3 to 1.0 ms | +0.2 ms | ESTIMATE; replaced by the parser benchmark of Story 1.6 and T3 |
| Extra for a token first seen on this pod, p99 | +0.3 ms | +0.1 ms | +0.05 ms | ESTIMATE: RS256 verify about 17 to 24 µs on cloud vCPUs |
| CPU per warm REST request | 200 µs | 80 µs | 60 µs | ESTIMATE (section 8.2) |
| Planned rps per worker vCPU at 50 % CPU | 2,500 | 6,250 | 8,300 | ESTIMATE = 0.5 / CPU per request |
| Propagation, Kafka acknowledgement to every healthy pod, p99 | 300 ms | about 40 ms at 6 to 10 pods | 20 ms | ESTIMATE |
| Propagation, PostgreSQL commit to every healthy pod, p99 | 500 ms | 150 to 300 ms | 50 ms | ESTIMATE |
| Management write overhead beyond PostgreSQL, `published` mode | 50 ms | 15 ms | 5 ms | ESTIMATE |
| Sync-Fence write, p99, no pod in transition | 1 s | 300 ms | 100 ms | ESTIMATE |
| Bootstrap to fresh, single joiner | 30 s | 3 to 20 s | 2 s | ESTIMATE; no krafka throughput figure exists |
| Policy snapshot memory, steady, at 1M users | 480 MB | 170 to 220 MB | 100 MB | ESTIMATE (section 17.4) |

The conservative column would miss the latency and capacity targets. That is deliberate: if the benchmark lands there, the fallback of section 20.4 applies.

### 20.2 First-release sizing (owner decision D6 part)

The decided peak is 1,000 rps. The first-release fleet is 6 gateway pods (2 per AZ), each requesting 1 CPU with no limit, 2 tokio workers and 2 GiB, scaling to 9. At about 170 rps per pod at peak (ESTIMATE) the fleet is sized by zone availability, not load. ADR 0031 records the first-release cuts: the CPU request lowered from 3 to 1, `maxReplicas` from 12 to 9, and the dedicated GraphQL parse pool replaced by the bounded blocking pool. The per-pod gates of NFR-34 stay as designed (owner decision D6). Mechanisms that matter only at tens or hundreds of pods are later-phase items (section 20.6). The design stays horizontally scalable: a request touches only the pod's own memory, so capacity grows with pods until upstream concurrency, the bootstrap budget during scale-out, or NLB and NIC limits bind.

### 20.3 Requirement targets

| Requirement | Target (unmeasured) | Proved by |
| --- | --- | --- |
| NFR-33 Gateway residence latency | Warm REST p95 ≤ 0.5 ms, p99 ≤ 1 ms on the hottest pod at ≤ 60 % CPU; GraphQL cache hit ≤ +0.1 ms; first-seen token p99 ≤ 1.2 ms; rate-limited routes p99 ≤ 2 ms; end-to-end added p99 ≤ 2 ms | T2, T3, T4, T24, T30 (Story 16.7); CI microbenchmarks are trend reports only |
| NFR-34 First-release capacity | 6 pods with 2 workers sustain 2,000 rps with zero gateway-caused 5xx at NFR-33 latencies; at least 5,000 planned rps per worker vCPU at 50 % CPU in a per-pod saturation run; saturation knee at least 8,000 rps per worker vCPU | T1, T2, T9 (Story 16.7) |
| NFR-35 Policy propagation | Commit to every healthy pod p99 ≤ 500 ms; Sync-Fence p99 ≤ 1 s with no pod in transition | T6, T7 (Story 16.7), T19 (Story 16.8) |
| NFR-36 Enforced staleness bound | No allow on a proof older than `FRESHNESS_HARD_BOUND` (15 s now, 5 s after T14) | T14, T15, T20 (Story 16.8); paused-time tests in Story 9.5 |
| NFR-37 Bootstrap to fresh | Single joiner ≤ 30 s at first-release size and at 1M users; startup budget 300 s | T8 |
| NFR-38 Snapshot memory | ≤ 12.5 % of the pod memory request | T13 |
| NFR-39 No CPU throttling | No CPU limit; zero throttled periods | T2 and the Bats checks of Story 15.3 |
| NFR-40 Smuggling and parser differential | Zero differentials | T21 in `make.integration_tests` (Story 16.4) |
| NFR-41 Availability under change | Rolling update, pod kill and scale-out at 1,000 rps with zero failed requests | T9, T10, T25 |
| NFR-42 Valkey degradation | Within NFR-33 plus `RATE_LIMIT_STORE_TIMEOUT`; no limiter 503; authorization unchanged | T30 |
| NFR-43 Zone locality | ≤ 5 % cross-AZ upstream requests at steady state | T24 |
| NFR-44 Access-log query bounds | p95 ≤ 5 s for 1 h, ≤ 30 s for 24 h; timeouts as 504 | T31 |
| NFR-19 Session revocation freshness | Event acknowledgement to every healthy pod p99 ≤ 1 s | T32 |

### 20.4 Phase-0 spikes and decision rules

Spike stories put `krafka` (with `test-broker`), `jsonwebtoken` and `criterion` only as dev-dependencies of `crates/service`, so they run before the allow-list change. Findings go to `docs/spikes/phase-0.md`.

| Capability | Spike story |
| --- | --- |
| (1) Produce and read headers on null-value records; (2) no-group `assign`, `read_committed` and the last stable offset, out-of-range detection, reseek after reconnect; (10) fault injection through `test-broker` | 1.2 |
| (3) Metadata to a chosen broker with the leader epoch; (4) `ListOffsets` with `current_leader_epoch` and the KIP-207/KIP-320 errors; (5) `DescribeConfigs` and `DescribeAcls` (multi-broker parts on a documented 3-broker compose profile outside `make ci`) | 1.3 |
| (6) Idempotent producing with `acks=all`, one request in flight, explicit partition, headers; (7) transactional producer `iam-relay` with epoch fencing | 1.4 |
| (8) Consumer group with commit after processing and rebalance; (9) SASL SCRAM-SHA-512 over TLS with a custom CA; (11) bootstrap read rate (target ≥ 100 MB/s, recorded as measured on the compose host only); (12) follower fetching (recorded only) | 1.5 |
| RS256 verify with the `aws_lc_rs` backend; the `async-graphql` parser (its `parser` re-export) on a representative corpus (1 to 64 KiB); results recorded as host-specific measurements, not gate values | 1.6 |
| Outcome and Kafka client decision (ADR 0026) | 1.7 |

Decision rules:

- **Kafka client.** If capabilities (1) to (6) or (9) fail, the freshness guarantee is not declared and the run stops before Epic 7 for an owner choice between the `rdkafka` fallback (build change and `openssl-sys` exception) and value framing plus strict mode. If (7) fails, the relay-epoch fallback is the only relay fencing. If (8) fails, `iam-control` consumes `user.events.v1` by manual assignment under the relay's advisory lock with offsets stored in PostgreSQL.
- **Data plane.** If T2 misses residence p99 ≤ 1 ms or 5,000 planned rps per worker vCPU, profile and optimise the hyper pipeline (allocator, h2 settings, log path, connection counts) and re-run. Pingora is evaluated only if the owner approves the dependency-policy exceptions (D21).
- **Freshness.** `T_hard` starts at 15 s; T14 decides the move to 5 s. T15 decides whether G4 and G8 hold unconditionally; if not, liveness ticks (D17) or the later-phase strict mode are built.
- **Rate limiting.** If T30 shows authorization affected or limiter 503s, the release is held until fixed.
- **Readiness.** If T16b or T17 show connection failures, add a minimum-ready floor in the load-balancer configuration before production.
- **Scale.** If T6b or T9 show a serving pod's proof aging past `T_ready`, lower the bulk cap and the scale-up cap before production.

### 20.5 Test list (first-release scope)

Tools: the gateway's server-side residence histogram (HdrHistogram) is the primary latency metric; wrk2 (HTTP/1.1) and oha (HTTP/2) with coordinated-omission correction for latency gates, generators at ≤ 50 % CPU; k6 `constant-arrival-rate` for behaviour; criterion for microbenchmarks. Topology: generators, the gateway and a hyper echo upstream (0 and 20 ms delay, 1 to 64 KB bodies) on dedicated EKS nodes across 3 AZs with Strimzi Kafka, Valkey and Loki as in production; the first-release pod only; a baseline direct to the echo upstream. The reference 5-CPU pod and an Envoy `ext_authz` baseline are later-phase characterisation (section 20.6).

| Id | Scenario | Pass criterion | Story |
| --- | --- | --- | --- |
| T1 | Ramp to the knee (highest rate with residence p99 ≤ 2 ms) | Knee per worker vCPU ≥ 8,000 on the production mix | 16.7 |
| T2 | Open loop at 25 / 50 / 60 / 75 % of the knee with realistic token arrival and protocol mix; a fleet run at 2,000 rps on 6 pods | At 50 % fleet CPU: residence p95 ≤ 0.5 ms, p99 ≤ 1 ms on the hottest pod; ≥ 5,000 rps per worker vCPU; zero throttled periods; 2,000 rps on 6 pods with zero gateway-caused 5xx | 16.7 |
| T3 | Warm GraphQL at 95 % and 0 % document-cache hit; documents of 1, 5, 8, 64 KiB | +0.1 ms at 95 % hit; other requests within target at 0 % hit | 16.7 |
| T4 | Cold tokens, keys in last position | Residence p99 ≤ 1.2 ms | 16.7 |
| T5 | Token-memo dilution at 50 and 200 pods | Later phase | – |
| T6 | IAM changes at 100/s plus 1,000-entity chunks and resyncs during load on packed nodes; a revocation behind a bulk | Request p99 within 10 % and p99.9 within 20 % of baseline; revocation propagation p99 ≤ 500 ms | 16.7 |
| T6b | 100,000-entity bulk at 6 and 9 pods with the record-rate cap | No pod's proof older than `T_ready` | 16.7 |
| T7 | Propagation at 6 and 9 pods | Commit to every healthy pod p99 ≤ 500 ms | 16.7 |
| T8 | Bootstrap from 50, 200 and 400 MB live state, 1 and several concurrent joiners | Single joiner ≤ 30 s at 1M users; digest equals PostgreSQL | 16.7 |
| T9 | Scale-out 6 → 9 pods mid-run | Serving pods' proofs never age past `T_ready`; zero failed requests | 16.7 |
| T10 | Rolling update at 1,000 rps with streams and subscriptions open | Zero failed requests; streams closed with 1001 and resumed | 16.7 |
| T11 | Forged-token flood alongside T2 | Legitimate p99 within target | 16.7 |
| T12 | Large GraphQL documents at the caps alongside T2 | Other requests' p99 within target | 16.7 |
| T13 | Memory at 100k and 1M subjects (10M is later-phase); many tenants | Snapshot ≤ 12.5 % of the request; no OOM | 16.7 |
| T14 | Broker failover: kill the partition leader; rolling broker restart | No false proof; proof gap measured; decides `T_hard` | 16.8 |
| T15 | Zombie leader: isolate one AZ with the old leader | No allow on frozen state beyond `T_hard` | 16.8 |
| T16 | One pod cut off from Kafka; CPU-starve one pod | Pod sheds connections at `T_ready` plus hysteresis | 16.8 |
| T16b | One AZ partitioned from Kafka | The AZ keeps registered targets; its clients get 503, not connection failures | 16.8 |
| T17 | Fleet-wide Kafka loss with NLB IP targets | Targets stay registered; clients get 503 with `Retry-After` | 16.8 |
| T18 | Relay stall and PostgreSQL failover (default mode) | Gateway serves; writes return `202` (compose-reproducible part in Story 16.3); strict-mode part only if strict mode is built | 16.3 |
| T19 | Sync-Fence with terminating, pending and bootstrapping pods during a 6-pod rollout | No new decision or open stream on old state after `complete` or `bounded` | 16.8 |
| T20 | Digest and derived-state corruption, gaps, topic recreation, relay duplicates, zombie relay batch, second partition, unclean-election configuration | Pods fence or ignore duplicates as specified; relay alarms within 10 s | 16.8 |
| T21 | Smuggling and parser-differential corpus | Zero differentials | 16.4 |
| T22 | Stream re-authorization with many open streams and revocation bursts | Revoked streams closed before Sync-Fence returns; apply thread not stalled (integration scale in Story 11.2; EKS scale through T33) | 11.2, 16.8 |
| T23 | HTTP/2 downstream with h2c upstream against HTTP/1.1 on both legs | CPU per request per protocol mix recorded | Later phase |
| T24 | Zone-local against cross-AZ upstream selection | Cross-AZ share ≤ 5 % | 16.7 |
| T25 | Kill 1 of 6 pods at 60 % load | Survivors' p99 within target after 30 s | 16.7 |
| T26 | Large responses (16, 64, 256 KB) | Per-KB CPU slope recorded | Later phase |
| T27 | Hot connections (a client multiplexing 128 streams) | No pod above 80 % CPU while the fleet averages 50 % | Later phase |
| T28 | Log loss under rotation and 100 % 5xx incident volume | Budgets hold; no acknowledged audit record lost | 16.7 |
| T29 | 5 MiB SDL upload through the gateway over REST and GraphQL | Both succeed | 16.7 |
| T30 | Valkey slowed to 20 ms, paused, killed, failed over | Breaker opens within 5 failures; p99 ≤ target + 5 ms; zero limiter 503; authorization unchanged | 16.7 |
| T31 | Loki query cost on 1 h and 24 h; Loki outage with always-audit traffic | Targets met or recorded; 504 on timeout; audit-or-deny engages after `ACCESS_LOG_AUDIT_MAX_PENDING` | 16.7 |
| T32 | User service revocation end to end at 10/s and bursts of 1,000; consumer killed mid-batch; poison record | p99 ≤ 1 s; no event lost or applied twice; poison record dead-lettered | 16.8 |
| T33 | 10,000 open GraphQL subscriptions over both subprotocols with revocations; malformed frames | Denied operations never reach the upstream; revoked subscriptions completed before Sync-Fence returns; malformed frames close the socket | 16.8 |

### 20.6 Later-phase items (no story implements them)

| Item | Trigger |
| --- | --- |
| Upstream subsetting | Fleet above about 50 pods or upstream connection limits near |
| Several h2c connections per endpoint; h2c to PHP upstreams | Fleet above about 50 pods, or D10 answered |
| Peer snapshot bootstrap with a collision-resistant set digest | Rollouts or scale-out limited by leader egress |
| `N`-aware commit-time bulk pacing replacing the record-rate cap | Fleet above about 20 pods or bulk changes above about 50 MB |
| Follower fetching (KIP-392) | Leader egress binds |
| Token-memo dilution work (memo sized to active sessions, T5 population study) | Fleet above about 20 pods or memo hit ratio below 90 % |
| Bootstrap-budget-derived HPA cap, per-AZ Deployments and HPAs, KEDA saturation scaler | Fleet above about 20 pods or per-AZ skew above 1.2 |
| 200-pod rollout target and emergency rollout mode | Fleet above about 50 pods |
| Linear-scaling proof at 50 pods; per-AZ utilisation SLO | Fleet above about 20 pods |
| Strict freshness mode with heartbeats | Spike Story 1.3 or T15 fails |
| Control-plane liveness ticks on the state topic | Quorum check cannot be built and D17 allows it |
| Persisted queries and the first-party allow-list mode | Owner request |
| Two-tier cache for assignments | Snapshot above 12.5 % of the pod memory request |
| Separate gateway binary without `sqlx` | D16 |
| WAF in front of the NLB | D9 WAF part answered yes |
| Reference 5-CPU pod characterisation, T13 at 10M subjects, T23 protocol-mix CPU, T26 per-KB slope, T27 hot connections, Envoy `ext_authz` baseline | Fleet above about 20 pods, or a first-release benchmark miss that needs the comparison |
| Dedicated gateway pod subnets (custom networking) so upstreams can trust a gateway-only CIDR | Security review asks for it |

## 21. Example Context and Template Bundle

- The example context `company-subdomain/some-module` stays in place, unchanged, through every story of this plan: its routes, GraphQL fields, migration, feature file and pinned contract entries keep the template gates green while IAM grows beside it, and the authentication layer does not apply to it.
- Its removal is outside this plan, as the product brief and the PRD state; it is a follow-up issue (section 24), planned under the service-scaffolding rules after IAM exists: find its traces, repair the three documentation-check lines that cite its directory, extend `.templatesyncignore`, replace (never delete) its GraphQL roots with IAM's, regenerate both snapshots (the removed operations are breaking and need the owner's `approved-breaking-change` decision), keep or drop its migration according to whether it was ever deployed, and pass the full gate sequence.
- The template's own bundle `specs/rust-service-template-bootstrap/` is left untouched; replacing it is a separate change.

> Assumption: The service identity (`description` and `repository` in `[workspace.package]`, which produce the OpenAPI title and contact URL) is set by the service-scaffolding bootstrap, not by this plan; the IAM stories work with either value, and the snapshot is regenerated whenever it changes.

## 22. Architecture Decision Records

New ADRs under `docs/adr/` (numbering continues after `0012`), indexed in `docs/adr/README.md`:

| ADR | Title | Status against the superseded plan | Records | Story |
| --- | --- | --- | --- | --- |
| 0013 | IAM bounded context `authorization/iam`, with the gateway as modules inside it | AMEND | One context, crate placement, why no split and why no separate gateway context (D19); Rust instead of the board's Go labels; naming rules of `research.md` section 2.5 | 1.1 |
| 0014 | PostgreSQL as system of record and an in-process replicated policy snapshot instead of DynamoDB and DAX | AMEND (the cache half replaced) | Datastore comparison kept; the R6 test (C1 to C8); why no external cache on the hot path; revisit triggers | 1.1 |
| 0015 | IAM is the API gateway: split planes, one image, two run modes | REPLACE (supersedes "invalidation workers as tasks of the single binary") | `iam-gateway` and `iam-control`, isolation by credentials and NetworkPolicy, alternatives (single binary, two images, Envoy with `ext_authz`, Pingora, NLB TLS) | 9.2 |
| 0016 | Token validation at the gateway without token persistence or liveness calls | AMEND | Offline RS256 with a key file of up to 3 keys, maximum lifetime, identity-only memo flushed on key-set change, revocation checked on every request, caller audience, no liveness call | 2.5 |
| 0017 | Policy state topic, transactional outbox and fenced Kafka relay | REPLACE (supersedes "transactional outbox and SQS relay") | State and event rows, framing, digest and `__head`, one partition, relay fencing (transactional or relay epoch), anti-entropy, bulk cap, resync | 7.4 |
| 0018 | Permission catalogue generated from OpenAPI and GraphQL specifications | KEEP | Key formats, wildcards, flags, versions, activation, orphans, specification scope | 5.3 |
| 0019 | Security audit log in PostgreSQL and access-decision log in Loki | AMEND | Hash chain and anchors kept; Loki lanes, audit-or-deny, stream layout, query bounds, retention basis and periods, pseudonymous identifiers; the partitioned table dropped | 2.2 (draft), 14.2, 14.5 |
| 0020 | Effective permissions composed at check time | KEEP | Compiled per-role sets plus assignment lists instead of a stored per-user `UserRolePermission` | 6.15 |
| 0021 | REST and GraphQL parity | KEEP | Every capability on both interfaces through one handler, write modes included | 2.8 |
| 0022 | Security controls of IAM and the gateway edge | AMEND | Caller authentication, self-authorization twice, reserved keys, route scope and system entries, bootstrap, edge hardening, path rule, credential forwarding, CORS and CSRF, east-west path, listener split, NetworkPolicy, Kafka ACLs, OWASP API Top 10 mapping | 16.9 |
| 0023 | Allow-list additions for the gateway | REWRITE | The exact delta of section 3.1, licences, the owner approval of 2026-11-21, applied in Story 2.3, the composition-root fallback | 2.3 |
| 0024 | Freshness contract: watermark proof, replica-quorum epoch check, `T_hard` and Sync-Fence | NEW | Section 9.5 to 9.8, G1 to G9, the contract boundary of the default mode, strict mode as a fallback | 9.5 |
| 0025 | Kafka scope (amended R5) and inbound User service events | NEW | Section 10 | 13.5 |
| 0026 | krafka as the Kafka client: phase-0 spike results and rdkafka fallback | NEW | Pass or fail per capability, the fallback rule | 1.7 |
| 0027 | Rate limiting with Valkey and its degradation | NEW | Section 11 | 12.3 |
| 0028 | Kubernetes on EKS: NLB with TLS in the pod, probes, AZ-aware readiness, zone-aware routing | NEW | Sections 17.1 to 17.10 | 15.3 |
| 0029 | Kafka on Strimzi and the configuration gates | NEW | Section 17.11 and FR-72 | 15.4 |
| 0030 | Streams through the gateway: WebSocket, SSE and GraphQL subscriptions | NEW | Sections 8.5 and 8.6 | 11.3 |
| 0031 | First-release sizing for 1,000 rps and deferred large-fleet mechanisms | NEW | Sections 20.2 and 20.6, with measured results | 16.7 |

Superseded decisions of the earlier plan: the versioned moka authorization cache with LISTEN/NOTIFY, floors, tombstones and stale grace (old 0014 cache half and old 0015), the SQS relay and SQS inbound queue (old 0017, part of old 0016), the User service liveness call (part of old 0016), and the partitioned access-decision table (part of old 0019). None of the superseded ADRs was ever written, so the new ADRs carry the same numbers.

### 22.1 Deviations from the Miro board

| Board element | This design | Why | ADR |
| --- | --- | --- | --- |
| Separate "API Gateway [DevOps]" box (load balancer, logging, tracing, request limiting) in front of IAM | IAM is the gateway; the NLB balances connections, the gateway balances requests, logs, propagates request ids and limits requests | Owner decision: IAM is the API gateway | 0015 |
| Database: DynamoDB | PostgreSQL 16 | A gap-free, commit-ordered global version needs one counter row in the writing transaction; PostgreSQL is the template stack | 0014 |
| Cache: DAX "stores authorization data" | In-process replicated snapshot fed by Kafka | An external TTL cache on the hot path fails the R6 test and the latency budget | 0014, 0024 |
| Invalidation cache workers container | Relay, anti-entropy and tombstone emitter in the `iam-control` Deployment | There is no cache to invalidate, only state to publish | 0015, 0017 |
| `TokenRepository` saves and loads `AccessToken` through Cache, Database and `UserAPIClient` | No token persistence; offline verify; per-pod identity memo; no `UserAPIClient` (revocations arrive over Kafka) | Verify is cheaper than any lookup; revocations are replicated state (D1) | 0016 |
| Message broker: AWS SQS "stores entity events" | Kafka on Strimzi: IAM produces `iam.policy.state.v1` and `iam.events.v1` and consumes `user.events.v1` | Owner decisions on Kafka scope (D1, D14b) | 0017, 0025 |
| "Other microservices → IAM: sync REST API and GraphQL" | Decision API on its own gateway listener and on `iam-control`; upstreams normally rely on principal headers; calls between services go through the gateway's east-west listener | Proxied requests are already authorized; principal headers can be trusted only if they always come from the gateway | 0015, 0022 |
| "IAM → Notification service: async message broker" | Notification service tails `iam.events.v1` (D7) | The board does not name the events; FR-48 does | 0025 |
| `ValidateAccessQueryHandler` creates `AccessToken` | In-process `DecisionPolicy` in the gateway pipeline; the handler obtains the token from `TokenRepository` | Owner decision: IAM is the gateway | 0015, 0016 |
| `UserRolePermission` as a stored read model | Compiled role sets plus assignment lists at check time; read API kept (FR-39) | Unchanged from the earlier plan | 0020 |
| "Security and access logs" (system context, no component) | Security audit chain in PostgreSQL; access-decision log in Loki, queryable through IAM's API with parity | Owner scope decision; D13 | 0019 |
| Cache "stores confirmation token, roles and permissions" | Roles and permissions in the replicated snapshot; Valkey holds rate-limit counters only | R6; D4 | 0014, 0027 |
| Go labels | Rust from the service template | Owner decision recorded in the board digest | 0013 |

## 23. Delivery Outline for the Epics

`epics.md` owns the delivery order, the stories and their `Depends on:` lines; this section does not repeat them. All 16 epics ship in one pull request for issue #8 (owner decision, 2026-11-22); Story 1.1 runs first and alone. In short, 16 epics: Epic 1 scaffolds `authorization/iam` and runs the phase-0 krafka and benchmark spikes, ending with the Kafka client decision and the mutation-gate sizing of Story 1.8; Epic 2 builds the policy core, the unit of work and token authentication; Epic 3 roles and assignments; Epic 4 specification ingestion; Epic 5 the permission catalogue and grants; Epic 6 the decision core and IAM's self-protection; Epic 7 policy replication from the control plane (state records, configuration gates, the fenced relay, events, published write mode, anti-entropy, maintenance, bulk operations, resync); Epic 8 the gateway management API (upstreams, routes, rate policies, declarative configuration, bootstrap seeding); Epic 9 the gateway runtime (snapshot, gateway mode, bootstrap and tail, freshness proof, derived-state check, startup and readiness); Epic 10 the request path for REST and GraphQL, edge hardening, read-your-writes, the decision API on its own listener, CORS and CSRF, and the east-west listener; Epic 11 streams and GraphQL subscriptions; Epic 12 rate limiting with Valkey; Epic 13 revocations, write modes, Sync-Fence and User service events; Epic 14 the access-decision log in Loki and audit queries; Epic 15 Kubernetes deployment and operations; Epic 16 hardening, benchmarks, EKS fault tests and documentation. Until IAM's own authorization lands (Stories 6.11 and 6.12), earlier API stories authenticate callers but do not yet check IAM keys; this intermediate state never leaves the feature branch. The spike outcome of Story 1.7 gates Epic 7 onward; every story of Epics 7 to 16 depends on Story 1.7 directly or transitively, so the gate holds under parallel dispatch.

## 24. Assumptions and Open Items

> Assumption: The issue is #8 (VilnaCRM-Org/api-gateway-service); the commit convention in `## Constraints` uses the literal `(#8)`, and all 16 epics ship in one pull request (owner decision, 2026-11-22).

> Assumption: The profile `.claude/rust-sdlc.yml` maps the ten dispatch keys to the targets of the same name (the key with underscores replaced by hyphens); the resolved names appear only in `## Constraints` above; `make.bench_spikes` (Story 1.6, `make/service.mk`) and `make.bats` resolve by the same rule; the default branch is `main` and the profile's `ci.base_ref` is `origin/main`.

> Assumption: The gateway code lives as modules inside the `authorization/iam` crates (owner item D19, default), for the reasons in section 3.

> Owner decision (2026-11-21): the protected allow-list change (ADR 0023) with exactly the delta of section 3.1 is approved; Story 2.3 applies it, and every story that uses one of its crates depends on Story 2.3. Spike Stories 1.2 to 1.6 need no approval because their crates are dev-dependencies of `crates/service`. Owner decision (2026-11-22): the Story 1.8 mutation-matrix resize is not approved and is recorded as a request only. Any other protected change is not approved and stops the story for the owner.

> Assumption: Valkey runs in the EKS cluster as one primary and two replicas with Sentinel, one per AZ (owner item D23, default); ElastiCache for Valkey is a configuration change.

> Assumption: Loki retention is 90 days for `lane="access"` and 400 days for `lane="audit"`, and audit-or-deny applies to always-audit and sensitive keys only (owner item D24, default).

> Assumption: The User service topic is `user.events.v1`, keyed by user id, with a neutral envelope carrying the event id, `occurredAt`, `userId` and, for session events, `sessionId` (owner item D25, default, to agree with the User service team).

> Assumption: Loki runs in simple scalable mode on EKS with S3 storage and replication factor 3, with a Grafana Alloy DaemonSet (owner item D26, default).

> Assumption: The first release is sized for a 1,000 rps peak (owner decision D6 part): 6 gateway pods, 2 per AZ, each requesting 1 CPU with no limit, 2 tokio workers and 2 GiB; `maxReplicas` 9; `iam-control` 2 to 3 pods. Large-fleet mechanisms are later-phase items (section 20.6).

> Assumption: `KAFKA_CONFIG_GATES=relaxed` exists only so the single-broker docker compose setup can run in `dev` and `test`; `service check-config` refuses it elsewhere.

> Assumption: The reference Kubernetes manifests and the Strimzi, Valkey, Loki and Alloy resources live under `deploy/` in this repository as reviewed reference artefacts checked by Bats; their production copies live in the platform repository (owner item D15 rest, default).

> Assumption: PostgreSQL production replication is synchronous (RDS Multi-AZ); a topic ahead of PostgreSQL after a failover is handled by the resync runbook.

> Assumption: The namespace is `iam` and the gateway fleet label is `app.kubernetes.io/part-of=iam-gateway`.

> Assumption: Effective permissions of service principals are listed through the assignment query (`subjectKind = service`); the effective-permission read model of FR-39 covers user subjects.

> Assumption: The `time` feature is added to the workspace `sqlx` dependency so that adapters map `timestamptz` through `sqlx::types::time::OffsetDateTime`; this edits the workspace dependency table, which is not protected, and adds no direct crate to any layer.

> Assumption: The health probes for `kafka` and `access-log-store` live in the composition root, and the `Dependency` enum (a template-ignored seam file) gains `Kafka` and `AccessLogStore`, because an IAM crate may not depend on the health-check context without a protected `[contexts]` edit.

> Assumption: IAM's GraphQL authorization in `iam-control` runs as an `async-graphql` extension over the coordinates of IAM-owned fields only, so the example context's GraphQL fields remain public and their contract is unchanged.

Open items for the owner, carried to the readiness check as confirmations with the stated defaults:

1. Resolved decision: the protected allow-list change of section 3.1 (ADR 0023) was approved by the owner on 2026-11-21 and is applied on the branch by Story 2.3; it is no longer open.
2. External prerequisites outside this repository: an EKS cluster with the AWS Load Balancer Controller, cert-manager, Strimzi, Valkey, Loki and Grafana Alloy (needed by Stories 16.7 and 16.8 and by production); User service publication of its four session and user events to `user.events.v1` (until then the 900 s token lifetime bounds revocation for upstreams without their own session check); Notification service's tail of `iam.events.v1`; JWT public keys per environment; production minting of `ROLE_SERVICE` tokens with the IAM caller audience.
3. The phase-0 spike outcome (Story 1.7): krafka accepted, or an owner choice of the `rdkafka` fallback before Epic 7.
4. Open design decisions with defaults: D5 anonymous routes fenced during a Kafka outage; D6 rest (real cardinality and traffic shape); D9 WAF (none in the first release); D10 host layout and h2c to PHP upstreams (one host per service, HTTP/1.1 to PHP); D11 `kid` and JWKS from User service (a key file with up to 3 keys until then); D12 token families (900 s first-party tokens only; League OAuth2 and 3,600 s tokens rejected); D15 rest (metrics stack, production home of the manifests); D16 separate gateway binary (later); D17 routes and rate policies as IAM updates, and liveness ticks only if the quorum check fails (yes to both); D18 retirement of the earlier AWS API Gateway plan (after the gateway enforces in TEST); D20 first-release CPU cost (accept); D21 Pingora exceptions (not pre-approved); D22 large-fleet rollout targets (not relevant to the first release).
5. Separate database roles in production: migrations under an owner role, the service under a runtime role with only `INSERT` and `SELECT` on the audit tables; and an external audit pipeline that keeps the `iam.security_audit.anchored` anchors.
6. The log-retention basis and periods, and that access records in Loki are not pseudonymised on `user.deleted` but age out.
7. The administrative write-rate assumption of `research.md` (well below the single-counter ceiling of about 100 to 500 writes/s, ESTIMATE).
8. Design choices made in this round that the owner may want to revisit: east-west calls through a gateway listener rather than mTLS between services (FR-90); CORS policy per route rather than per host (FR-89); credentials forwarded only to upstreams flagged `forwardCredentials` (FR-68); route configurations limited to one version of at most 1,000 routes (FR-58); a separate decision listener and a loopback-only drain (FR-86).
9. Whether the first release should drop AZ-aware peer-relative readiness (FR-85), the peer cross-check (FR-73) and zone-aware upstream selection with the EndpointSlice watch (FR-87, NFR-43) in favour of local readiness and ClusterIP Services with topology-aware routing, as owner decision D6 might allow; the plan keeps them by default because they address correlated failures that exist at 6 pods.
10. A follow-up issue, outside this plan, to remove the template's example context `company-subdomain/some-module` (section 21), which needs the owner's `approved-breaking-change` decision.
