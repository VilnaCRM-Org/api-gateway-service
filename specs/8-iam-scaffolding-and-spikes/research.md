# Research: Scaffold the IAM Context and Run the Phase-0 Spikes

| Field | Value |
| --- | --- |
| Bundle | `specs/8-iam-scaffolding-and-spikes/` |
| Issue | `#8` "Scaffold the IAM context and run the phase-0 spikes" (VilnaCRM-Org/api-gateway-service) |
| Date | 2026-11-22 |
| Inputs | The master research `specs/0-iam-authorization-service/research.md` (iam-service checkout, 2026-11-21); read-only reconnaissance of `api-gateway-service` on 2026-11-22 (`Cargo.toml`, `architecture.toml`, `deny.toml`, `protected-config.toml`, `.templatesyncignore`, `Makefile`, `docs/make-targets.md`, `.claude/rust-sdlc.yml`, `scripts/ci/mutation-plan.sh`, `.github/workflows/tests.yml`, `docker-compose.yml`, `xtask/src/scaffold/name.rs`) |

This file condenses the master research to what bears on Epic 1: the facts of the target repository, the layer rules and allow-lists, the naming rules, the datastore decision behind ADR 0014, the dependency and protected-change rules, the krafka capability questions with the `rdkafka` fallback, and the benchmark targets. Section numbers follow the master research so that citations (`research.md` section 2.5, section 5) stay valid; the numbering therefore has gaps. A one-paragraph summary of the whole product closes the file.

## 0. Scope of This Condensed File

> Assumption: This bundle plans Epic 1 only (stories 1.1 to 1.8 of the master plan), because the implementation workflow implements every story of a bundle in one pull request and the FR/NFR gate traces every requirement id of the bundle's PRD to that pull request. The other fifteen epics are later features with their own bundles.

> Assumption: The master plan was written against the `iam-service` checkout, an unmodified template copy; `api-gateway-service` is a fresh copy of the same template whose service is named "VilnaCRM API Gateway". Every template fact the master research states and Epic 1 relies on was re-checked against `api-gateway-service`; the differences are listed in section 1.5.

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

No IAM code exists. No member path starts with `crates/authorization/iam/`, so the story-1 rule applies: Story 1.1 is "Scaffold authorization/iam" with the checklist C1 to C12. The scaffolder (`make new-context group=<g> context=<c>`, `xtask/src/scaffold/`) accepts names matching `^[a-z][a-z0-9]*(-[a-z0-9]+)*$` and refuses the reserved context names `shared`, `service`, `xtask`, `test-support` and `e2e-tests`; `iam` is not reserved.

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

### 1.4 What Epic 1 must build

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

## 2. Naming

### 2.5 Board names adapted to Rust

Rust type names follow the API guidelines and treat an acronym as one word (`GraphQl`, `OpenApi`, `UserApi`); handler names are verb-first (`CreateGraphQlPermissionsCommandHandler` for the board's `GraphQLCreatePermissionsCommandHandler`), matching the template's `CreateExampleApiResourceCommandHandler`; `LoadGraphQLCommandHandler` gains the `Spec` suffix (`LoadGraphQlSpecCommandHandler`) for symmetry with `LoadOpenApiSpecCommandHandler`. PostgreSQL adapters are prefixed `Pg`. ADR 0013 records these rules. For Epic 1 the names are `PolicyVersion`, `PolicyDigestValue`, `LogEpoch`, `RelayEpoch`, `PolicyEpoch`, `PolicyEpochRepository`, `PgPolicyEpochRepository`, `GetPolicyEpochQueryHandler`, `InvalidIamValue`, `IamError`, `IamState`, `IamQuery` and `IamMutation`.

## 5. Datastore Decision (summary for ADR 0014)

The board specifies DynamoDB and DAX; the template ships PostgreSQL through `sqlx`. The master research keeps PostgreSQL 16 as the system of record and replaces any cache-aside design with an in-process snapshot replicated from Kafka:

- **PostgreSQL** gives one transaction for a change with its outbox and audit rows, a gap-free commit-ordered policy version through one counter row locked in the writing transaction (`iam_policy_epoch`, created by Story 1.1), conditional writes, consistent reverse lookups, constraints, multi-MiB documents, and local testing that meets the coverage and mutation gates.
- **DAX** is rejected because it cannot be tested locally or in CI (VPC-only) and because its query cache is not invalidated by writes, so no revocation bound can be guaranteed; **DynamoDB** without DAX lacks a gap-free global version and atomic large changes, and either option would change protected PostgreSQL-specific configuration.
- **No shared cache for policy**: a Valkey round trip costs far more than the in-process decision, and asynchronous replication or eviction can lose a revocation. Valkey is used later for rate-limit counters only.
- **Revisit triggers**: administrative write rates near the single-counter ceiling (about 100 to 500 writes per second, ESTIMATE), or a requirement PostgreSQL cannot meet.

> Assumption: The data-store decision is PostgreSQL as the source of truth and Kafka-fed in-process snapshots for reads; nothing uses DynamoDB, DAX or a shared cache for authorization data. ADR 0014 (Story 1.1) records it.

## 9. Dependencies and Protected Changes

The gateway needs one protected allow-list change, recorded in ADR 0023: the delta listed in `architecture.md` section 3.1 (application dev-only `criterion`; infrastructure `arc-swap`, `bytes`, `http`, `http-body-util`, `hyper`, `hyper-rustls`, `hyper-util`, `jsonwebtoken`, `krafka`, `matchit`, `rand`, `redis`, `rustix`, `rustls`, `rustls-pki-types`, `serde`, `serde_json`, `sha2`; infrastructure dev-only `aws-lc-rs`, `criterion`, `krafka`). The owner approved it on 2026-11-21. It is applied in a later feature, before Story 2.3 of the master plan, in a pull request carrying the `approved-config-change` label applied by a maintainer.

Rules that bind Epic 1:

- The phase-0 spikes put `krafka`, `jsonwebtoken`, `criterion` and `aws-lc-rs` only as dev-dependencies of `crates/service`, so they need no allow-list change.
- `openssl-sys` stays banned by `deny.toml`; every added crate must pass `make.check_security` (licences, advisories, bans, sources) and `make.unused_dependencies`.
- The `rsa` crate is not used: it carries RUSTSEC-2023-0071 with no patched release. Test RSA keys come from `aws-lc-rs` at run time, so no key is committed and the protected `.gitleaksignore` stays untouched.
- `rdkafka`, the documented Kafka fallback, needs librdkafka (a C library) and a lift of the `openssl-sys` ban or a non-OpenSSL build: an owner-approved build change and dependency-policy exception (section 15).
- The mutation-matrix resize that Story 1.8 may request alters the protected `tests/CLI/bats/ci_scripts.bats`; it is a separate protected change, not covered by the ADR 0023 approval.

## 15. Kafka Client and the krafka Risk

### 15.1 Precedent in the organisation

Only `notification-service` uses Kafka today: `krafka =0.32.0` pinned, `default-features = false` with the `rustls-aws-lc-rs` feature, behind three domain ports; one single-partition topic, no consumer group, position in memory, `read_committed`. Its ADR rejected `rdkafka` because `deny.toml` bans OpenSSL and the builder image has no C toolchain, and it names krafka's weakness: one author, pre-1.0, breaking changes in minor releases. IAM reuses the client, the exact pin and the port style, but must fail closed where Notification service only flips readiness.

### 15.2 Rust Kafka clients (crates.io, 2026-11-21)

| Client | Reading |
| --- | --- |
| `krafka` 0.32.0 (pure Rust, MIT OR Apache-2.0) | Group-less consumer, idempotent and transactional producer (per its README), rustls TLS, SASL. **Chosen (owner decision D14a)**, with a phase-0 spike first |
| `rdkafka` 0.40.0 (C librdkafka) | Most mature; needs a C library and OpenSSL by default, which `deny.toml` bans. Documented fallback with an owner-approved build change and exception |
| `rskafka`, `kafka`, `samsa` | Lack consumer groups or transactions, or are stale or too young; not recommended |

Risk acceptance for krafka: exact pin `=x.y.z`, a port abstraction (later epics), the in-memory `test-broker` (dev-dependency only) for fault injection, and a soak against a real broker before each version bump.

### 15.3 Capabilities to verify in the spike

Phase-0 spike stories verify through krafka's public API, against its test broker and a real KRaft broker, every capability the freshness guarantee relies on, before that guarantee is declared unconditional. The twelve capabilities and their stories are listed in `architecture.md` section 20.4: headers on null-value records; group-less assignment with `read_committed`, the last stable offset, out-of-range detection and reseek after reconnect; metadata addressed to a chosen broker with the leader epoch; `ListOffsets` with `current_leader_epoch` (KIP-320) and the KIP-207 errors; `DescribeConfigs` and `DescribeAcls`; idempotent producing; transactions and relay fencing; consumer groups; SASL SCRAM-SHA-512 over TLS with a custom root CA; fault injection; bootstrap read rate; follower fetching (recorded only). Must-pass: capabilities 1 to 6 and 9.

> Assumption: The spike results go to `docs/spikes/phase-0.md` and ADR 0026. If a must-pass capability fails and value framing with strict mode is not chosen, the fallback is another Kafka client (`rdkafka`), not an external cache, because the replication conditions do not depend on where the cache lives.

> Assumption: The authorizer property `allow.everyone.if.no.acl.found` lies outside the broker configuration definition and may not be returned by `DescribeConfigs`; Story 1.3 records whether it is, and the fallback (a negative probe with a principal that has no ACL, or reliance on the Strimzi `Kafka` resource plus a Bats check) when it is not.

## 17. Benchmark Targets (summary)

All figures are targets or estimates; nothing has been measured on VilnaCRM code or hardware.

| Item | Figure | Status |
| --- | --- | --- |
| Warm REST residence in the gateway | p95 ≤ 0.5 ms, p99 ≤ 1 ms on the hottest pod at ≤ 60 % CPU (NFR-33) | target; estimate p50 0.09 ms, p95 0.20 ms, p99 0.45 ms |
| First-seen token residence | p99 ≤ 1.2 ms (NFR-33) | target; RS256 verify cost is the unknown Story 1.6 measures first |
| GraphQL document parse | Off-worker parse above 8 KB; corpus 1 to 64 KiB | Story 1.6 measures parse cost per size |
| Bootstrap read rate | ≥ 100 MB/s from the compacted state topic | target; Story 1.5 records a compose-host measurement |
| Bootstrap to fresh | Single joiner ≤ 30 s at first-release size and 1M users (NFR-37) | target; estimate 3 to 20 s |

Spike and bench results are recorded with the host and CPU model and are never gate values; the EKS benchmarks of Story 16.7 are the real proof.

## 19. Owner Decisions That Bind This Feature

| Id | Decision | Date |
| --- | --- | --- |
| D14a | krafka is the Kafka client, with a spike first; `rdkafka` stays the fallback | 2026-11-21 |
| D19 (default) | The gateway code lives as modules inside the `authorization/iam` crates | 2026-11-21 |
| ADR 0023 | The protected allow-list change of `architecture.md` section 3.1 is approved; protected files still need the `approved-config-change` label, applied by a maintainer, on the pull request that changes them | 2026-11-21 |
| D1, D2, D3, D4, D6 (part), D7, D8, D9, D13, D14b, D15 | Shape the later epics (Kafka for User service events, `T_hard` 15 s now and 5 s target, Valkey for rate limits, 1,000 rps first release, Notification service tails `iam.events.v1`, streams in phase 1, TLS in the pod, Loki for the access log, EKS with Strimzi) | 2026-11-21 |

## 20. Open Decisions Relevant to This Feature

| Item | Default |
| --- | --- |
| Agreement to run diff mutation runs on pushes (Story 1.8) | Recorded on 2026-11-22: agreed |
| Protected resize of the mutation matrix to 16 shards of 60 mutants (Story 1.8) | Not approved: recorded as a request in `docs/operations.md` |
| The Kafka client decision after the spikes (Story 1.7) | krafka accepted if capabilities 1 to 6 and 9 pass; otherwise the run stops for an owner choice |

## Summary of the Whole Product

The master plan turns `api-gateway-service` into VilnaCRM's API gateway with identity and access management built in: `iam-gateway` terminates TLS, verifies User service RS256 tokens offline, authorizes every REST operation and GraphQL field coordinate from an in-process policy snapshot and proxies to the upstream services (WebSocket, SSE and subscriptions included); `iam-control` owns PostgreSQL, serves the management API with REST and GraphQL parity, publishes policy state through a fenced relay to one ordered Kafka topic, and consumes User service revocation events. A pod allows only while its snapshot carries a freshness proof younger than `T_hard`. Logs go to a hash-chained audit table and to Loki; rate limits to Valkey; deployment to AWS EKS. Epic 1 lays the foundation and removes the biggest technical risk (the Kafka client) before any of that is built.
