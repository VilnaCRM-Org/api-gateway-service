# Architecture: Scaffold the IAM Context and Run the Phase-0 Spikes

| Field | Value |
| --- | --- |
| Bundle | `specs/8-iam-scaffolding-and-spikes/` |
| Issue | `#8` "Scaffold the IAM context and run the phase-0 spikes" (VilnaCRM-Org/api-gateway-service) |
| Date | 2026-11-22 |
| Inputs | `research.md`, `product-brief.md`, `prd.md` of this bundle; the master architecture `specs/0-iam-authorization-service/architecture.md` (iam-service checkout, 2026-11-21) |
| Bounded context | `authorization/iam` (absent from `[workspace].members`; Story 1.1 scaffolds it) |

This document places what Epic 1 builds into the layers of one bounded context and into the template's composition root, and states the spike plan that verifies the Kafka client before later features depend on it. It is cut from the master architecture: sections keep the master's numbers (so `epics.md` citations such as "section 19" and "section 20" stay valid) and the numbering therefore has gaps. The section "Target architecture (later epics)" summarises where the context is heading; it is orientation only and not part of this feature. Requirements are cited by their PRD identifiers; gates by their `make.*` key. Every performance figure is labelled **ESTIMATE**, **target** or **CONFIG**; nothing here has been measured yet.

## Tech Stack

- Rust toolchain 1.99.1 (channel from `rust-toolchain.toml`), edition 2024
- Workspace crates used: `shared-domain`, `shared-application`, `shared-infrastructure`, `health-check-domain`, `service`, `test-support`, `e2e-tests`
- Workspace crates added: `iam-domain`, `iam-application`, `iam-infrastructure`
- Runtime crates used: `async-trait`, `thiserror`, `uuid`, `axum`, `async-graphql` (including its `parser` re-export), `utoipa`, `utoipa-axum`, `serde`, `validator`, `sqlx` (postgres, macros, migrate, uuid), `tokio`, `tracing`
- Test crates used: `rstest`, `proptest`, `fake`, `cucumber`, `http-body-util`, `tower`
- Dev-only crates added to `crates/service` for the spikes: `krafka` (exact version, feature `test-broker`), `jsonwebtoken` (feature `aws_lc_rs`), `criterion`, `aws-lc-rs` (already in the dependency graph)

## Constraints

(a) Commit convention: commit each story with the hooks active as `<type>(#8): story N.M <title>` (type one of feat, fix, refactor, build, chore, ci, docs, style, perf, test). Stay on the branch the plugin checked out and never commit on `main`; never push, the plugin command pushes; never bypass a hook.

(b) Story dispatch: a story whose `Depends on:` stories are done is independent.
When the rust-backend-sdlc:rust-implementer agent is available, independent stories may run as parallel subagents under the DB rule; otherwise implement stories sequentially under the same DB rule.
DB rule: parallel agents run only the DB-free targets `make.format` (make format), `make.lint_code` (make lint-code), `make.unit_tests` (make unit-tests), `make.architecture` (make architecture) and `make.complexity` (make complexity); one serialized verify step at a time runs the DB-backed targets `make.setup_test_db` (make setup-test-db), `make.integration_tests` (make integration-tests), `make.tests_with_coverage` (make tests-with-coverage), `make.e2e_tests` (make e2e-tests) and `make.sqlx_prepare` (make sqlx-prepare). A target that reads not available is skipped and reported.

- Scope: Epic 1 only (stories 1.1 to 1.8). Story 1.1 runs first and alone; the spike stories add tests, never production code that uses krafka.
- Change no protected file (architecture.toml, deny.toml, clippy.toml, make/gates.mk, .cargo/mutants.toml, tests/CLI/bats/, protected scripts). The ADR 0023 allow-list change is owner-approved (2026-11-21) but belongs to a later feature. Story 1.8 applies the mutation-matrix resize only after a separate owner-approved protected change with the approved-config-change label set by a maintainer; otherwise it records the request.
- krafka, jsonwebtoken (aws_lc_rs), criterion and aws-lc-rs are dev-dependencies of crates/service only, each version declared once in [workspace.dependencies]; never the rsa crate; openssl-sys stays banned.
- Time only through the Clock port, identifiers only through UuidGenerator; no mod.rs; no unwrap, expect, panic or indexing on production paths.
- Never add #[allow], #[mutants::skip], #[coverage(off)] or a coverage exclusion; meet 100% coverage, zero surviving mutants and the complexity limits with code and tests.
- Migration create_iam_policy_epoch: one reversible pair via make create-migration, reviewed down migration, one rollback round trip when an operator allows it (make migrate-rollback is an ask rule), else recorded not run (ask rule) with make validate-sqlx-metadata passing; commit regenerated .sqlx/ in the same story.
- Spike and benchmark figures are host-specific measurements, never gate values; benches run only through the service target bench-spikes in make/service.mk, documented in docs/make-targets-service.md.
- Keep the crates/service integration suite within 15 s on the CI runner (section 19); the spike modules leave in Story 1.7.
- Leave some-module and the template Makefile untouched; never change lib.rs. Add a synchronised file (docker-compose.yml, crates/service/tests/integration/main.rs, .github/workflows/tests.yml) to .templatesyncignore in the story that first changes it, and extend the seam-check test.
- Local runs on the developer machine: host ports 8080, 8081 and 18081 are taken, so set APP_PORT=28081 and STRUCTURIZR_PORT=28080 (and a free LOAD_TEST_APP_PORT for targets that start the isolated stack).

## 1. Context Map and System Context

### 1.1 Systems around IAM (target, abbreviated)

| System | Relationship to IAM | Touched by this feature |
| --- | --- | --- |
| Clients (CRM SPA, website, partners) | Send every API request through `iam-gateway` once the later epics land | No |
| User service | Issues the RS256 tokens IAM verifies offline; publishes session events to `user.events.v1` | Indirectly: Story 1.6 benchmarks RS256 verification; Story 1.5 proves the consumer-group capability |
| Notification service | Tails `iam.events.v1` | No |
| PostgreSQL 16 | IAM's system of record, used by `iam-control` only | Yes: `iam_policy_epoch` (Story 1.1) |
| Kafka (Strimzi in production; a single-node KRaft broker in compose) | Carries `iam.policy.state.v1`, `iam.events.v1`, `user.events.v1` | Yes: spike tests against the compose broker and krafka's `test-broker` (Stories 1.2 to 1.5) |
| Valkey, Loki, Kubernetes API, AWS NLB | Rate-limit counters, access log, discovery, L4 entry | No |

### 1.2 Context map

- **IAM** is the authorization context and, in the target, VilnaCRM's API gateway. In this feature it owns only the policy epoch.
- **User service to IAM** is conformist with an anticorruption layer inside IAM (`JwtAccessTokenVerifier`, `KrafkaUserEventSource`, both later). Nothing of User service's wire format leaks past `iam-infrastructure`.
- **IAM to the platform** (Kafka, Valkey, Loki, Kubernetes API) runs through IAM-owned ports with infrastructure adapters, so the domain and application layers name no platform product. The spikes of this feature test the Kafka client directly in `crates/service/tests` and define no port yet.

## 3. Bounded Context and Crates

> Assumption: IAM is one bounded context, `authorization/iam`, with the gateway code as modules inside its three crates (owner item D19, default). A separate `gateway` context could not depend on `iam`, because the architecture gate accepts only the `shared` key under `[contexts]`. The group `authorization` keeps the context out of the template-synchronised `company-subdomain` group. ADR 0013 records this.

| Crate (package) | Path | Layer | Modules added by this feature |
| --- | --- | --- | --- |
| `iam-domain` | `crates/authorization/iam/domain` | domain | `value_object/` (`PolicyVersion`, `PolicyDigestValue`, `LogEpoch`, `RelayEpoch`, `PolicyEpoch`), `port/` (`PolicyEpochRepository`), `error.rs` (`InvalidIamValue`) |
| `iam-application` | `crates/authorization/iam/application` | application | `command/` (empty), `query/` (`GetPolicyEpochQueryHandler`), `subscriber/` (documented as empty), `error.rs` (`IamError`), `http.rs` (`IamState`, `router()`), `http/dto.rs`, `http/handler.rs`, `graphql.rs` (`IamQuery`, `IamMutation`) |
| `iam-infrastructure` | `crates/authorization/iam/infrastructure` | infrastructure | `persistence.rs` (`PgPolicyEpochRepository`), `tests/integration/{main,repository,migration}.rs` |
| `service` | `crates/service` | composition root | `bootstrap.rs`, `http.rs`, `openapi.rs` wiring; dev-only spike tests `tests/integration/kafka_spike/` (removed in Story 1.7), `tests/integration/template_seams.rs`, `benches/` |
| `test-support` | `tests/support` | test support | `FakePolicyEpochRepository` (`new()`, `failing()`), policy-epoch fixture |
| `e2e-tests` | `tests/e2e` | e2e | `steps/iam.rs`, `world.rs` changes; `features/iam.feature` |

Dependency edges (each one becomes a `workspace.dsl` relationship, section 18):

- `iam-domain` depends on `shared-domain`.
- `iam-application` depends on `iam-domain`, `shared-domain` and `shared-application`.
- `iam-infrastructure` depends on `iam-domain`, `shared-domain` and `shared-infrastructure`.
- `service` depends on all three IAM crates and on `health-check-domain` (already present).
- `test-support` depends on `iam-domain` (dev-only for the IAM application and infrastructure crates).

Application and infrastructure never depend on each other. No `[contexts]` change and no change to the `shared-*` crates. The `[workspace.dependencies]` path entries for the three crates are added at first use, as the unused-dependency gate requires. Module layout follows the template: one file plus a sibling directory per module (no `mod.rs`), unit tests in a sibling `tests.rs`, integration tests in `tests/integration/{main,...}.rs` of the crate. The name rules are checked before scaffolding: `authorization` and `iam` match `^[a-z][a-z0-9]*(-[a-z0-9]+)*$`, and `iam` is not one of the scaffolder's reserved names (`shared`, `service`, `xtask`, `test-support`, `e2e-tests`).

### 3.1 Allow-list delta (ADR 0023, owner-approved 2026-11-21, applied in a later feature)

No story of this feature edits `architecture.toml`; the spikes use dev-dependencies of `crates/service`, whose allow-list is `["*"]`. The delta is listed here so implementers know the target and do not place crates where the current lists forbid them:

- Domain `external`: unchanged (`async-trait`, `thiserror`, `uuid`).
- Application `external`: unchanged; `dev_external`: add `criterion`.
- Infrastructure `external`: add `arc-swap`, `bytes`, `http`, `http-body-util`, `hyper`, `hyper-rustls`, `hyper-util`, `jsonwebtoken`, `krafka`, `matchit`, `rand`, `redis`, `rustix`, `rustls`, `rustls-pki-types`, `serde`, `serde_json`, `sha2`.
- Infrastructure `dev_external`: add `aws-lc-rs`, `criterion`, `krafka`. The `rsa` crate is not requested (RUSTSEC-2023-0071, no patched release); Story 1.6 confirms that `aws-lc-rs` passes `make.check_security`.
- Not requested for infrastructure: `tokio`, unless spikes 1.2 to 1.5 show that krafka's public API exposes `tokio` types; ADR 0026 then records it and a further owner-approved change is needed.
- The change is applied before Story 2.3 of the master plan, in a pull request with the `approved-config-change` label applied by a maintainer. If it were withdrawn, the affected adapters move into the composition root behind the same ports.

## 4. Domain Layer (`iam-domain`, Epic 1 slice)

Allowed dependencies: `async-trait`, `thiserror`, `uuid`, `shared-domain` (NFR-5). No `serde`, no clock, no crypto, no async runtime.

| Component | Kind | Rules |
| --- | --- | --- |
| `PolicyVersion` | value object | Non-negative `i64`, gap-free and commit-ordered; the seeded value is 0 |
| `PolicyDigestValue` | value object | Exactly 16 bytes; the seeded value is all zeros; construction from any other length is an `InvalidIamValue` violation |
| `LogEpoch`, `RelayEpoch` | value objects | Non-negative `i64` counters |
| `PolicyEpoch` | value object | Policy version, digest, log epoch, relay epoch and catalogue epoch, built only from valid parts |
| `PolicyEpochRepository` | port (`Debug + Send + Sync`, `#[async_trait]`) | `current() -> Result<PolicyEpoch, RepositoryError>`; reads the single row |
| `InvalidIamValue` | error enum | One variant per violated rule, with `property_path()` and `code()`, following `InvalidExampleApiResource` |
| `RepositoryError` | port error | `NotFound`, `Unavailable(BoxError)` in this slice (later epics add `AlreadyExists` and `Conflict`) |

Value objects follow the template pattern: private fields, a validating constructor, accessors, no panics. Unit tests in sibling `tests.rs` use table-driven `rstest` cases and `proptest` for the round trip of each value object.

## 5. Application Layer (`iam-application`, Epic 1 slice)

Allowed crates: `async-graphql`, `async-trait`, `axum`, `futures-util`, `humantime`, `serde`, `thiserror`, `tokio`, `tracing`, `utoipa`, `utoipa-axum`, `uuid`, `validator`.

### 5.2 Queries

`GetPolicyEpochQuery` and `GetPolicyEpochQueryHandler` read the current epoch through `PolicyEpochRepository`, registered on the template's `QueryBus` by the composition root. No REST route or GraphQL field calls it in this feature.

### 5.5 Application error enum

One enum, `IamError`, for the whole context, with `impl From<IamError> for Problem` in `error.rs`, built with the public `Problem::new(status)` and `with_detail` of `shared-application`; no synchronised shared file changes. In this slice it needs `NotFound` (404) and `Storage(BoxError)` (500 through `Problem::internal`, which logs the chain once); later epics add the remaining variants (`Invalid`, `Unauthenticated`, `Forbidden`, `Conflict` and the precondition and dependency variants) with their GraphQL codes.

### 5.6 Background task loops (rule for every loop)

**Mutation rule for loops (NFR-2).** cargo-mutants counts a timed-out mutant as surviving, and `exclude_re` is protected. Every loop is therefore a pure step function `(state, input) -> (state, actions)` in the domain or application layer, unit-tested directly; the async task or OS-thread shell only receives inputs, calls the step and performs its actions, with no branching of its own; every test that drives a shell waits with a bound (`recv_timeout`, `tokio::time::timeout`), so a mutant that would hang fails instead. This feature adds no production loop; the rule applies to any helper loop a story writes, and to every task loop of the later epics.

### 5.7 Interface modules

- `http.rs` with `IamState` (`command_bus`, `query_bus`, `uuid_generator`, `clock`), exposed through `FromRef`, and `router<S>() -> OpenApiRouter<S>` with no route yet; `http/dto.rs` and `http/handler.rs` hold the extractor-check test that every later handler must satisfy (only `ApiPath`, `ValidatedQuery`, `ValidatedJson` and `ApiJson`).
- `graphql.rs` with `IamQuery` and `IamMutation` (`#[Object]`), not merged into the schema until the first operation exists (Story 2.8 of the master plan), because an object type without fields is not valid GraphQL.
- `subscriber/` holds no subscriber: durable reactions will go through the outbox.

## 6. Infrastructure Layer (`iam-infrastructure`, Epic 1 slice)

Allowed crates today: `async-trait`, `aws-config`, `aws-sdk-sqs`, `moka`, `sqlx`, `thiserror`, `tracing`, `uuid` (dev-only: `aws-smithy-mocks`, `rstest`, `tokio`). IAM uses neither `aws-config` nor `aws-sdk-sqs`.

### 6.1 Repository (PostgreSQL through `sqlx`)

`PgPolicyEpochRepository` follows `PgExampleApiResourceRepository`: a compile-time checked `sqlx::query_as!`, a private `Row` struct, a `translate(sqlx::Error)` that maps everything to `Unavailable` (and a missing row to `NotFound`), and `restore(row)` through the value objects; a stored digest that is not 16 bytes is reported as `Unavailable`, never panics. Integration tests in `tests/integration/{repository,migration}.rs` run against the real PostgreSQL container and prove the seeded row, the `CHECK (id = 1)` constraint and the down migration's effect.

### 6.2 Kafka adapters (later epics; verified by the spikes here)

No Kafka adapter is built in this feature. The spikes verify, through krafka's public API, the capabilities that the later adapters `KrafkaPolicyLogProducer`, `KrafkaPolicyLogTail`, `KrafkaPolicyLogProbe`, `KrafkaTopicInspector` and `KrafkaUserEventSource` rely on (section 20.4). All Kafka adapters will authenticate with SASL SCRAM-SHA-512 over TLS trusting the Strimzi cluster CA, with `PLAINTEXT` only in `dev` and `test`.

> Assumption: krafka passes the phase-0 capabilities of section 20.4. If a must-pass capability fails, Story 1.7 records it and the run stops for an owner decision before any Kafka-dependent feature; `rdkafka` is the documented fallback and needs an owner-approved build change and an `openssl-sys` exception (ADR 0026). If the consumer-group capability fails, `iam-control` will consume `user.events.v1` by manual assignment under the relay's advisory lock and store offsets in PostgreSQL in the revocation transaction.

## 7. Composition Root and Run Modes (Epic 1 slice)

### 7.1 Wiring

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

### 7.2 Run modes

Only `service serve` (the template server, later `iam-control`) is wired in this feature. `service gateway`, `iam-bootstrap` and `drain` are later epics.

## 13. Data Model and Migrations (Epic 1 slice)

| Table | Key columns | Constraints | Purpose | Story |
| --- | --- | --- | --- | --- |
| `iam_policy_epoch` | `id smallint` (always 1), `version bigint`, `digest bytea` (16 bytes, initial zeros), `log_epoch bigint`, `relay_epoch bigint`, `catalog_epoch bigint`, `updated_at timestamptz` | `CHECK (id = 1)`; one seeded row | Gap-free policy version, state digest, log and relay epochs; its row lock will serialise versioned writes in later epics | 1.1 |

Migration `create_iam_policy_epoch`: a reversible pair created with `make.create_migration` (timestamp assigned at creation), the up migration creating and seeding the table, the down migration dropping it. Later migrations (audit log, outbox, idempotency keys, change receipts, revocations, roles, assignments, specifications, task state, bulk operations, gateway configuration, token-lifetime floor) belong to later epics in the master's order; no foreign key will point from an earlier table to a later one. The template's `example_api_resources` table and migration stay untouched.

## 18. Architecture Model (`workspace.dsl`) Changes (Epic 1 slice)

- Components: group `Authorization/Iam` with `Authorization/Iam/Domain`, `/Application` and `/Infrastructure`, holding `iamDomain` ("iam-domain"), `iamApplication` ("iam-application") and `iamInfrastructure` ("iam-infrastructure"), tagged by layer, following the existing `CompanySubdomain/SomeModule` group.
- Internal relationships, one per workspace dependency edge: `iamDomain -> sharedDomain`; `iamApplication -> iamDomain`, `iamApplication -> sharedDomain`, `iamApplication -> sharedApplication`; `iamInfrastructure -> iamDomain`, `iamInfrastructure -> sharedDomain`, `iamInfrastructure -> sharedInfrastructure`; `compositionRoot -> iamDomain`, `compositionRoot -> iamApplication`, `compositionRoot -> iamInfrastructure`.
- The system rename to "IAM API gateway", the people, external systems and containers (`gateway`, `control`, `database`, `kafka`, `valkey`, `loki`, `loadBalancer`, `kubernetesApi`) are applied by Story 16.9 of the master plan, not here.
- Gate: `make.validate_architecture_model` checks one component per crate and one relationship per internal dependency edge.

## 19. Test Strategy

| Layer or surface | What is tested in this feature | How | Key |
| --- | --- | --- | --- |
| `iam-domain` | The five value objects, `InvalidIamValue` codes and property paths | Table-driven `rstest`; `proptest` round trips | `make.unit_tests` |
| `iam-application` | `GetPolicyEpochQueryHandler` with `FakePolicyEpochRepository::new()` and `failing()`; `IamError` to `Problem` mapping; the extractor-check test | Unit tests in sibling `tests.rs` | `make.unit_tests` |
| `iam-infrastructure` | `PgPolicyEpochRepository`; the migration's seeded row, constraint and down migration | Integration tests against real PostgreSQL; rollback round trip when an operator allows it | `make.setup_test_db`, `make.integration_tests`, `make.sqlx_prepare` |
| `crates/service` | Wiring and the three `Adapters` literals; the Kafka spike modules (capabilities 1 to 11) against the compose broker and `test-broker`; the seam check `template_seams.rs` | Unit and integration tests of the composition root | `make.unit_tests`, `make.integration_tests` |
| End to end | Smoke scenario: the service starts with the IAM context wired and every template health dependency reported | `features/iam.feature`, `tests/e2e/steps/iam.rs` | `make.e2e_tests` |
| Benchmarks (outside `make ci`) | RS256 verify with one and three keys; GraphQL parse at 1, 5, 8 and 64 KiB | `criterion` benches in `crates/service/benches/` | `make.bench_spikes` |
| Coverage and mutation | 100 % lines and functions; zero surviving and timed-out mutants on changed code; the mutation workflow starts the compose `kafka` service | Template gates, no exclusions | `make.tests_with_coverage`, `make.mutation_tests_diff` |
| Static and repository gates | Formatting, clippy and rustdoc, layer rules, complexity, crate isolation, unused dependencies, dependency policy, invariants, Bats | Template gates | `make.format`, `make.lint_code`, `make.architecture`, `make.complexity`, `make.check_crate_isolation`, `make.unused_dependencies`, `make.check_security`, `make.validate_invariants`, `make.bats` |
| Contracts | Snapshots regenerated and unchanged (no IAM operation yet) | Template gates | contract gates |

**Mutation runtime budget (NFR-2).** The template caps the matrix in `scripts/ci/mutation-plan.sh` at 8 shards of 150 mutants (`per_shard=150`, `max_shards=8`), each shard has `timeout-minutes: 45`, and the protected `scripts/check-invariants.sh` forbids a longer timeout. Every mutant reruns its crate's whole test suite, and every non-pull-request push runs `make mutation-tests` over the whole workspace. 150 mutants per shard fit in 45 minutes only if one mutant, build and crate suite together, takes about 18 s (ESTIMATE). The plan therefore sets these rules:

- Budget: the integration suite of `iam-infrastructure` and of `crates/service` each finishes in at most 15 s on the CI runner while the matrix stays at 150 mutants per shard, and in at most 30 s once the owner approves the resize below (targets, measured from Story 1.2 on and printed by `make.integration_tests`). Every story that adds integration tests to either crate keeps its suite inside the budget before it closes.
- Most broker tests run against krafka's in-process `test-broker`; the compose broker is kept for the few tests that need real log semantics (transactions, compaction, consumer-group rebalance). The Kafka spike modules leave `crates/service/tests` in Story 1.7, once their results are recorded.
- Story 1.8 changes the non-pull-request step of the mutation shard job in `tests.yml` from `make mutation-tests` over the whole workspace to `make mutation-tests-diff` against the previous commit of the pushed branch; `scripts/ci/mutation-plan.sh` is unchanged, so its shard count for a push stays an over-estimate capped at 8 and each shard runs its part of the diff. This needs the owner's agreement but no protected file. Resizing the matrix to 16 shards of 60 mutants in `scripts/ci/mutation-plan.sh` (not protected itself, template-synchronised) breaks the assertions of the protected `tests/CLI/bats/ci_scripts.bats`, so it is a second protected change that waits for owner approval; with it, about 960 mutants per diff run at roughly 30 s each fit (ESTIMATE).
- Fallback when a story still exceeds the budget: split the story so that its changed code fits the matrix (8 × 150 mutants at 18 s, or 16 × 60 at 30 s after the resize), move further tests to `test-broker`, and, if that is not enough, stop and report to the owner. The plan never raises a shard timeout above 45 minutes, never adds an exclusion and never deletes tests to fit.

Testability rules (NFR-4): time and identifiers come from injected ports; `clippy.toml` already disallows `Instant::now` and `SystemTime::now` outside the composition root; benches and spike tests generate their keys and certificates at run time, so nothing secret is committed and the protected `.gitleaksignore` stays untouched.

## 20. Performance Targets and Proof Plan (Epic 1 slice)

### 20.3 Requirement targets touched by the spikes

| Requirement | Target (unmeasured) | This feature records | Proved by (later) |
| --- | --- | --- | --- |
| NFR-33 Gateway residence latency | Warm REST p95 ≤ 0.5 ms, p99 ≤ 1 ms on the hottest pod at ≤ 60 % CPU; first-seen token p99 ≤ 1.2 ms | RS256 verify and GraphQL parse medians and p99 per operation, host-labelled (Story 1.6) | Story 16.7 |
| NFR-36 Enforced staleness bound | No allow on a proof older than `FRESHNESS_HARD_BOUND` (15 s now, 5 s target); conditional until confirmed | Pass or fail of capabilities 3, 4, 5 and the 3-broker observations (Story 1.3) | Story 9.5, Story 16.8 (T14, T15) |
| NFR-37 Bootstrap to fresh | Single joiner ≤ 30 s at first-release size and at 1M users | Group-less read rate from a 200 MB topic next to the 100 MB/s target, compose host only (Story 1.5) | Story 16.7 (T8) |

### 20.4 Phase-0 spikes and decision rules

Spike stories put `krafka` (with `test-broker`), `jsonwebtoken` and `criterion` only as dev-dependencies of `crates/service`, so they need no allow-list change. Findings go to `docs/spikes/phase-0.md`.

| Capability | Spike story |
| --- | --- |
| (1) Produce and read headers on null-value records; (2) no-group `assign`, `read_committed` and the last stable offset, out-of-range detection, reseek after reconnect; (10) fault injection through `test-broker` | 1.2 |
| (3) Metadata to a chosen broker with the leader epoch; (4) `ListOffsets` with `current_leader_epoch` and the KIP-207/KIP-320 errors; (5) `DescribeConfigs` and `DescribeAcls` (multi-broker parts on a documented 3-broker compose profile outside `make ci`) | 1.3 |
| (6) Idempotent producing with `acks=all`, one request in flight, explicit partition, headers; (7) transactional producer `iam-relay` with epoch fencing | 1.4 |
| (8) Consumer group with commit after processing and rebalance; (9) SASL SCRAM-SHA-512 over TLS with a custom CA; (11) bootstrap read rate (target ≥ 100 MB/s, recorded as measured on the compose host only); (12) follower fetching (recorded only) | 1.5 |
| RS256 verify with the `aws_lc_rs` backend; the `async-graphql` parser on a representative corpus (1 to 64 KiB); results recorded as host-specific measurements, not gate values | 1.6 |
| Outcome and Kafka client decision (ADR 0026) | 1.7 |

Decision rule (Kafka client): if capabilities (1) to (6) or (9) fail, the freshness guarantee is not declared and the run stops before any Kafka-dependent feature for an owner choice between the `rdkafka` fallback (build change and `openssl-sys` exception) and value framing plus strict mode. If (7) fails, the relay-epoch header is the only relay fencing (Story 7.4). If `DescribeConfigs` does not return `allow.everyone.if.no.acl.found`, Story 7.3 uses the fallback recorded by Story 1.3. If (8) fails, `iam-control` consumes `user.events.v1` by manual assignment under the relay's advisory lock with offsets stored in PostgreSQL (Story 13.5). The data-plane, freshness, rate-limit, readiness and scale decision rules of the master plan apply to the later benchmark epics only.

## 22. Architecture Decision Records

New ADRs under `docs/adr/` (numbering continues after `0012`), indexed in `docs/adr/README.md`:

| ADR | Title | Records | Story |
| --- | --- | --- | --- |
| 0013 | IAM bounded context `authorization/iam`, with the gateway as modules inside it | One context, crate placement, why no split and why no separate gateway context (D19); Rust instead of the board's Go labels; the naming rules of `research.md` section 2.5 | 1.1 |
| 0014 | PostgreSQL as system of record and an in-process replicated policy snapshot instead of DynamoDB and DAX | Datastore comparison; why no external cache on the hot path; revisit triggers (`research.md` section 5) | 1.1 |
| 0026 | krafka as the Kafka client: phase-0 spike results and `rdkafka` fallback | Pass or fail per capability 1 to 12, the krafka version, the fallback rule of section 20.4 | 1.7 |

ADR 0023 (allow-list additions for the gateway, owner-approved on 2026-11-21) is written in the later feature that applies the change (Story 2.3 of the master plan). ADRs 0015 to 0022, 0024, 0025 and 0027 to 0031 belong to later epics.

## Target architecture (later epics)

This section is orientation only. It is not part of this feature, defines no requirement and is not traced by the review gate.

- **Topology.** One image, two run modes: `iam-gateway` (`service gateway`, data plane: TLS termination, offline token verification, REST and GraphQL authorization from an in-process snapshot, proxying, streams, rate limiting) and `iam-control` (`service serve`, control plane: PostgreSQL, the management API on REST and GraphQL with parity, the decision API, the outbox relay, the User service event consumer, Sync-Fence). Gateway pods hold no database credentials.
- **Replication and freshness.** Every versioned write bumps `iam_policy_epoch` under its row lock and writes state rows, outbox events and an audit row in one transaction. A fenced relay publishes state records to the single-partition compacted topic `iam.policy.state.v1`; every gateway pod tails it without a consumer group, assembles complete versions, checks the digest, applies to a copy-on-write snapshot and allows only while a replica-quorum freshness proof is younger than `FRESHNESS_HARD_BOUND`.
- **Crates.** The domain grows the policy kernel, gateway aggregates (`Upstream`, `Route`, `RatePolicy`), replication, revocation and bulk modules; the application grows handlers, gateway use cases and step-function task loops; the infrastructure grows the `Pg*` repositories and unit of work, the krafka adapters, the snapshot, token, Valkey, Loki and Kubernetes adapters (after ADR 0023 is applied); the composition root grows the gateway listeners and pipeline.
- **Platform.** AWS EKS with an NLB, Kafka on Strimzi, Valkey with Sentinel, Loki with Grafana Alloy; reference manifests checked by Bats. Benchmarks and fault tests run on EKS outside `make ci` (Stories 16.7, 16.8).
- **Delivery.** Epics 2 to 16 of the master plan, each a later feature with its own bundle; Kafka-dependent epics start only after ADR 0026 accepts krafka or the owner chooses the fallback.

## 24. Assumptions and Open Items

> Assumption: The issue is #8; the commit convention in `## Constraints` uses the literal `(#8)`; the default branch is `main` (profile `project.default_branch`).

> Assumption: The profile `.claude/rust-sdlc.yml` maps the ten dispatch keys to the targets of the same name (listed in `## Constraints`), all present in `make help` and `docs/make-targets.md`.

> Assumption: The gateway code lives as modules inside the `authorization/iam` crates (owner item D19, default), for the reasons in section 3.

> Assumption: The owner approved the protected allow-list change of section 3.1 (ADR 0023) on 2026-11-21; it is applied by a later feature, and no story of this feature needs it.

> Assumption: The compose Kafka broker is a single-node `apache/kafka` KRaft image pinned to an exact version, used only in `dev` and `test`; the 3-broker profile runs outside `make ci` and its results are compose-host observations.

> Assumption: The benches parse GraphQL through `async-graphql`'s `parser` re-export, so no separate `async-graphql-parser` dependency is added; if the re-export does not expose what the bench needs, Story 1.6 adds the parser crate as a dev-dependency of `crates/service` only.

Open items for the owner (none blocks the start of this feature):

1. The push-step change of Story 1.8 is agreed (2026-11-22). The protected mutation-matrix resize (`tests/CLI/bats/ci_scripts.bats`) is not approved in this feature; Story 1.8 records the request and the 15-second budget applies.
2. The phase-0 outcome (Story 1.7): krafka accepted, or an owner choice of the `rdkafka` fallback before any Kafka-dependent feature.
3. A follow-up issue, outside this plan, to remove the template's example context `company-subdomain/some-module`.
