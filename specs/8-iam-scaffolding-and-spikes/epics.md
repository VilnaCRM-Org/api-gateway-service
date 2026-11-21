# Epics and Stories: Scaffold the IAM Context and Run the Phase-0 Spikes

| Field | Value |
| --- | --- |
| Bundle | `specs/8-iam-scaffolding-and-spikes/` |
| Issue | `#8` "Scaffold the IAM context and run the phase-0 spikes" (VilnaCRM-Org/api-gateway-service) |
| Date | 2026-11-22 |
| Inputs | `research.md`, `product-brief.md`, `prd.md`, `architecture.md` of this bundle; Epic 1 of the master plan `specs/0-iam-authorization-service/epics.md` (iam-service checkout, 2026-11-21) |
| Bounded context | `authorization/iam` (packages `iam-domain`, `iam-application`, `iam-infrastructure`; absent from the live `[workspace].members`, so Story 1.1 scaffolds it) |

This file holds one epic and eight stories: Epic 1 of the sixteen-epic master plan, copied with its story text, acceptance criteria and `**Depends on:**` lines unchanged except that the commit convention uses `(#8)`. The implementation workflow implements every story of this file in one pull request, and the FR/NFR review gate traces every requirement id of this bundle's `prd.md` to test evidence in that pull request. Epics 2 to 16 are later features with their own bundles; references in the story text to later stories (2.8, 7.3, 7.4, 13.5) or to Epic 7 are context only, and no story here depends on them.

Each story is sized for one implementation session, follows the layer order domain, then application, then infrastructure, then the `crates/service` wiring, names the requirements it covers (`FR-n`, `NFR-n`) in its `Covers` line and names the gates that prove it by their `make.*` keys: every behavioural criterion ends with the gate that proves it, and a closing criterion lists the full gate set of the story. The resolved target behind each of the ten dispatch keys is listed once, in `## Constraints` of `architecture.md`. A story is committed as `<type>(#8): story N.M <title>`.

The story that adds a migration (Story 1.1) writes and reviews its down migration, runs the rollback round trip when an operator allows it (the rollback target is an `ask` rule in `.claude/settings.json`, so an unattended run records it as `not run (ask rule)`), passes `make.validate_sqlx_metadata` and commits the regenerated `.sqlx/` metadata. A story that adds an environment variable adds its row to `docs/environment.md` and its local defaults to `.env` and `.env.test` in the same story (Story 1.1 adds none). A story that adds a crate edge keeps `workspace.dsl` in step. Every performance figure in a story is a target or a host-specific measurement; no latency or capacity figure is a gate inside `make ci`. No story plans an `#[allow]`, `#[mutants::skip]`, `#[coverage(off)]`, a coverage exclusion, an allow-list edit or a lowered bar. Any loop is written as a pure step function `(state, input) -> (state, actions)` in the domain or application layer and unit-tested directly, with a branch-free shell and bounded waits in every test that drives it (`architecture.md` section 5.6). The story that adds a compose service the integration tests need (Kafka in Story 1.2) also makes the mutation workflow start it.

**Recurring gate sets.** Each story names its gates by their literal `make.*` keys. For reference, the recurring groups are:

- DB-free gates: `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity` (may run in parallel agents).
- Persistence gates: `make.setup_test_db`, `make.integration_tests`, `make.sqlx_prepare`, `make.validate_sqlx_metadata` (DB-backed, one serialized verify step at a time); the optional rollback round trip uses `make.migrate_rollback` then `make.migrate` only when an operator allows it.
- Kafka-backed tests: integration tests that need a broker run inside `make.integration_tests` against krafka's in-process `test-broker` by default, and against the single-node KRaft broker that Story 1.2 adds to `docker-compose.yml` only where real log semantics are needed (transactions, compaction, consumer-group rebalance); multi-broker runs use a documented compose profile outside `make ci`.
- Mutation runtime budget: every mutant reruns its crate's suite and a mutation shard may not exceed 45 minutes, so every story that adds integration tests to `iam-infrastructure` or `crates/service` keeps that crate's integration suite within 15 seconds on the CI runner, or 30 seconds once the owner approves the matrix resize of Story 1.8 (targets printed by `make.integration_tests`, `architecture.md` section 19). A story that exceeds it moves tests to `test-broker` or is split before it closes; if that is not enough it stops and reports.
- Contract gates: `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`).
- Closing gates of every story: `make.tests_with_coverage` (100% lines and functions), `make.mutation_tests_diff` (zero surviving or timed-out mutants on the changed code), and `make.e2e_tests` and `make.docs_check` whenever the story changes an operation, a variable or a document.

**Assumptions made while writing the epics:**

> Assumption: The issue is #8, so every story commit uses the literal `(#8)` and the `story N.M` subject form; this bundle is the planning bundle of Epic 1 only, derived from the master plan on 2026-11-22.

> Assumption: The profile `.claude/rust-sdlc.yml` maps every `make.*` key named here to the target of the same name with underscores replaced by hyphens, except two keys that the profile does not list: `make.bench_spikes` is the service target `bench-spikes` that Story 1.6 adds to `make/service.mk` (documented in `docs/make-targets-service.md`, as `docs/make-targets.md` requires for service targets), and `make.bats` resolves by the same naming rule to the template target `bats` (gate G16, listed by `make help` and in `docs/make-targets.md`). Stories pass `base_ref=main` to base-ref readers as written; the profile's `ci.base_ref` is `origin/main`, which the CI jobs use.

> Assumption: Every story lists Story 1.1 explicitly in its `Depends on:` line, in addition to its direct predecessors, so the story-1 rule holds without relying on transitive dependencies.

> Assumption: The scaffold story delivers the context skeleton and its first persisted slice (the policy epoch) but no public operation, because every IAM operation needs the authentication pipeline of a later feature; the first public operation (token resolution, Story 2.8 of the master plan) adds the `iam` OpenAPI tag, the `bearerAuth` scheme and the merge of the IAM GraphQL roots, since an object type without fields is not valid GraphQL and an unused tag or scheme would be a Spectral finding.

> Assumption: The owner approved the protected allow-list change of ADR 0023 (`architecture.toml`, the delta of `architecture.md` section 3.1) on 2026-11-21. No story of this feature applies it: the spike stories 1.2 to 1.6 put `krafka`, `jsonwebtoken`, `criterion` and `aws-lc-rs` only as dev-dependencies of `crates/service`, whose allow-list is `["*"]`, so they need no allow-list entry. The change is applied in a later feature before Story 2.3 of the master plan, in a pull request that carries the `approved-config-change` label applied by a maintainer.

> Assumption: The rollback target is an `ask` rule in `.claude/settings.json`; in an unattended run the rollback round trip of Story 1.1 is recorded `not run (ask rule)`, and the story closes on its reviewed down migration and `make.validate_sqlx_metadata`.

> Assumption: The phase-0 spike results gate the replication epics of the later features: Story 1.7 records krafka as accepted, or records the failed must-pass capability and stops the run for an owner decision (the `rdkafka` fallback needs an owner-approved build change and an `openssl-sys` exception) before any Kafka-dependent feature starts.

> Owner decision (2026-11-22, standing instruction to take the recommended option): the owner agrees to the push-step change of the mutation shard job, so Story 1.8 implements it. The protected matrix resize (`scripts/ci/mutation-plan.sh`, `tests/CLI/bats/ci_scripts.bats`) is NOT approved in this feature: the story takes the no-approval branch, leaves both files unchanged and records the request in `docs/operations.md`.

> Assumption: The removal of the template's example context is not a story of this feature, because the product brief and the PRD put it out of scope.

**Requirement coverage.** Every FR and NFR defined in this bundle's `prd.md` maps to at least one story, built from the `Covers` line of each of the eight stories:

| Requirement | Stories |
| --- | --- |
| FR-15 | 1.6 |
| FR-18 | 1.5 |
| FR-46 | 1.4 |
| FR-60 | 1.6 |
| FR-71 | 1.2 |
| FR-72 | 1.3 |
| FR-73 | 1.3 |
| NFR-1 | 1.1 |
| NFR-2 | 1.1, 1.8 |
| NFR-3 | 1.1 |
| NFR-4 | 1.1 |
| NFR-5 | 1.1 |
| NFR-8 | 1.1 |
| NFR-9 | 1.1, 1.2 |
| NFR-30 | 1.1, 1.7 |
| NFR-31 | 1.1 |
| NFR-33 | 1.6 |
| NFR-36 | 1.3 |
| NFR-37 | 1.5 |

## Epic 1: Scaffolding and phase-0 spikes

This epic creates the `authorization/iam` context with its first persisted slice and runs the phase-0 spikes that verify, before any gateway code depends on them, every krafka capability the replication and freshness design relies on, plus the token-verify and GraphQL parser benchmarks. It ends with the recorded Kafka client decision that gates Epic 7 onward.

### Story 1.1: Scaffold authorization/iam

As the IAM team, I want the `authorization/iam` bounded context scaffolded and wired end to end with its first persisted table, so that every later story adds behaviour to an existing, gate-green context.
Covers NFR-1, NFR-2, NFR-3, NFR-4, NFR-5, NFR-8, NFR-9, NFR-30, NFR-31.
The context is absent from the live `[workspace].members`, so this story runs first and has the test database to itself. Before C1 it re-checks the name rules (`authorization` and `iam` match `^[a-z][a-z0-9]*(-[a-z0-9]+)*$`, `iam` is not a reserved context name, and no `iam` crate directory, member path or package exists). Its first slice is the policy epoch: the `PolicyVersion`, `PolicyDigestValue`, `LogEpoch`, `RelayEpoch` and `PolicyEpoch` value objects, the `PolicyEpochRepository` port and the `InvalidIamValue` error enum (domain); `GetPolicyEpochQueryHandler`, `IamError` with its `From<IamError> for Problem` conversion, `IamState` and the IAM REST router and GraphQL root types (application); `PgPolicyEpochRepository` and the migration `create_iam_policy_epoch` (infrastructure); and the composition-root wiring of `service serve`. The IAM router and GraphQL roots expose no operation until Story 2.8.

**Acceptance Criteria:**
- **Given** the names `authorization` and `iam` pass the name rules and no `iam` crate, member or package exists in the live tree, **When** `make.new_context` runs with `group=authorization context=iam`, **Then** C1 is done: `iam-domain`, `iam-application` and `iam-infrastructure` exist under `crates/authorization/iam/`, the three member paths are registered in sorted order, and `make.architecture` and `make.check_crate_isolation` pass.
- **Given** the three crates and their dependency edges, **When** `workspace.dsl` gains the `Authorization/Iam` group with one component per crate and one relationship per workspace-internal dependency edge (including the composition root to each IAM crate), **Then** C2 is done and `make.validate_architecture_model` passes.
- **Given** the first crate that depends on each IAM crate, **When** the `[workspace.dependencies]` path entries for `iam-domain`, `iam-application` and `iam-infrastructure` are added in that change and inherited with `.workspace = true`, **Then** C3 is done and `make.check_security` and `make.unused_dependencies` pass.
- **Given** the domain crate holds `PolicyVersion`, `PolicyDigestValue` (16 bytes), `LogEpoch`, `RelayEpoch`, `PolicyEpoch` (version, digest, log epoch, relay epoch, catalogue epoch), the `PolicyEpochRepository` port and the `InvalidIamValue` enum with `property_path()` and `code()`, depending only on `async-trait`, `shared-domain`, `thiserror` and `uuid`, **When** the domain gates run, **Then** C4 is done and `make.architecture`, `make.static_analysis` and `make.complexity` pass.
- **Given** the application crate holds `command/`, `query/` with `GetPolicyEpochQueryHandler`, `subscriber/` (documented as empty because IAM events go through the outbox), `error.rs` with `IamError` and its `Problem` conversion, `http.rs` with `IamState` and `router()`, `http/dto.rs`, `http/handler.rs` with the extractor-check test, and `graphql.rs` with the `IamQuery` and `IamMutation` types, **When** the application is checked, **Then** C5 is done and `make.static_analysis` and `make.tests_with_coverage` pass.
- **Given** the infrastructure crate holds `persistence.rs` with `PgPolicyEpochRepository` and `tests/integration/{main,repository,migration}.rs`, **When** the integration tests run against the real PostgreSQL container, **Then** C6 is done and `make.tests_with_coverage` passes.
- **Given** `tests/support` declares `iam-domain.workspace = true` and offers `FakePolicyEpochRepository` with `new()` and `failing()`, a policy-epoch fixture and a sibling `tests.rs`, **When** the test-support crate is checked, **Then** C7 is done and `make.unused_dependencies` and `make.tests_with_coverage` pass.
- **Given** the reversible pair `create_iam_policy_epoch` created with `make.create_migration` (table `iam_policy_epoch` with `CHECK (id = 1)`, the columns `version`, `digest` (16 bytes, seeded with zeros), `log_epoch`, `relay_epoch`, `catalog_epoch` and `updated_at`, and its seeded row) and its reviewed down migration, **When** `make.migrate` and then `make.sqlx_prepare` run, `.sqlx/` is committed with the migration, and the rollback round trip (`make.migrate_rollback` then `make.migrate`) runs once when an operator allows it or is recorded `not run (ask rule)`, **Then** C8 is done and `make.validate_sqlx_metadata` passes.
- **Given** `crates/service` depends on the IAM crates, `bootstrap.rs` adds the policy-epoch adapter to `Adapters` and `Adapters::connect`, registers `GetPolicyEpochQueryHandler` on the query bus and builds `IamState`, `http.rs` adds `IamState` to `AppState`, `openapi.rs` nests the IAM router under `/api`, and the three `Adapters { .. }` literals in `bootstrap/tests.rs`, `http/router/tests.rs` and `tests/integration/panic.rs` use the IAM fake, while the merge of `IamQuery` and `IamMutation` into `graphql/schema.rs`, the `.data(iam_state)` call on the schema builder, the `iam` tag and the `bearerAuth` scheme are deferred to Story 2.8 because no operation exists yet, and the pinning tests `src/openapi/tests.rs` and `src/graphql/schema/tests.rs` stay unchanged and pass, **When** the composition root is tested, **Then** C9 is done and `make.tests_with_coverage` and `make.e2e_tests` pass.
- **Given** `make.generate_openapi_spec` and `make.generate_graphql_spec` regenerate both snapshots (unchanged, because no IAM operation exists yet) and `features/iam.feature` with `tests/e2e/steps/iam.rs`, its module line in `steps.rs` and the `world.rs` changes adds a smoke scenario proving the service starts with the IAM context wired and every template health dependency still reported, **When** the contract and end-to-end gates run, **Then** C10 is done and `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff` and `make.graphql_diff` (base `main`) and `make.e2e_tests` pass.
- **Given** `docs/architecture.md` lists the IAM context in its bounded-context table, `docs/requests.http` gains an IAM section, ADR 0013 (the IAM bounded context `authorization/iam`, with the gateway as modules inside it) and ADR 0014 (PostgreSQL as system of record and an in-process replicated policy snapshot instead of DynamoDB and DAX) are added and indexed, and no environment variable is new, **When** the documentation is checked, **Then** C11 is done and `make.docs_check` passes.
- **Given** the C1 to C11 work is committed as `feat(#8): story 1.1 Scaffold authorization/iam`, **When** `make.ci_preflight` (with `base_ref=main CONFIG_CHANGE_APPROVED=`), `make.ci_static_analysis`, `make.ci_tests`, `make.ci_contracts` (with `base_ref=main`), `make.ci_mutation` (with `base_ref=main`) and `make.ci_delivery` run one call each, followed by `make.validate_configuration` with `base_ref=main CONFIG_CHANGE_APPROVED=`, **Then** C12 is done: every stage passes and 0 protected files changed.

**Depends on:** none

### Story 1.2: Spike: krafka tail without a consumer group

As the IAM team, I want krafka's tail without a consumer group proven against a real broker before any gateway code depends on it, so that the replication design rests on verified client behaviour.
Covers FR-71, NFR-9.
Spike only; no production crate depends on krafka. `docker-compose.yml` gains a single-node `apache/kafka` KRaft broker service `kafka` (PLAINTEXT listener, used only in `dev` and `test`, image pinned to an exact version) and is added to `.templatesyncignore` in this story, together with `crates/service/tests/integration/main.rs`, which gains the spike module. The mutation workflow (a seam file, added to `.templatesyncignore`) starts the compose `kafka` service on every shard, because integration tests rerun for each infrastructure mutant (ESTIMATE in `architecture.md` section 19). `crates/service` gains `krafka` (exact version, feature `test-broker`) as a dev-dependency only. Integration tests in `crates/service/tests/integration/kafka_spike/` prove capabilities 1, 2 and 10 of the phase-0 rules in `architecture.md` section 20: headers on null-value records; `assign` of one partition without a group, `read_committed` and the last stable offset, out-of-range detection and reseek after reconnect; fault injection through `test-broker`. The findings, with pass or fail per capability and the krafka version, start `docs/spikes/phase-0.md`. The story also adds the seam check, `crates/service/tests/integration/template_seams.rs`, an integration test that applies the documented probe (`sed 's/#.*//' .templatesyncignore | xargs -r git ls-files -- | grep -Fx`, reimplemented in Rust) to a listed set of paths and asserts that each is covered by `.templatesyncignore`, and that inspects the workflow files for the compose services each job starts and the make targets each job calls. The protected `scripts/check-invariants.sh` checks neither, so every later story that adds a seam file or a workflow step extends this test's list.

**Acceptance Criteria:**
- **Given** a one-partition test topic on the compose broker, **When** the test produces records with the headers `iam-version`, `iam-seq`, `iam-count`, `iam-digest-after`, `iam-op`, `iam-schema`, `iam-log-epoch` and `iam-relay-epoch`, one of them with a null value, and reads them back, **Then** every header of the null-value record is returned byte-identical and the value is reported as null, proven in `make.integration_tests`.
- **Given** a reader that assigns partition 0 without a consumer group in `read_committed` mode and an open transaction injected through `test-broker`, **When** the reader fetches, **Then** it stops at the last stable offset and returns none of the uncommitted records until the transaction commits, proven in `make.integration_tests`.
- **Given** a stored position below the log start offset, **When** the reader fetches from it, **Then** krafka reports an out-of-range error to the caller and never resets the position by itself, proven in `make.integration_tests`.
- **Given** a tail in progress and the broker connection dropped by fault injection, **When** the connection is restored and the test reseeks to its in-memory position, **Then** every record is read exactly once and in order, proven in `make.integration_tests`.
- **Given** injected `OFFSET_OUT_OF_RANGE`, `NOT_LEADER_OR_FOLLOWER` and request-timeout faults, **When** the reader meets each, **Then** each surfaces as a distinguishable typed error, proven in `make.integration_tests`.
- **Given** the spike results, **When** `docs/spikes/phase-0.md` is checked, **Then** it records pass or fail for capabilities 1, 2 and 10 with the krafka version, and `make.docs_check` passes.
- **Given** the mutation workflow, **When** the seam check inspects it, **Then** every mutation shard starts the compose `kafka` service before the tests run and `.templatesyncignore` covers the workflow file, `docker-compose.yml` and `crates/service/tests/integration/main.rs`, proven in `make.integration_tests`.
- **Given** the integration suite of `crates/service` with the spike module, **When** `make.integration_tests` runs, **Then** it prints the wall time of each crate's integration suite, and the story records the baseline for `crates/service` next to the 15-second budget of `architecture.md` section 19 as a measured CI figure, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.validate_invariants`, `make.check_security`, `make.unused_dependencies`, `make.format`, `make.lint_code`, `make.integration_tests` and `make.tests_with_coverage` run, **Then** all pass and no crate other than `crates/service` (dev-dependency) names krafka.

**Depends on:** 1.1

### Story 1.3: Spike: krafka metadata, leader epochs and configuration reads

As the IAM team, I want krafka's metadata, leader-epoch and configuration requests verified, so that the freshness proof and the Kafka configuration gates can be built on them.
Covers FR-72, FR-73, NFR-36.
Spike only. Capabilities 3, 4 and 5: Metadata requests addressed to a chosen broker with the leader epoch in the response; `ListOffsets` with `current_leader_epoch` (KIP-320) and the `OFFSET_NOT_AVAILABLE`, `FENCED_LEADER_EPOCH` and `UNKNOWN_LEADER_EPOCH` errors (KIP-207); `DescribeConfigs` for the topic and the broker, and `DescribeAcls`. The spike also records whether `DescribeConfigs` on the broker returns `allow.everyone.if.no.acl.found` at all: it is an authorizer property outside the broker configuration definition and may be missing; if it is missing, ADR 0026 records the fallback that Story 7.3 then uses (a negative probe with a principal that has no ACL, or reliance on the Strimzi `Kafka` resource plus the Bats check of Story 15.4). Single-broker parts run in `make.integration_tests`; the multi-broker parts run on a documented 3-broker compose profile outside `make ci`, and their results are recorded as measured on the compose host only.

**Acceptance Criteria:**
- **Given** the compose broker, **When** the test sends a Metadata request addressed to that broker, **Then** the response names the leader and the leader epoch of partition 0 and the partition count, proven in `make.integration_tests`.
- **Given** `ListOffsets` sent with the current leader epoch, a stale epoch and a future epoch, and `OFFSET_NOT_AVAILABLE` injected through `test-broker`, **When** each request returns, **Then** the first yields the high watermark and the others surface `FENCED_LEADER_EPOCH`, `UNKNOWN_LEADER_EPOCH` and `OFFSET_NOT_AVAILABLE` as distinguishable typed errors, proven in `make.integration_tests`.
- **Given** a test topic created with `cleanup.policy=compact`, `min.insync.replicas`, `unclean.leader.election.enable=false` and `message.timestamp.type=LogAppendTime`, **When** `DescribeConfigs` reads the topic and the broker and `DescribeAcls` lists the ACLs, **Then** every value the configuration gates of FR-72 need is returned, or the missing capability is recorded as failed, proven in `make.integration_tests`.
- **Given** the 3-broker compose profile run outside `make ci`, **When** the partition leader is stopped and a new leader is elected, **Then** the spike records whether at least 2 of 3 brokers report the same new leader and epoch, and whether any broker's Metadata response was older than the leader epoch its own replica fetcher used (the point behind guarantee G4), proven in `make.integration_tests`.
- **Given** the spike results, **When** `docs/spikes/phase-0.md` is checked, **Then** it records pass or fail for capabilities 3, 4 and 5 and labels the multi-broker observations as compose-host measurements, and `make.docs_check` passes.
- **Given** the compose broker started with the `simple` authorizer and `allow.everyone.if.no.acl.found=false`, **When** `DescribeConfigs` reads the broker, **Then** the spike records whether the setting is returned and, when it is not, the chosen fallback, proven in `make.docs_check`.
- **Given** the story's changes, **When** `make.format`, `make.lint_code`, `make.integration_tests` and `make.tests_with_coverage` run, **Then** all pass.

**Depends on:** 1.1, 1.2

### Story 1.4: Spike: krafka idempotent and transactional producing

As the IAM team, I want krafka's idempotent and transactional producers verified, so that the relay can publish the state topic in order and fence a zombie relay.
Covers FR-46.
Spike only. Capabilities 6 and 7: idempotent producing with `acks=all`, one request in flight, an explicit partition, headers and lz4 compression; a transactional producer with `transactional.id` `iam-relay` and epoch fencing of a second producer.

**Acceptance Criteria:**
- **Given** an idempotent producer with `acks=all`, at most one request in flight, explicit partition 0 and lz4 compression, **When** it produces 10,000 records with retriable errors injected through `test-broker`, **Then** the partition holds every record exactly once and in order, and the returned offsets are contiguous, proven in `make.integration_tests`.
- **Given** a transactional producer with `transactional.id` `iam-relay` that has written records in an open transaction, **When** a second producer with the same id initialises, **Then** the first producer's commit is rejected with a fencing error and none of its records becomes visible to a `read_committed` reader, proven in `make.integration_tests`.
- **Given** an aborted transaction, **When** a `read_committed` reader fetches, **Then** none of its records is returned, proven in `make.integration_tests`.
- **Given** an open transaction, **When** `ListOffsets` with isolation `READ_COMMITTED` is sent before and after its commit, **Then** the first answer is the last stable offset below the transaction's first record and the second lies beyond its last record, and a producer configured with `transaction.timeout.ms` of 10 seconds that stops without committing has its transaction aborted by the broker within that timeout, proven in `make.integration_tests`.
- **Given** the spike results, **When** `docs/spikes/phase-0.md` is checked, **Then** it records pass or fail for capabilities 6 and 7, and `make.docs_check` passes.
- **Given** the story's changes, **When** `make.format`, `make.lint_code`, `make.integration_tests` and `make.tests_with_coverage` run, **Then** all pass.

**Depends on:** 1.1, 1.2

### Story 1.5: Spike: consumer group, SCRAM over TLS with a custom CA, and bootstrap read rate

As the IAM team, I want krafka's consumer groups, SCRAM authentication over TLS and bootstrap read rate verified, so that `iam-control` can consume User service events and pods can bootstrap through the Strimzi listener.
Covers FR-18, NFR-37.
Spike only. Capabilities 8, 9, 11 and 12: consumer-group membership with manual commit after processing and rebalance handling; SASL SCRAM-SHA-512 over TLS trusting a custom root CA (standing in for the Strimzi cluster CA), on a second compose listener whose certificates a fixture script generates at test time (no key is committed); the read rate from a 200 MB topic (target ≥ 100 MB/s, recorded as measured on the compose host only, not a gate); follower fetching, recorded only (later phase).

**Acceptance Criteria:**
- **Given** two consumers in one group on a three-partition test topic, **When** one consumer leaves after processing but before committing some records, **Then** the partitions are reassigned, the uncommitted records are delivered again to the remaining member, and no committed record is delivered twice, proven in `make.integration_tests`.
- **Given** the SASL_SSL listener with a CA generated at test time, **When** the client connects trusting that CA file with the right SCRAM-SHA-512 credentials, a wrong password, and an untrusted CA, **Then** the first connects and the other two fail with distinguishable typed errors, proven in `make.integration_tests`.
- **Given** a 200 MB topic on the compose broker and a documented command run outside `make ci`, **When** a reader without a group reads it from offset 0, **Then** the read rate is recorded in `docs/spikes/phase-0.md` as a compose-host measurement next to the 100 MB/s target, never as a gate value, proven in `make.docs_check`.
- **Given** the spike results, **When** `docs/spikes/phase-0.md` is checked, **Then** it records pass or fail for capabilities 8, 9 and 11 and whether follower fetching (capability 12) is available, and `make.docs_check` passes.
- **Given** the story's changes, **When** `make.format`, `make.lint_code`, `make.integration_tests` and `make.tests_with_coverage` run, **Then** all pass.

**Depends on:** 1.1, 1.2

### Story 1.6: Spike: token-verify backend and GraphQL parser benchmarks

As the IAM team, I want the RS256 verify cost and the GraphQL parse cost measured on a known host, so that the latency estimates of the gateway have a first measured reference.
Covers FR-15, FR-60, NFR-33.
Spike only. `criterion` benches in `crates/service/benches/` (`jsonwebtoken` with the `aws_lc_rs` backend and `criterion` as dev-dependencies of `crates/service` only): RS256 verify with one and with three trusted keys tried newest first, with RSA key pairs generated at bench time through `aws-lc-rs` (already in the dependency graph through the `aws_lc_rs` backend of `jsonwebtoken`), never through the `rsa` crate; `async-graphql-parser` on a representative corpus of documents from 1 to 64 KiB. The service target `bench-spikes` in `make/service.mk` (key `make.bench_spikes`) runs the benches outside `make ci`. Results are recorded as host-specific measurements with the CPU model, not as gate values; the NFR-33 figures stay targets.

**Acceptance Criteria:**
- **Given** the benches, **When** `make.bench_spikes` runs them, **Then** RS256 verify with one and three keys and parsing of the 1, 5, 8 and 64 KiB documents each report a median and a p99 per operation.
- **Given** the `aws_lc_rs` backend of `jsonwebtoken`, **When** `make.check_security` runs, **Then** it passes, no `openssl-sys` crate enters the dependency graph, and the story records whether `aws-lc-rs` key generation passes the advisory check, so that the test-key crate of ADR 0023 is `aws-lc-rs` and never `rsa` while RUSTSEC-2023-0071 is open.
- **Given** the bench sources, **When** they are inspected, **Then** no private key or token is committed; keys are generated when the bench starts, proven in `make.docs_check`.
- **Given** the results, **When** `docs/spikes/phase-0.md` is checked, **Then** it lists the CPU model and labels every figure as measured on that host and not as a gate value, and `make.docs_check` passes.
- **Given** the story's changes, **When** `make.check_security`, `make.unused_dependencies`, `make.format` and `make.lint_code` run, **Then** all pass.

**Depends on:** 1.1, 1.2

### Story 1.7: Record the phase-0 outcome and the Kafka client decision

As the owner of IAM, I want the phase-0 results and the Kafka client decision recorded in one place, so that Epic 7 starts only on verified ground and a failed capability reaches me before code depends on it.
Covers NFR-30.
ADR 0026 (krafka as the Kafka client: phase-0 spike results and `rdkafka` fallback) records pass or fail per capability 1 to 12 and the fallback rule: if capabilities 1 to 6 or 9 fail, the freshness guarantee is not declared and the owner chooses between the `rdkafka` fallback (build change and `openssl-sys` exception) and value framing with strict mode; if capability 7 fails, the relay-epoch header is the only relay fencing; if `DescribeConfigs` does not return `allow.everyone.if.no.acl.found`, Story 7.3 uses the fallback recorded by Story 1.3; if capability 8 fails, `iam-control` consumes `user.events.v1` by manual assignment under the relay's advisory lock and stores offsets in PostgreSQL in the revocation transaction. `docs/spikes/phase-0.md` is completed with the benchmark results of Story 1.6. Once the results are recorded, the spike modules under `crates/service/tests/integration/kafka_spike/` are removed, with their module line in `main.rs`, so that they no longer run for every `crates/service` mutant; the krafka dev-dependency of `crates/service` goes with them unless a remaining test uses it.

**Acceptance Criteria:**
- **Given** the results of Stories 1.2 to 1.6, **When** ADR 0026 is written and indexed, **Then** it lists every capability 1 to 12 with its outcome, the krafka version and the fallback rule above, and `make.docs_check` passes.
- **Given** every must-pass capability (1 to 6 and 9) passed, **When** the story closes, **Then** ADR 0026 is accepted and records that Epic 7 may start, proven in `make.docs_check`.
- **Given** a must-pass capability failed, **When** the story closes, **Then** ADR 0026 stays proposed, the failure and the owner's options are recorded, and the run stops for an owner decision before any story of Epic 7 starts, proven in `make.docs_check`.
- **Given** capability 7 failed while every must-pass capability passed, **When** the ADR is written, **Then** it states that Story 7.4 implements the relay-epoch fencing only, proven in `make.docs_check`.
- **Given** capability 8 failed, **When** the ADR is written, **Then** it states that Story 13.5 implements the manual-assignment fallback, proven in `make.docs_check`.
- **Given** the results recorded in `docs/spikes/phase-0.md`, **When** the spike modules are removed, **Then** `crates/service/tests/integration/kafka_spike/` no longer exists, the `crates/service` integration suite is back within the 15-second budget, and `make.integration_tests` and `make.unused_dependencies` pass.

**Depends on:** 1.1, 1.2, 1.3, 1.4, 1.5, 1.6

### Story 1.8: Fit the mutation gate to the IAM test suites

As the owner of IAM, I want the mutation gate kept attainable for crates whose every mutant reruns a broker-backed suite, so that it stays within the 45-minute shard limit as the gateway grows.
Covers NFR-2.
Prerequisite: the owner agrees to the CI change below; the agreement is recorded (2026-11-22). The fallback of `architecture.md` section 19 (split stories, move tests to `test-broker`, report) applies when a suite still exceeds the budget. Co-changes: the non-pull-request step of the mutation shard job in `.github/workflows/tests.yml` runs `make mutation-tests-diff` against the previous commit of the pushed branch instead of `make mutation-tests` over the whole workspace, still calling only a gate target of `make ci-list`; the workflow file is added to `.templatesyncignore` and to the seam check of Story 1.2; the contributor documentation records the suite budget, the shard capacity and the fallback. `scripts/ci/mutation-plan.sh` stays unchanged, so its push count is an over-estimate capped at 8 shards, each running its part of the diff. Resizing the matrix to 16 shards of 60 mutants would break the assertions of the protected `tests/CLI/bats/ci_scripts.bats`, so the story records it as a protected-change request for the owner, next to ADR 0023, and applies it only after approval (`ALLOW_PROTECTED_CONFIG_EDIT=1` and the `approved-config-change` label). Shard timeouts stay at 45 minutes and `.cargo/mutants.toml` is unchanged.

**Acceptance Criteria:**
- **Given** the mutation shard job, **When** the seam check of Story 1.2 inspects `tests.yml`, **Then** the pull-request step and the push step both call `make mutation-tests-diff`, every shard keeps `timeout-minutes: 45`, and `.templatesyncignore` covers the workflow file, proven in `make.integration_tests`.
- **Given** the changed workflow, **When** `make.validate_invariants` runs, **Then** it passes, because no timeout exceeds 45 minutes and every workflow runs only gate targets of `make ci-list`.
- **Given** the owner approved the protected resize, **When** `scripts/ci/mutation-plan.sh` sets `per_shard` to 60 and `max_shards` to 16 and `ci_scripts.bats` is updated in the same approved change, **Then** a count of 961 gives 16 shards and 120 gives 2 shards, proven in `make.bats`.
- **Given** no approval of the resize, **When** the story closes, **Then** `scripts/ci/mutation-plan.sh` and `ci_scripts.bats` are unchanged, the request is recorded in the protected-change list of `docs/operations.md`, and the 15-second suite budget stays in force, proven in `make.docs_check`.
- **Given** the documentation, **When** it is checked, **Then** it states the suite budget, the shard capacity as an estimate and the fallback, and `make.docs_check` passes.
- **Given** the story's changes, **When** `make.integration_tests`, `make.validate_invariants`, `make.bats` and `make.docs_check` run, **Then** all pass and no protected file changed without the owner's approval.

**Depends on:** 1.1, 1.2
