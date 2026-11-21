# Product Requirements Document: Scaffold the IAM Context and Run the Phase-0 Spikes

| Field | Value |
| --- | --- |
| Bundle | `specs/8-iam-scaffolding-and-spikes/` |
| Issue | `#8` "Scaffold the IAM context and run the phase-0 spikes" (VilnaCRM-Org/api-gateway-service) |
| Date | 2026-11-22 |
| Inputs | `research.md`, `product-brief.md` of this bundle; the master PRD `specs/0-iam-authorization-service/prd.md` (iam-service checkout, 2026-11-21), whose requirement ids this file keeps |

## Executive Summary

The VilnaCRM API Gateway (`api-gateway-service`, a fresh copy of the Rust service template) will become VilnaCRM's API gateway with identity and access management built in: one image running as `iam-gateway` (data plane) and `iam-control` (control plane), an in-process policy snapshot replicated from one ordered Kafka topic, offline RS256 token validation, REST and GraphQL authorization and proxying. The master plan delivers that in sixteen epics. This feature is the first of them, Epic 1, and delivers two things only:

1. **The scaffolded bounded context.** `authorization/iam` exists as three crates (`iam-domain`, `iam-application`, `iam-infrastructure`) wired into the composition root of `service serve`, with its first persisted slice, the policy epoch (`iam_policy_epoch` table, value objects, repository port and PostgreSQL adapter, query handler), every repository gate green and no public operation yet.
2. **The phase-0 spikes.** Integration tests and benchmarks in `crates/service` verify, before any production code depends on them, the krafka capabilities the replication and freshness design relies on (twelve capabilities, listed in `architecture.md` section 20.4), and measure RS256 verification and GraphQL parsing on a known host. Story 1.7 records the outcome and the Kafka client decision in ADR 0026; Story 1.8 fits the mutation gate to broker-backed suites.

Many requirement ids below come from the master PRD and are only partly delivered here: a spike proves a capability, and the feature that uses it lands in a later epic. Each such requirement is labelled "(Epic 1 slice)" and its statement is limited to what this feature delivers and can prove with tests or recorded measurements; a separate "Out of scope for this feature" note names the later epic that completes it and defines no requirement.

Conventions:

- Evidence names the observable behaviour and the gate that proves it, by its `make.*` key (the resolved targets are listed in `## Constraints` of `architecture.md`).
- Figures are labelled **target** (a goal to be measured), **ESTIMATE** (unmeasured) or **measured on host** (a recorded spike result that is never a gate value).
- Requirement ids are those of the master PRD, so the numbering has gaps; only the ids defined below belong to this feature.

## Functional Requirements

### Token verification and GraphQL parsing (spike)

**FR-15 Offline token validation (Epic 1 slice).** A benchmark in `crates/service/benches/` verifies RS256 JWS tokens with `jsonwebtoken` using its `aws_lc_rs` backend, against one trusted public key and against three trusted keys tried newest first, with RSA key pairs and tokens generated when the benchmark starts through `aws-lc-rs` (never the `rsa` crate). No private key or token is committed, no `openssl-sys` crate enters the dependency graph, and the dependency-policy gate passes with `jsonwebtoken` and `aws-lc-rs` as dev-dependencies of `crates/service` only.
Evidence: `make.bench_spikes` reports a median and a p99 per operation for one and three keys; `make.check_security` passes and the story records whether `aws-lc-rs` key generation passes the advisory check; `make.docs_check` passes with the bench sources free of committed keys and `docs/spikes/phase-0.md` listing the results (Story 1.6).

**FR-60 GraphQL proxying (Epic 1 slice).** A benchmark in `crates/service/benches/` parses a representative corpus of GraphQL documents of 1, 5, 8 and 64 KiB with the `async-graphql` parser and reports the parse cost per document size, recorded as measured on the named host with its CPU model and never as a gate value. The result is the first measured reference for the decision, in a later epic, to parse documents above 8 KB off the request workers.
Evidence: `make.bench_spikes` reports a median and a p99 per document size; `make.docs_check` passes with `docs/spikes/phase-0.md` listing the CPU model and labelling every figure as a host measurement (Story 1.6).

### Kafka client capabilities (spike)

**FR-18 Revocation events from User service over Kafka (Epic 1 slice).** Spike tests prove the two krafka capabilities the User service event consumer relies on: (a) consumer-group membership with manual commit after processing and rebalance handling, where records processed but not committed by a member that leaves are delivered again to the remaining member and no committed record is delivered twice; (b) SASL SCRAM-SHA-512 over TLS trusting a custom root CA generated at test time (no key committed), where the right credentials connect and a wrong password or an untrusted CA fail with distinguishable typed errors. The outcome of capabilities 8 and 9, and whether follower fetching (capability 12) is available, is recorded.
Evidence: integration tests in `crates/service/tests/integration/kafka_spike/` against the compose broker and its SASL_SSL listener (`make.integration_tests`); `docs/spikes/phase-0.md` records pass or fail per capability (`make.docs_check`) (Story 1.5).

**FR-46 Transactional outbox and Kafka relay (Epic 1 slice).** Spike tests prove the producer capabilities the relay relies on: (a) an idempotent producer with `acks=all`, at most one request in flight, explicit partition 0 and lz4 compression writes 10,000 records under injected retriable errors exactly once, in order and with contiguous offsets; (b) a transactional producer with `transactional.id` `iam-relay` is fenced when a second producer with the same id initialises, and none of its records becomes visible to a `read_committed` reader; (c) aborted transactions are invisible to a `read_committed` reader; (d) `ListOffsets` with isolation `READ_COMMITTED` stops at the last stable offset while a transaction is open, and the broker aborts a transaction whose producer stops within a 10-second `transaction.timeout.ms`. The outcome of capabilities 6 and 7 is recorded.
Evidence: integration tests against the compose broker and krafka's `test-broker` (`make.integration_tests`); `docs/spikes/phase-0.md` records pass or fail (`make.docs_check`) (Story 1.4).

**FR-71 Gateway policy consumer, bootstrap and apply (Epic 1 slice).** Spike tests prove the krafka capabilities the gateway's group-less tail relies on: (a) headers `iam-version`, `iam-seq`, `iam-count`, `iam-digest-after`, `iam-op`, `iam-schema`, `iam-log-epoch` and `iam-relay-epoch` on a null-value record are read back byte-identical and the value is reported as null; (b) a reader that assigns partition 0 without a consumer group in `read_committed` mode stops at the last stable offset and returns no uncommitted record until the transaction commits; (c) a stored position below the log start offset yields an out-of-range error to the caller and krafka never resets the position by itself; (d) after a dropped and restored connection, a reseek to the in-memory position reads every record exactly once and in order; (e) injected `OFFSET_OUT_OF_RANGE`, `NOT_LEADER_OR_FOLLOWER` and request-timeout faults surface as distinguishable typed errors. The outcome of capabilities 1, 2 and 10, with the krafka version, is recorded.
Evidence: integration tests against the compose broker and krafka's `test-broker` (`make.integration_tests`); `docs/spikes/phase-0.md` records pass or fail (`make.docs_check`) (Story 1.2).

**FR-72 Kafka configuration gates (Epic 1 slice).** Spike tests prove that krafka can read every value the later configuration gates need: `DescribeConfigs` on a test topic created with `cleanup.policy=compact`, `min.insync.replicas`, `unclean.leader.election.enable=false` and `message.timestamp.type=LogAppendTime`, `DescribeConfigs` on the broker, and `DescribeAcls`; each value is returned or the missing capability is recorded as failed. With the compose broker started with the `simple` authorizer and `allow.everyone.if.no.acl.found=false`, the spike records whether `DescribeConfigs` returns that setting and, when it does not, the chosen fallback. The outcome of capability 5 is recorded.
Evidence: integration tests against the compose broker (`make.integration_tests`); `docs/spikes/phase-0.md` records the outcome and the fallback (`make.docs_check`) (Story 1.3).

**FR-73 Freshness proof and staleness bound (Epic 1 slice).** Spike tests prove the krafka requests the freshness proof relies on: (a) a Metadata request addressed to a chosen broker returns the leader, the leader epoch of partition 0 and the partition count; (b) `ListOffsets` sent with the current leader epoch returns the high watermark, and with a stale epoch, a future epoch and an injected `OFFSET_NOT_AVAILABLE` it surfaces `FENCED_LEADER_EPOCH`, `UNKNOWN_LEADER_EPOCH` and `OFFSET_NOT_AVAILABLE` as distinguishable typed errors. On a documented 3-broker compose profile run outside `make ci`, the spike records whether at least 2 of 3 brokers report the same new leader and epoch after a leader stop, and whether any broker's Metadata answer lagged its own replica fetcher, labelled as compose-host observations. The outcome of capabilities 3 and 4 is recorded.
Evidence: integration tests against the compose broker and krafka's `test-broker` (`make.integration_tests`); `docs/spikes/phase-0.md` records pass or fail and labels the multi-broker observations (`make.docs_check`) (Story 1.3).

## Non-Functional Requirements

### Repository bars (restated or tightened, never relaxed)

**NFR-1 Coverage.** Line and function coverage stay at 100% over unit and integration tests for every crate this feature adds or changes (`iam-domain`, `iam-application`, `iam-infrastructure`, `tests/support`, `crates/service`), with no coverage exclusion, no `#[coverage(off)]` and no change to the coverage command. Gate: `make.tests_with_coverage`.

**NFR-2 Mutation testing (Epic 1 slice).** Zero surviving and zero timed-out mutants on the code this feature changes, with no `#[mutants::skip]` and no new `exclude_re` entry in the protected `.cargo/mutants.toml`; a suspected equivalent mutant is removed by restructuring the code or escalated to the owner. Any loop this feature adds is a pure step function with a branch-free shell and bounded waits. The mutation workflow starts the compose `kafka` service on every shard, because each `crates/service` mutant reruns the spike suite. The integration suite of `crates/service` stays within 15 seconds on the CI runner (target, measured from Story 1.2 on and printed by `make.integration_tests`; back within budget once Story 1.7 removes the spike modules). With the owner's agreement, the push step of the mutation shard job runs `make mutation-tests-diff` instead of the whole-workspace run, every shard keeps `timeout-minutes: 45`, and the matrix resize to 16 shards of 60 mutants is applied only after an owner-approved protected change; without approval it is recorded as a request and the 15-second budget stays. Gates: the mutation gate (`make.mutation_tests_diff`), `make.integration_tests` (seam check), `make.validate_invariants`, `make.bats`, `make.docs_check`.

**NFR-3 Complexity.** Every function stays within cognitive complexity 8, 50 lines, 5 arguments and nesting depth 5, with the limits of `clippy.toml` unchanged. Gate: `make.complexity`.

**NFR-4 Static analysis and style (Epic 1 slice).** Zero clippy warnings under the workspace lint set, zero rustdoc warnings, every public item documented, no `#[allow]`, no `unsafe`, no `unwrap`, `expect`, `panic` or indexing on production paths, no `mod.rs`; time is obtained only through the `Clock` port and identifiers only through the `UuidGenerator` port. Gates: `make.lint_code`, `make.format`, `make.static_analysis`.

**NFR-5 Layer boundaries (Epic 1 slice).** The IAM domain crate depends only on `async-trait`, `thiserror`, `uuid` and `shared-domain`; the service adds exactly one bounded context, `authorization/iam`; application and infrastructure never depend on each other; `workspace.dsl` gains the group `Authorization/Iam` with one component per new crate and one relationship per workspace-internal dependency edge; every crate builds alone. Gates: `make.architecture`, `make.check_crate_isolation`, `make.validate_architecture_model`.

**NFR-8 Persistence discipline.** The migration `create_iam_policy_epoch` is a reversible up and down pair created with `make.create_migration`, with a reviewed down migration and one rollback round trip when an operator allows it (else recorded `not run (ask rule)`); applied migrations are never edited; its queries are compile-time checked with current offline metadata committed in `.sqlx/`; its integration tests run against the real PostgreSQL container. Gates: `make.setup_test_db`, `make.sqlx_prepare`, `make.validate_sqlx_metadata`, `make.integration_tests`.

**NFR-9 Test levels (Epic 1 slice).** The IAM domain rules have unit tests (`make.unit_tests`); `PgPolicyEpochRepository` and the migration have integration tests against real PostgreSQL, and the spike tests run against the compose Kafka broker and krafka's `test-broker` (`make.integration_tests`); no test uses LocalStack SQS for IAM; `tests/support` offers `FakePolicyEpochRepository` with `new()` and `failing()`; a Gherkin smoke scenario proves the service starts with the IAM context wired (`make.e2e_tests`); the existing Bats suites stay green.

### Documentation and template compatibility

**NFR-30 Documentation and decisions (Epic 1 slice).** ADR 0013 (the IAM bounded context `authorization/iam`, with the gateway as modules inside it), ADR 0014 (PostgreSQL as system of record and an in-process replicated policy snapshot instead of DynamoDB and DAX) and ADR 0026 (krafka as the Kafka client: phase-0 results and the `rdkafka` fallback, listing every capability 1 to 12 with its outcome and the krafka version) are written and indexed in `docs/adr/README.md`; `docs/architecture.md` lists the IAM context; `docs/requests.http` gains an IAM section; `docs/spikes/phase-0.md` records every spike outcome and benchmark; `workspace.dsl` describes the new crates. Gates: `make.docs_check`, `make.validate_architecture_model`.

**NFR-31 Template-sync compatibility (Epic 1 slice).** The IAM wiring of this feature (code, manifests, compose and workflow files) changes only files already listed in `.templatesyncignore` (for example `crates/service/src/bootstrap.rs`, `bootstrap/`, `http/router/tests.rs`, `tests/integration/panic.rs`, `tests/e2e/`, `docs/adr/`), new files, and the seam files `docker-compose.yml`, `crates/service/tests/integration/main.rs` and the mutation workflow `.github/workflows/tests.yml`, each added to `.templatesyncignore` in the story that first changes it; `crates/service/src/lib.rs` and the template `Makefile` are not changed (the service target goes into `make/service.mk`). A seam-check integration test asserts the coverage of each listed seam file and the compose services and make targets each workflow job uses. Gates: `make.validate_invariants`, `make.integration_tests` (seam check), review of the template-sync ignore list.

### Performance references (spike, never gates)

**NFR-33 Gateway residence latency (Epic 1 slice).** The RS256 verify and GraphQL parse benchmarks of FR-15 and FR-60 give the first measured reference for the latency estimates: each figure is recorded in `docs/spikes/phase-0.md` with the CPU model as measured on that host, and the residence-latency figures of the master plan stay targets, not gate values. Evidence: `make.bench_spikes` (outside `make ci`) and `make.docs_check` (Story 1.6).

**NFR-36 Enforced staleness bound (Epic 1 slice).** The freshness bound stays labelled conditional; this feature supplies the spike evidence it is conditional on: the leader-epoch and `ListOffsets` capabilities of FR-73 and the configuration reads of FR-72 pass or are recorded as failed, and the replica-quorum observations on the 3-broker compose profile are recorded as compose-host measurements. Evidence: `make.integration_tests` and `make.docs_check` (Story 1.3).

**NFR-37 Bootstrap to fresh (Epic 1 slice).** A reader without a consumer group reads a 200 MB topic on the compose broker from offset 0 with a documented command run outside `make ci`, and the read rate is recorded in `docs/spikes/phase-0.md` as a compose-host measurement next to the 100 MB/s target, never as a gate value. Evidence: `make.docs_check` (Story 1.5).

### Out of scope for this feature

This note defines no requirement. It names, for each requirement above that this feature delivers only in part, the later epic of the master plan that completes it; those epics are later features with their own bundles.

| Requirement | Delivered here | Completed by (master plan) |
| --- | --- | --- |
| FR-15 | RS256 verify backend benchmark and dependency-policy check | Epic 2 (Story 2.5: `JwtAccessTokenVerifier`, every claim rule, reason codes, key reload) |
| FR-18 | Consumer-group and SCRAM-over-TLS capabilities | Epic 2 (Story 2.6, revocation state) and Epic 13 (Story 13.5, the `user.events.v1` consumer) |
| FR-46 | Idempotent and transactional producer capabilities | Epic 2 (Story 2.3, outbox and unit of work) and Epic 7 (Story 7.4, the fenced relay) |
| FR-60 | GraphQL parse benchmark | Epic 10 (Story 10.8, GraphQL proxying limits and envelope rules) |
| FR-71 | Group-less tail capabilities | Epic 9 (Stories 9.1, 9.3, 9.4: snapshot, bootstrap, tail and apply) |
| FR-72 | Configuration and ACL reads | Epic 7 (Story 7.3), Epic 9 (Story 9.4) and Epic 15 (Story 15.4) |
| FR-73 | Metadata and `ListOffsets` leader-epoch capabilities | Epic 9 (Story 9.5) and Epic 16 (Story 16.8, failover tests) |
| NFR-2 | Changed-code mutation bar, Kafka in the mutation workflow, push diff runs | Valkey and Loki compose services in Epics 12 and 14; later loops in Epics 6 to 14 |
| NFR-4 | Clock and UuidGenerator discipline | `BootClock` and `Rng` ports, which later epics add |
| NFR-5 | Crates, components and edges of the new context | Story 16.9 (containers `gateway`, `control`, `database`, `kafka`, `valkey`, `loki`, `loadBalancer`, `kubernetesApi` in `workspace.dsl`) |
| NFR-9 | PostgreSQL, compose Kafka and `test-broker` test levels, smoke scenario | Valkey, Loki and fake Kubernetes API levels and per-capability scenarios in Epics 2 to 16 |
| NFR-30 | ADRs 0013, 0014, 0026 and the spike report | ADRs 0015 to 0025 and 0027 to 0031, `docs/environment.md` and `docs/operations.md` runbooks in later epics |
| NFR-31 | Seam rules for the seams this feature touches | Further seams (`command.rs`, `command/serve.rs`, `http/router.rs`, `graphql/handler.rs`, Dockerfile) in later epics |
| NFR-33 | First measured reference | Story 16.7 (EKS benchmarks, the real gate) |
| NFR-36 | Spike evidence for the conditions | Story 9.5 (paused-time tests) and Story 16.8 (T14, T15) |
| NFR-37 | Compose-host read rate | Stories 9.3, 9.4 and 16.7 (test T8) |

## Product Scope

### In scope (Epic 1: Scaffolding and phase-0 spikes)

| Story | Delivers |
| --- | --- |
| 1.1 Scaffold authorization/iam | The three IAM crates, the policy-epoch slice and its migration, composition-root wiring, test-support fake, smoke scenario, ADRs 0013 and 0014, checklist C1 to C12 |
| 1.2 Spike: krafka tail without a consumer group | Compose KRaft broker, mutation workflow starts it, seam check, capabilities 1, 2 and 10, `docs/spikes/phase-0.md` started |
| 1.3 Spike: krafka metadata, leader epochs and configuration reads | Capabilities 3, 4 and 5, the authorizer-setting fallback, 3-broker compose observations |
| 1.4 Spike: krafka idempotent and transactional producing | Capabilities 6 and 7 |
| 1.5 Spike: consumer group, SCRAM over TLS with a custom CA, and bootstrap read rate | Capabilities 8, 9, 11 and 12 |
| 1.6 Spike: token-verify backend and GraphQL parser benchmarks | Criterion benches, the `bench-spikes` service target, host-labelled results |
| 1.7 Record the phase-0 outcome and the Kafka client decision | ADR 0026, completed spike report, removal of the spike modules |
| 1.8 Fit the mutation gate to the IAM test suites | Diff mutation runs on pushes (with owner agreement), suite budget documentation, resize request |

### Out of scope (later features of the master plan)

| Epic | Title | One line |
| --- | --- | --- |
| 2 | Policy core and token authentication | Unit of work, outbox, security audit log, offline token validation, revocation state, authentication and the first public operation |
| 3 | Roles and user-role assignments | Role and assignment aggregates, their management API on REST and GraphQL |
| 4 | Specification ingestion for GraphQL and OpenAPI | Upload, parse, diff and store service specifications |
| 5 | Permission catalogue and role grants | Permission keys generated from specifications, grants, orphans |
| 6 | Decision core and IAM self-protection | Decision rule, validate-access API, IAM's own authorization and bootstrap |
| 7 | Policy replication from the control plane | State records, configuration gates, fenced relay, events, anti-entropy, bulk operations, resync |
| 8 | Gateway management API | Upstreams, routes, rate policies, route configuration, bootstrap seeding |
| 9 | Gateway runtime: snapshot, consumer and freshness | `service gateway`, snapshot, bootstrap and tail, freshness proof, readiness |
| 10 | Request path for REST and GraphQL | Proxy pipeline, edge hardening, read-your-writes, decision listener, CORS and CSRF, east-west listener |
| 11 | Streams and GraphQL subscriptions | WebSocket, SSE and subscription authorization and re-evaluation |
| 12 | Rate limiting with Valkey | Exact global quotas with a conservative local fallback |
| 13 | Revocations, write modes and Sync-Fence | Operator revocations, propagated writes, User service event consumer |
| 14 | Access-decision log in Loki and audit queries | Access-log lanes, Loki push and query, audit queries |
| 15 | Kubernetes deployment and operations | Reference manifests, probes, drain, Strimzi resources, runbooks |
| 16 | Hardening, benchmarks and documentation | Configuration rules, metrics, hardening suites, EKS benchmarks and fault tests, final ADRs |

Also out of scope: the protected allow-list change of ADR 0023 (owner-approved on 2026-11-21, applied in a later feature), the removal of the template's example context, and every platform prerequisite (EKS, Strimzi, Valkey, Loki).
