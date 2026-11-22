# Epics and Stories: IAM API Gateway and Authorization Service

| Field | Value |
| --- | --- |
| Bundle | `specs/8-iam-scaffolding-and-spikes/` |
| Issue | `#8` "Scaffold the IAM context and run the phase-0 spikes" (VilnaCRM-Org/api-gateway-service); one pull request delivers all 16 epics (owner decision, 2026-11-22) |
| Date | 2026-11-22 (derived from the master plan of 2026-11-21) |
| Inputs | `research.md`, `product-brief.md`, `prd.md`, `architecture.md` of this bundle; the master plan `specs/0-iam-authorization-service/` (iam-service checkout, 2026-11-21, placeholder issue 0) and the Epic 1 bundle of this directory (2026-11-22) |
| Bounded context | `authorization/iam` (packages `iam-domain`, `iam-application`, `iam-infrastructure`; the gateway is a set of modules inside them; Story 1.1 scaffolds it) |

This file breaks the PRD into sixteen epics and 127 stories, all delivered in one pull request for issue #8: the owner decided on 2026-11-22 that every epic ships in that one pull request, which replaces the earlier one-bundle-per-epic method. IAM is the API gateway: one image runs as `iam-gateway` (data plane, `service gateway`) and as `iam-control` (control plane, `service serve`). Story 1.1 runs first and alone; every other story starts when the stories of its `**Depends on:**` line are done. Each story is sized for one implementation session, follows the layer order domain, then application, then infrastructure, then the `crates/service` wiring, names the requirements it covers (`FR-n`, `NFR-n`) in its `Covers` line and names the gates that prove it by their `make.*` keys: every behavioural criterion ends with the gate that proves it, and a closing criterion lists the full gate set of the story. The FR/NFR review gate traces every requirement id of this bundle's `prd.md` to test evidence in the pull request. The resolved target behind each of the ten dispatch keys is listed once, in `## Constraints` of `architecture.md`. A story is committed as `<type>(#8): story N.M <title>`.

Epic 1 below is the Epic 1 section of the earlier Epic 1 bundle of this directory, kept verbatim because it holds the refinements that match the Story 1.1 code already in the working tree (for example the items Story 1.1 defers to Story 2.8). Epics 2 to 16 are the master plan's text with the commit literal `(#8)` and the changes listed in the assumptions below.

Every story that adds or changes a REST or GraphQL operation ships both interfaces through one handler (FR-1), regenerates both contract snapshots and updates the pinning tests in the same story; the review gate fails any management capability exposed on one interface only, and the API Surface Summary table of `prd.md` is the checklist. Proxied upstream traffic is not an IAM capability and has no contract snapshot. Every story that adds a migration writes and reviews its down migration, runs the rollback round trip when an operator allows it (the rollback target is an `ask` rule in `.claude/settings.json`, so an unattended run records it as `not run (ask rule)`), passes `make.validate_sqlx_metadata` and commits the regenerated `.sqlx/` metadata. Every story that adds an environment variable adds its row to `docs/environment.md` and its local defaults to `.env` and `.env.test` in the same story. Every story that adds a crate edge keeps `workspace.dsl` in step. Every performance figure in a story is a target or an estimate; no latency or capacity figure is a gate inside `make ci`. No story plans an `#[allow]`, `#[mutants::skip]`, `#[coverage(off)]`, a coverage exclusion, an allow-list edit or a lowered bar. Every loop (task, thread, tail, prober, watchdog, long poll, coordinator, runner) is written as a pure step function `(state, input) -> (state, actions)` in the domain or application layer and unit-tested directly; its task or thread shell has no branching, and every test that drives a shell uses bounded waits, so a mutant that hangs fails instead of timing out (`architecture.md` section 5.6). Every story that adds a compose service the integration tests need (Kafka in Story 1.2, Valkey in Story 12.2, Loki in Story 14.2) also makes the mutation workflow start it.

**Recurring gate sets.** Each story names its gates by their literal `make.*` keys. For reference, the recurring groups are:

- DB-free gates: `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity` (may run in parallel agents).
- Persistence gates: `make.setup_test_db`, `make.integration_tests`, `make.sqlx_prepare`, `make.validate_sqlx_metadata` (DB-backed, one serialized verify step at a time); the optional rollback round trip uses `make.migrate_rollback` then `make.migrate` only when an operator allows it.
- Kafka-backed tests: integration tests that need a broker run inside `make.integration_tests` against krafka's in-process `test-broker` by default, and against the single-node KRaft broker that Story 1.2 adds to `docker-compose.yml` only where real log semantics are needed (transactions, compaction, consumer-group rebalance); multi-broker runs use a documented compose profile outside `make ci`.
- Mutation runtime budget: every mutant reruns its crate's suite and a mutation shard may not exceed 45 minutes, so every story that adds integration tests to `iam-infrastructure` or `crates/service` keeps that crate's integration suite within 15 seconds on the CI runner, or 30 seconds once the owner approves the matrix resize of Story 1.8 (targets printed by `make.integration_tests`, `architecture.md` section 19). A story that exceeds it moves tests to `test-broker` or is split before it closes; if that is not enough it stops and reports.
- Contract gates: `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`) and `make.schemathesis_validate` (from Story 2.8 on, with the ephemeral credentials of that story).
- Closing gates of every story: `make.tests_with_coverage` (100% lines and functions), `make.mutation_tests_diff` (zero surviving or timed-out mutants on the changed code), and `make.e2e_tests` and `make.docs_check` whenever the story changes an operation, a variable or a document.

**Assumptions made while writing the epics:**

> Assumption: The issue is #8 (VilnaCRM-Org/api-gateway-service), so every story commit uses the literal `(#8)` and the `story N.M` subject form; this bundle covers all sixteen epics of the master plan, derived on 2026-11-22, and the whole plan ships in one pull request (owner decision, 2026-11-22).

> Assumption: The profile `.claude/rust-sdlc.yml` maps every `make.*` key named here to the target of the same name with underscores replaced by hyphens. Keys the profile does not list resolve by the same rule to template or service targets listed by `make help`: `make.bench_spikes` is the service target `bench-spikes` that Story 1.6 adds to `make/service.mk` (documented in `docs/make-targets-service.md`), and `make.bats` is the template target `bats`; the same holds for `make.new_context`, `make.check_crate_isolation`, `make.check_security`, `make.unused_dependencies`, `make.static_analysis`, `make.validate_architecture_model`, `make.create_migration`, `make.migrate`, `make.migrate_rollback`, `make.validate_sqlx_metadata`, the contract keys, `make.schemathesis_validate`, `make.docs_check`, `make.mutation_tests_diff`, `make.smoke_load_tests`, `make.lint_yaml`, `make.secrets_scan`, `make.image_scan`, `make.validate_invariants`, the `make.ci_*` stage keys and `make.validate_configuration`. Stories pass `base_ref=main` to base-ref readers as written; the profile's `ci.base_ref` is `origin/main`, which the CI jobs use.

> Assumption: Every story lists Story 1.1 explicitly in its `Depends on:` line, in addition to its direct predecessors, so the story-1 rule holds without relying on transitive dependencies.

> Assumption: The scaffold story delivers the context skeleton and its first persisted slice (the policy epoch) but no public operation, because every IAM operation needs the authentication pipeline of Epic 2; the first public operation (token resolution, Story 2.8) adds the `iam` OpenAPI tag, the `bearerAuth` scheme, the merge of the IAM GraphQL roots and the `.data(iam_state)` call on the schema builder, since an object type without fields is not valid GraphQL and an unused tag or scheme would be a Spectral finding.

> Owner decision (2026-11-21): the protected allow-list change of ADR 0023 (`architecture.toml`, the delta of `architecture.md` section 3.1) is APPROVED. Story 2.3 applies it on the branch of the single pull request, with `ALLOW_PROTECTED_CONFIG_EDIT=1` and the `approved-config-change` label set by a maintainer. Where a later story names the approved change as a prerequisite or says "merged", it means applied on the branch by Story 2.3; Stories 2.5 and 7.3 list Story 2.3 in their `Depends on:` lines so the dispatcher cannot start them earlier (Story 2.6 and every later user of the delta follow transitively), and if Story 4.6 takes its infrastructure fallback for `serde_json` it runs after Story 2.3. The spike stories 1.2 to 1.6 put `krafka`, `jsonwebtoken`, `criterion` and `aws-lc-rs` only as dev-dependencies of `crates/service`, whose allow-list is `["*"]`, so they need no allow-list entry. `tokio` is not part of the delta; a direct `tokio` dependency of `iam-infrastructure` would be a new protected change, which is not approved.

> Owner decision (2026-11-22, standing instruction to take the recommended option): the owner agrees to the push-step change of the mutation shard job, so Story 1.8 implements it. The protected matrix resize (`scripts/ci/mutation-plan.sh`, `tests/CLI/bats/ci_scripts.bats`) is NOT approved: Story 1.8 takes the no-approval branch, leaves both files unchanged and records the request in `docs/operations.md`, and the 15-second suite budget stays in force for every story.

> Assumption: Every protected-file change other than the two above that a story turns out to need (for example a `deny.toml` exception, the `rdkafka` build change, a new entry in `make/tool-versions.mk` or `make/gates.mk`, an edit to a Bats file that exists on `main`) is not approved: the story stops and reports to the owner without editing the file.

> Assumption: Each environment variable of FR-55 is added by the story that first wires it, with its CLI declaration, validation, `docs/environment.md` row and local defaults in `.env` and `.env.test`, so that `make.e2e_tests` and the delivery gates can start both run modes after every story; the e2e world writes its ephemeral public key to a per-scenario `JWT_PUBLIC_KEYS_FILE`. Story 16.1 completes the cross-field rules for both modes and proves every rule through `service check-config --mode gateway` and `--mode control`.

> Assumption: Until Stories 6.11 and 6.12 land, IAM operations authenticate callers but do not check IAM keys; this intermediate state never leaves the feature branch, and Story 6.12 moves the earlier end-to-end scenarios onto the bootstrapped administrator.

> Assumption: The grant-right rules for grants and assignments (FR-24, FR-25) and the specification-scope rules (FR-30) are enforced in Story 6.14, after IAM's own authorization exists; Story 5.7 validates grant keys against the catalogue only, and Stories 4.4 and 4.8 only refuse uploads for the reserved service `iam`.

> Assumption: The composition-root task supervisor (`bootstrap/tasks.rs`, `bootstrap::start_tasks`) is introduced by Story 6.9 for per-replica tasks, because the rejected-attempt writer of Story 6.11 needs it; Story 7.1 adds fenced singleton batches, and Story 9.2 adds the gateway task set. From Story 6.9 on, the e2e world calls `bootstrap::register_iam_specs` and `bootstrap::start_tasks` for every scenario database, because it builds the app without `serve::run`.

> Assumption: The rollback target is an `ask` rule in `.claude/settings.json`; in an unattended run the rollback round trip of a migration story is recorded `not run (ask rule)`, and the story closes on its reviewed down migration and `make.validate_sqlx_metadata`.

> Assumption: The phase-0 spike results gate Epic 7 onward: Story 1.7 records krafka as accepted, or records the failed must-pass capability and stops the run for an owner decision (the `rdkafka` fallback needs an owner-approved build change and an `openssl-sys` exception) before any story of Epic 7 starts. The gate is encoded in the dependency graph: every story of Epics 7 to 16 depends on Story 1.7 directly or transitively (Stories 7.1, 7.2, 7.3, 7.8, 7.9, 8.1, 8.2, 9.1, 9.2, 10.1, 12.1 and 14.4 list it), so the dispatcher cannot start one before the decision. Epics 2 to 6 do not use Kafka and may proceed.

> Assumption: The tests that need Amazon EKS (latency, capacity, propagation and bootstrap benchmarks, broker failover and zombie-leader faults) run in Stories 16.7 and 16.8 outside `make ci`; every other story proves its behaviour with compose services, krafka's `test-broker`, a fake upstream and a fake Kubernetes API.

> Assumption: The removal of the template's example context is not a story of this plan, because the product brief and the PRD put it out of scope; it is recorded as an open item in `architecture.md` section 24.

> Assumption: Relative to the master plan, Epics 2 to 16 change only as follows: Story 2.3 applies the approved allow-list change instead of waiting for an external merge (prerequisite sentence and two criteria); Stories 2.5 and 2.6 read "not applied on the branch (Story 2.3)" instead of "not merged"; Stories 2.5 and 7.3 gain Story 2.3 in their `Depends on:` lines; Story 2.8 gains a criterion for the items Story 1.1 defers to it (`.data(iam_state)` among them, which the master story text omits); Story 7.3 gains a criterion for the `allow.everyone.if.no.acl.found` fallback recorded by Story 1.3; Story 13.5 gains a criterion for the manual-assignment fallback that Story 1.7 names for a failed capability 8.

> Assumption: Because the whole plan is one pull request, each story's `make.mutation_tests_diff` with `base_ref=main` covers every change made since `main`, so the mutated set grows with every story; a story whose diff run exceeds the shard budget narrows the run to its own commits (the previous story's commit as the base, as the push step of Story 1.8 does) and records the base it used.

**Requirement coverage.** Every FR and NFR defined in this bundle's `prd.md` maps to at least one story, built from the `Covers` line of each of the 127 stories (retired master ids are listed in `run-summary.md`):

| Requirement | Stories |
| --- | --- |
| FR-1 | 2.8, 3.3, 3.4, 3.6, 3.7, 3.8, 4.4, 4.5, 4.8, 4.9, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8, 6.5, 6.7, 6.8, 6.12, 6.15, 7.9, 7.10, 8.3, 8.4, 8.5, 8.6, 13.1, 13.2, 13.7, 14.3, 14.4, 14.5 |
| FR-2 | 2.1, 2.3, 2.4, 3.3, 3.4, 3.6, 3.7, 3.8, 4.4, 5.3, 5.5, 5.7, 5.8, 7.6, 8.3, 8.4, 8.5 |
| FR-3 | 2.7 |
| FR-4 | 6.9, 6.11, 6.12, 10.2 |
| FR-5 | 6.10, 8.7 |
| FR-6 | 6.4, 6.5, 6.7, 10.11 |
| FR-7 | 6.2, 6.5, 10.2 |
| FR-8 | 6.6, 6.7, 10.8 |
| FR-9 | 2.1, 6.4, 6.5 |
| FR-10 | 6.1, 6.3 |
| FR-11 | 6.8, 10.11 |
| FR-12 | 6.13 |
| FR-13 | 6.4, 10.2, 16.3 |
| FR-14 | 6.5, 10.10 |
| FR-15 | 1.6, 2.5 |
| FR-17 | 2.6, 13.1 |
| FR-18 | 1.5, 2.6, 13.5 |
| FR-19 | 2.7, 2.8, 10.11 |
| FR-20 | 3.1, 3.2, 3.3 |
| FR-21 | 3.2, 3.3 |
| FR-22 | 3.1, 3.4 |
| FR-23 | 3.1, 3.8, 13.4 |
| FR-24 | 3.1, 5.7, 6.14, 13.8 |
| FR-25 | 6.14 |
| FR-26 | 3.5, 3.6 |
| FR-27 | 3.5, 3.6 |
| FR-28 | 3.5, 3.7, 13.8 |
| FR-29 | 3.5, 3.7, 13.8 |
| FR-30 | 4.1, 4.2, 4.3, 4.4, 6.14 |
| FR-31 | 4.1, 4.5 |
| FR-32 | 5.1, 5.2, 5.3 |
| FR-33 | 5.4 |
| FR-34 | 4.6, 4.7, 4.8, 6.14 |
| FR-35 | 4.9 |
| FR-36 | 5.1, 5.2, 5.5 |
| FR-37 | 5.6 |
| FR-38 | 5.1, 5.2, 5.8, 7.8 |
| FR-39 | 6.15 |
| FR-43 | 7.8 |
| FR-45 | 6.9, 7.1, 9.2 |
| FR-46 | 1.4, 2.3, 7.4 |
| FR-47 | 2.3, 7.4, 7.5 |
| FR-48 | 7.5 |
| FR-49 | 2.2, 2.3, 6.11 |
| FR-50 | 14.1, 14.2 |
| FR-51 | 14.3 |
| FR-52 | 7.8, 14.4, 14.5 |
| FR-53 | 15.4 |
| FR-54 | 7.3, 9.2, 9.7, 14.3 |
| FR-55 | 2.5, 7.3, 9.2, 16.1 |
| FR-56 | 8.1, 8.3 |
| FR-57 | 8.1, 8.4 |
| FR-58 | 8.6 |
| FR-59 | 10.2, 10.3 |
| FR-60 | 1.6, 10.8 |
| FR-61 | 11.1, 11.2, 11.4 |
| FR-62 | 11.3, 11.4 |
| FR-63 | 8.4, 10.6 |
| FR-64 | 8.1, 8.5 |
| FR-65 | 12.1, 12.2, 12.3 |
| FR-66 | 10.5 |
| FR-67 | 9.2, 10.9 |
| FR-68 | 10.4 |
| FR-69 | 8.4, 10.7 |
| FR-70 | 7.2, 8.2, 13.1 |
| FR-71 | 1.2, 9.1, 9.3, 9.4 |
| FR-72 | 1.3, 7.3, 9.4, 15.4 |
| FR-73 | 1.3, 9.5, 16.8 |
| FR-74 | 9.6 |
| FR-75 | 7.6, 8.6, 13.4, 13.8 |
| FR-76 | 13.3, 13.4 |
| FR-77 | 7.7 |
| FR-78 | 7.10 |
| FR-79 | 13.6 |
| FR-80 | 13.1 |
| FR-81 | 13.2 |
| FR-82 | 13.7 |
| FR-83 | 13.7 |
| FR-84 | 7.9, 13.8 |
| FR-85 | 15.1, 16.8 |
| FR-86 | 15.2, 16.7 |
| FR-87 | 10.1, 10.3 |
| FR-88 | 15.3, 15.4 |
| FR-89 | 10.12 |
| FR-90 | 10.13 |
| NFR-1 | 1.1, 2.1 |
| NFR-2 | 1.1, 1.8, 2.1 |
| NFR-3 | 1.1, 2.1 |
| NFR-4 | 1.1, 2.1 |
| NFR-5 | 1.1, 16.9 |
| NFR-6 | 2.3, 2.5 |
| NFR-7 | 2.8, 16.5 |
| NFR-8 | 1.1, 2.2, 2.3, 3.2, 3.5, 4.3, 4.7, 5.2, 7.2, 8.2 |
| NFR-9 | 1.1, 1.2, 2.1, 2.4 |
| NFR-14 | 15.5, 16.3 |
| NFR-15 | 16.3, 16.8 |
| NFR-16 | 5.1, 6.1, 6.15, 9.1 |
| NFR-19 | 13.5, 16.8 |
| NFR-20 | 2.2, 2.5, 2.6, 14.1, 16.2 |
| NFR-21 | 4.2, 4.6, 6.6, 10.9, 16.4, 16.5 |
| NFR-22 | 6.11, 16.9 |
| NFR-23 | 2.2, 14.5 |
| NFR-24 | 14.1, 14.2 |
| NFR-25 | 15.4 |
| NFR-26 | 2.3, 7.4 |
| NFR-27 | 16.2 |
| NFR-28 | 6.3, 9.3, 15.5, 16.9 |
| NFR-29 | 16.6 |
| NFR-30 | 1.1, 1.7, 2.8, 15.5, 16.9 |
| NFR-31 | 1.1, 2.7, 9.2 |
| NFR-33 | 1.6, 16.7 |
| NFR-34 | 16.6, 16.7 |
| NFR-35 | 9.4, 16.7, 16.8 |
| NFR-36 | 1.3, 9.5, 16.8 |
| NFR-37 | 1.5, 9.3, 9.4, 16.7 |
| NFR-38 | 9.1, 16.7 |
| NFR-39 | 15.3, 16.7 |
| NFR-40 | 10.9, 16.4 |
| NFR-41 | 15.1, 15.2, 16.6, 16.7 |
| NFR-42 | 12.3, 16.7 |
| NFR-43 | 10.1, 16.7 |
| NFR-44 | 14.3, 16.7 |

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

## Epic 2: Policy core and token authentication

This epic adds the domain primitives every later story uses, the transactional policy core (security audit log, unit of work with the gap-free policy version and the outbox, idempotency and change receipts) and the token pipeline that authenticates every caller of IAM's own API without any call to User service.

### Story 2.1: Define the IAM domain primitives

As a developer of later IAM stories, I want the shared value objects, error enums and time and randomness ports of the IAM domain in place, so that aggregates, decisions and adapters all validate identities, keys, scopes and versions the same way and never read time or randomness directly.
Covers FR-2, FR-9, NFR-1, NFR-2, NFR-3, NFR-4, NFR-9.
Domain only: `RoleId`, `UserRoleId`, `SpecId`, `PermissionId`, `DecisionId`, `ChangeId`, `SubjectId`, `SubjectKind`, `SubjectRef` (a user UUID or a service name), `ProjectId`, `EntityVersion`, `RequestId`, `IdempotencyKey`, `ServiceName`, `AssignmentScope`, `ScopeSet`, `PermissionKey` (`Rest`, `Gql`, `Reserved` forms with their service segment), `WildcardPattern` (the four structured forms of FR-10), `PermissionGrant`, `PermissionGrantSet` (at most 5,000), `PermissionFlags`, `ReservedPermission` (exactly the reserved keys of FR-4, including `iam:route:{service}` and `iam:route:*`; `iam:cache:flush` does not exist), `ActorRef`, `AuditAction`, `AuditOutcome` and `BootInstant`, plus `InvalidPermissionKey`, `VersionConflict` (`Missing`, `Stale`) and the port error `RepositoryError { AlreadyExists, NotFound, Conflict, Unavailable }`. New ports `BootClock` (elapsed time on `CLOCK_BOOTTIME`, never compared across hosts) and `Rng` (every random draw); `tests/support` gains `FakeBootClock` (controlled advance, including jumps) and `FakeRng` (seeded and reproducible). There is no `CacheTier` value object and no `AccessDecision` entity.

**Acceptance Criteria:**
- **Given** keys in the forms `rest:{service}:{METHOD} {template}`, `gql:{service}:{Type}.{field}` and the reserved `iam:` keys, plus malformed variants, **When** `PermissionKey` parses them, **Then** valid keys expose their kind and service segment, malformed ones yield `InvalidPermissionKey` with a property path and a code, and a property test shows that formatting a parsed key and parsing it again returns the same key, proven in `make.unit_tests`.
- **Given** the four wildcard forms and near-miss strings such as `gql:{service}:*.field`, **When** `WildcardPattern` parses them, **Then** only `gql:{service}:{Type}.*`, `gql:{service}:*`, `rest:{service}:{METHOD} *` and `rest:{service}:*` are accepted, proven in `make.unit_tests`.
- **Given** service names of valid and invalid shape and length, **When** `ServiceName::new` runs, **Then** only names matching `^[a-z][a-z0-9]*(-[a-z0-9]+)*$` of at most 63 characters are accepted, proven in `make.unit_tests`.
- **Given** subject references of kind `user` with a UUID and of kind `service` with a service name, plus a user reference with a non-UUID id and a service reference with an invalid name, **When** `SubjectRef` is constructed, **Then** only the first two are accepted, proven in `make.unit_tests`.
- **Given** the reserved keys `iam:validate:{service}`, `iam:validate:*`, `iam:grant:{service}`, `iam:grant:*`, `iam:grant:sensitive`, `iam:grant:wildcard`, `iam:spec:{service}`, `iam:spec:*`, `iam:audit:read`, `iam:revoke:sessions`, `iam:revoke:global`, `iam:policy:resync`, `iam:route:anonymous`, `iam:route:{service}` and `iam:route:*`, plus `iam:cache:flush`, **When** `ReservedPermission` parses them and checks coverage, **Then** each listed key parses, `iam:cache:flush` is rejected as unknown, `iam:grant:*` covers every service, and `iam:spec:*` and `iam:route:*` each cover every service except `iam` and refuse `iam`, proven in `make.unit_tests`.
- **Given** an `AssignmentScope::Project` without a project id, a grant set of 5,001 keys and an `EntityVersion` compared with a different expected version, **When** they are constructed or compared, **Then** each is rejected with its typed error, and `VersionConflict::Missing` and `VersionConflict::Stale` are distinguishable, proven in `make.unit_tests`.
- **Given** `ActorRef` values for a user, a service and the system components `bootstrap`, `user-service` and `startup`, **When** they are rendered, **Then** their stable textual forms (`system:<component>` for system actors) round-trip through parsing, proven in `make.unit_tests`.
- **Given** a `FakeBootClock` advanced by steps and by one jump, and two `FakeRng` instances with the same seed, **When** elapsed times and draws are read, **Then** elapsed time never decreases and the jump is visible as one gap, and both generators yield the same sequence, proven in `make.unit_tests`.
- **Given** the domain changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity` run with `make.tests_with_coverage` and `make.mutation_tests_diff`, **Then** all pass with 100% coverage and zero surviving mutants, and `iam-domain` still depends only on `async-trait`, `thiserror`, `uuid` and `shared-domain`.

**Depends on:** 1.1

### Story 2.2: Record the hash-chained security audit log

As a security officer, I want every audit record stored append-only in a hash chain, so that administrative history cannot be altered without detection.
Covers FR-49, NFR-8, NFR-20, NFR-23.
Domain: the `SecurityAuditEvent` entity and the `SecurityAuditLog` port (`append_batch` for buffered rejected attempts, used from Story 6.11, and queries; the committed-change path is used by the unit of work of Story 2.3). Infrastructure: the migration `create_iam_security_audit_log` (`iam_security_audit_events`, `iam_security_audit_chain_head`, the trigger rejecting `UPDATE` and `DELETE`) and `PgSecurityAuditLog`, which computes `sha256(prev_hash || canonical_form)` in SQL under the chain-head lock and emits each record as a JSON `tracing` event with target `audit`. Composition root: the adapter in `Adapters` and the three literals; `tests/support`: `FakeSecurityAuditLog` with `new()` and `failing()`. ADR 0019 (security audit log in PostgreSQL and access-decision log in Loki) is created here in draft; Story 14.2 adds the Loki parts and Story 14.5 adds the threat model.

**Acceptance Criteria:**
- **Given** two records appended in sequence (one through `append_batch` with two records), **When** the chain head and the rows are read, **Then** the second record's `prev_hash` equals the first record's `hash` and each `hash` equals the SQL digest of the previous hash and the record's canonical form, proven in `make.integration_tests`.
- **Given** an existing audit row, **When** a test issues `UPDATE` or `DELETE` against `iam_security_audit_events`, **Then** the trigger rejects the statement and the row is unchanged, proven in `make.integration_tests`.
- **Given** appends committed concurrently from two connections, **When** both transactions finish, **Then** the sequence has no gap and the chain verifies over all rows, proven in `make.integration_tests`.
- **Given** a record with before and after summaries, **When** it is appended, **Then** the log recorder sees one JSON event with target `audit`, and neither the row nor the event contains a token or a specification body, proven in `make.integration_tests`.
- **Given** the migration pair created with `make.create_migration` and the queries, **When** `make.setup_test_db`, `make.integration_tests`, `make.sqlx_prepare`, `make.validate_sqlx_metadata` and `make.tests_with_coverage` and `make.mutation_tests_diff` run, **Then** they pass, the down migration is reviewed (its rollback round trip runs when an operator allows it, else it is recorded `not run (ask rule)`), and the regenerated `.sqlx/` metadata is committed.

**Depends on:** 1.1, 2.1

### Story 2.3: Commit changes atomically through the IAM unit of work

As an operator of IAM, I want every policy change, its audit record, its events, its change receipt and its idempotency record committed in one transaction under a gap-free policy version, so that no change is ever visible without its audit trail or its event, and every change has a total order.
Covers FR-2, FR-46, FR-47, FR-49, NFR-6, NFR-8, NFR-26.
Protected change: the allow-list change of `architecture.md` section 3.1 (ADR 0023), approved by the owner on 2026-11-21, which adds among others `serde` and `serde_json` to the infrastructure layer; this story applies it to `architecture.toml` in its first commit with `ALLOW_PROTECTED_CONFIG_EDIT=1`, and a maintainer sets the `approved-config-change` label on the pull request of issue #8. No other protected file changes. Domain: the `IamUnitOfWork` port, the `IamChange` description (aggregate statements, pulled domain events, audit record, change receipt, idempotency record, whether decisions are affected, whether the change is revocation-class) and the `EventEnvelope` rules (`{id, type, occurredAt, data}`, type pattern, 64 KiB bound). Infrastructure: the migrations `create_iam_outbox` (`iam_outbox` with `id`, identity `position`, `kind` (`state`, `event`), `topic`, `record_key`, `payload` (null for a tombstone), `policy_version`, `seq`, `count`, `digest_after`, `log_epoch`, `event_type`, `aggregate_id`, `occurred_at`, `published_at`, `published_offset`, `relay_epoch`, and a partial index on `position` where unpublished), `create_iam_idempotency_keys` and `create_iam_change_receipts`, and `PgIamUnitOfWork`, which locks the `iam_policy_epoch` row with `SELECT ... FOR UPDATE`, increments `version` by one when the change affects decisions, runs the aggregate statements, inserts outbox event rows (`kind = event`, topic `iam.events.v1`, record key the aggregate id), the audit record (the same-transaction audit write of FR-49), the change receipt and the idempotency record in one transaction. Until Story 7.2 the unit of work writes event rows only; state rows, the digest and the `__head` row follow there. No `pg_notify` is sent; Story 7.4 adds the relay wake-up. ADR 0017 (policy state topic, transactional outbox and fenced Kafka relay) is added in draft, and ADR 0023 (allow-list additions for the gateway) records exactly the approved delta.

**Acceptance Criteria:**
- **Given** the owner-approved delta of `architecture.md` section 3.1, **When** the story applies it to `architecture.toml`, **Then** the file differs from `main` by exactly that delta and nothing else, no other protected file changes, and `make.architecture` passes; if the change cannot be applied as approved, the story stops and reports without editing any protected file.
- **Given** a change that affects decisions, **When** `PgIamUnitOfWork::commit` succeeds, **Then** the policy version is incremented by one under the row lock, and the audit row, the outbox event rows, the change receipt (change id, target, resulting entity version and policy version) and the idempotency record all become visible together, proven in `make.integration_tests`.
- **Given** the same change with a statement forced to fail, **When** the commit runs, **Then** nothing is visible: no version change, no audit row, no outbox row, no change receipt and no idempotency record, proven in `make.integration_tests`.
- **Given** 100 changes committed concurrently from four connections, **When** all transactions finish, **Then** their policy versions are consecutive with no gap and no duplicate, and each outbox row carries the version of its own transaction, proven in `make.integration_tests`.
- **Given** a change that does not affect decisions, **When** it commits, **Then** the policy version is unchanged and the change receipt has no policy version, proven in `make.integration_tests`.
- **Given** a committed outbox event row, **When** it is read, **Then** it has `kind = event`, topic `iam.events.v1`, the aggregate id as record key, the envelope as payload and no `published_at`, and the partial index covers it, proven in `make.integration_tests`.
- **Given** domain events of each kind, **When** they are encoded as envelopes, **Then** unit tests show the UUID v7 id, the type pattern, RFC 3339 UTC `occurredAt`, the 64 KiB bound and the absence of tokens and specification bodies in `data`, proven in `make.integration_tests`.
- **Given** ADR 0023, **When** it is compared with the applied allow-list change, **Then** it lists exactly that delta, and `make.validate_configuration` with `base_ref=main` reports `architecture.toml` as the only protected file changed (passing with `CONFIG_CHANGE_APPROVED=1`, which mirrors the `approved-config-change` label).
- **Given** the new crates and migrations, **When** `make.check_security`, `make.unused_dependencies`, `make.setup_test_db`, `make.integration_tests`, `make.sqlx_prepare`, `make.validate_sqlx_metadata`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass and the three down migrations are reviewed (their rollback round trips run when an operator allows it, else they are recorded `not run (ask rule)`).

**Depends on:** 1.1, 2.2

### Story 2.4: Apply idempotency keys, entity versions and change receipts

As an administrator using REST or GraphQL, I want safe retries and optimistic concurrency on every write, so that a repeated request never applies a change twice and a stale edit never overwrites a newer one.
Covers FR-2, NFR-9.
Domain: the `ChangeReceipt` record and the `ChangeReceiptRepository` and `IdempotencyRepository` ports. Application: the `IdempotencyKeyHeader` and `IfMatchHeader` extractors in IAM's `http/extract.rs`, the response helpers for `ETag`, `Location` and `Iam-Policy-Version`, `GetChangeReceiptQueryHandler`, the `IamError` variants `Conflict`, `IdempotencyMismatch`, `PreconditionRequired`, `PreconditionFailed` and `NotFound`, and `iam_problem_to_graphql_error` with the codes of `architecture.md` section 5.5. Infrastructure: `PgChangeReceiptRepository` (reading `iam_change_receipts`, created in Story 2.3) and `PgIdempotencyRepository`. Composition root: the adapters, the handler registration and the three literals.

**Acceptance Criteria:**
- **Given** an update request without `If-Match` (GraphQL: without `expectedVersion`), **When** the extractor runs, **Then** it rejects with a 428 problem (GraphQL `PRECONDITION_REQUIRED`), proven in `make.integration_tests`.
- **Given** an update request with a stale `If-Match` (GraphQL: a stale `expectedVersion`), **When** the change is applied, **Then** it is rejected with 412 (GraphQL `PRECONDITION_FAILED`), proven in `make.integration_tests`.
- **Given** a committed change with an idempotency key, **When** the same actor repeats the key with the same request digest within 24 hours, **Then** the original `ChangeReceipt` is returned with the original `ETag` and `Iam-Policy-Version`, and no second audit or outbox row exists, proven in `make.integration_tests`.
- **Given** a committed change with an idempotency key, **When** the same actor repeats the key with a different body within 24 hours, **Then** the result is a 422 `IdempotencyMismatch` problem, proven in `make.unit_tests`.
- **Given** an idempotency record older than 24 hours by the `Clock` port, **When** the key is reused, **Then** the request is treated as new, proven in `make.integration_tests`.
- **Given** each `IamError` variant, **When** it is converted to a `Problem` and to a GraphQL error, **Then** the HTTP status and `extensions.code` match the table of `architecture.md` section 5.5, proven in `make.unit_tests`.
- **Given** the story's changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.setup_test_db`, `make.integration_tests`, `make.sqlx_prepare`, `make.validate_sqlx_metadata`, `make.tests_with_coverage` and `make.mutation_tests_diff` run, **Then** all pass and the regenerated `.sqlx/` metadata is committed.

**Depends on:** 1.1, 2.3

### Story 2.5: Validate User service tokens offline

As the gateway, I want IAM to accept only correctly signed, current User service tokens of bounded lifetime, so that a forged, replayed or long-lived credential can never reach a decision.
Covers FR-15, FR-55, NFR-6, NFR-20.
Prerequisite: the approved allow-list change that adds `jsonwebtoken` (feature `aws_lc_rs`) and the dev-only `aws-lc-rs` for test keys. Domain: `AccessToken`, `Credential` (its `Debug` prints nothing), `TokenRejection`, `SessionId`, `TokenId`, the `AccessTokenVerifier` port and `TokenLifetimeRule` (`exp − iat > MAX_TOKEN_LIFETIME` is `token_invalid`; time checks against injected instants with `JWT_CLOCK_SKEW`). Infrastructure: `JwtAccessTokenVerifier` (RS256 only; keys from `JWT_PUBLIC_KEYS_FILE`, 1 to 3 PEM keys, newest last in the file and tried newest first, hot-reloaded through a file watch, the last valid set kept when a reload fails; issuer and audience; `exp`, `nbf` and `iat` checked through the `Clock` port; a service-name `sub` for `ROLE_SERVICE` tokens; strict header rules), tested with RSA keys generated at test time through `aws-lc-rs`. Composition root: the adapter in `Adapters` and the three literals, and the variables `JWT_PUBLIC_KEYS_FILE`, `JWT_ISSUER`, `JWT_AUDIENCE`, `JWT_CLOCK_SKEW` and `MAX_TOKEN_LIFETIME` in `cli.rs` and `config.rs`, their rows in `docs/environment.md` and local defaults in `.env` and `.env.test` (a development public-key file whose private half is never committed; the e2e world overrides it with its ephemeral key). `tests/support`: `FakeAccessTokenVerifier`. ADR 0016 (token validation at the gateway without token persistence or liveness calls) is added.

**Acceptance Criteria:**
- **Given** the approved allow-list change is not applied on the branch (Story 2.3), **When** the story starts, **Then** it stops and reports without editing any protected file, proven in `make.unit_tests`.
- **Given** tokens signed with a test key for a `ROLE_USER` and a `ROLE_SERVICE` subject, **When** they are verified, **Then** each yields an `AccessToken` with subject id, subject kind `user` or `service`, session id, `jti`, roles claim, issued-at and expiry, proven in `make.integration_tests`.
- **Given** tokens using `none`, any HMAC algorithm or another asymmetric algorithm, carrying `jwk`, `jku`, `x5u`, `x5c` or `crit`, with a wrong issuer or audience, without `sub` or `jti`, with `roles` but no `sid`, or a `ROLE_SERVICE` token whose `sub` is not a valid service name, **When** they are verified, **Then** each is rejected as `token_invalid`; an `exp` beyond the skew is `token_expired`; an empty credential is `token_missing`, proven in `make.integration_tests`.
- **Given** a token whose `exp − iat` exceeds `MAX_TOKEN_LIFETIME`, or whose `nbf` or `iat` lies beyond the skew in the future by the controlled `Clock`, **When** it is verified, **Then** it is rejected as `token_invalid`, proven in `make.integration_tests`.
- **Given** a key file with three keys of which the token was signed by the oldest, **When** the token is verified, **Then** it is accepted after the newer keys were tried first, proven in `make.integration_tests`.
- **Given** a running verifier, **When** the key file is replaced with a new valid key set and then with an unparsable file, **Then** tokens of the new key are accepted after the reload, and after the failed reload the last valid set stays in force and an error is logged, proven in `make.integration_tests`.
- **Given** `JWT_CLOCK_SKEW` above 60 seconds, a key file with no key or more than three keys, or an unparsable PEM key, **When** `service check-config` runs, **Then** it exits 2 with a message naming the variable, proven in `make.integration_tests`.
- **Given** a credential formatted with `Debug` or logged through an error path, **When** the log recorder inspects the output, **Then** no part of the raw token appears, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.check_security`, `make.unused_dependencies`, `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.integration_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass.

**Depends on:** 1.1, 2.1, 2.3

### Story 2.6: Memoize token resolutions and check revocations

As the gateway, I want token identities memoized briefly by digest while revocations are checked on every request, so that the hot path stays fast without ever honouring a revoked session.
Covers FR-17, FR-18, NFR-20.
Prerequisite: the approved allow-list change that adds `sha2`. Domain: the `TokenRepository` (board name), `TokenMemo`, `RevocationView` and `RevocationRepository` ports, `TokenIdentity` (subject, kind, session, `iat`, `exp`, `jti`; never permissions), `CredentialDigest` (its `Debug` prints only the 8-character prefix), the `SessionRevocation`, `UserTokenCutoff` and `GlobalTokenCutoff` records and `RevocationRule` (reject when the session is revoked, `iat <=` the user cut-off or `iat <=` the global cut-off). Infrastructure: the migration `create_iam_token_revocations` (`iam_revoked_sessions` with `id`, `session_id`, `user_id`, `source`, `revoked_by`, `revoked_at`, `prune_after`; `iam_user_token_validity` with `source` and `prune_after`; `iam_global_token_cutoff` with `CHECK (id = 1)`; `iam_inbound_events` with `event_id` as primary key, `topic`, `partition`, `offset`, `event_type`, `outcome` and `error`), `PgRevocationRepository` (writes used by Stories 13.1 and 13.5, reads, idempotent inbound-event records), `PgRevocationView` (reads for `iam-control`), `MokaTokenMemo` (a positive memo of `TokenIdentity` keyed by `CredentialDigest` with TTL `min(exp − now, TOKEN_MEMO_MAX_TTL)` and capacity `TOKEN_MEMO_CAPACITY`, and a negative memo of 10,000 entries for 5 seconds, both flushed when the trusted key set changes) and `CachingTokenRepository`, the single owner of the memos, which digests the credential, consults the negative and positive memos, verifies on a miss (concurrent misses for one digest share one verification) and checks the `RevocationView` on every call, memo hits included. Composition root: the adapters, the three literals and `TOKEN_MEMO_CAPACITY` and `TOKEN_MEMO_MAX_TTL` with their `docs/environment.md` rows and local defaults. `tests/support`: fakes for the four ports.

**Acceptance Criteria:**
- **Given** the approved allow-list change is not applied on the branch (Story 2.3), **When** the story starts, **Then** it stops and reports without editing any protected file, proven in `make.integration_tests`.
- **Given** a valid user token checked repeatedly, **When** the controlled `Clock` advances past `min(exp − now, TOKEN_MEMO_MAX_TTL)`, **Then** the verifier ran exactly once before that instant and once more after it, proven in `make.integration_tests`.
- **Given** 50 concurrent checks of one unmemoized token, **When** they resolve, **Then** the verifier runs exactly once, proven in `make.integration_tests`.
- **Given** a memoized valid token, **When** its session is recorded as revoked, the user's cut-off is set at or after its `iat`, or the global cut-off is set at or after its `iat`, **Then** the next check returns `token_revoked` without a new verification, proven in `make.integration_tests`.
- **Given** a flood of more than 10,000 distinct invalid tokens, **When** they are checked, **Then** previously memoized valid entries are still served from the positive memo, and an invalid token is verified again after its 5-second negative entry expires, proven in `make.integration_tests`.
- **Given** a memoized token, **When** the trusted key set changes, **Then** both memos are flushed and the next check verifies again, proven in `make.integration_tests`.
- **Given** stored rows, memo keys and log lines produced by these checks, **When** a test searches them for the raw credential, **Then** none contains it, and the memo holds no permission or role grant, proven in `make.integration_tests`.
- **Given** `TOKEN_MEMO_CAPACITY` below 1,000 or `TOKEN_MEMO_MAX_TTL` above `MAX_TOKEN_LIFETIME`, **When** `service check-config` runs, **Then** it exits 2 naming the variable, proven in `make.integration_tests`.
- **Given** an inbound event id recorded twice and a second row in `iam_global_token_cutoff`, **When** the statements run, **Then** the primary key and the check constraint reject them, proven in `make.integration_tests`.
- **Given** the migration pair created with `make.create_migration` and the queries, **When** `make.check_security`, `make.unused_dependencies`, `make.setup_test_db`, `make.integration_tests`, `make.sqlx_prepare`, `make.validate_sqlx_metadata`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass and the down migration is reviewed (its rollback round trip runs when an operator allows it, else it is recorded `not run (ask rule)`).

**Depends on:** 1.1, 2.5

### Story 2.7: Authenticate callers of IAM's own API

As the owner of IAM, I want every IAM route and GraphQL field to require a valid bearer token, so that no anonymous request reaches IAM's data.
Covers FR-3, FR-19, NFR-31.
Application: `ResolveTokenQuery` with `ResolveTokenQueryHandler` (over `TokenRepository`, whose revocation check in `iam-control` goes through `PgRevocationView`; there is no liveness call to User service), `Principal`, and `IamError::Unauthenticated` mapped to 401 with `WWW-Authenticate: Bearer` and to GraphQL `UNAUTHENTICATED`. Composition root: the new `http/authentication.rs` middleware, which reads the token from `Authorization: Bearer` or, when that header is absent, from the `__Host-auth_token` cookie (the gateway forwards the cookie to `iam-control`, FR-68, and checks cross-site use of it, FR-89), applied in `http/router.rs` to the IAM router only, inside the request-id, security-header and `TraceLayer` layers, which also requires `JWT_CALLER_AUDIENCE` in the `aud` of a service caller's token and a lifetime of at most `JWT_SERVICE_TOKEN_MAX_LIFETIME`; the two variables with their `docs/environment.md` rows and local defaults; `graphql/handler.rs` passes `Option<Principal>` into the GraphQL request data. Both seam files and their `tests.rs` are added to `.templatesyncignore` in this story. Because the IAM router exposes no operation until Story 2.8, the router tests mount a test-local protected route on the IAM router layer to exercise the middleware.

**Acceptance Criteria:**
- **Given** the test-local protected route mounted on the IAM router layer and a request with no `Authorization` header, **When** the router test serves it, **Then** the response is 401 with an `application/problem+json` body and `WWW-Authenticate: Bearer`, proven in `make.integration_tests`.
- **Given** a service caller's token without `JWT_CALLER_AUDIENCE` in `aud`, or with a lifetime above `JWT_SERVICE_TOKEN_MAX_LIFETIME`, **When** it is sent to the test-local route, **Then** the response is the same 401 shape; a valid service token with the IAM audience passes, proven in `make.integration_tests`.
- **Given** malformed, expired and revoked bearer tokens (the revoked one recorded in `iam_revoked_sessions`), **When** each is sent to the test-local route, **Then** each yields the same 401 shape without revealing which check failed, proven in `make.integration_tests`.
- **Given** `JWT_SERVICE_TOKEN_MAX_LIFETIME` above 3,600 seconds or above `MAX_TOKEN_LIFETIME`, **When** `service check-config` runs, **Then** it exits 2 naming it, proven in `make.integration_tests`.
- **Given** requests without a token to `/ping`, `/api/health`, `/api/docs`, `/api/docs/openapi.json` and the example context's routes, **When** they are served, **Then** each keeps its template behaviour, proven in `make.docs_check`.
- **Given** a GraphQL request with and without a valid bearer token, **When** it is executed, **Then** the request data holds `Some(Principal)` or `None`, and the `Unauthenticated` error maps to `extensions.code = UNAUTHENTICATED`, proven in `make.integration_tests`.
- **Given** spans and log lines recorded during authentication, **When** the log recorder inspects them, **Then** the `Authorization` header value never appears, proven in `make.integration_tests`.
- **Given** a request to the test-local route that carries a valid token only in the `__Host-auth_token` cookie, **When** it is served, **Then** the request is authenticated like a bearer request, and an invalid cookie token yields the same 401 shape, proven in `make.integration_tests`.
- **Given** the seam files changed, **When** `make.validate_invariants`, `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.integration_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass, and the seam check of Story 1.2, extended with `http/router.rs`, `graphql/handler.rs` and their test files, shows that `.templatesyncignore` covers them in `make.integration_tests`.

**Depends on:** 1.1, 1.2, 2.6

### Story 2.8: Expose the token-resolution API

As a microservice, I want to resolve a User service token into its subject over REST or GraphQL, so that I can identify a caller without parsing tokens myself.
Covers FR-1, FR-19, NFR-7, NFR-30.
Application: the REST operation `POST /api/token-resolutions` and the GraphQL query `resolveToken(input)`, both dispatching `ResolveTokenQuery`. Composition root: the `iam` tag and the `bearerAuth` HTTP bearer security scheme in `openapi.rs`, and the merge of `IamQuery` and `IamMutation` into the schema roots in `graphql/schema.rs`. Co-changes: both snapshots and their pinning tests, `features/iam_token_resolution.feature` with its steps; in `tests/e2e/world.rs`, runtime-signed tokens from an ephemeral key whose public key is written to the per-scenario `JWT_PUBLIC_KEYS_FILE`, and a step that records a session revocation for a scenario-chosen session directly through `PgRevocationRepository`; a service target in `make/service.mk` (documented in `docs/make-targets-service.md`) that issues a short-lived `ROLE_SERVICE` token with the IAM caller audience from an ephemeral key for Schemathesis through `SCHEMATHESIS_FLAGS` (no key or token is committed and the template `Makefile` is unchanged); `docs/requests.http` samples and ADR 0021 (REST and GraphQL parity). The same operation is served from the snapshot on the gateway's decision listener (`GATEWAY_DECISION_LISTEN`) in Story 10.11.

**Acceptance Criteria:**
- **Given** a valid user token as `credential` and an authenticated caller, **When** the caller resolves it over REST and over GraphQL, **Then** both return the same subject id, subject kind, session id, roles claim and expiry, and neither echoes the credential, proven in `make.e2e_tests`.
- **Given** expired, revoked and invalid credentials, **When** they are resolved, **Then** both interfaces return 200 data with `resolved = false` and the token reason code, proven in `make.e2e_tests`.
- **Given** a session recorded as revoked by the e2e step, **When** a token of that session is resolved over REST and over GraphQL, **Then** both return `resolved = false` with `token_revoked`, proven in `make.e2e_tests`.
- **Given** a request without a bearer token or with a rejected one, **When** it is sent over REST and over GraphQL, **Then** each 401 cause yields the REST problem with `WWW-Authenticate: Bearer` and the GraphQL error `UNAUTHENTICATED` in end-to-end scenarios, proven in `make.e2e_tests`.
- **Given** the generated OpenAPI document, **When** it is inspected, **Then** the operation carries the `bearerAuth` requirement and the `iam` tag and documents 400, 401, 403, 413, 415, 422 and default problem responses with `application/problem+json`, proven in `make.e2e_tests`.
- **Given** the operations are wired, **When** `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate` run, **Then** the pinning tests are updated and the gates pass with additions only, Spectral reports zero findings, and Schemathesis reaches the operation past the 401 with the ephemeral credentials.
- **Given** the items Story 1.1 deferred to this story (the merge of `IamQuery` and `IamMutation` into the schema roots in `graphql/schema.rs`, the `.data(iam_state)` call on the schema builder, the `iam` tag and the `bearerAuth` scheme in `openapi.rs`), **When** the composition root is tested, **Then** all four are present, `resolveToken` reaches `IamState` through the schema data, and the pinning tests `src/openapi/tests.rs` and `src/graphql/schema/tests.rs` assert them, proven in `make.tests_with_coverage`.
- **Given** the full story, **When** `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass and `docs/requests.http` holds one REST and one GraphQL sample for the operation.

**Depends on:** 1.1, 2.7

## Epic 3: Roles and user-role assignments

This epic delivers role management without grants and the assignment of roles to users at global and project scope. Grants follow in Epic 5, once the permission catalogue exists.

### Story 3.1: Model the Role aggregate

As a developer, I want the `Role` aggregate with its rules and events in the domain, so that role behaviour is unit-testable without I/O.
Covers FR-20, FR-22, FR-23, FR-24.
Domain only: `Role` (board name) with `RoleName` (1 to 100 characters, no control characters, case-insensitive comparison form), `RoleDescription` (at most 1,000 characters), `RoleKind` (`System`, `Custom`), its `PermissionGrantSet`, `EntityVersion` and timestamps from the `Clock` port; the events `RoleCreated`, `RoleUpdated`, `RoleDeleted` and `RolePermissionsChanged` with `NAME` values `iam.role.created`, `iam.role.updated`, `iam.role.deleted` and `iam.role_permissions.changed`; the `RoleRepository` port (board name); and `InvalidRole`.

**Acceptance Criteria:**
- **Given** names that are empty, longer than 100 characters or contain control characters, and descriptions longer than 1,000 characters, **When** a role is created, **Then** `InvalidRole` is returned with the property path and code of each violation, proven in `make.unit_tests`.
- **Given** a valid name, **When** `Role::create` runs with ids and an instant supplied by the caller, **Then** the role has kind `Custom`, no grants, version 1 and exactly one recorded `RoleCreated` event; `Role::restore` records no event, proven in `make.unit_tests`.
- **Given** a system role, **When** a rename or a deletion is attempted, **Then** the aggregate refuses it with a typed error that the application maps to 403, proven in `make.unit_tests`.
- **Given** an expected version different from the current one, **When** an update, a deletion or a grant replacement is attempted, **Then** `VersionConflict::Stale` is returned and no event is recorded, proven in `make.unit_tests`.
- **Given** a grant replacement, **When** it is applied, **Then** `RolePermissionsChanged` carries the added and removed keys and the version increases by one, proven in `make.unit_tests`.
- **Given** the domain changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.tests_with_coverage` and `make.mutation_tests_diff` run, **Then** all pass.

**Depends on:** 1.1, 2.1

### Story 3.2: Persist roles

As a developer, I want roles stored in PostgreSQL with unique names and stable pagination, so that the role API can rely on durable, concurrency-safe storage.
Covers FR-20, FR-21, NFR-8.
Infrastructure: the migration `create_iam_roles_and_permissions` (`iam_roles`, `iam_role_permissions`, the unique index on `lower(name)` among non-deleted roles, the length checks) and `PgRoleRepository` (role statements contributed to `PgIamUnitOfWork`, `find_by_id`, `find_page` with cursor, name-prefix and kind filters). Composition root: the adapter and the three literals. `tests/support`: `FakeRoleRepository` with `new()` and `failing()` and a role fixture.

**Acceptance Criteria:**
- **Given** an existing role named `Billing`, **When** a role named `billing` is saved, **Then** the repository returns `AlreadyExists`, proven in `make.integration_tests`.
- **Given** a role named `Billing` has been deleted, **When** a role named `billing` is saved, **Then** it is stored, proven in `make.integration_tests`.
- **Given** an update saved with an outdated version, **When** the statement runs inside the unit of work, **Then** no row changes and the repository reports a version conflict, proven in `make.integration_tests`.
- **Given** 250 roles, **When** pages of 1, 37 and 100 are read with a name prefix and a kind filter, **Then** every matching role appears exactly once in a stable order across pages, proven in `make.integration_tests`.
- **Given** the migration pair created with `make.create_migration` and the queries, **When** `make.setup_test_db`, `make.integration_tests`, `make.sqlx_prepare`, `make.validate_sqlx_metadata`, `make.tests_with_coverage` and `make.mutation_tests_diff` run, **Then** they pass, the down migration is reviewed (its rollback round trip runs when an operator allows it, else it is recorded `not run (ask rule)`) and the regenerated `.sqlx/` metadata is committed.

**Depends on:** 1.1, 2.3, 3.1

### Story 3.3: Create and read roles over REST and GraphQL

As an administrator, I want to create roles and read them back over either interface, so that I can build my organisation's role model.
Covers FR-1, FR-2, FR-20, FR-21.
Application: `CreateRoleCommandHandler`, `GetRoleQueryHandler` and `ListRolesQueryHandler`; the REST operations `POST /api/roles`, `GET /api/roles/{id}` and `GET /api/roles` in `http/role.rs`; the GraphQL fields `createRole(input)`, `role(id)` and `roles(first, after, namePrefix, kind)`. The create handler commits through `IamUnitOfWork` with the audit record and the `iam.role.created` outbox event. Composition root: handler registration. Co-changes: snapshots and pinning tests, `features/iam_roles.feature`, `docs/requests.http`.

**Acceptance Criteria:**
- **Given** an authenticated caller and a valid name, **When** a role is created over REST, **Then** the response is 201 with `Location`, `ETag`, the id and version 1, and the outbox holds `iam.role.created` and the audit log a committed record in the same transaction; the GraphQL mutation returns the same data, proven in `make.e2e_tests`.
- **Given** a duplicate name or an invalid name, **When** the role is created, **Then** REST returns 409 or a 422 problem with violations, and GraphQL returns `CONFLICT` or `VALIDATION_FAILED` with the same violations, proven in `make.e2e_tests`.
- **Given** a create repeated with the same `Idempotency-Key` (GraphQL `idempotencyKey`) and body, **When** it is replayed, **Then** the original result is returned and no second role, audit record or event exists, proven in `make.e2e_tests`.
- **Given** existing roles, **When** they are read by id and listed with cursor pagination and filters, **Then** both interfaces return id, name, description, kind, grant count, version and timestamps; an unknown id returns 404 over REST and `null` over GraphQL, proven in `make.e2e_tests`.
- **Given** the operations are wired, **When** `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate` run, **Then** the pinning tests are updated and the gates pass with additions only.
- **Given** the full story, **When** `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass and `docs/requests.http` holds one REST and one GraphQL sample per new operation.

**Depends on:** 1.1, 2.4, 2.8, 3.2

### Story 3.4: Update roles

As an administrator, I want to rename a role or change its description safely, so that concurrent edits never silently overwrite each other.
Covers FR-1, FR-2, FR-22.
Application: `UpdateRoleCommandHandler`, REST `PATCH /api/roles/{id}` with `If-Match`, GraphQL `updateRole(input)` with `expectedVersion`; the `iam.role.updated` event and the audit record go through the unit of work. Co-changes: snapshots and pinning tests, the roles feature file, `docs/requests.http`.

**Acceptance Criteria:**
- **Given** a custom role and its current `ETag`, **When** its name is changed over REST and over GraphQL, **Then** the version increases, a new `ETag` is returned, and `iam.role.updated` and an audit record are committed, proven in `make.e2e_tests`.
- **Given** an update without a version, **When** it is sent, **Then** REST returns 428 and GraphQL `PRECONDITION_REQUIRED`, proven in `make.e2e_tests`.
- **Given** an update with a stale version, **When** it is sent, **Then** REST returns 412 and GraphQL `PRECONDITION_FAILED`, proven in `make.e2e_tests`.
- **Given** a system role seeded by a fixture, **When** an update is attempted, **Then** REST returns 403 and GraphQL `FORBIDDEN`, and the role is unchanged, proven in `make.e2e_tests`.
- **Given** the operations are wired, **When** `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass with additions only.

**Depends on:** 1.1, 3.3

### Story 3.5: Model and persist user-role assignments

As a developer, I want the `UserRole` aggregate and its storage, so that assignment rules (scope, expiry, uniqueness) hold in the domain and in the database.
Covers FR-26, FR-27, FR-28, FR-29, NFR-8.
Domain: `UserRole` (board name) with `UserRoleId`, `SubjectRef` (a user UUID or a service name), `RoleId`, `AssignmentScope`, `AssignmentExpiry` (in the future by the `Clock` port when set), `EntityVersion` and revocation state; the events `UserRoleAssigned`, `UserRoleUpdated`, `UserRoleRevoked` and `PrivilegedRoleAssigned`; the `UserRoleRepository` port (board name); `InvalidUserRole`. Infrastructure: the migration `create_iam_user_roles` and `PgUserRoleRepository`. Composition root: the adapter and the three literals. `tests/support`: `FakeUserRoleRepository` and fixtures.

**Acceptance Criteria:**
- **Given** an expiry that is not in the future by the controlled `Clock`, **When** an assignment is created or its expiry is changed, **Then** `InvalidUserRole` is returned with the property path `expiresAt`, proven in `make.unit_tests`.
- **Given** an active assignment of a role to a subject at a scope, **When** the same subject, role and scope are saved again, **Then** the partial unique index makes the repository return `AlreadyExists`, proven in `make.integration_tests`.
- **Given** an assignment of a role to a subject at a scope that has been revoked, **When** the same subject, role and scope are saved again, **Then** the new assignment is stored, proven in `make.unit_tests`.
- **Given** a project-scoped row without a project id, a global row with one, a `user` row whose subject id is not a UUID, or a `service` row whose subject id is not a valid service name, **When** it is inserted, **Then** the check constraint rejects it, proven in `make.integration_tests`.
- **Given** active, expired and revoked assignments of user and service subjects, **When** they are listed with the filters `subjectKind`, `subjectId`, `roleId`, `projectId` and `includeExpired`, **Then** revoked rows are excluded and expired rows appear only when requested, proven in `make.integration_tests`.
- **Given** the story's changes, including the migration pair created with `make.create_migration`, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.setup_test_db`, `make.integration_tests`, `make.sqlx_prepare`, `make.validate_sqlx_metadata`, `make.tests_with_coverage` and `make.mutation_tests_diff` run, **Then** all pass and the down migration is reviewed (its rollback round trip runs when an operator allows it, else it is recorded `not run (ask rule)`).

**Depends on:** 1.1, 3.2

### Story 3.6: Assign roles and read assignments

As an administrator, I want to assign roles to users globally or per project and see the assignments, so that people get exactly the access their job needs.
Covers FR-1, FR-2, FR-26, FR-27.
Application: `AssignUserRoleCommandHandler`, `GetUserRoleQueryHandler` and `ListUserRolesQueryHandler`; REST `POST /api/user-roles`, `GET /api/user-roles/{id}` and `GET /api/user-roles`; GraphQL `assignUserRole(input)`, `userRole(id)` and `userRoles(...)`. The assign handler records `iam.user_role.assigned`, and also `iam.privileged_role.assigned` when the role grants a wildcard or a reserved `iam:` key, and bumps the policy version. Co-changes: snapshots and pinning tests, `features/iam_user_roles.feature`, `docs/requests.http`.

**Acceptance Criteria:**
- **Given** an existing role, **When** it is assigned to a user subject at global scope and at project scope over both interfaces, **Then** 201 with `Location` and `ETag` is returned, the policy version is bumped, and `iam.user_role.assigned` (with `subject` and `userId`) and an audit record are committed, proven in `make.e2e_tests`.
- **Given** an existing role, **When** it is assigned to a service subject such as `{kind: service, id: billing-worker}` over both interfaces, **Then** the assignment is stored and listed with `subjectKind = service`, proven in `make.e2e_tests`.
- **Given** a role whose grants include a wildcard or a reserved key (seeded by a fixture), **When** it is assigned, **Then** `iam.privileged_role.assigned` is committed as well, carrying the privileged keys, proven in `make.e2e_tests`.
- **Given** a duplicate assignment, a past expiry or an unknown role id, **When** it is submitted, **Then** REST returns 409, 422 or 422 with a violation on `roleId`, and GraphQL returns the matching codes, proven in `make.e2e_tests`.
- **Given** assignments, **When** they are read by id and listed with filters and cursor pagination, **Then** both interfaces return role name, scope, expiry, version and timestamps, proven in `make.e2e_tests`.
- **Given** the operations are wired, **When** `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass with additions only.

**Depends on:** 1.1, 3.3, 3.5

### Story 3.7: Update and revoke assignments

As an administrator, I want to change an assignment's expiry or revoke it, so that temporary access ends on time and removed access ends immediately.
Covers FR-1, FR-2, FR-28, FR-29.
Application: `UpdateUserRoleCommandHandler` and `RevokeUserRoleCommandHandler`; REST `PATCH /api/user-roles/{id}` and `DELETE /api/user-roles/{id}`; GraphQL `updateUserRole(input)` and `revokeUserRole(input)`. Revocation bumps the policy version. The revocation-class default write mode of FR-29, and of an expiry shortened or newly set (FR-28), is added by Story 13.8. Co-changes: snapshots and pinning tests, the user-roles feature file, `docs/requests.http`.

**Acceptance Criteria:**
- **Given** an assignment and its version, **When** its expiry is set, extended, shortened or cleared over both interfaces, **Then** the new expiry and version are returned and `iam.user_role.updated` is committed; an expiry that is not in the future returns 422, proven in `make.e2e_tests`.
- **Given** an assignment, **When** it is revoked over REST and over GraphQL, **Then** it disappears from active listings, the policy version is bumped, and `iam.user_role.revoked` and an audit record are committed, proven in `make.e2e_tests`.
- **Given** a missing or stale version, **When** either change is sent, **Then** 428 or 412 (GraphQL `PRECONDITION_REQUIRED` or `PRECONDITION_FAILED`) is returned, proven in `make.e2e_tests`.
- **Given** the operations are wired, **When** `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass with additions only.

**Depends on:** 1.1, 3.6

### Story 3.8: Delete roles with cascading revocation

As an administrator, I want deleting a role to revoke every assignment of it in the same step, so that no user keeps access through a role that no longer exists.
Covers FR-1, FR-2, FR-23.
Application: `DeleteRoleCommandHandler`; REST `DELETE /api/roles/{id}`; GraphQL `deleteRole(input)`. In one unit-of-work transaction the handler deletes the role, revokes its assignments, records `iam.role.deleted` and one `iam.user_role.revoked` per revoked assignment, writes the audit records and bumps the policy version. The revocation-class default write mode of FR-23 is added by Story 13.4. Co-changes: snapshots and pinning tests, the roles feature file, `docs/requests.http`.

**Acceptance Criteria:**
- **Given** a custom role with three active assignments, **When** it is deleted over REST and over GraphQL, **Then** the response reports three revoked assignments, the role and the assignments are gone from active listings, and `iam.role.deleted` plus three `iam.user_role.revoked` events are committed with the policy-version bump, proven in `make.e2e_tests`.
- **Given** a deletion with a statement forced to fail, **When** it runs, **Then** neither the role nor any assignment changes and no event or audit record exists, proven in `make.e2e_tests`.
- **Given** a system role or a stale version, **When** a deletion is attempted, **Then** 403 or 412 is returned (GraphQL `FORBIDDEN` or `PRECONDITION_FAILED`), proven in `make.e2e_tests`.
- **Given** a deletion without a version, **When** it is sent, **Then** REST returns 428 and GraphQL `PRECONDITION_REQUIRED`, proven in `make.e2e_tests`.
- **Given** a committed deletion with an `Idempotency-Key` (GraphQL `idempotencyKey`), **When** it is replayed with the same key and body, **Then** the original result, including the number of revoked assignments, is returned and nothing changes a second time, proven in `make.e2e_tests`.
- **Given** the operations are wired, **When** `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass with additions only.

**Depends on:** 1.1, 3.4, 3.7

## Epic 4: Specification ingestion for GraphQL and OpenAPI

This epic lets each service upload its GraphQL SDL and its OpenAPI document as immutable draft versions with a diff against the active versions, symmetric for both interfaces.

### Story 4.1: Model GraphQL specifications and the specification diff

As a developer, I want the `GraphQlSpec` aggregate and the diff rules in the domain, so that versioning and diffing are testable without a parser or a database.
Covers FR-30, FR-31.
Domain only: `GraphQlSpec` (board `GraphQLSpec`) with `SpecId`, `ServiceName`, `ContentHash`, `SpecStatus` (`Draft`, `Active`, `Retired`), `GraphQlTypeGraph`, `GraphQlCoordinate` and `CoordinateSet`; the events `GraphQlSpecLoaded` and `GraphQlSpecRetired`; the `GraphQlSpecRepository` (board `GraphQLSpecRepository`) and `GraphQlSchemaParser` ports; the `SpecDiff` service (added, removed, removed with grants, wildcard grants gaining elements); `InvalidSpec` with a line and column or a JSON pointer.

**Acceptance Criteria:**
- **Given** a draft version, **When** it is activated and then retired, **Then** the activation records no specification event (the catalogue records `GraphQlPermissionsCreated` in Story 5.1), the retirement records `GraphQlSpecRetired` with `NAME` `iam.graphql_spec.retired`, and every other transition (retiring a draft, activating a retired version) is refused with a typed error, proven in `make.unit_tests`.
- **Given** a candidate coordinate set and the union of active sets, **When** `SpecDiff` runs, **Then** table-driven cases return the added and removed coordinates, the removed ones that have grants with their roles, the wildcard grants that would cover added coordinates, and the flag downgrades (coordinates that would lose the sensitive or always-audit flag in the union of active versions), proven in `make.unit_tests`.
- **Given** random coordinate sets, **When** property tests run, **Then** the diff of a set with itself is empty and added and removed coordinates swap when the arguments swap, proven in `make.unit_tests`.
- **Given** the domain changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass.

**Depends on:** 1.1, 2.1

### Story 4.2: Parse GraphQL SDL with limits

As the owner of IAM, I want uploaded SDL parsed into a type graph with strict limits, so that a hostile or oversized schema cannot exhaust IAM.
Covers FR-30, NFR-21.
Application: `AsyncGraphQlSchemaParser` implements `GraphQlSchemaParser` with `async-graphql`'s parser; it enforces the 5 MiB size before parsing and the limits of 10,000 types and 100,000 fields, builds the coordinates (root fields as `Query.x`, `Mutation.y`, `Subscription.z`), the return types and the possible types of interfaces and unions, and records the `@iamSensitive` and `@iamAuditAlways` field directives.

**Acceptance Criteria:**
- **Given** a valid SDL with queries, mutations, an interface, a union and directive-marked fields, **When** it is parsed, **Then** the type graph holds every coordinate, the possible types and the sensitive and always-audit flags, proven in `make.unit_tests`.
- **Given** SDL with a syntax error, **When** it is parsed, **Then** `InvalidSpec` carries the parser's line and column, proven in `make.unit_tests`.
- **Given** a document over 5 MiB, more than 10,000 types or more than 100,000 fields, **When** it is submitted, **Then** it is rejected, and the size check happens before parsing starts, proven in `make.unit_tests`.
- **Given** the application changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.tests_with_coverage` and `make.mutation_tests_diff` run, **Then** all pass.

**Depends on:** 1.1, 4.1

### Story 4.3: Persist GraphQL specification versions

As a developer, I want GraphQL versions stored immutably with their content hash and coordinate set, so that identical uploads are detected and every version stays reproducible.
Covers FR-30, NFR-8.
Infrastructure: the migration `create_iam_graphql_specs_and_permissions` (`iam_graphql_specs`, `iam_graphql_spec_fields`, `iam_graphql_spec_possible_types`, `iam_graphql_permissions`) and `PgGraphQlSpecRepository` (insert through the unit of work with the content hash computed by SQL `sha256()`, lookup by service and hash, list with filters, get with optional SDL). Composition root: the adapter and the three literals. `tests/support`: `FakeGraphQlSpecRepository` and an SDL fixture.

**Acceptance Criteria:**
- **Given** an uploaded version, **When** the same content is looked up for the same service, **Then** the existing version is found; the same content for another service is a different version, proven in `make.integration_tests`.
- **Given** a stored version, **When** a test tries to change its SDL or coordinate set through the repository, **Then** no API allows it and the body stays byte-identical, proven in `make.integration_tests`.
- **Given** versions of several services and statuses, **When** they are listed with the `service` and `status` filters, **Then** only matching versions are returned, with SDL only when requested, proven in `make.integration_tests`.
- **Given** the migration pair created with `make.create_migration` and the queries, **When** `make.setup_test_db`, `make.integration_tests`, `make.sqlx_prepare`, `make.validate_sqlx_metadata`, `make.tests_with_coverage` and `make.mutation_tests_diff` run, **Then** they pass, the down migration is reviewed (its rollback round trip runs when an operator allows it, else it is recorded `not run (ask rule)`) and the regenerated `.sqlx/` metadata is committed.

**Depends on:** 1.1, 2.3, 4.1

### Story 4.4: Load GraphQL specifications

As a delivery pipeline of a service, I want to upload my GraphQL SDL and see what it changes, so that new fields become permission candidates without manual work.
Covers FR-1, FR-2, FR-30.
Application: `LoadGraphQlSpecCommandHandler` (board `LoadGraphQLCommandHandler`); REST `POST /api/graphql-specs`; GraphQL `loadGraphqlSpec(input)`; the response includes the diff against the active versions; `iam.graphql_spec.loaded` and the audit record go through the unit of work. Composition root: a 6 MiB body limit on the specification routes only. Co-changes: snapshots and pinning tests, `features/iam_graphql_specs.feature`, `docs/requests.http`.

**Acceptance Criteria:**
- **Given** a new SDL for a service, **When** it is uploaded over REST and over GraphQL, **Then** a draft version is returned (REST 201) with its hash, coordinate count and diff, and `iam.graphql_spec.loaded` is committed, proven in `make.e2e_tests`.
- **Given** content identical to an existing version, **When** it is uploaded again, **Then** REST returns 200 with that version and no new version or event exists, proven in `make.e2e_tests`.
- **Given** invalid SDL or an invalid service name, **When** it is uploaded, **Then** REST returns 422 with the line and column or the violation, and GraphQL returns `VALIDATION_FAILED`, proven in `make.e2e_tests`.
- **Given** an SDL for the reserved service `iam` uploaded by any actor other than `system:startup`, **When** it is sent over REST and over GraphQL, **Then** REST returns 403 and GraphQL `FORBIDDEN`, and no version is stored, proven in `make.e2e_tests`.
- **Given** a body over 6 MiB on a specification route and a body over the template limit on another IAM route, **When** they are sent, **Then** both return 413, proven in `make.e2e_tests`.
- **Given** the operations are wired, **When** `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass with additions only.

**Depends on:** 1.1, 2.4, 2.8, 4.2, 4.3

### Story 4.5: Read GraphQL specifications and diffs

As an administrator, I want to browse GraphQL versions and their diffs, so that I can see which grants an activation would affect before I confirm it.
Covers FR-1, FR-31.
Application: `GetGraphQlSpecsQueryHandler`; REST `GET /api/graphql-specs`, `GET /api/graphql-specs/{id}` and `GET /api/graphql-specs/{id}/diff`; GraphQL `graphqlSpecs(...)`, `graphqlSpec(id)` and the field `GraphQlSpec.diff`. The diff reads grants from `iam_role_permissions`. Co-changes: snapshots and pinning tests, the GraphQL-specs feature file, `docs/requests.http`.

**Acceptance Criteria:**
- **Given** versions of several services, **When** they are listed with filters over both interfaces, **Then** each returns service, hash, status, uploader, timestamps and coordinate count, with the SDL only when requested, proven in `make.e2e_tests`.
- **Given** a draft that removes a coordinate granted to a role (grant seeded by a fixture), **When** its diff is read, **Then** the removed coordinate is listed with the affected role, and wildcard grants gaining new coordinates are listed, proven in `make.e2e_tests`.
- **Given** a draft that drops the `@iamSensitive` directive from an active sensitive field, **When** its diff is read over both interfaces, **Then** the field is listed as a flag downgrade, proven in `make.e2e_tests`.
- **Given** an unknown id, **When** it is read, **Then** REST returns 404 and GraphQL `null`, proven in `make.e2e_tests`.
- **Given** the operations are wired, **When** `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass with additions only.

**Depends on:** 1.1, 3.2, 4.4

### Story 4.6: Model OpenAPI specifications and parse JSON documents

As the owner of IAM, I want OpenAPI documents turned into a validated operation set, so that REST operations get permission keys the same way GraphQL fields do.
Covers FR-34, NFR-21.
Domain: `OpenApiSpec` with `RestOperation`, `HttpMethod` and `PathTemplate` (parameter names replaced by `{}`), the events `OpenApiSpecLoaded` and `OpenApiSpecRetired`, and the `OpenApiSpecRepository` and `OpenApiDocumentParser` ports. Application: `JsonOpenApiDocumentParser` for OpenAPI 3.0.x and 3.1.x JSON, resolving only internal `#/` references, rejecting external references, more than 5,000 operations and two operations normalising to the same key, and recording `x-iam-sensitive: true` and `x-iam-audit: always`.

**Acceptance Criteria:**
- **Given** valid 3.0 and 3.1 JSON documents, **When** they are parsed, **Then** the operation set holds method, normalised template, `operationId` label and flags for every operation, proven in `make.unit_tests`.
- **Given** a document with an external `$ref`, **When** it is parsed, **Then** `InvalidSpec` carries the JSON pointer of the reference and nothing is fetched, proven in `make.unit_tests`.
- **Given** a document with two operations that normalise to the same key, more than 5,000 operations or YAML content, **When** it is parsed, **Then** it is rejected with the JSON pointer or the violation, proven in `make.unit_tests`.
- **Given** the JSON decoding available to the application layer, **When** the parser is implemented, **Then** no crate is added to the application allow-list; if that decoding proves unsuitable, the story stops and reports so that the parser moves behind the same port into `iam-infrastructure`, where `serde_json` is allowed after the approved allow-list change, proven in `make.unit_tests`.
- **Given** the story's changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.tests_with_coverage` and `make.mutation_tests_diff` run, **Then** all pass.

**Depends on:** 1.1, 4.1

### Story 4.7: Persist OpenAPI specification versions

As a developer, I want OpenAPI versions stored immutably with their operation set, so that REST catalogue entries can be derived and reproduced.
Covers FR-34, NFR-8.
Infrastructure: the migration `create_iam_openapi_specs_and_permissions` (`iam_openapi_specs`, `iam_openapi_spec_operations`, `iam_rest_permissions`) and `PgOpenApiSpecRepository`. Composition root: the adapter and the three literals. `tests/support`: `FakeOpenApiSpecRepository` and a document fixture.

**Acceptance Criteria:**
- **Given** an uploaded document, **When** the same content is looked up for the same service, **Then** the existing version is found, keyed by the SQL-computed content hash, proven in `make.integration_tests`.
- **Given** versions of several services and statuses, **When** they are listed with filters, **Then** only matching versions are returned, with the document only when requested, proven in `make.integration_tests`.
- **Given** the migration pair created with `make.create_migration` and the queries, **When** `make.setup_test_db`, `make.integration_tests`, `make.sqlx_prepare`, `make.validate_sqlx_metadata`, `make.tests_with_coverage` and `make.mutation_tests_diff` run, **Then** they pass, the down migration is reviewed (its rollback round trip runs when an operator allows it, else it is recorded `not run (ask rule)`) and the regenerated `.sqlx/` metadata is committed.

**Depends on:** 1.1, 2.3, 4.6

### Story 4.8: Load OpenAPI specifications

As a delivery pipeline of a service, I want to upload my OpenAPI document and see its diff, so that new REST operations become permission candidates automatically.
Covers FR-1, FR-34.
Application: `LoadOpenApiSpecCommandHandler`; REST `POST /api/openapi-specs`; GraphQL `loadOpenapiSpec(input)`; the response includes the diff; `iam.openapi_spec.loaded` and the audit record go through the unit of work. Co-changes: snapshots and pinning tests, `features/iam_openapi_specs.feature`, `docs/requests.http`.

**Acceptance Criteria:**
- **Given** a new document, **When** it is uploaded over both interfaces, **Then** a draft version is returned (REST 201) with hash, operation count and diff, and `iam.openapi_spec.loaded` is committed; identical content returns 200 with the existing version, proven in `make.e2e_tests`.
- **Given** a document with an external reference or a duplicate normalised key, **When** it is uploaded, **Then** REST returns 422 with the JSON pointer and GraphQL `VALIDATION_FAILED`, proven in `make.e2e_tests`.
- **Given** a document for the reserved service `iam` uploaded by any actor other than `system:startup`, **When** it is sent, **Then** REST returns 403 and GraphQL `FORBIDDEN`, and no version is stored, proven in `make.e2e_tests`.
- **Given** a body over 6 MiB, **When** it is uploaded, **Then** REST returns 413, proven in `make.e2e_tests`.
- **Given** the operations are wired, **When** `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass with additions only.

**Depends on:** 1.1, 4.4, 4.7

### Story 4.9: Read OpenAPI specifications and diffs

As an administrator, I want to browse OpenAPI versions and their diffs, so that REST changes are as visible as GraphQL changes.
Covers FR-1, FR-35.
Application: `GetOpenApiSpecsQueryHandler`; REST `GET /api/openapi-specs`, `GET /api/openapi-specs/{id}` and `GET /api/openapi-specs/{id}/diff`; GraphQL `openapiSpecs(...)`, `openapiSpec(id)` and the field `OpenApiSpec.diff`. Co-changes: snapshots and pinning tests, the OpenAPI-specs feature file, `docs/requests.http`.

**Acceptance Criteria:**
- **Given** versions of several services, **When** they are listed and read over both interfaces, **Then** both return the version metadata and, when requested, the document, proven in `make.e2e_tests`.
- **Given** a draft removing a granted operation (grant seeded by a fixture), **When** its diff is read, **Then** the removed key is listed with the affected role, and wildcard grants gaining new operations are listed, proven in `make.e2e_tests`.
- **Given** an unknown id, **When** it is read, **Then** REST returns 404 and GraphQL `null`, proven in `make.e2e_tests`.
- **Given** the operations are wired, **When** `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass with additions only.

**Depends on:** 1.1, 4.5, 4.8

## Epic 5: Permission catalogue and role grants

This epic activates specification versions into the GraphQL and REST permission catalogues, handles orphaned grants and lets administrators grant catalogue keys to roles.

### Story 5.1: Model catalogue entries and the orphan policy

As a developer, I want catalogue entries and the orphan rules in the domain, so that activation, retirement and renames behave identically for GraphQL and REST.
Covers FR-32, FR-36, FR-38, NFR-16.
Domain only: `GraphQlPermission` (board `GraphQLPermission`) and `RestPermission` with `PermissionId`, `PermissionKey` and `PermissionFlags`; the `GraphQlPermissionRepository` (board `GraphQLPermissionRepository`) and `RestPermissionRepository` ports; `OrphanPolicy`; the activation result (created keys, flag changes, flag downgrades, orphaned grants, renames); the events `GraphQlPermissionsCreated` and `RestPermissionsCreated` (carrying `createdKeys`, `renamed` and `flagChanges`) and `PermissionsOrphaned`.

**Acceptance Criteria:**
- **Given** a GraphQL coordinate set, **When** catalogue entries are derived, **Then** every `{Type}.{field}`, every root field and `gql:{service}:__introspection` get a key, proven in `make.unit_tests`.
- **Given** a REST operation set, **When** catalogue entries are derived, **Then** each operation gets `rest:{service}:{METHOD} {template}`, proven in `make.unit_tests`.
- **Given** several active versions of one service, **When** the catalogue is computed, **Then** it is the union of their keys, and a key that leaves every active version marks its grants as orphaned, proven in `make.unit_tests`.
- **Given** two active versions of which only one flags a key sensitive or always-audit, **When** the catalogue is computed, **Then** the key carries the most restrictive flags, and an activation that would remove such a flag from the union is reported as a flag downgrade and recorded in `flagChanges` with the old and new flags, proven in `make.unit_tests`.
- **Given** an orphaned grant whose key reappears in a later activation, **When** the policy is applied, **Then** the grant stays inactive, proven in `make.unit_tests`.
- **Given** a rename map from old to new coordinates, **When** it is applied, **Then** grants move to the new key and the rename is part of the activation result, proven in `make.unit_tests`.
- **Given** the domain changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.tests_with_coverage` and `make.mutation_tests_diff` run, **Then** all pass, including property tests of the union and non-reactivation rules.

**Depends on:** 1.1, 4.1, 4.6

### Story 5.2: Persist the permission catalogue and activation

As a developer, I want activation stored atomically with its catalogue entries, orphan marks and version bumps, so that the catalogue never reflects half an activation.
Covers FR-32, FR-36, FR-38, NFR-8.
Infrastructure: `PgGraphQlPermissionRepository` and `PgRestPermissionRepository` (lists with filters for service, type or method, active, sensitive and key prefix, with cursor pagination) and the activation statements contributed to `PgIamUnitOfWork` (create entries, update flags, mark the version active, set `orphaned_at` on grants, apply renames, bump the policy version and the catalogue epoch). The tables exist since Stories 4.3 and 4.7. Composition root: the adapters and the three literals. `tests/support`: the two fakes.

**Acceptance Criteria:**
- **Given** a draft version, **When** its activation commits, **Then** the entries, flags, version status, orphan marks, the policy-version bump and the catalogue-epoch bump become visible together; with a statement forced to fail, none does, proven in `make.integration_tests`.
- **Given** grants on keys that the activation removes from every active version (grants seeded directly), **When** the activation commits, **Then** those grants are inactive with `orphaned_at` set, proven in `make.integration_tests`.
- **Given** a rename map, **When** the activation commits, **Then** the affected grants carry the new keys, proven in `make.integration_tests`.
- **Given** the queries, **When** `make.setup_test_db`, `make.integration_tests`, `make.sqlx_prepare`, `make.validate_sqlx_metadata`, `make.tests_with_coverage` and `make.mutation_tests_diff` run, **Then** they pass and the regenerated `.sqlx/` metadata is committed.

**Depends on:** 1.1, 3.2, 4.3, 4.7, 5.1

### Story 5.3: Activate GraphQL versions (CreateGraphQlPermissions)

As an administrator, I want to activate a GraphQL version so that its fields become grantable permissions, so that new features can be authorized as soon as they ship.
Covers FR-1, FR-2, FR-32.
Application: `CreateGraphQlPermissionsCommandHandler` (board `GraphQLCreatePermissionsCommandHandler`); REST `POST /api/graphql-specs/{id}/permissions`; GraphQL `createGraphqlPermissions(input)` with `confirmOrphans`, `confirmFlagDowngrade` and `renames`; the events `iam.graphql_permissions.created` (with `createdKeys`, `renamed` and `flagChanges`) and, when grants were orphaned, `iam.permissions.orphaned`. The `iam:grant:sensitive` requirement for a confirmed flag downgrade is enforced in Story 6.14; the revocation-class default write mode of an orphaning activation is added by Story 13.8. ADR 0018 (permission catalogue generated from OpenAPI and GraphQL specifications) is added. Co-changes: snapshots and pinning tests, the GraphQL-specs feature file, `docs/requests.http`.

**Acceptance Criteria:**
- **Given** a draft version, **When** it is activated over both interfaces, **Then** the created keys and the new `policyVersion` are returned, the version is active, and `iam.graphql_permissions.created` is committed with `createdKeys`, `renamed` and `flagChanges`, proven in `make.e2e_tests`.
- **Given** an activation that would downgrade a sensitive flag without `confirmFlagDowngrade`, **When** it is sent, **Then** REST returns 409 listing the keys and GraphQL `FLAG_DOWNGRADE_CONFIRMATION_REQUIRED`, proven in `make.e2e_tests`.
- **Given** a committed activation sent with an `Idempotency-Key` (GraphQL `idempotencyKey`), **When** it is replayed with the same key and body, **Then** the original result and `policyVersion` are returned and no second event exists, proven in `make.e2e_tests`.
- **Given** an activation that would orphan grants (seeded by a fixture) without `confirmOrphans`, **When** it is sent, **Then** REST returns 409 listing the grants and GraphQL `ORPHAN_CONFIRMATION_REQUIRED`; with confirmation, the grants are orphaned and `iam.permissions.orphaned` is committed, proven in `make.e2e_tests`.
- **Given** an already active version, **When** it is activated again, **Then** the call is a no-op returning 200, proven in `make.e2e_tests`.
- **Given** two active versions of one service, **When** the catalogue is read, **Then** it holds the union of their keys, proven in `make.e2e_tests`.
- **Given** the operations are wired, **When** `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass with additions only.

**Depends on:** 1.1, 4.5, 5.2

### Story 5.4: Get GraphQL permissions (GetGraphQlPermissions)

As an administrator, I want to browse the GraphQL permission catalogue, so that I can find the keys to grant and see who holds them.
Covers FR-1, FR-33.
Application: `GetGraphQlPermissionsQueryHandler` (board `GraphQLGetPermissionsQueryHandler`); REST `GET /api/graphql-permissions` and `GET /api/graphql-permissions/{id}`; GraphQL `graphqlPermissions(...)` and `graphqlPermission(id)`. Co-changes: snapshots and pinning tests, `features/iam_permissions.feature`, `docs/requests.http`.

**Acceptance Criteria:**
- **Given** an activated catalogue, **When** permissions are listed with the filters `service`, `type`, `active`, `sensitive` and key prefix over both interfaces, **Then** each entry shows key, service, type, field, flags, active state, the versions containing it and the roles granting it, proven in `make.e2e_tests`.
- **Given** an unknown id, **When** it is read, **Then** REST returns 404 and GraphQL `null`, proven in `make.e2e_tests`.
- **Given** the operations are wired, **When** `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass with additions only.

**Depends on:** 1.1, 5.3

### Story 5.5: Activate OpenAPI versions (CreateRestPermissions)

As an administrator, I want to activate an OpenAPI version so that its operations become grantable REST permissions, so that REST and GraphQL are authorized the same way.
Covers FR-1, FR-2, FR-36.
Application: `CreateRestPermissionsCommandHandler`; REST `POST /api/openapi-specs/{id}/permissions`; GraphQL `createRestPermissions(input)`; orphan and flag-downgrade confirmation, most-restrictive flags, renames, multiple active versions and version bumps as in Story 5.3; the events `iam.rest_permissions.created` (with `createdKeys`, `renamed` and `flagChanges`) and `iam.permissions.orphaned`. Co-changes: snapshots and pinning tests, the OpenAPI-specs feature file, `docs/requests.http`.

**Acceptance Criteria:**
- **Given** a draft OpenAPI version, **When** it is activated over both interfaces, **Then** `RestPermission` entries with keys `rest:{service}:{METHOD} {template}` exist, the version is active, and `iam.rest_permissions.created` is committed with `createdKeys`, `renamed` and `flagChanges`, proven in `make.e2e_tests`.
- **Given** an activation that would drop `x-iam-sensitive` from an active operation, **When** it is sent without and then with `confirmFlagDowngrade`, **Then** the first returns 409 (GraphQL `FLAG_DOWNGRADE_CONFIRMATION_REQUIRED`) and the second activates the version and records the flag change, proven in `make.e2e_tests`.
- **Given** a committed activation sent with an `Idempotency-Key` (GraphQL `idempotencyKey`), **When** it is replayed with the same key and body, **Then** the original result is returned and nothing changes a second time, proven in `make.e2e_tests`.
- **Given** an activation that would orphan seeded grants, **When** it is sent without and then with `confirmOrphans`, **Then** the first returns 409 with the grants and the second orphans them and commits `iam.permissions.orphaned`, proven in `make.e2e_tests`.
- **Given** an already active version, **When** it is activated again, **Then** the call is a no-op returning 200, proven in `make.e2e_tests`.
- **Given** the operations are wired, **When** `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass with additions only.

**Depends on:** 1.1, 4.9, 5.2, 5.3

### Story 5.6: Get REST permissions (GetRestPermissions)

As an administrator, I want to browse the REST permission catalogue, so that I can grant REST operations as easily as GraphQL fields.
Covers FR-1, FR-37.
Application: `GetRestPermissionsQueryHandler`; REST `GET /api/rest-permissions` and `GET /api/rest-permissions/{id}`; GraphQL `restPermissions(...)` and `restPermission(id)`. Co-changes: snapshots and pinning tests, the permissions feature file, `docs/requests.http`.

**Acceptance Criteria:**
- **Given** an activated REST catalogue, **When** permissions are listed with the filters `service`, `method`, `active`, `sensitive` and template prefix over both interfaces, **Then** each entry shows key, service, method, template, flags, active state, versions and granting roles, proven in `make.e2e_tests`.
- **Given** an unknown id, **When** it is read, **Then** REST returns 404 and GraphQL `null`, proven in `make.e2e_tests`.
- **Given** the operations are wired, **When** `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass with additions only.

**Depends on:** 1.1, 5.5

### Story 5.7: Manage role permission grants

As an administrator, I want to replace a role's grant set with catalogue keys and wildcards, so that roles express exactly the operations their holders may perform.
Covers FR-1, FR-2, FR-24.
Application: `SetRolePermissionsCommandHandler`; REST `GET /api/roles/{id}/permissions` and `PUT /api/roles/{id}/permissions` with `If-Match`; GraphQL field `Role.permissions` and mutation `setRolePermissions(input)`. Keys must exist in an active catalogue or be one of the four wildcard forms of an existing service; wildcard grants are audited with `coversFutureElements = true`; the change records `iam.role_permissions.changed`, updates the grant count and bumps the policy version. The grant-right rules (`iam:grant:{service}`, `iam:grant:sensitive`, `iam:grant:wildcard`) are added by Story 6.14; the revocation-class default write mode for a replacement that removes a key is added by Story 13.8. Co-changes: snapshots and pinning tests, the roles feature file, `docs/requests.http`.

**Acceptance Criteria:**
- **Given** a role and catalogue keys of two services, **When** its grant set is replaced over both interfaces, **Then** the grants are returned with key, kind, service, active flag and wildcard flag, the policy version is bumped, and `iam.role_permissions.changed` carries the added and removed keys, proven in `make.e2e_tests`.
- **Given** unknown keys or more than 5,000 keys, **When** the grant set is replaced, **Then** REST returns 422 with one violation per unknown key and GraphQL `VALIDATION_FAILED`, proven in `make.e2e_tests`.
- **Given** a wildcard for an existing service, **When** it is granted, **Then** the audit record holds `coversFutureElements = true`, proven in `make.e2e_tests`.
- **Given** a missing or stale version, **When** the replacement is sent, **Then** 428 or 412 is returned, proven in `make.e2e_tests`.
- **Given** the operations are wired, **When** `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass with additions only.

**Depends on:** 1.1, 3.4, 5.3, 5.5

### Story 5.8: Retire versions and confirm orphaned grants

As an administrator, I want to retire specification versions and see orphaned grants handled explicitly, so that removed operations never stay silently grantable.
Covers FR-1, FR-2, FR-38.
Application: `RetireGraphQlSpecCommandHandler` and `RetireOpenApiSpecCommandHandler`, recording `iam.graphql_spec.retired` and `iam.openapi_spec.retired`; REST `POST /api/graphql-specs/{id}/retirement` and `POST /api/openapi-specs/{id}/retirement`; GraphQL `retireGraphqlSpec(input)` and `retireOpenapiSpec(input)`, under the orphan-confirmation rule. This story also adds the end-to-end scenarios for orphan confirmation and renames of Stories 5.3 and 5.5 with grants created through the API of Story 5.7. Purging orphaned grants after retention is Story 7.8. Co-changes: snapshots and pinning tests, the specification feature files, `docs/requests.http`.

**Acceptance Criteria:**
- **Given** an active version whose removal would orphan grants, **When** it is retired without and then with confirmation over both interfaces, **Then** the first returns 409 with the grants and the second retires the version, orphans the grants and commits `iam.permissions.orphaned` and `iam.graphql_spec.retired` (or `iam.openapi_spec.retired`), proven in `make.e2e_tests`.
- **Given** a committed retirement sent with an `Idempotency-Key` (GraphQL `idempotencyKey`), **When** it is replayed with the same key and body, **Then** the original result is returned and no second event exists, proven in `make.e2e_tests`.
- **Given** an orphaned grant, **When** a later version that contains its key is activated, **Then** the grant stays inactive until an administrator grants it again, proven in `make.e2e_tests`.
- **Given** an activation with a rename map over grants created through the API, **When** it is confirmed, **Then** the grants carry the new keys and the rename is audited, proven in `make.e2e_tests`.
- **Given** the operations are wired, **When** `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass with additions only.

**Depends on:** 1.1, 5.4, 5.6, 5.7

## Epic 6: Decision core and IAM self-protection

This epic implements the decision rule that both planes run, the decision API in `iam-control` for REST operations, permission keys and GraphQL documents, single and batch, and then protects IAM's own API with its own catalogue, the bootstrap administrator, caller authorization and escalation guards. It ends with the effective-permission read model.

### Story 6.1: Implement the decision rule and the decision corpus

As the owner of IAM, I want the decision rule implemented as pure domain code with a maintained corpus, so that every allow and deny is provably correct in both planes.
Covers FR-10, NFR-16.
Domain only: `DecisionPolicy`, `WildcardMatcher` (never covering sensitive keys), `CompiledRoleSet`, `AccessCheck` with its targets, `Decision`, `DecisionReason` (the twelve codes of FR-6) and `DecisionOutcome`; the decision corpus as table-driven cases in the domain crate's tests. The same `DecisionPolicy` later runs on inputs from PostgreSQL in `iam-control` and from the snapshot in `iam-gateway`.

**Acceptance Criteria:**
- **Given** a subject holding a key exactly or through a covering wildcard in an active, unexpired global assignment, **When** a check is decided, **Then** it is allowed with `scopes = all`, proven in `make.unit_tests`.
- **Given** a sensitive key and a wildcard that would cover it, **When** a check is decided, **Then** the wildcard does not grant it, proven in `make.unit_tests`.
- **Given** project assignments only, **When** a check carries a matching `projectId`, a different one or none, **Then** it is allowed, denied with `scope_missing`, or allowed with the project ids listed in `scopes`, respectively, proven in `make.unit_tests`.
- **Given** assignments that are expired by the supplied instant or grants that are orphaned, **When** a check is decided, **Then** they contribute nothing and the result is `permission_missing` when no other grant holds the key, proven in `make.unit_tests`.
- **Given** random policies, **When** property tests run, **Then** adding a grant never turns an allow into a deny, removing one never turns a deny into an allow, and the corpus shows zero false allows and zero false denies, proven in `make.unit_tests`.
- **Given** the domain changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.tests_with_coverage` and `make.mutation_tests_diff` run, **Then** all pass.

**Depends on:** 1.1, 2.1

### Story 6.2: Normalise and match REST operations

As the gateway, I want concrete request paths decoded exactly once, matched to the right OpenAPI operation and re-encoded canonically, so that every REST request maps to exactly one permission key or is denied, and the upstream decodes exactly the bytes that were authorized.
Covers FR-7.
Domain only: `PathNormalizer` (single leading slash, no trailing slash, no empty segments, query ignored, percent-decode exactly once) producing `NormalizedPath` and the `CanonicalPath` that the gateway forwards, and `RestOperationMatcher` over `NormalizedPath` and the `PathTemplate` set of a service.

**Acceptance Criteria:**
- **Given** table-driven paths with repeated slashes, a trailing slash, a query string and percent-encoding, **When** they are normalised, **Then** each yields the expected single-leading-slash form, and a property test shows normalisation is idempotent, proven in `make.unit_tests`.
- **Given** paths containing `.` or `..` segments, an encoded slash, a NUL, a backslash or more than 2,048 bytes, **When** they are normalised, **Then** each yields `malformed_operation`, proven in `make.unit_tests`.
- **Given** a path such as `/api/%252e%252e/roles` that still contains `%` after one decode, **When** it is normalised, **Then** the result is `malformed_operation`, never a second decode, proven in `make.unit_tests`.
- **Given** random accepted paths, **When** a property test decodes the `CanonicalPath` once, **Then** the result equals the `NormalizedPath` that was matched, proven in `make.unit_tests`.
- **Given** templates `/api/roles/{id}` and `/api/roles/batch`, **When** `/api/roles/batch` is matched, **Then** the literal template wins, and the key is `rest:{service}:{METHOD} /api/roles/batch`; parameterised matches use `{}` in the key, proven in `make.unit_tests`.
- **Given** a path with no matching template, **When** it is matched, **Then** the result is `unknown_operation`, proven in `make.unit_tests`.
- **Given** the domain changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.tests_with_coverage` and `make.mutation_tests_diff` run, **Then** all pass.

**Depends on:** 1.1, 4.6

### Story 6.3: Read policy data in one snapshot

As the owner of IAM, I want a subject's assignments, the role sets and the service catalogue read together with the policy version, so that every decision in `iam-control` is based on one consistent state.
Covers FR-10, NFR-28.
Domain: the `PolicyReadRepository` port and the `ServiceCatalog` value. Application: `ServiceCatalogLoader`. Infrastructure: `PgPolicyReadRepository`, which reads the subject's assignment list, the compiled role sets (active grants only), the active REST templates and GraphQL type graph of a service, and the current `PolicyEpoch` in one repeatable-read snapshot. Composition root: the adapter and the three literals. `tests/support`: `FakePolicyReadRepository`.

**Acceptance Criteria:**
- **Given** a write committing concurrently with a read, **When** the read returns, **Then** its data and its policy version come from the same snapshot (either both before or both after the write), proven in `make.integration_tests`.
- **Given** a test hook that commits a role revocation after the assignment rows are read and before the epoch is read, **When** the load runs in its `REPEATABLE READ READ ONLY` transaction, **Then** the returned stamp is the pre-commit version, never the new one, proven in `make.integration_tests`.
- **Given** expired assignments and orphaned grants, **When** policy data is read, **Then** assignments carry their expiry for evaluation by the `Clock` port and orphaned grants are excluded from the compiled sets, proven in `make.integration_tests`.
- **Given** a service without an active version, **When** its catalogue is loaded, **Then** the result is absent, which the decision path maps to `unknown_service`, proven in `make.integration_tests`.
- **Given** the queries, **When** `make.setup_test_db`, `make.integration_tests`, `make.sqlx_prepare`, `make.validate_sqlx_metadata`, `make.tests_with_coverage` and `make.mutation_tests_diff` run, **Then** they pass and the regenerated `.sqlx/` metadata is committed.

**Depends on:** 1.1, 3.5, 5.2, 6.1

### Story 6.4: Resolve required keys and decide, failing closed

As a caller of the decision API, I want one decision service that never allows on error, so that an outage or a bug can only deny.
Covers FR-6, FR-9, FR-13.
Application: `RequiredKeyResolver` (REST through the domain matcher, permission keys through the key parser and catalogue lookup; the GraphQL branch follows in Story 6.7) and `AccessDecisionService` (subject token through `TokenRepository` with the token reasons, required keys, policy data from `PolicyReadRepository`, `DecisionPolicy`, decision id from `UuidGenerator`). Every error in token resolution, catalogue loading or policy reads becomes `deny` with `unavailable`. There is no cache, no stale-grace window and no database fallback; the gateway feeds the same service from `PolicyView` in Story 10.2, where a stale snapshot also yields `unavailable`.

**Acceptance Criteria:**
- **Given** 1 to 100 permission keys for the request's service, **When** some are unknown or belong to another service, **Then** the result is `deny` with `unknown_operation` and the offending keys in `denied`; reserved `iam:` keys are accepted, proven in `make.unit_tests`.
- **Given** credentials that are missing, invalid, expired or revoked, **When** a check is decided, **Then** the reason is the matching `token_*` code, proven in `make.unit_tests`.
- **Given** the `failing()` fakes of `TokenRepository`, `PolicyReadRepository` and the catalogue loader, **When** a check is decided, **Then** every result is `deny` with `unavailable` and none is `allow`, proven in `make.unit_tests`.
- **Given** an unknown service, **When** a check is decided, **Then** the reason is `unknown_service`, proven in `make.unit_tests`.
- **Given** the application changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.tests_with_coverage` and `make.mutation_tests_diff` run, **Then** all pass.

**Depends on:** 1.1, 2.6, 6.2, 6.3

### Story 6.5: Validate REST operations and permission keys

As a microservice, I want to ask IAM whether a subject may perform a REST operation or hold permission keys, so that I can enforce access centrally where the gateway's route check is not enough.
Covers FR-1, FR-6, FR-7, FR-9, FR-14.
Application: `ValidateAccessQueryHandler` (board name); REST `POST /api/access-validations`; GraphQL query `validateAccess(input)` with the `rest` and `permissions` target forms, `projectId`, `minPolicyVersion` and `requestId`. A valid request always returns 200 with a decision body. In `iam-control` a `minPolicyVersion` above the current policy version returns 422; the gateway's bounded wait follows in Story 10.10, and the gateway's decision listener serves the same operation in Story 10.11. Co-changes: snapshots and pinning tests, `features/iam_access_validation.feature`, `docs/requests.http`.

**Acceptance Criteria:**
- **Given** roles, grants and assignments created through the API, **When** checks are sent over REST and over GraphQL, **Then** both return equivalent decisions with `decision`, `reason`, `denied`, `scopes`, `subject`, `decisionId`, `policyVersion` and the echoed `requestId`, covering `allowed`, every `token_*` reason, `unknown_service`, `unknown_operation`, `malformed_operation`, `permission_missing` and `scope_missing`, proven in `make.e2e_tests`.
- **Given** a request with no target form, two target forms or more than 100 keys, **When** it is sent, **Then** REST returns 422 and GraphQL `VALIDATION_FAILED`; no other non-200 status describes the subject's decision, proven in `make.e2e_tests`.
- **Given** a `minPolicyVersion` above the current policy version, **When** it is sent over REST and over GraphQL, **Then** REST returns 422 and GraphQL `VALIDATION_FAILED`, proven in `make.e2e_tests`.
- **Given** an assignment that is then revoked, or a role that is then deleted, **When** the former holder is checked on `iam-control`, **Then** the decision is `deny` immediately, proven in `make.e2e_tests`.
- **Given** an activated OpenAPI version, **When** an integration test validates concrete paths, **Then** matching uses that version's templates, proven in `make.e2e_tests`.
- **Given** a failing database injected in an integration test, **When** a check is sent, **Then** the response is 200 with `deny` and `unavailable`, proven in `make.e2e_tests`.
- **Given** the operations are wired, **When** `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass with additions only.

**Depends on:** 1.1, 2.8, 5.7, 5.8, 6.4

### Story 6.6: Extract GraphQL coordinates with parser limits

As the owner of IAM, I want GraphQL documents reduced to the schema coordinates they touch under strict limits, so that hostile documents are refused cheaply and every touched field, subscription roots included, is checked.
Covers FR-8, NFR-21.
Domain: the `GraphQlDocumentAnalyzer` port, `DocumentLimits` (64 KiB at the decision API, depth 15, 500 coordinates, 50 aliases, 100 fragments) and `DocumentKey` (a 128-bit hash of the document plus the operation name plus the catalogue version; a cache hit counts only after a full-text comparison of the document). Application: `AsyncGraphQlDocumentAnalyzer`, which selects the operation, resolves fragments, inline fragments and type conditions against the active type graph, uses interface coordinates outside concrete fragments, maps the root fields of subscription operations to `Subscription.z` coordinates, ignores `__typename` and maps `__schema` and `__type` to `gql:{service}:__introspection`. The document cache itself (`MokaDocumentCache`) follows in Story 10.8.

**Acceptance Criteria:**
- **Given** documents with named and inline fragments, interfaces, aliases, introspection and a subscription operation, **When** they are analysed, **Then** the coordinate sets match the expected `Query.x`, `Mutation.y`, `Subscription.z` and `{Type}.{field}` sets, proven in `make.unit_tests`.
- **Given** a document over 64 KiB, deeper than 15, with more than 500 coordinates, 50 aliases or 100 fragments, **When** it is analysed, **Then** the result is `limits_exceeded` and the check runs before resolution, proven in `make.unit_tests`.
- **Given** a document that does not parse, does not validate against the type graph, or names a missing or unknown operation, **When** it is analysed, **Then** the result is `malformed_operation`; a field unknown to every active version is `unknown_operation`, proven in `make.unit_tests`.
- **Given** two different documents forced to the same 128-bit hash by a test hook, the same document with another operation name, and the same document under another catalogue version, **When** their `DocumentKey` values are compared for a cache hit, **Then** the full-text comparison tells the first pair apart and the other two produce different keys, proven in `make.unit_tests`.
- **Given** the story's changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.tests_with_coverage` and `make.mutation_tests_diff` run, **Then** all pass.

**Depends on:** 1.1, 4.2

### Story 6.7: Validate GraphQL documents

As the gateway, I want to validate whole GraphQL documents, so that a request is allowed only when every field it selects is permitted.
Covers FR-1, FR-6, FR-8.
Application: the GraphQL branch of `RequiredKeyResolver` and the `graphql {document, operationName?}` target form of `validateAccess` on both interfaces; decisions are all-or-nothing and `denied` lists every denied coordinate. Co-changes: snapshots and pinning tests, the access-validation feature file, `docs/requests.http`.

**Acceptance Criteria:**
- **Given** a subject holding some of the coordinates a document selects, **When** it is validated over REST and over GraphQL, **Then** both deny and list every denied coordinate; holding all of them allows, proven in `make.e2e_tests`.
- **Given** a document exceeding a limit, **When** it is validated, **Then** the decision is `deny` with `limits_exceeded`, proven in `make.e2e_tests`.
- **Given** a newly activated GraphQL version, **When** an integration test validates a document using one of its new fields, **Then** the decision is evaluated against the new catalogue, proven in `make.e2e_tests`.
- **Given** the operations are wired, **When** `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass with additions only.

**Depends on:** 1.1, 6.5, 6.6

### Story 6.8: Validate checks in batches

As a caller of the decision API, I want to validate up to 100 checks in one call, so that pages that need many decisions do not need many round trips.
Covers FR-1, FR-11.
Application: `ValidateAccessBatchQueryHandler`; REST `POST /api/access-validations/batch`; GraphQL query `validateAccessBatch(inputs)`; results in request order, each with its own `decisionId`; each distinct credential resolved once per batch. Co-changes: snapshots and pinning tests, the access-validation feature file, `docs/requests.http`.

**Acceptance Criteria:**
- **Given** a batch mixing allowed, denied and malformed checks, **When** it is sent over both interfaces, **Then** one result per check is returned in request order, and malformed items are `deny` with their reason without failing the others, proven in `make.e2e_tests`.
- **Given** a batch with 101 checks or none, **When** it is sent, **Then** REST returns 422 and GraphQL `VALIDATION_FAILED`, proven in `make.e2e_tests`.
- **Given** a batch using two distinct credentials across 50 checks, **When** an integration test counts token resolutions, **Then** exactly two resolutions happen, proven in `make.e2e_tests`.
- **Given** the operations are wired, **When** `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass with additions only.

**Depends on:** 1.1, 6.7

### Story 6.9: Register IAM's own specifications at startup

As the owner of IAM, I want IAM's own operations registered in its catalogue at startup, so that IAM's admin API is authorized by the same model it serves.
Covers FR-4, FR-45.
Application: `RegisterOwnSpecsCommandHandler`, which loads IAM's generated OpenAPI operations (filtered by the `iam` tag) and its IAM-owned GraphQL coordinates as specifications of service `iam` and activates them additively and idempotently by content hash, with actor `system:startup`: a new IAM version is activated beside the older active ones and nothing is orphaned. Composition root: the reusable `bootstrap::register_iam_specs(&adapters)` (under a PostgreSQL transaction-level advisory lock), and `bootstrap/tasks.rs` with `TaskSupervisor` and `bootstrap::start_tasks(&adapters, mode, shutdown)` for per-replica tasks (empty until later stories register theirs), with graceful shutdown within `SHUTDOWN_GRACE_PERIOD`; `command/serve.rs` calls both after `Adapters::connect`; `serve.rs` and its tests are added to `.templatesyncignore` in this story. Co-changes: `tests/e2e/world.rs` calls `bootstrap::register_iam_specs` and `bootstrap::start_tasks` for every scenario database, because it builds the app from `Adapters` and `router` without `serve::run`.

**Acceptance Criteria:**
- **Given** a fresh database, **When** the service starts, **Then** the catalogue holds keys such as `rest:iam:POST /api/roles` and `gql:iam:Mutation.createRole`, and the `iam` versions are active, proven in `make.integration_tests`.
- **Given** a second start of the same build, **When** registration runs, **Then** no new version, event or audit record is created, proven in `make.integration_tests`.
- **Given** two instances starting concurrently, **When** both reach registration, **Then** exactly one registers and the other finds the active version, proven in `make.integration_tests`.
- **Given** a build whose IAM contract removes an operation, **When** it starts, **Then** the new version is activated beside the older active version, no grant is orphaned, and the activation is audited with actor `system:startup`, proven in `make.integration_tests`.
- **Given** IAM contract versions 2, then 1, then 2 registered in that order (a rolling deployment with a rollback), **When** the catalogue is read after each registration, **Then** no grant on an IAM key is orphaned at any point, proven in `make.integration_tests`.
- **Given** an e2e scenario database, **When** the e2e world prepares it, **Then** IAM's own specifications are registered and the task supervisor is running, exactly as under `service serve`, proven in `make.e2e_tests`.
- **Given** SIGTERM with a per-replica test task in flight, **When** shutdown runs, **Then** the task stops within `SHUTDOWN_GRACE_PERIOD`, proven in `make.integration_tests`.
- **Given** the seam file changed, **When** `make.validate_invariants`, `make.integration_tests`, `make.e2e_tests`, `make.tests_with_coverage` and `make.mutation_tests_diff` run, **Then** all pass, and the seam check of Story 1.2, extended with `command/serve.rs` and its tests, shows that `.templatesyncignore` covers them in `make.integration_tests`.

**Depends on:** 1.1, 1.2, 5.3, 5.5

### Story 6.10: Bootstrap the first administrator

As an operator, I want a CLI command that creates the first IAM administrator, so that a new environment can be administered without a backdoor in the API.
Covers FR-5.
Application: `BootstrapIamCommandHandler` and the domain `LastAdministratorGuard` applied in `UpdateUserRoleCommandHandler` and `RevokeUserRoleCommandHandler` (409 `LAST_ADMINISTRATOR`, audited). Composition root: `command/iam_bootstrap.rs`, declared with its dispatch arm in `command.rs`, which is added to `.templatesyncignore` in this story, and the subcommand `service iam-bootstrap --admin-user <uuid>` or `--admin-service <service-name>` in `cli.rs` (run in production as the `iam-bootstrap` Job). Under a transaction-level advisory lock it first calls `bootstrap::register_iam_specs`, then creates the system role `iam-platform-admin` with `rest:iam:*`, `gql:iam:*` and every reserved key: `iam:validate:*`, `iam:grant:*`, `iam:grant:sensitive`, `iam:grant:wildcard`, `iam:spec:*`, `iam:audit:read`, `iam:revoke:sessions`, `iam:revoke:global`, `iam:policy:resync`, `iam:route:anonymous` and `iam:route:*`, assigns it globally and audits with actor `system:bootstrap`. Story 8.7 extends the same command to seed IAM's own upstream and routes. Co-changes: the e2e world bootstraps an administrator before the scenarios; the Schemathesis credential target of Story 2.8 first bootstraps its service principal with `--admin-service`; `docs/operations.md` documents the command and the break-glass procedure.

**Acceptance Criteria:**
- **Given** an empty IAM database, **When** `service iam-bootstrap --admin-user <uuid>` runs, **Then** it exits 0, IAM's own specifications are registered, the system role with exactly the keys listed above and the global assignment exist, and an audit record with actor `system:bootstrap` is committed, proven in `make.integration_tests`.
- **Given** an empty IAM database, **When** `service iam-bootstrap --admin-service schemathesis` runs, **Then** it exits 0 and the assignment's subject is the service principal `schemathesis`, proven in `make.integration_tests`.
- **Given** an active assignment of `iam-platform-admin`, **When** the command runs again, **Then** it exits 1 and nothing changes, proven in `make.integration_tests`.
- **Given** two bootstrap runs started concurrently on an empty database, **When** both finish, **Then** exactly one exits 0, the other exits 1, and one administrator assignment exists, proven in `make.integration_tests`.
- **Given** an invalid UUID, both or neither of the two subject options, or invalid configuration, **When** the command runs, **Then** it exits 2 with a message, proven in `make.integration_tests`.
- **Given** the bootstrapped system role, **When** an administrator tries to rename or delete it through either interface, **Then** the request is refused with 403 (GraphQL `FORBIDDEN`), proven in `make.integration_tests`.
- **Given** a single active global assignment of `iam-platform-admin`, **When** it is revoked or given an expiry over either interface, **Then** REST returns 409 and GraphQL `LAST_ADMINISTRATOR`, the assignment is unchanged, and the refusal is audited, proven in `make.e2e_tests`.
- **Given** the story's changes, **When** `make.validate_invariants`, `make.integration_tests`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass, and the seam check of Story 1.2, extended with `command.rs`, shows that `.templatesyncignore` covers it in `make.integration_tests`.

**Depends on:** 1.1, 1.2, 3.8, 6.9

### Story 6.11: Enforce IAM keys on IAM's REST operations

As the owner of IAM, I want every IAM REST operation to require its key under the rule of FR-4, so that administrators can only do what their roles allow and refused attempts are recorded without slowing the service.
Covers FR-4, FR-49, NFR-22.
Application: `IamAccessGuard` over `AccessDecisionService` with the rule table of FR-4: the decision API needs `iam:validate:*` or `iam:validate:{service}` and token resolution the rule of Story 6.13, with no catalogue key; access-log, audit and revocation reads need `iam:audit:read`; revoking sessions and user cut-offs need `iam:revoke:sessions`; the global cut-off needs `iam:revoke:global`; the resync needs `iam:policy:resync`; setting `anonymous = true` or `enforcement = audit` on a route needs `iam:route:anonymous` in addition to the route's catalogue key; every other operation needs its catalogue key plus the reserved keys of FR-25 and FR-30 where they apply. Rows for operations delivered by later stories are added by those stories. `RecordRejectedAttemptCommandHandler` offers the attempt without awaiting to `BufferedRejectedAttemptLog` (summarising identical attempts per actor, action and reason within 60 seconds); the per-replica `RejectedAttemptWriter` loop appends buffered records at most every second through `PgSecurityAuditLog::append_batch`; `IamError::Forbidden` maps to 403 and `FORBIDDEN`. This is the enforcement in `iam-control` against PostgreSQL; the gateway applies the same rule first from the snapshot in Story 10.2. Composition root: the guard as `route_layer` on the IAM router in `http/router.rs`, and `RejectedAttemptWriter` registered with `bootstrap::start_tasks`. Co-changes: new REST scenarios for subjects lacking keys.

**Acceptance Criteria:**
- **Given** a subject without the operation's catalogue key, **When** it calls an IAM REST operation, **Then** REST returns 403 with a problem, and within one second the audit log holds a rejected-attempt record with actor, action and outcome `Rejected`, proven in `make.unit_tests`.
- **Given** a subject holding `iam:validate:*` but no catalogue key, **When** it validates access over REST, **Then** the check is decided, because validation needs the reserved key only, proven in `make.unit_tests`.
- **Given** the rule table, **When** a unit test checks every row against the reserved keys of FR-4, **Then** each reserved-key operation names exactly its reserved key, no row names `iam:cache:flush`, and an operation missing from the table is refused, proven in `make.unit_tests`.
- **Given** 1,000 identical refused requests from one actor within 60 seconds, **When** the writer flushes, **Then** one summarised rejected-attempt record with a count of 1,000 is appended and no request waited for the chain-head lock, proven in `make.integration_tests`.
- **Given** a request with no valid token, **When** it is refused with 401, **Then** no audit record is written, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.integration_tests`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass.

**Depends on:** 1.1, 2.2, 6.8, 6.10

### Story 6.12: Enforce IAM keys on IAM's GraphQL fields and move scenarios onto the administrator

As the owner of IAM, I want IAM's GraphQL fields protected by the same rule as its REST operations, so that both interfaces enforce identical authorization.
Covers FR-1, FR-4.
Application: `IamAuthorizationExtension`, an `async-graphql` extension that, when a document selects any IAM-owned field, requires a principal and runs `IamAccessGuard` over the IAM coordinates before execution; refusals map to `FORBIDDEN` and are offered to `BufferedRejectedAttemptLog`. Composition root: the extension on the schema builder in `bootstrap.rs`. Co-changes: every earlier IAM feature file authenticates as the bootstrapped administrator, and new GraphQL scenarios cover subjects lacking keys.

**Acceptance Criteria:**
- **Given** a subject without the operation's key, **When** it calls an IAM operation over GraphQL, **Then** GraphQL returns `FORBIDDEN` and the audit log holds a rejected-attempt record, matching the REST behaviour of Story 6.11, proven in `make.e2e_tests`.
- **Given** the bootstrapped administrator, **When** it calls every IAM operation delivered so far over REST and over GraphQL, **Then** each succeeds as before, proven in `make.e2e_tests`.
- **Given** a GraphQL document selecting only example-context fields without a token, **When** it is executed, **Then** it behaves as in the template, proven in `make.e2e_tests`.
- **Given** a GraphQL document selecting an IAM field without a token, **When** it is executed, **Then** the extension returns `UNAUTHENTICATED`, proven in `make.e2e_tests`.
- **Given** the story's changes, **When** `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass with no breaking change.

**Depends on:** 1.1, 6.11

### Story 6.13: Authorize callers of validation and token resolution

As the owner of IAM, I want a service to validate only for itself unless it holds a broader key, so that a compromised service cannot use IAM as an oracle for another service's policy.
Covers FR-12.
Application: the caller rule in `IamAccessGuard` and `IamAuthorizationExtension`: validating for target service `s` requires `iam:validate:s` or `iam:validate:*` (every item of a batch is checked), and token resolution requires `iam:validate:{caller's service name}` for a service caller or `iam:validate:*` for any caller; no catalogue key is required for these operations; refusals return 403 and are audited. Co-changes: the access-validation and token-resolution feature files.

**Acceptance Criteria:**
- **Given** a service principal `core` holding `iam:validate:core`, **When** it validates a check for `core`, **Then** the check is decided, proven in `make.e2e_tests`.
- **Given** a service principal `core` holding `iam:validate:core`, **When** it validates a check for `payment`, **Then** REST returns 403 (GraphQL `FORBIDDEN`) and a rejected-attempt record is audited, proven in `make.e2e_tests`.
- **Given** a service principal holding `iam:validate:*`, **When** it validates checks for any service, **Then** each is decided, proven in `make.e2e_tests`.
- **Given** a batch with one item for a service the caller may not validate, **When** it is sent, **Then** the whole request returns 403, proven in `make.e2e_tests`.
- **Given** a service caller without `iam:validate:{its service name}` or `iam:validate:*`, **When** it resolves a token, **Then** 403 is returned, proven in `make.e2e_tests`.
- **Given** the bootstrapped user administrator, who holds `iam:validate:*`, **When** it resolves a token over REST and over GraphQL, **Then** the token is resolved, proven in `make.e2e_tests`.
- **Given** the story's changes, **When** `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass.

**Depends on:** 1.1, 6.12

### Story 6.14: Guard against privilege escalation and cross-service specification changes

As a security officer, I want administrators unable to grant, assign or change specifications beyond their administrative rights, so that no one can raise their own privileges or rewrite another service's catalogue.
Covers FR-24, FR-25, FR-30, FR-34.
Domain: `EscalationGuard` and `SpecScopeGuard`. Application: `EscalationGuard` in `SetRolePermissionsCommandHandler`, `AssignUserRoleCommandHandler`, `UpdateUserRoleCommandHandler` and `RevokeUserRoleCommandHandler` (`iam:grant:{service}` or `iam:grant:*` at global scope for every key, plus `iam:grant:sensitive` for sensitive keys and `iam:grant:wildcard` for wildcards; no action on an assignment whose subject is the actor); `SpecScopeGuard` in the load, activation and retirement handlers of both interfaces (`iam:spec:{service}` or `iam:spec:*`, which never covers `iam`; a confirmed flag downgrade also needs `iam:grant:sensitive`); violations return 403 and are audited. Both guards run against PostgreSQL inside the write transaction. Co-changes: the roles, user-roles and specification feature files.

**Acceptance Criteria:**
- **Given** the bootstrapped administrator and a custom role, **When** it grants a `core` key and a sensitive `core` key to the role over REST and over GraphQL, **Then** both grants succeed, proven in `make.e2e_tests`.
- **Given** an actor holding `iam:grant:core` only at project scope, **When** it grants a `core` key to a role, **Then** 403 is returned and the attempt is audited, proven in `make.unit_tests`.
- **Given** an actor holding `iam:grant:core` but not `iam:grant:sensitive`, **When** it grants a sensitive `core` key, **Then** 403 is returned, proven in `make.unit_tests`.
- **Given** an actor without `iam:grant:wildcard`, **When** it grants a wildcard over REST and over GraphQL, **Then** both return 403 (GraphQL `FORBIDDEN`), proven in `make.e2e_tests`.
- **Given** a role granting `payment` keys and an actor holding only `iam:grant:core`, **When** the actor assigns the role, **Then** 403 is returned, proven in `make.unit_tests`.
- **Given** an actor that is a user or a service principal, **When** it creates, changes or revokes an assignment whose subject is itself, **Then** 403 is returned, proven in `make.unit_tests`.
- **Given** a delivery pipeline principal holding `iam:spec:core`, **When** it uploads an SDL for `core` and then one for `payment`, **Then** the first is stored and the second returns 403, proven in `make.unit_tests`.
- **Given** an actor holding `iam:spec:*`, **When** it retires a version of service `iam`, **Then** 403 is returned, because only `iam:spec:iam` covers IAM's own specifications, proven in `make.unit_tests`.
- **Given** an actor holding `iam:spec:core` but not `iam:grant:sensitive`, **When** it activates a `core` version with `confirmFlagDowngrade = true`, **Then** 403 is returned and the flags are unchanged, proven in `make.unit_tests`.
- **Given** the domain and application changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass.

**Depends on:** 1.1, 5.7, 5.8, 6.12

### Story 6.15: Expose effective permissions (UserRolePermission)

As an administrator, I want to see a user's effective permissions with the roles and scopes behind them, so that I can answer "why can this user do that?".
Covers FR-1, FR-39, NFR-16.
Domain: `EffectivePermissionComposer` and the `UserRolePermission` read model (board name) with `EffectivePermission` entries. Application: `GetUserRolePermissionsQueryHandler`, computed by `iam-control` from PostgreSQL; REST `GET /api/users/{userId}/role-permissions`; GraphQL `userRolePermissions(userId, projectId, service)`. Co-changes: snapshots and pinning tests, `features/iam_effective_permissions.feature`, `docs/requests.http`, ADR 0020 (effective permissions composed at check time).

**Acceptance Criteria:**
- **Given** a user with global and project assignments, **When** the read model is requested over both interfaces, **Then** each held key or wildcard is listed with its granting roles, its scopes (`all` or project ids), the shortest contributing expiry and the `policyVersion`, proven in `make.e2e_tests`.
- **Given** random policies, **When** a property test compares the read model with `DecisionPolicy`, **Then** the read model's key set equals the set of keys the decision rule allows, proven in `make.e2e_tests`.
- **Given** a subject lacking the operation's key, **When** it requests the read model, **Then** 403 is returned, proven in `make.e2e_tests`.
- **Given** the operations are wired, **When** `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass with additions only.

**Depends on:** 1.1, 6.3, 6.12

## Epic 7: Policy replication from the control plane

This epic turns every versioned write into state records on the ordered state topic `iam.policy.state.v1`: singleton fencing, state records with the version digest and `__head`, the Kafka configuration gates, the fenced outbox relay, IAM events on `iam.events.v1`, the `published` write mode, anti-entropy with shadow bootstrap, maintenance, bulk operations and the resync that replaces the cache flush. It starts only after Story 1.7 has recorded krafka as accepted.

### Story 7.1: Fence singleton tasks with advisory-lock leadership

As an operator, I want exactly one `iam-control` replica to run each batch of a singleton task, so that the control plane needs no separate worker deployment and two leaders can never act at once.
Covers FR-45.
Domain: the `SingletonLeadership` port. Infrastructure: `AdvisoryLockLeadership`, its adapter, which opens each singleton batch transaction with `pg_try_advisory_xact_lock(<task constant>)` and reports whether this replica leads the batch; the migration `create_iam_task_state` and its repository. Application: the singleton loop helper that skips a batch without the lock and retries at the task's next interval (at most 10 seconds). Composition root: `bootstrap::start_tasks` gains the singleton set for `service serve`. There is no `service worker` mode; the gateway task set of `service gateway` follows in Story 9.2.

**Acceptance Criteria:**
- **Given** two `iam-control` instances running a singleton test task, **When** an integration test observes them, **Then** no batch ever runs on both at once, proven in `make.integration_tests`.
- **Given** the lock holder's connection terminated with `pg_terminate_backend` in the middle of a batch, **When** the other instance runs its next batch, **Then** the first batch was rolled back and the two batches never overlapped, proven in `make.integration_tests`.
- **Given** the leader stops, **When** at most one retry interval passes, **Then** the other instance runs the next batch, proven in `make.integration_tests`.
- **Given** SIGTERM during an in-flight singleton batch, **When** shutdown runs, **Then** the batch commits or rolls back and the process exits within `SHUTDOWN_GRACE_PERIOD` with the template's exit codes, proven in `make.integration_tests`.
- **Given** the CLI, **When** `service worker` is invoked, **Then** it is rejected as an unknown subcommand with exit code 2, proven in `make.integration_tests`.
- **Given** the migration pair created with `make.create_migration` and the queries, **When** `make.setup_test_db`, `make.integration_tests`, `make.sqlx_prepare`, `make.validate_sqlx_metadata`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** they pass and the down migration is reviewed (its rollback round trip runs when an operator allows it, else it is recorded `not run (ask rule)`).

**Depends on:** 1.1, 1.7, 6.9

### Story 7.2: Write policy state records, the version digest and `__head`

As the owner of IAM, I want every versioned transaction to write the full new state of each changed entity, a running digest and a version head into the outbox, so that the gateway can rebuild and verify the complete policy from the state topic alone.
Covers FR-70, NFR-8.
Domain: `StateKey` (the keys `role/<uuid>`, `subject/<kind>/<id>`, `catalog/<service>/manifest`, `catalog/<service>/<catVer>/<chunk>`, `route/<id>`, `upstream/<name>`, `ratepolicy/<id>`, `revocation/session/<sid>`, `revocation/user/<uid>`, `revocation/global` and `__head`, parsed and printed), `StateRecord`, the `StateRecordCodec` and `PolicyDigest` ports and `InvalidStateRecord`. Infrastructure: `JsonStateRecordCodec` (canonical JSON with `schemaVersion`; the same state always encodes to the same bytes) and `Sha256PolicyDigest` (entity hash = first 16 bytes of SHA-256 of key and canonical state; `digest ^= h_old ^ h_new`, computed in Rust). `PgIamUnitOfWork` now writes, for every changed entity of a versioned transaction, one outbox state row (`kind = state`, topic `iam.policy.state.v1`, the state key, the full new state or a null tombstone, `policy_version`, `seq`, `count`, `digest_after`, `log_epoch`) plus one `__head` row `{version, digest}`, and stores the new digest in `iam_policy_epoch`. This story emits the role, subject (the full assignment list of the subject) and catalogue records (a manifest plus content-addressed chunks of at most 1 MiB; unchanged chunks are not written again) from every write handler of Epics 3 to 6; the gateway-configuration records follow in Story 8.2 and the revocation records in Story 13.1. No migration is needed: the outbox columns exist since Story 2.3.

**Acceptance Criteria:**
- **Given** a role created through the API, **When** the transaction commits, **Then** the outbox holds one state row with key `role/<uuid>`, the full role state with `schemaVersion`, the transaction's version, `seq` 1 of `count` 2, and a `__head` row as the last record of the version carrying the version and the new digest, proven in `make.integration_tests`.
- **Given** a role deleted with two assignments, **When** the transaction commits, **Then** the role row is a null tombstone, each affected subject has a `subject/<kind>/<id>` row with its remaining assignment list, and `seq` runs 1 to `count` without a gap, proven in `make.unit_tests`.
- **Given** a catalogue activation, **When** it commits, **Then** a manifest and chunks of at most 1 MiB are written, and a second activation that leaves a chunk unchanged does not write that chunk again, proven in `make.unit_tests`.
- **Given** any committed versioned transaction, **When** the rows are read, **Then** the `digest_after` of its last record equals `iam_policy_epoch.digest`, proven in `make.unit_tests`.
- **Given** random sequences of role, assignment and catalogue changes, **When** a property test replays their state rows into an empty map (highest version per key wins, tombstones delete) and computes the digest, **Then** it equals the PostgreSQL digest, and applying the same changes in another order of entities within one version gives the same digest, proven in `make.integration_tests`.
- **Given** a transaction with a statement forced to fail, or a transaction that does not affect decisions, **When** it ends, **Then** no state row and no `__head` row exist and the digest is unchanged, proven in `make.unit_tests`.
- **Given** each state kind, **When** the codec encodes and decodes it, **Then** the round trip returns the same state and the same bytes, proven in `make.unit_tests`.
- **Given** the story's changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.setup_test_db`, `make.integration_tests`, `make.sqlx_prepare`, `make.validate_sqlx_metadata`, `make.tests_with_coverage` and `make.mutation_tests_diff` run, **Then** all pass and the regenerated `.sqlx/` metadata is committed.

**Depends on:** 1.1, 1.7, 2.3, 3.8, 5.8

### Story 7.3: Check Kafka topic configuration and ACLs from the control plane

As the owner of IAM, I want `iam-control` to refuse to publish to a state topic whose configuration could lose or reorder records, so that the freshness guarantees never rest on a misconfigured topic.
Covers FR-54, FR-55, FR-72.
Prerequisite: Story 1.7 records krafka as accepted, and the approved allow-list change adds `krafka` to the infrastructure layer. Domain: the `KafkaTopicInspector` port. Infrastructure: `KrafkaTopicInspector` (`DescribeConfigs` for the topic and the broker, `DescribeAcls`), returning a configuration verdict: cleanup policy `compact`, unclean leader election off, `min.insync.replicas` 2, replication factor 3, exactly one partition and `message.timestamp.type=LogAppendTime`, plus the ACL checks (only `iam-control` may write the state topic; `allow.everyone.if.no.acl.found=false`, read with `DescribeConfigs` on the cluster, which the `iam-control` principal is granted, or checked through the fallback that Story 1.3 recorded when the broker does not return the setting). Composition root: the control-plane Kafka variables (`KAFKA_BOOTSTRAP_SERVERS`, `KAFKA_SECURITY_PROTOCOL`, `KAFKA_SASL_MECHANISM`, `KAFKA_SASL_USERNAME`, `KAFKA_SASL_PASSWORD`, `KAFKA_CA_FILE`, `KAFKA_CLIENT_ID`, `KAFKA_CONNECT_TIMEOUT`, `KAFKA_REQUEST_TIMEOUT`, `KAFKA_RETRY_DELAY`, `KAFKA_CONFIG_GATES`, `POLICY_TOPIC`, `EVENTS_TOPIC`) with hidden secret values, their `docs/environment.md` rows and local defaults (`KAFKA_CONFIG_GATES=relaxed` and `PLAINTEXT` in `.env` and `.env.test`); the `Kafka` variant of `Dependency` in `health-check-domain` (a template-ignored seam file) and its probe, healthy when producer metadata is reachable and the verdict passes. A compose init step creates both topics with the required settings and replication factor 1, because the compose broker is a single node. The verdict is consulted by the relay of Story 7.4 before it publishes.

**Acceptance Criteria:**
- **Given** the compose topics with every required setting except replication factor 1 and `KAFKA_CONFIG_GATES=relaxed` in `APP_ENV=test`, **When** the inspector runs, **Then** the verdict passes and a warning naming the relaxed gate is logged on every check, proven in `make.integration_tests`.
- **Given** test topics that each break one rule (cleanup policy `delete`, unclean election on, `min.insync.replicas` 1, two partitions, `CreateTime`), and ACL responses injected through `test-broker` that allow another principal to write or allow everyone without an ACL, **When** the inspector runs with `KAFKA_CONFIG_GATES=enforce`, **Then** each verdict fails and names the offending setting, proven in `make.integration_tests`.
- **Given** `KAFKA_CONFIG_GATES=relaxed` or `KAFKA_SECURITY_PROTOCOL=PLAINTEXT` outside `APP_ENV` `dev` and `test`, or a missing `KAFKA_BOOTSTRAP_SERVERS`, **When** `service check-config` runs, **Then** it exits 2 naming the variable, proven in `make.integration_tests`.
- **Given** the compose broker running and then stopped, **When** `/api/health` is read, **Then** it reports the `kafka` dependency healthy and then unhealthy, the overall status follows the template's rule, and the template's health scenarios stay green, proven in `make.e2e_tests`.
- **Given** spans and log lines recorded while connecting, **When** the log recorder inspects them, **Then** `KAFKA_SASL_PASSWORD` never appears, proven in `make.integration_tests`.
- **Given** a broker whose `DescribeConfigs` answer omits `allow.everyone.if.no.acl.found` (the case Story 1.3 records and ADR 0026 names), **When** the inspector runs with `KAFKA_CONFIG_GATES=enforce`, **Then** it checks the setting through the fallback recorded by Story 1.3, the verdict names that fallback as the source of the check, and an allow-everyone answer injected through `test-broker` still fails the verdict, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.check_security`, `make.unused_dependencies`, `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.integration_tests`, `make.generate_openapi_spec`, `make.validate_contract_snapshots`, `make.openapi_diff` (base `main`, no breaking change), `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass.

**Depends on:** 1.1, 1.7, 2.3

### Story 7.4: Relay the outbox to Kafka with relay fencing

As the owner of IAM, I want one fenced relay to publish every outbox row to Kafka in version order, so that the state topic carries every acknowledged change exactly in commit order and a zombie relay can never overwrite newer state.
Covers FR-46, FR-47, NFR-26.
Domain: the `OutboxStore` and `PolicyLogProducer` ports. Application: the `OutboxRelay` singleton loop: it wakes on `LISTEN iam_outbox` (held by the current leader only) or every 100 ms, claims unpublished rows in `(policy_version, seq)` order inside a batch fenced by `AdvisoryLockLeadership`, produces them, stores the returned offsets in `published_offset`, marks the rows published, refuses to publish while the configuration verdict of Story 7.3 fails or the state topic has more than one partition, releases the lock on SIGTERM, and deletes published rows older than 7 days. Infrastructure: `PgOutboxStore`, and `KrafkaPolicyLogProducer` (state rows to `POLICY_TOPIC` partition 0 and event rows to `EVENTS_TOPIC`, `acks=all`, idempotent, one request in flight, lz4, the record headers `iam-version`, `iam-seq`, `iam-count`, `iam-digest-after`, `iam-op`, `iam-schema`, `iam-log-epoch`, `iam-relay-epoch`; the transactional producer `iam-relay` when ADR 0026 records capability 7 as passed, with `transaction.timeout.ms` from `KAFKA_TRANSACTION_TIMEOUT` (default 10 seconds, accepted from 1 to 10 seconds; the rule that it stays below `FRESHNESS_HARD_BOUND` is completed in Story 16.1), and in that mode a row is marked published, with its offset stored, only after the transaction that contains it has committed, while rows of an aborted transaction stay unpublished and are sent again; always the relay-epoch header from `iam_policy_epoch.relay_epoch`, incremented on every relay takeover, after which the new leader republishes the current state of every key in the takeover range). `PgIamUnitOfWork` adds `pg_notify('iam_outbox', '')` as a wake-up that carries no keys. Composition root: the task registration, `DATABASE_LISTEN_URL` and `KAFKA_TRANSACTION_TIMEOUT` with their `docs/environment.md` rows and local defaults. ADR 0017 is completed.

**Acceptance Criteria:**
- **Given** committed changes producing state and event rows, **When** the relay runs against the compose broker, **Then** state rows land on partition 0 of the state topic in `(policy_version, seq)` order with every header, tombstones as null values with their headers, event rows land on the events topic keyed by aggregate id, and every row holds its stored offset and `published_at`, proven in `make.integration_tests`.
- **Given** the broker stopped while rows are pending, **When** the relay retries and the broker returns, **Then** no row was marked published before its acknowledgement and every row is delivered afterwards, proven in `make.integration_tests`.
- **Given** two `iam-control` instances with relays, **When** both run, **Then** only the lock holder produces in each batch and no row is claimed by both, proven in `make.integration_tests`.
- **Given** a relay takeover, **When** the new leader starts, **Then** `relay_epoch` is incremented, its records carry the new epoch, the current state of every key in the takeover range is published again, and a reader that keeps the highest version per key reconstructs the PostgreSQL state, proven in `make.integration_tests`.
- **Given** a late batch from the previous leader, sent by a second producer instance that the test drives against the compose broker or krafka's `test-broker` after a takeover, **When** it reaches the broker in transactional mode, **Then** the broker rejects the old transactional epoch with a fencing error and none of its records becomes visible to a `read_committed` reader, proven in `make.integration_tests`.
- **Given** the same late batch in relay-epoch-only mode (the ADR 0026 branch for a failed capability 7), **When** it is appended with the lower `iam-relay-epoch`, **Then** a `read_committed` reader that keeps the highest version per key and ignores lower relay epochs reconstructs the PostgreSQL state, proven in `make.integration_tests`.
- **Given** a state topic with two partitions, **When** the relay runs, **Then** it publishes nothing, marks nothing and logs the misconfiguration, proven in `make.integration_tests`.
- **Given** transactional mode and a relay transaction whose commit is delayed and then aborted through `test-broker`, **When** the relay handles it, **Then** no row is marked published and no offset is stored before the commit, the aborted rows are sent again in a later transaction, and a `KAFKA_TRANSACTION_TIMEOUT` outside 1 to 10 seconds makes `service check-config` exit 2, proven in `make.integration_tests`.
- **Given** 50 administrative writes per second on the compose broker, **When** a test reader records append times, **Then** the time from commit to append is at most 2 seconds at p99 (target of NFR-26 on the compose broker), proven in `make.integration_tests`.
- **Given** a lost wake-up notification, **When** a row is committed, **Then** the 100 ms poll publishes it, proven in `make.integration_tests`.
- **Given** a relay stopped in the middle of a batch, **When** it restarts, **Then** every row is delivered at least once, and duplicates carry identical `iam-digest-after` values, proven in `make.integration_tests`.
- **Given** published rows older than 7 days by the controlled `Clock`, **When** cleanup runs, **Then** they are deleted, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.check_security`, `make.integration_tests`, `make.sqlx_prepare`, `make.validate_sqlx_metadata`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass and the regenerated `.sqlx/` metadata is committed.

**Depends on:** 1.1, 1.4, 7.1, 7.2, 7.3

### Story 7.5: Publish IAM events and notification events on `iam.events.v1`

As Notification service and other consumers, I want every IAM change event, including the four notification events, on `iam.events.v1` with the documented fields, so that I can alert users and security staff by tailing one topic.
Covers FR-47, FR-48.
Tests and co-changes: in `world.rs`, a per-scenario `EVENTS_TOPIC` created on the compose broker (scenarios run concurrently, so a shared topic would mix their events), the outbox relay started through `bootstrap::start_tasks` for each scenario database, and steps that read the scenario's topic; scenarios in `features/iam_notifications.feature`; the event `data` mappers for `iam.user_role.assigned`, `iam.user_role.revoked`, `iam.privileged_role.assigned` and `iam.permissions.orphaned` completed where fields are missing. IAM writes into no topic of Notification service; Notification service tails `iam.events.v1` and selects events by `type`. `docs/architecture.md` documents the topic and the envelope.

**Acceptance Criteria:**
- **Given** an assignment, a revocation and a role deletion through the API, **When** the scenario's topic is read, **Then** `iam.user_role.assigned` and `iam.user_role.revoked` appear with `subject`, `userId`, `roleId`, `roleName`, `scope` and actor, keyed by the aggregate id, each envelope at most 64 KiB, proven in `make.e2e_tests`.
- **Given** two scenarios running concurrently, **When** each reads its own topic, **Then** it sees only the events of its own database, proven in `make.e2e_tests`.
- **Given** an assignment of a role granting a wildcard, **When** the topic is read, **Then** `iam.privileged_role.assigned` appears with `privilegedKeys`, proven in `make.e2e_tests`.
- **Given** an activation or retirement that orphans grants, **When** the topic is read, **Then** `iam.permissions.orphaned` appears with the service, the specification version id, the orphaned keys and the affected role ids, proven in `make.e2e_tests`.
- **Given** every write delivered so far, **When** the topics on the broker are listed, **Then** IAM has produced only to the state topic and the events topic, and no record has the type `iam.authorization_cache.flushed`, proven in `make.e2e_tests`.
- **Given** the story's changes, **When** `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass.

**Depends on:** 1.1, 5.8, 6.14, 7.4

### Story 7.6: Return writes after Kafka acknowledgement (published mode)

As an administrator, I want a write to return only when its policy version is acknowledged by Kafka, and to be told plainly when it is not, so that I know whether a change can already be in force on the gateway.
Covers FR-2, FR-75.
Domain: `WriteMode` (`Published`, `Propagated`) and `PropagationOutcome`. Application: `IamUnitOfWork::commit(change, write_mode)`; after the commit the handler waits for the relay's stored offset of the version's `__head` row (stored at the Kafka acknowledgement with the idempotent relay and only at the completed commit with the transactional relay) for at most `PUBLISH_WAIT_TIMEOUT`, then stores the `PropagationOutcome` on the change receipt; `WriteOutcomeMapper` maps one handler result to REST (`200`/`201` with `Iam-Policy-Version` and `Iam-Policy-Offset`, or `202` with status `committed_pending_propagation`) and to the GraphQL payload field `propagation {status, policyVersion, podsAcknowledged, podsTimedOut}`; the `PreferWaitHeader` extractor and the GraphQL input field `consistency: PUBLISHED | PROPAGATED` on every write. Until Story 13.4 delivers the `propagated` mode, a request for it is refused with 422 naming the mode; this intermediate state never leaves the feature branch. Infrastructure: the reversible pair `add_propagation_to_iam_change_receipts` (the outcome column on `iam_change_receipts`). Composition root: `PUBLISH_WAIT_TIMEOUT` with its `docs/environment.md` row and local default. Co-changes: every write operation's contract, both snapshots and pinning tests, the feature files of the write operations, `docs/requests.http`.

**Acceptance Criteria:**
- **Given** the relay running, **When** a role is created over REST and over GraphQL, **Then** REST returns 201 with `Iam-Policy-Version` and an `Iam-Policy-Offset` equal to the stored offset of the version's `__head` row, and GraphQL returns `propagation {status: PUBLISHED, policyVersion}` with the same version, proven in `make.e2e_tests`.
- **Given** the relay stopped, **When** a write is sent and `PUBLISH_WAIT_TIMEOUT` passes on the controlled clock, **Then** REST returns 202 with `committed_pending_propagation` and `Iam-Policy-Version`, GraphQL returns status `COMMITTED_PENDING`, and the change and its audit record are committed, proven in `make.integration_tests`.
- **Given** a committed write replayed with the same `Idempotency-Key`, **When** the replay returns, **Then** it carries the stored propagation outcome and waits for nothing, proven in `make.integration_tests`.
- **Given** a write that does not affect decisions, **When** it returns, **Then** it carries no `Iam-Policy-Offset` and did not wait, proven in `make.integration_tests`.
- **Given** `Prefer: wait=propagated` or `consistency: PROPAGATED`, **When** a write is sent before Story 13.4, **Then** REST returns 422 and GraphQL `VALIDATION_FAILED` naming the unsupported mode, proven in `make.integration_tests`.
- **Given** the operations are wired, **When** `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate` run, **Then** every write documents 202 and the new headers, every write input carries `consistency`, every write payload carries `propagation`, and the gates pass with additions only.
- **Given** an invalid `PUBLISH_WAIT_TIMEOUT`, **When** `service check-config` runs, **Then** it exits 2 naming it, proven in `make.integration_tests`.
- **Given** the migration pair created with `make.create_migration` and the full story, **When** `make.setup_test_db`, `make.integration_tests`, `make.sqlx_prepare`, `make.validate_sqlx_metadata`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass and the down migration is reviewed (its rollback round trip runs when an operator allows it, else it is recorded `not run (ask rule)`).

**Depends on:** 1.1, 7.4

### Story 7.7: Verify the published log with anti-entropy and shadow bootstrap

As the owner of IAM, I want the control plane to compare the state topic with PostgreSQL continuously and repair lost records, so that a broker or relay fault cannot leave the gateway on a silently wrong policy.
Covers FR-77.
Domain: the `PolicyLogTail` port in its first form (read a range up to a watermark, read the record at one offset). Application: the `AntiEntropyChecker` singleton loop: every `ANTI_ENTROPY_HEAD_INTERVAL` it compares the topic's newest `__head` with PostgreSQL, verifies that recently stored published offsets still hold the expected versions, and, for each key written since the previous check, compares the version of the key's last record by offset (read from the tail) with the newest PostgreSQL version of that key and republishes the current state when the record is lower, well inside `min.compaction.lag.ms` (1 hour), so compaction never keeps a stale value written by a zombie relay; every `ANTI_ENTROPY_FULL_INTERVAL` it runs a shadow bootstrap that rebuilds the state from the topic (highest version per key, tombstones delete, lower relay epochs ignored) and compares the full digest with PostgreSQL. A lost record is republished by clearing `published_at` on its outbox row so the relay sends it again (pods ignore the duplicate); a loss older than the 7-day outbox retention, a digest mismatch or a topic ahead of PostgreSQL raises an alert (error log and the `anti_entropy_repairs_total` counter) within 10 seconds and calls for the resync of Story 7.10. Infrastructure: `KrafkaPolicyLogTail` with the bounded reads above; Story 9.3 adds the bootstrap principal, tail mode and reseek for the gateway. Composition root: the task registration and `ANTI_ENTROPY_HEAD_INTERVAL` and `ANTI_ENTROPY_FULL_INTERVAL` with their `docs/environment.md` rows and local defaults; bookkeeping in `iam_task_state`.

**Acceptance Criteria:**
- **Given** a topic in step with PostgreSQL, **When** the head check and the full check run, **Then** both find the same version and digest and nothing is repaired, proven in `make.integration_tests`.
- **Given** a record the relay skipped through a test hook on the compose broker and PostgreSQL, **When** the next head check runs on the controlled clock, **Then** the loss is detected within 10 seconds, the row is published again, the following full check matches, and `anti_entropy_repairs_total` increased by one, proven in `make.integration_tests`.
- **Given** a record whose value was corrupted on a test topic, **When** the shadow bootstrap runs, **Then** the digest mismatch is reported within one full interval and nothing is marked healthy, proven in `make.integration_tests`.
- **Given** a topic on the compose broker whose newest `__head` version, written by a test producer, is above PostgreSQL's version, **When** the head check runs and new rows are committed, **Then** the relay publishes nothing while the topic is ahead and the alert names the topic-ahead runbook, proven in `make.integration_tests`.
- **Given** the topic-ahead alert, **When** `docs/operations.md` is checked, **Then** it holds the topic-ahead runbook the alert names, and `make.docs_check` passes.
- **Given** two `iam-control` instances against the compose broker and PostgreSQL, **When** both run the checker, **Then** only the lock holder runs each batch, proven in `make.integration_tests`.
- **Given** an interval of zero or a full interval shorter than the head interval, **When** `service check-config` runs, **Then** it exits 2 naming the variable, proven in `make.integration_tests`.
- **Given** a record with a lower relay epoch and a lower version appended by a second producer after the new leader's takeover republish, **When** the next head check runs on the controlled clock, **Then** the key is detected within `ANTI_ENTROPY_HEAD_INTERVAL` and its current state is republished, so the key's last record by offset carries the newest version before compaction could run, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.integration_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass.

**Depends on:** 1.1, 7.4

### Story 7.8: Run the maintenance task

As an operator, I want a periodic task that purges expired records and anchors the audit chain, so that IAM stays small and its audit history stays verifiable from outside.
Covers FR-38, FR-43, FR-52.
Application: `RunMaintenanceCommandHandler` and the `PolicyMaintenance` singleton loop (every `MAINTENANCE_INTERVAL`, each run inside a fenced batch), which purges orphaned grants older than `ORPHANED_GRANT_RETENTION` through the unit of work with an audit record each, removes idempotency records and change receipts older than 24 hours and inbound-event ids older than 7 days, and publishes the current audit chain head as `iam.security_audit.anchored` through the outbox. It does not reconcile any cache: drift detection is the anti-entropy task of Story 7.7, and revocation records are pruned only through the tombstones of Story 13.6. Composition root: the task registration and `MAINTENANCE_INTERVAL` and `ORPHANED_GRANT_RETENTION` with their `docs/environment.md` rows and local defaults.

**Acceptance Criteria:**
- **Given** orphaned grants older than the retention by the controlled `Clock`, **When** maintenance runs, **Then** they are purged with an audit record each, younger ones remain, and the affected role state records are written in the same transaction, proven in `make.integration_tests`.
- **Given** idempotency records and change receipts older than 24 hours and inbound-event ids older than 7 days, **When** maintenance runs, **Then** they are removed and younger ones remain, proven in `make.integration_tests`.
- **Given** session revocations and cut-offs of any age, **When** maintenance runs, **Then** none is removed, proven in `make.integration_tests`.
- **Given** a run of maintenance, **When** it commits, **Then** one `iam.security_audit.anchored` event with the current chain head's `seq` and `hash` is in the outbox, proven in `make.integration_tests`.
- **Given** two `iam-control` instances, **When** both run the task, **Then** only the lock holder runs each batch, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.integration_tests`, `make.sqlx_prepare`, `make.validate_sqlx_metadata`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass and the regenerated `.sqlx/` metadata is committed.

**Depends on:** 1.1, 1.7, 2.4, 5.8, 7.1

### Story 7.9: Run bulk changes in chunks with progress

As an operator, I want large changes split into ordered, rate-capped chunks that I can follow, so that a bulk change never makes the policy more permissive than intended and never floods the state topic in front of a revocation.
Covers FR-1, FR-84.
Domain: the `BulkOperation` aggregate (`BulkKind` with `role_deletion`, `catalogue`, `resync` and `other`, `BulkStatus`, total and applied records, first and last version, requester, error) with the event `BulkOperationCompleted`, `BulkChunker` (revoke-type chunks before grant-type chunks, at most `BULK_CHUNK_ENTITIES` entities per version) and the `BulkOperationRepository` port. Application: the unit of work hands any change with more than `BULK_CHUNK_ENTITIES` changed entities to the bulk path, which records a pending bulk operation and returns 202 with `Location: /api/bulk-operations/{id}` (GraphQL: the nullable payload field `bulkOperationId`); the `BulkOperationRunner` singleton (fenced per operation) commits the chunks at most `BULK_MAX_RECORDS_PER_SECOND` records per second and lets revocation-class writes commit between chunks; the bulk-operation read model also carries `propagation {status, policyVersion, podsAcknowledged, podsTimedOut}` for revocation-class bulk operations, null until Story 13.8 fences their chunks; `GetBulkOperationQueryHandler` and `ListBulkOperationsQueryHandler` with REST `GET /api/bulk-operations/{id}` and `GET /api/bulk-operations` and GraphQL `bulkOperation(id)` and `bulkOperations(...)`. Infrastructure: the migration `create_iam_bulk_operations` (created with `make.create_migration`) and `PgBulkOperationRepository`. Composition root: the runner registration and `BULK_CHUNK_ENTITIES` and `BULK_MAX_RECORDS_PER_SECOND` with their `docs/environment.md` rows and local defaults. Co-changes: snapshots and pinning tests, `features/iam_bulk_operations.feature`, `docs/requests.http`.

**Acceptance Criteria:**
- **Given** a role with 2,500 assignments, **When** it is deleted over REST and over GraphQL, **Then** REST returns 202 with the bulk operation's `Location` and GraphQL returns its `bulkOperationId`, the bulk operation has kind `role_deletion`, the change is committed as versions of at most 1,000 entities, and the final state equals the result of a single transaction, proven in `make.e2e_tests`.
- **Given** a test change mixing removals and additions above one chunk, **When** it runs, **Then** every revoke-type version precedes every grant-type version, and a property test shows that no intermediate version grants a key that neither the previous state nor the final state grants, proven in `make.integration_tests`.
- **Given** `BULK_MAX_RECORDS_PER_SECOND` 2,000 and a bulk change of 10,000 records, **When** it runs on the controlled clock, **Then** the commits take at least 5 seconds of clock time, proven in `make.integration_tests`.
- **Given** a revocation submitted while a bulk operation runs, **When** it commits, **Then** it commits between two chunks and does not wait for the bulk operation to finish, proven in `make.integration_tests`.
- **Given** a running and a completed bulk operation, **When** they are read and listed over both interfaces, **Then** both return kind, status, applied and total records, first and last version and requester; an unknown id returns 404 over REST and `null` over GraphQL, proven in `make.e2e_tests`.
- **Given** a completed bulk operation, **When** the outbox is read, **Then** `iam.bulk_operation.completed` is present, proven in `make.integration_tests`.
- **Given** a runner stopped in the middle of a bulk operation, **When** it restarts, **Then** it resumes from the applied records without committing a chunk twice, proven in `make.integration_tests`.
- **Given** `BULK_CHUNK_ENTITIES` outside 1 to 1,000, **When** `service check-config` runs, **Then** it exits 2 naming it, proven in `make.integration_tests`.
- **Given** the operations are wired, **When** `make.setup_test_db`, `make.integration_tests`, `make.sqlx_prepare`, `make.validate_sqlx_metadata`, `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass with additions only and the down migration is reviewed (its rollback round trip runs when an operator allows it, else it is recorded `not run (ask rule)`).

**Depends on:** 1.1, 1.7, 6.12, 7.1, 7.2

### Story 7.10: Resync policy state to a new log epoch

As an operator, I want to republish the complete current policy as a new log epoch with a reason, so that I can repair the state topic after an incident without touching the gateway pods by hand.
Covers FR-1, FR-78.
Application: `ResyncPolicyCommandHandler`; REST `POST /api/policy-resyncs` and GraphQL `resyncPolicy(input)` with a required `reason`; the operation needs `iam:policy:resync` (its row is added to the rule table of `IamAccessGuard`). The handler increments `log_epoch` in `iam_policy_epoch` and republishes the full current state of every entity as a bulk operation of kind `resync`, with versions continuing above both the PostgreSQL version and the highest `__head` version on the topic (read through `KrafkaPolicyLogTail`); it is audited and records `iam.policy.resynced`. It replaces the operator cache flush: `POST /api/authorization-cache/flushes` and `flushAuthorizationCache` do not exist. Co-changes: snapshots and pinning tests, `features/iam_operations.feature`, `docs/requests.http`, `docs/operations.md` (when to resync).

**Acceptance Criteria:**
- **Given** an operator holding `iam:policy:resync`, **When** it resyncs with a reason over REST and over GraphQL, **Then** both return 202 with the bulk operation, and on completion the topic holds every current entity under the new log epoch with versions above the previous topic maximum, a shadow bootstrap's digest equals PostgreSQL's, and an audit record and `iam.policy.resynced` are committed, proven in `make.e2e_tests`.
- **Given** a caller without `iam:policy:resync` or a request without a reason, **When** it resyncs, **Then** 403 (GraphQL `FORBIDDEN`) or 422 (GraphQL `VALIDATION_FAILED`) is returned, proven in `make.integration_tests`.
- **Given** a topic whose highest version is above PostgreSQL's, **When** a resync runs, **Then** its first version is above the topic maximum, so no reader sees a version regression, proven in `make.integration_tests`.
- **Given** a committed resync sent with an `Idempotency-Key` (GraphQL `idempotencyKey`), **When** it is replayed with the same key and body, **Then** the original bulk operation is returned and no second resync starts, proven in `make.integration_tests`.
- **Given** the contract, **When** it is inspected, **Then** no cache-flush operation exists on either interface, proven in `make.integration_tests`.
- **Given** the operations are wired, **When** `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate`, `make.integration_tests`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass with additions only.

**Depends on:** 1.1, 7.7, 7.9

## Epic 8: Gateway management API

This epic lets administrators manage what the gateway proxies: upstreams, routes, rate policies and a declarative route configuration per host, each over REST and GraphQL through one handler, each change a versioned write with its state record on the state topic. It ends by seeding IAM's own upstream and routes at bootstrap, so the management API itself is reached through the gateway.

### Story 8.1: Model upstreams, routes and rate policies

As a developer, I want the gateway configuration aggregates and their guards in the domain, so that route conflicts, anonymous routes and rate policies are unit-testable without I/O and decided the same way everywhere.
Covers FR-56, FR-57, FR-64.
Domain only: `Upstream` (`UpstreamId`, `UpstreamName` with the service-name pattern and immutable after creation, Kubernetes namespace and Service name, the catalogue `ServiceName` it serves (`catalogService`), port, `UpstreamProtocol` (`Http1`, `H2c`), `forwardCredentials` (default false), the `system` flag, connect and response timeouts, concurrency limit, retry budget percent, outlier threshold, `EntityVersion`) with `UpstreamCreated`, `UpstreamUpdated`, `UpstreamDeleted`; `Route` (`RouteId`, `RouteHost`, `HttpMethod` set, `PathPattern`, catalogue `ServiceName`, `UpstreamId`, `RouteFlags` (`graphql`, `streaming`, `anonymous`), `EnforcementMode` (`Enforce`, `Audit`), `BodyLimit`, `RouteTimeouts`, `RetryPolicy` (`None`, `Idempotent`), ordered `RatePolicyId` list, an optional `CorsPolicy` (exact origins, methods, headers, `allowCredentials`, `maxAgeSeconds` at most 86,400), the `system` flag, `EntityVersion`) with `RouteCreated`, `RouteUpdated`, `RouteDeleted` and `RouteConfigurationApplied`; `RatePolicy` (`RatePolicyId`, name, `RateKeyKind` (`Ip`, `Subject`, `SubjectRoute`, `Route`), limit, period, burst, `RateFallback` (`Divided`, `Full`), `EntityVersion`) with `RatePolicyCreated`, `RatePolicyUpdated`, `RatePolicyDeleted`; the domain services `RouteConflictGuard` (same host and pattern with intersecting methods is a conflict; an anonymous route whose pattern is broader than a protected route on the same host, through a parameter or catch-all segment, is a conflict; a full host configuration is validated as a set), `AnonymousRouteGuard` (setting `anonymous = true` or `enforcement = audit`, or changing either flag, needs `iam:route:anonymous`), `RouteScopeGuard` (creating, changing or deleting a route or upstream whose catalogue service is S needs `iam:route:{S}` or `iam:route:*` at global scope; a route's `service` must equal its upstream's `catalogService`; entries of service `iam` and every `system` entry are refused) and the `RouteTableCompiler` port (compiles one host's routes into the matcher the gateway uses); the revocation-class rule for routes (clearing `anonymous`, moving `enforcement` from `audit` to `enforce`, or deleting the route); the ports `UpstreamRepository`, `RouteRepository` and `RatePolicyRepository`; the errors `InvalidUpstream`, `InvalidRoute`, `InvalidRatePolicy`, `RouteConflict` and `ReferencedByRoute`.

**Acceptance Criteria:**
- **Given** upstreams with an invalid name, a port outside 1 to 65,535, a zero timeout, a concurrency limit of zero or a retry budget above 100 percent, **When** they are created, **Then** `InvalidUpstream` names each violation with its property path and code; a rename of an existing upstream is refused, proven in `make.unit_tests`.
- **Given** routes with an upper-case or invalid host, no method, a path pattern not starting with `/`, an invalid service name or a zero body limit, **When** they are created, **Then** `InvalidRoute` names each violation, proven in `make.unit_tests`.
- **Given** two routes on the same host and pattern with methods `GET, POST` and `POST, PUT`, and two with `GET` and `DELETE`, **When** `RouteConflictGuard` checks them, **Then** the first pair is a `RouteConflict` and the second is accepted; a host configuration containing the first pair is refused as a set, proven in `make.unit_tests`.
- **Given** a principal with and without `iam:route:anonymous`, **When** a route is created or changed with `anonymous = true` or `enforcement = audit`, or either flag is changed back, **Then** `AnonymousRouteGuard` allows only the holder, proven in `make.unit_tests`.
- **Given** route updates that clear `anonymous`, move `enforcement` from `audit` to `enforce`, change only a timeout, and a deletion, **When** the revocation-class rule classifies them, **Then** the first, second and fourth are revocation-class and the third is not, proven in `make.unit_tests`.
- **Given** rate policies with each key kind, a zero limit, a zero period and a negative burst, **When** they are created, **Then** valid ones are accepted and `InvalidRatePolicy` names each violation, proven in `make.unit_tests`.
- **Given** a principal holding `iam:route:core`, `iam:route:*` or neither, **When** `RouteScopeGuard` checks a route of service `core`, a route of service `iam`, a `system` route and a route whose `service` differs from its upstream's `catalogService`, **Then** the first two holders may change the `core` route, nobody may change the `iam` or `system` routes, and the mismatched route is refused, proven in `make.unit_tests`.
- **Given** an anonymous route `/api/{rest:*}` and a protected route `/api/orders` on the same host, **When** `RouteConflictGuard` checks the set, **Then** it reports a conflict, while the same pair with both routes protected is accepted, proven in `make.unit_tests`.
- **Given** the domain changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.tests_with_coverage` and `make.mutation_tests_diff` run, **Then** all pass, including property tests of the conflict rule (symmetric, and never a conflict for disjoint methods).

**Depends on:** 1.1, 1.7, 2.1

### Story 8.2: Persist upstreams, routes and rate policies with their state records

As a developer, I want the gateway configuration stored in PostgreSQL and replicated as state records, so that every pod can rebuild its route table from the state topic.
Covers FR-70, NFR-8.
Infrastructure: the migration `create_iam_gateway_configuration`, created with `make.create_migration` (`iam_upstreams` with `name` unique among non-deleted rows and the columns `catalog_service`, `forward_credentials` and `system`; `iam_routes` with `cors jsonb` and `system`; `iam_rate_policies` with `name` unique among non-deleted rows; `iam_routes` with a foreign key to `iam_upstreams` and an index on (`host`, `path_pattern`); `iam_route_rate_policies` with primary key (`route_id`, `rate_policy_id`) and `position`), `PgUpstreamRepository`, `PgRouteRepository` (lists with filters host, upstream and service, cursor pagination) and `PgRatePolicyRepository`, whose statements run inside `PgIamUnitOfWork`; each change writes the state record `upstream/<name>`, `route/<id>` or `ratepolicy/<id>` (full state, or a tombstone on delete) and updates the digest. Composition root: the adapters and the three literals. `tests/support`: the three fakes and fixtures.

**Acceptance Criteria:**
- **Given** an upstream named `core`, **When** another upstream named `core` is saved, **Then** the repository returns `AlreadyExists`; after the first is deleted, the name can be reused, proven in `make.integration_tests`.
- **Given** a route whose upstream id does not exist, **When** it is inserted, **Then** the foreign key rejects it, proven in `make.integration_tests`.
- **Given** a route with three rate policies, **When** it is read back, **Then** the policies come back in their stored order, proven in `make.integration_tests`.
- **Given** an upstream, a route and a rate policy created, updated and deleted through the unit of work, **When** each transaction commits, **Then** the outbox holds the matching state record with the full new state, a tombstone on deletion, and a `__head` row whose digest equals `iam_policy_epoch.digest`, proven in `make.integration_tests`.
- **Given** 150 routes on three hosts, **When** they are listed by host, upstream and service in pages of 1, 37 and 100, **Then** every matching route appears exactly once in a stable order, proven in `make.integration_tests`.
- **Given** the migration pair created with `make.create_migration` and the queries, **When** `make.setup_test_db`, `make.integration_tests`, `make.sqlx_prepare`, `make.validate_sqlx_metadata`, `make.tests_with_coverage` and `make.mutation_tests_diff` run, **Then** they pass, the down migration is reviewed (its rollback round trip runs when an operator allows it, else it is recorded `not run (ask rule)`) and the regenerated `.sqlx/` metadata is committed.

**Depends on:** 1.1, 1.7, 7.2, 8.1

### Story 8.3: Manage upstreams over REST and GraphQL

As an administrator, I want to create, read, update and delete upstreams over either interface, so that I can register the services the gateway proxies to.
Covers FR-1, FR-2, FR-56.
Application: `CreateUpstreamCommandHandler`, `UpdateUpstreamCommandHandler`, `DeleteUpstreamCommandHandler`, `GetUpstreamQueryHandler` and `ListUpstreamsQueryHandler`; REST `POST /api/upstreams`, `GET /api/upstreams/{id}`, `GET /api/upstreams`, `PATCH /api/upstreams/{id}` with `If-Match` and `DELETE /api/upstreams/{id}` in `http/upstream.rs`; GraphQL `createUpstream(input)`, `upstream(id)`, `upstreams(...)`, `updateUpstream(input)` and `deleteUpstream(input)`. Each change is a versioned write with its `upstream/<name>` state record, its `iam.upstream.created`, `iam.upstream.updated` or `iam.upstream.deleted` event and an audit record; a delete is refused with 409 while a route references the upstream. The handlers apply `RouteScopeGuard`: a write on an upstream whose `catalogService` is S needs `iam:route:{S}` or `iam:route:*`, and an upstream of service `iam` or flagged `system` is refused with 409 `system_entry` and audited. The `iam:route:{service}` and `iam:route:*` rows are added to the rule table of `IamAccessGuard`. The operations are registered in IAM's own catalogue at startup and authorized by their catalogue keys. Co-changes: snapshots and pinning tests, `features/iam_upstreams.feature`, `docs/requests.http`.

**Acceptance Criteria:**
- **Given** the bootstrapped administrator, **When** it creates an upstream over REST and over GraphQL, **Then** REST returns 201 with `Location`, `ETag` and `Iam-Policy-Version`, GraphQL returns the same data, and the outbox holds the `upstream/<name>` state record, `iam.upstream.created` and an audit record from one transaction, proven in `make.e2e_tests`.
- **Given** invalid fields or a duplicate name, **When** an upstream is created, **Then** REST returns 422 with violations or 409, and GraphQL returns `VALIDATION_FAILED` or `CONFLICT`, proven in `make.e2e_tests`.
- **Given** an upstream and its version, **When** it is updated with the current, a stale and no version, **Then** the first succeeds with `iam.upstream.updated`, the second returns 412 (GraphQL `PRECONDITION_FAILED`) and the third 428 (GraphQL `PRECONDITION_REQUIRED`); an update that changes the name returns 422, proven in `make.e2e_tests`.
- **Given** an upstream referenced by a route seeded through the repository, **When** it is deleted over both interfaces, **Then** REST returns 409 and GraphQL `CONFLICT`; an unreferenced upstream is deleted with a tombstone state record and `iam.upstream.deleted`, proven in `make.e2e_tests`.
- **Given** upstreams, **When** they are read by id and listed with cursor pagination, **Then** both interfaces return every field of FR-56 with version and timestamps; an unknown id returns 404 over REST and `null` over GraphQL, proven in `make.e2e_tests`.
- **Given** a subject without the operation's catalogue key, **When** it calls any of the operations, **Then** REST returns 403 and GraphQL `FORBIDDEN`, and the attempt is audited, proven in `make.e2e_tests`.
- **Given** a create repeated with the same `Idempotency-Key` (GraphQL `idempotencyKey`) and body, **When** it is replayed, **Then** the original result is returned and no second upstream, event or state record exists, proven in `make.e2e_tests`.
- **Given** a principal holding `iam:route:core` only, **When** it creates an upstream with `catalogService` `core` and one with `catalogService` `payment` over both interfaces, **Then** the first succeeds and the second gets 403 (GraphQL `FORBIDDEN`); any write on the seeded upstream `iam-control` gets 409 `system_entry` (GraphQL `CONFLICT`) and is audited, proven in `make.e2e_tests`.
- **Given** the operations are wired, **When** `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass with additions only and `docs/requests.http` holds one REST and one GraphQL sample per new operation.

**Depends on:** 1.1, 6.12, 8.2

### Story 8.4: Manage routes over REST and GraphQL

As an administrator, I want to create, read, update and delete routes over either interface, so that I decide which host, methods and paths reach which upstream and under which authorization rules.
Covers FR-1, FR-2, FR-57, FR-63, FR-69.
Application: `CreateRouteCommandHandler`, `UpdateRouteCommandHandler`, `DeleteRouteCommandHandler`, `GetRouteQueryHandler` and `ListRoutesQueryHandler`; REST `POST /api/routes`, `GET /api/routes/{id}`, `GET /api/routes` (filters host, upstream, service), `PATCH /api/routes/{id}` with `If-Match` and `DELETE /api/routes/{id}` in `http/route.rs`; GraphQL `createRoute(input)`, `route(id)`, `routes(...)`, `updateRoute(input)` and `deleteRoute(input)`. The handlers apply `RouteConflictGuard` (409), `AnonymousRouteGuard` and `RouteScopeGuard` against PostgreSQL inside the write transaction, and build the candidate route table of the host through `RouteTableCompiler` (`MatchitRouteTableCompiler`, the same `matchit` version and builder code the gateway snapshot uses), refusing with 409 `route_table_conflict` any set the gateway could not build; the precedence is literal segments before parameter segments before catch-all segments; the optional `cors` policy is validated and stored with the route; routes of service `iam` and `system` routes are refused with 409 `system_entry` and audited; the `iam:route:anonymous` row is added to the rule table of `IamAccessGuard` and to `IamAuthorizationExtension`; a change of `anonymous` or `enforcement` is audited with the old and new values; an unknown upstream or rate policy id is a 422 violation. Each change writes its `route/<id>` state record and an `iam.route.created`, `iam.route.updated` or `iam.route.deleted` event. The revocation-class default write mode for route changes is added by Story 13.8. Co-changes: snapshots and pinning tests, `features/iam_routes.feature`, `docs/requests.http`.

**Acceptance Criteria:**
- **Given** an upstream and the bootstrapped administrator, **When** a route is created over REST and over GraphQL, **Then** REST returns 201 with `Location`, `ETag` and `Iam-Policy-Version`, GraphQL returns the same data, and the `route/<id>` state record, `iam.route.created` and an audit record are committed together, proven in `make.e2e_tests`.
- **Given** an existing route on host `app.example.test` with pattern `/api/orders/{id}` and method `GET`, **When** a route with the same host and pattern and methods `GET, PATCH` is created, **Then** REST returns 409 and GraphQL `CONFLICT`; the same pattern with method `DELETE` is accepted, proven in `make.e2e_tests`.
- **Given** a principal holding the route catalogue keys but not `iam:route:anonymous`, **When** it creates a route with `anonymous = true` or changes `enforcement` to `audit` over both interfaces, **Then** REST returns 403 and GraphQL `FORBIDDEN` and the attempt is audited; the administrator succeeds and the audit record names the flag change, proven in `make.e2e_tests`.
- **Given** an unknown upstream id, an unknown rate policy id or an invalid pattern, **When** a route is created, **Then** REST returns 422 with violations and GraphQL `VALIDATION_FAILED`, proven in `make.e2e_tests`.
- **Given** a route and its version, **When** it is updated with a stale and with no version, **Then** 412 and 428 are returned (GraphQL `PRECONDITION_FAILED` and `PRECONDITION_REQUIRED`); a deletion writes a tombstone state record and `iam.route.deleted`, proven in `make.e2e_tests`.
- **Given** routes on several hosts, **When** they are listed with the filters host, upstream and service and read by id over both interfaces, **Then** both return every field of FR-57; an unknown id returns 404 over REST and `null` over GraphQL, proven in `make.e2e_tests`.
- **Given** a route `/users/{id}` on a host, **When** a route `/users/{name}` with the same method is created over both interfaces, **Then** REST returns 409 `route_table_conflict` and GraphQL `CONFLICT`, and nothing is written, proven in `make.e2e_tests`.
- **Given** a principal holding `iam:route:core` and broad keys of service `core`, **When** it creates a route on `payment.example.test` with `service = core` pointing at the `payment` upstream, a route of service `iam`, and a change to a seeded IAM route, **Then** the first is refused with 422 because the service differs from the upstream's `catalogService`, the second with 403, and the third with 409 `system_entry`, each audited, proven in `make.e2e_tests`.
- **Given** a route created with a `cors` policy, **When** it is read over both interfaces, **Then** the policy is returned unchanged, and an origin that is not an exact `https` origin is refused with 422, proven in `make.e2e_tests`.
- **Given** the operations are wired, **When** `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass with additions only.

**Depends on:** 1.1, 8.3

### Story 8.5: Manage rate policies over REST and GraphQL

As an administrator, I want to create, read, update and delete rate policies over either interface, so that I can attach global quotas to routes.
Covers FR-1, FR-2, FR-64.
Application: `CreateRatePolicyCommandHandler`, `UpdateRatePolicyCommandHandler`, `DeleteRatePolicyCommandHandler`, `GetRatePolicyQueryHandler` and `ListRatePoliciesQueryHandler`; REST `POST /api/rate-policies`, `GET /api/rate-policies/{id}`, `GET /api/rate-policies`, `PATCH /api/rate-policies/{id}` with `If-Match` and `DELETE /api/rate-policies/{id}` in `http/rate_policy.rs`; GraphQL `createRatePolicy(input)`, `ratePolicy(id)`, `ratePolicies(...)`, `updateRatePolicy(input)` and `deleteRatePolicy(input)`. Each change writes its `ratepolicy/<id>` state record and an `iam.rate_policy.created`, `iam.rate_policy.updated` or `iam.rate_policy.deleted` event; a delete is refused with 409 while a route references the policy. Enforcement of the policies follows in Epic 12. Co-changes: snapshots and pinning tests, `features/iam_rate_policies.feature`, `docs/requests.http`.

**Acceptance Criteria:**
- **Given** the bootstrapped administrator, **When** it creates a rate policy with key `subject_route`, limit 100, period 60,000 ms, burst 20 and fallback `divided` over REST and over GraphQL, **Then** REST returns 201 with `Location`, `ETag` and `Iam-Policy-Version`, GraphQL returns the same data, and the state record, `iam.rate_policy.created` and an audit record are committed together, proven in `make.e2e_tests`.
- **Given** invalid fields or a duplicate name, **When** a policy is created, **Then** REST returns 422 or 409 and GraphQL `VALIDATION_FAILED` or `CONFLICT`, proven in `make.e2e_tests`.
- **Given** a policy referenced by a route seeded through the repository, **When** it is deleted over both interfaces, **Then** REST returns 409 and GraphQL `CONFLICT`; an unreferenced policy is deleted with a tombstone state record and `iam.rate_policy.deleted`, proven in `make.e2e_tests`.
- **Given** a policy and its version, **When** it is updated with a stale and with no version, **Then** 412 and 428 are returned (GraphQL `PRECONDITION_FAILED` and `PRECONDITION_REQUIRED`), proven in `make.e2e_tests`.
- **Given** policies, **When** they are read by id and listed over both interfaces, **Then** both return every field of FR-64; an unknown id returns 404 over REST and `null` over GraphQL, proven in `make.e2e_tests`.
- **Given** the operations are wired, **When** `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass with additions only.

**Depends on:** 1.1, 6.12, 8.2

### Story 8.6: Apply a declarative route configuration

As a platform engineer, I want to replace the full route set of one host in one atomic operation, with a dry run first, so that route changes can live in version control and be applied without drift.
Covers FR-1, FR-58, FR-75.
Application: `ApplyRouteConfigurationCommandHandler` and `GetRouteConfigurationQueryHandler`; REST `PUT /api/route-configurations/{host}` (query parameter `dryRun`) with `If-Match` carrying the ETag that `GET` returns for the current set, and `GET /api/route-configurations/{host}`; GraphQL `applyRouteConfiguration(input)` (input field `dryRun`) and `routeConfiguration(host)`. The handler validates the whole set with `RouteConflictGuard`, the candidate route table of `RouteTableCompiler`, and each route with `AnonymousRouteGuard`, `RouteScopeGuard` and the route rules of FR-57; one violation rejects the whole set. A set holds at most `ROUTE_CONFIGURATION_MAX_ROUTES` (1,000, CONFIG) routes; a larger set returns 422. A dry run returns the diff (added, changed and removed routes) and writes nothing. An applied set creates, updates and deletes routes in one versioned transaction (always one policy version, never a bulk operation) with their state records and records `iam.route_configuration.applied`. An applied set whose diff deletes a route, clears `anonymous` or moves `enforcement` from `audit` to `enforce` is revocation-class (FR-75) and runs in `propagated` mode by default once Story 13.8 makes it the default. Configuration: `ROUTE_CONFIGURATION_MAX_ROUTES` with its `docs/environment.md` row and local default. Co-changes: snapshots and pinning tests, `features/iam_route_configurations.feature`, `docs/requests.http`.

**Acceptance Criteria:**
- **Given** a host with routes A and B, **When** a set of B (changed) and C is applied over REST and over GraphQL, **Then** A is deleted, B updated and C created in one version, each with its state record, and `iam.route_configuration.applied` and an audit record are committed, proven in `make.e2e_tests`.
- **Given** the same set with `dryRun = true`, **When** it is sent over both interfaces, **Then** the response lists A as removed, B as changed and C as added, and no route, state record, event or version bump exists, proven in `make.e2e_tests`.
- **Given** a set containing two conflicting routes, or an anonymous route sent by a principal without `iam:route:anonymous`, **When** it is applied, **Then** the whole set is rejected with 409 or 403 (GraphQL `CONFLICT` or `FORBIDDEN`) and no route changes, proven in `make.unit_tests`.
- **Given** a set of 1,000 routes and a set of 1,001 routes, **When** they are applied over both interfaces, **Then** the first is committed as one policy version and `GET` returns exactly the 1,000 routes, and the second returns 422 (GraphQL `VALIDATION_FAILED`), proven in `make.e2e_tests`.
- **Given** a set containing `/users/{id}` and `/users/{name}` with the same method, **When** it is applied, **Then** the whole set is rejected with 409 `route_table_conflict` and no route changes, proven in `make.e2e_tests`.
- **Given** applied sets whose diff deletes a route, clears `anonymous`, moves `enforcement` from `audit` to `enforce`, or only changes a timeout, **When** the revocation-class rule classifies them, **Then** the first three are revocation-class and the last is not, proven in `make.unit_tests`.
- **Given** a stale `If-Match`, **When** a set is applied, **Then** REST returns 412 and GraphQL `PRECONDITION_FAILED`, proven in `make.unit_tests`.
- **Given** the operations are wired, **When** `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass with additions only.

**Depends on:** 1.1, 8.4, 8.5

### Story 8.7: Seed IAM's own upstream and routes at bootstrap

As an operator, I want the first-administrator bootstrap to seed the upstream `iam-control` and the routes of IAM's management API, so that the management API is reachable through the gateway from the first deployment without a manual step.
Covers FR-5.
Application: `BootstrapIamCommandHandler` extended: in the run that creates the first administrator, under the same transaction-level advisory lock and audited as `system:bootstrap`, it seeds idempotently the upstream `iam-control` (namespace `iam`, Service `iam-control`, port 80, protocol `http1`, `catalogService` `iam`, `forwardCredentials` true) and the routes on IAM's host: the REST management paths under `/api`, the GraphQL route `POST /api/graphql` flagged `graphql` with a 6 MiB body limit, and the specification upload routes with a 6 MiB body limit, all with service `iam`, `enforcement = enforce` and the `system` flag, which makes them immutable through the API (409 `system_entry`, audited), like system roles. Composition root: the option `--iam-host <host>` of `service iam-bootstrap`, optional: without it the seed is skipped and reported, so the e2e world of Story 6.10 and the Schemathesis credential target of Story 2.8 keep working unchanged; an invalid host exits 2. The seed only inserts what is absent and never changes an existing upstream or route. `service iam-bootstrap --repair-routes --iam-host <host>` restores the seeded upstream and routes to their seeded state whether or not an administrator exists, under the same advisory lock, as an audited revocation-class change; without `--iam-host` it exits 2. Co-changes: the e2e world passes its IAM host; `docs/operations.md` lists the seeded entries.

**Acceptance Criteria:**
- **Given** an empty IAM database, **When** `service iam-bootstrap --admin-user <uuid> --iam-host iam.example.test` runs, **Then** it exits 0, the upstream `iam-control` and the IAM routes exist with the limits above, their state records are in the outbox of the same transaction, and the audit records carry actor `system:bootstrap`, proven in `make.integration_tests`.
- **Given** an upstream `iam-control` and its routes that already exist (a break-glass re-run after the last administrator was lost), **When** the bootstrap runs again, **Then** exactly one upstream and one route set exist and the existing entries are unchanged, proven in `make.integration_tests`.
- **Given** two bootstrap runs started concurrently on an empty database, **When** both finish, **Then** one upstream and one route set exist, proven in `make.integration_tests`.
- **Given** an invalid `--iam-host`, **When** the command runs, **Then** it exits 2 with a message and nothing changes; without `--iam-host` the administrator is created, no route is seeded and the output says so, proven in `make.integration_tests`.
- **Given** the seeded IAM routes, **When** the administrator tries to delete or change one over REST and over GraphQL, **Then** both are refused with 409 `system_entry` (GraphQL `CONFLICT`) and audited, proven in `make.e2e_tests`.
- **Given** a seeded IAM route deleted directly in the database by a test and an active administrator, **When** `service iam-bootstrap --repair-routes --iam-host iam.example.test` runs, **Then** it exits 0, the route is restored with its state record, the change is audited as `system:bootstrap`, and a run without `--iam-host` exits 2, proven in `make.integration_tests`.
- **Given** the bootstrapped administrator, **When** it lists routes for the IAM host over REST and over GraphQL, **Then** both return the seeded routes, proven in `make.e2e_tests`.
- **Given** the story's changes, **When** `make.integration_tests`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass.

**Depends on:** 1.1, 6.10, 8.4

## Epic 9: Gateway runtime: snapshot, consumer and freshness

This epic builds the data plane's policy runtime: the immutable policy snapshot and its apply rules, the `service gateway` run mode with its listeners, bootstrap and tail of the state topic without a consumer group, the freshness proof that enforces `T_hard`, the derived-state check, and startup and readiness gated on freshness. The gateway never reads PostgreSQL; every decision reads one published snapshot.

### Story 9.1: Model the policy snapshot and its apply rules

As the gateway, I want the replicated policy held as an immutable, versioned snapshot that is built only from complete versions, so that every decision reads one consistent state and incremental apply can never drift from a full rebuild.
Covers FR-71, NFR-16, NFR-38.
Domain: `VersionAssembly` (collects the records of one version by `iam-seq`, drops duplicates, and reports complete, incomplete, duplicate with the same `iam-digest-after`, conflicting content, gap, lower log epoch or lower relay epoch); the apply rules (per-key version guard `v > current(K)`, highest version wins, tombstones delete, records of a lower relay epoch than one already seen are ignored, a lower log epoch or conflicting content for an applied version is a fence verdict); the ring of the `iam-digest-after` values of the last 100,000 versions; the `PolicyView` port and the read API of `PolicySnapshot` (route lookup, upstream table, compiled role sets, assignment lists, revocation sets and cut-offs, rate policies, service catalogues and type graphs, version, digest, derived hash, log epoch and freshness proof). Infrastructure: `ArcSwapPolicySnapshot` and its builder: 4,096 copy-on-write shards keyed by `StateKey`, each touched shard cloned at most once per published snapshot; the derived structures (compiled role sets, the role-to-subject reverse index, interned assignment lists, per-host `matchit` routers, upstream table, revocation sets, rate policies, catalogues and type graphs) updated for the touched entities; the digest checked after each version through `Sha256PolicyDigest`; records decoded through `JsonStateRecordCodec`; publication at most once per 5 ms (CONFIG) measured on the `BootClock` port (`FakeBootClock` in tests), always at a version boundary; the builder reads no wall clock. There is no Kafka and no apply thread yet: tests drive the builder, and Story 9.3 runs it on the apply thread. `tests/support`: `FakePolicyView` with `new()` and `failing()`.

**Acceptance Criteria:**
- **Given** the records of one version delivered in shuffled order with duplicates, **When** `VersionAssembly` collects them, **Then** the version is complete only when all `count` records are present, duplicates are dropped, and a property test shows that the outcome does not depend on the order within a version, proven in `make.unit_tests`.
- **Given** a builder at version V and records of version V+2, **When** they are offered, **Then** the gap verdict is reported and the published snapshot stays at V, proven in `make.unit_tests`.
- **Given** a record for an already applied version, **When** its `iam-digest-after` equals the value in the ring, differs from it, carries a lower log epoch, or carries a lower relay epoch than one already seen, **Then** it is ignored, reported as conflicting content (fence), reported as a lower log epoch (fence), or ignored, in that order, proven in `make.unit_tests`.
- **Given** a complete version whose last `iam-digest-after` differs from the incremental digest, **When** it is applied, **Then** the builder reports a digest mismatch and does not publish that version, proven in `make.unit_tests`.
- **Given** random histories of role, subject, catalogue, route, upstream, rate-policy and revocation records including duplicates, tombstones and relay takeovers, **When** a property test compares incremental apply with a full rebuild from the final raw state, **Then** the raw state, the digest and every derived structure are equal, proven in `make.unit_tests`.
- **Given** the decision corpus of Story 6.1 written through the API and replayed from its state rows into the builder, **When** an integration test decides every corpus check through `PolicyView` and through `PolicyReadRepository` on PostgreSQL, **Then** every decision is identical, with zero false allows and zero false denies, proven in `make.integration_tests`.
- **Given** 50 versions applied within 5 ms of controlled clock time, **When** the builder publishes, **Then** it publishes at most once and at a version boundary, and a reader holding an earlier `Arc` keeps reading its own version unchanged, proven in `make.unit_tests`.
- **Given** a snapshot built from 100,000 synthetic subjects, **When** the test computes its accounted size, **Then** the figure is printed as a measurement on the test host and labelled as not a gate value; the 12.5% bound of NFR-38 is proven in Story 16.7, proven in `make.unit_tests`.
- **Given** a backward jump of the wall clock (`Clock`) while versions are applied, **When** the builder publishes, **Then** publication timing is unchanged, because the coalescing interval is measured on `BootClock` only, proven in `make.unit_tests`.
- **Given** the story's changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.integration_tests`, `make.tests_with_coverage` and `make.mutation_tests_diff` run, **Then** all pass.

**Depends on:** 1.1, 1.7, 6.1, 7.2, 8.2

### Story 9.2: Run the gateway mode with its listeners and configuration

As an operator, I want `service gateway` to start the data plane from the same image as `iam-control`, with a TLS public listener, an internal listener and a probe listener, so that the two deployables are two run modes of one build and the data plane needs no database.
Covers FR-45, FR-54, FR-55, FR-67, NFR-31.
Composition root: `command/gateway.rs` (new) with its own tokio runtime builder (`TOKIO_WORKER_THREADS` honoured, `max_blocking_threads` 16) and the `gateway` dispatch arm in `command.rs`; `bootstrap/gateway/listener.rs` (rustls with TLS 1.3 and 1.2, ALPN `h2` and `http/1.1`, the certificate from `GATEWAY_TLS_CERT_FILE` and `GATEWAY_TLS_KEY_FILE` hot-reloaded through an `ArcSwap` certificate resolver, the last valid pair kept when a reload fails; plain HTTP is accepted only in `dev` and `test` without the files); `bootstrap/gateway/internal.rs` with the internal router on `GATEWAY_INTERNAL_LISTEN` (admitted only from `iam-control` and gateway pods; it later serves `/internal/freshness` and `/internal/policy/applied` of Stories 9.5 and 13.3) and `bootstrap/gateway/probe.rs` with the probe router on `GATEWAY_PROBE_LISTEN` (`/ping` now; `/internal/startup`, `/internal/ready`, `/internal/drain` and `/metrics` from Stories 9.7, 15.2 and 16.2); the gateway task set registered with the task supervisor of Story 6.9 (empty until Story 9.3); `SeededRng` (the `Rng` adapter, seeded from the operating system) in the gateway's adapters; SIGTERM handling within `SHUTDOWN_GRACE_PERIOD`. The gateway mode parses the JWT key set at start and never creates a PostgreSQL pool. Until the pipeline of Story 10.2 exists, the public listener answers every request with 503 `iam_stale`, because no snapshot is published. Configuration: `service check-config --mode gateway` validates a gateway configuration without database settings and `--mode control` (the default) the control configuration; the variables `GATEWAY_LISTEN`, `GATEWAY_INTERNAL_LISTEN`, `GATEWAY_PROBE_LISTEN`, `GATEWAY_TLS_CERT_FILE`, `GATEWAY_TLS_KEY_FILE`, `POD_NAME` and `POD_NAMESPACE` with their `docs/environment.md` rows and local defaults, and `TOKIO_WORKER_THREADS` documented as read by tokio. `service healthcheck --mode gateway` probes `/ping` on the probe listener (FR-54); the Dockerfile health check and a compose service `iam-gateway` running `service gateway` use it; the Dockerfile, `command/check_config.rs`, `command/healthcheck.rs`, their sibling tests and `tests/integration/check_config.rs`, `healthcheck.rs` and `support.rs` are added to `.templatesyncignore` in this story, because it changes them. The listener binds in `command/gateway.rs` carry `#[expect(clippy::disallowed_methods, reason = ...)]` like the template's own socket owners, and the socket-owner rule list in `docs/architecture.md` names them. ADR 0015 (IAM is the API gateway: split planes, one image, two run modes) is added.

**Acceptance Criteria:**
- **Given** a gateway configuration without any `DATABASE_*` variable, **When** `service check-config --mode gateway` runs, **Then** it exits 0, and the same configuration with `--mode control` exits 2 naming `DATABASE_URL`, proven in `make.integration_tests`.
- **Given** equal addresses for any two listeners, missing TLS files outside `APP_ENV` `dev` and `test`, or a missing `JWT_PUBLIC_KEYS_FILE`, **When** `service check-config --mode gateway` runs, **Then** it exits 2 naming the variable, proven in `make.integration_tests`.
- **Given** `service gateway` started with a test certificate, **When** clients connect with TLS 1.3, TLS 1.2 and TLS 1.1, **Then** the first two succeed with `h2` and `http/1.1` negotiable through ALPN and TLS 1.1 is refused, proven in `make.integration_tests`.
- **Given** a running gateway, **When** the certificate files are replaced with a new valid pair and then with an unparsable file, **Then** new handshakes present the new certificate, and after the failed reload the last valid pair stays in force and an error is logged, proven in `make.integration_tests`.
- **Given** a running gateway without a published snapshot, **When** a request reaches the public listener, **Then** it gets 503 `iam_stale` with `Retry-After: 1`, while `/ping` on the probe listener answers 200, proven in `make.integration_tests`.
- **Given** `DATABASE_URL` unset, **When** `service gateway` starts, **Then** it starts and no PostgreSQL connection is attempted, proven in `make.integration_tests`.
- **Given** `TOKIO_WORKER_THREADS=2`, **When** the gateway runtime starts, **Then** the runtime reports two worker threads and a blocking-thread limit of 16, proven in `make.integration_tests`.
- **Given** SIGTERM, **When** shutdown runs, **Then** the process exits within `SHUTDOWN_GRACE_PERIOD` with the template's exit codes, proven in `make.integration_tests`.
- **Given** the built image, **When** the container health check runs `service healthcheck --mode gateway`, **Then** it reports healthy from the probe listener, `lib.rs` is unchanged, and the seam check of Story 1.2, extended with the Dockerfile, `command/check_config.rs`, `command/healthcheck.rs` and their tests, shows that `.templatesyncignore` covers them, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.validate_invariants`, `make.check_security`, `make.unused_dependencies`, `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.integration_tests`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass and ADR 0015 is indexed.

**Depends on:** 1.1, 1.7, 2.5, 6.9

### Story 9.3: Bootstrap the gateway snapshot from the state topic

As the gateway, I want each pod to rebuild the complete policy from the state topic on a dedicated apply thread, so that every pod starts from the same verified state and PostgreSQL never takes part.
Covers FR-71, NFR-28, NFR-37.
Infrastructure: `KrafkaPolicyLogTail` (first form from Story 7.7) gains the bootstrap connection under principal `iam-gateway-bootstrap` with client id `iam-gateway-bootstrap`: `assign` partition 0, `read_committed`, reads from offset 0 up to the offset captured at start (`HW0`, from `ListOffsets` with isolation `READ_COMMITTED`, so the last stable offset), never an automatic reset, raw batches only. Application: the bootstrap part of the `PolicyTail` task, written as a pure step function `(state, input) -> (state, actions)` as `architecture.md` section 5.6 requires: bootstrap captures `HW0`, reads from offset 0, finishes the version that straddles `HW0` or publishes at V−1 when that version is incomplete, fails closed when any record carries a version above the highest complete `__head`, and requires the computed digest to equal that `__head.digest` (one retry, then the pod stays not started). Composition root: `bootstrap/gateway/apply_thread.rs`, a dedicated OS thread that decodes and applies through the builder of Story 9.1 and frees retired snapshots only when their strong count reaches 1 (deferred reclamation); a dead apply thread exits the process; tests that drive the thread use bounded waits. Configuration: the Kafka variables in gateway mode, `KAFKA_BOOTSTRAP_SASL_USERNAME` and `KAFKA_BOOTSTRAP_SASL_PASSWORD`, with `docs/environment.md` rows and local defaults; metric events `policy_applied_version` and `policy_bootstrap_seconds`. Co-changes: the e2e world starts an in-process gateway per scenario on that scenario's own `POLICY_TOPIC`, fed by the scenario's relay. Until Story 9.4 the pod does not tail after bootstrap; this intermediate state never leaves the feature branch.

**Acceptance Criteria:**
- **Given** a state topic published by the relay from a database holding roles, assignments, catalogues, upstreams and routes, **When** a pod bootstraps from it, **Then** its published version equals the highest complete `__head` version, its digest equals the PostgreSQL digest, and its decisions over the corpus equal those of `iam-control` (NFR-28), proven in `make.integration_tests`.
- **Given** a relay stopped in the middle of a version through `test-broker`, **When** a pod bootstraps, **Then** it publishes the previous version and reports the trailing version as incomplete, proven in `make.integration_tests`.
- **Given** a record whose version is above the highest complete `__head`, **When** bootstrap ends, **Then** the pod stays not started, logs an error naming the version, and retries exactly once, proven in `make.integration_tests`.
- **Given** a computed digest that differs from the highest complete `__head.digest`, **When** the bootstrap step function finishes, **Then** it requests exactly one retry and then reports "not started", proven in `make.unit_tests`.
- **Given** a retired snapshot whose last reference is held by a request task, **When** the task drops it, **Then** a test hook shows that the destructor ran on the apply thread, proven in `make.integration_tests`.
- **Given** a panic injected into the apply thread, **When** the process observes it, **Then** the process exits with a nonzero code, proven in `make.integration_tests`.
- **Given** missing bootstrap credentials outside `dev` and `test`, **When** `service check-config --mode gateway` runs, **Then** it exits 2 naming the variable, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.check_security`, `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.integration_tests`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass.

**Depends on:** 1.1, 1.2, 7.4, 7.7, 9.1, 9.2

### Story 9.4: Tail the state topic and fence on inconsistency

As the gateway, I want each pod to follow the state topic in order after bootstrap and to fence itself on any inconsistency, so that every pod converges on the same verified state and a broken log never yields a decision.
Covers FR-71, FR-72, NFR-35, NFR-37.
Infrastructure: `KrafkaPolicyLogTail` gains tail mode under principal `iam-gateway` with client id `iam-gateway-<pod-name>`: the position kept in memory, `fetch.min.bytes` 1 and `KAFKA_FETCH_MAX_WAIT`, and a reseek to the in-memory position after a reconnect or when the watermark moves while the tail is idle. Application: the tail part of the `PolicyTail` step function hands raw batches to the apply thread over a bounded channel. Fence causes are conflicting content for one version, a lower log epoch, a gap, a broker append time older than 1 hour in tail mode, a watermark regression, an out-of-range position and a digest mismatch; the apply thread checks each version's digest before it publishes that version, so a version with a mismatching digest is never published. These are log-level faults: a fenced pod keeps its last verified snapshot until `FRESHNESS_HARD_BOUND` and rebootstraps through the path of Story 9.3 after a random delay between 0 and `FRESHNESS_READY_BOUND` drawn through `Rng`; a dead tail task exits the process. Before startup completes, the gateway evaluates the topic verdict of `KrafkaTopicInspector` under `KAFKA_CONFIG_GATES` (the ACL checks stay with `iam-control`). Configuration: `KAFKA_FETCH_MAX_WAIT`, `FRESHNESS_READY_BOUND` and `FRESHNESS_HARD_BOUND` (3 to 30 seconds and above the ready bound) with `docs/environment.md` rows and local defaults. Co-changes: the e2e world's in-process gateway tails after bootstrap.

**Acceptance Criteria:**
- **Given** a pod that published the version before an incomplete trailing version at bootstrap, **When** the remaining records of that version arrive, **Then** the pod applies it in tail mode, proven in `make.integration_tests`.
- **Given** two in-process gateways in tail mode, **When** versions are committed through the API, **Then** both apply them in order and reach the same version and digest, proven in `make.integration_tests`.
- **Given** versions republished after a relay takeover, **When** the tail reads them, **Then** they are ignored as duplicates and the pod neither fences nor rebootstraps, proven in `make.integration_tests`.
- **Given** each fence cause injected through `test-broker` or a test topic, **When** the pod meets it, **Then** it fences, keeps its last verified snapshot, and starts a rebootstrap after a delay drawn by the seeded `Rng` within 0 to `FRESHNESS_READY_BOUND` of controlled clock time, proven in `make.integration_tests`.
- **Given** the broker connection dropped and restored by fault injection, **When** the tail resumes, **Then** it reseeks to its in-memory position and applies every record once and in order, proven in `make.integration_tests`.
- **Given** a state topic with `cleanup.policy=delete` or two partitions and `KAFKA_CONFIG_GATES=enforce`, **When** the gateway starts, **Then** startup never completes and the log names the setting; with `relaxed` in `APP_ENV=test` a replication factor of 1 passes with a warning, proven in `make.integration_tests`.
- **Given** a version whose computed digest differs from its `iam-digest-after`, **When** the apply thread finishes it, **Then** the version is never published, the previous version keeps serving, and the pod fences, proven in `make.integration_tests`.
- **Given** a panic injected into the tail task, **When** the process observes it, **Then** the process exits with a nonzero code, proven in `make.integration_tests`.
- **Given** a `FRESHNESS_HARD_BOUND` outside 3 to 30 seconds or not above `FRESHNESS_READY_BOUND`, **When** `service check-config --mode gateway` runs, **Then** it exits 2 naming the variable, proven in `make.integration_tests`.
- **Given** a 50 MB compose topic and 50 administrative writes per second, **When** a pod bootstraps and two pods tail, **Then** the bootstrap time and the commit-to-applied p99 are printed as compose-host measurements next to the 30-second target of NFR-37 and the 500 ms target of NFR-35, never as gate values, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.integration_tests`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass.

**Depends on:** 1.1, 7.3, 9.3

### Story 9.5: Prove freshness and enforce the staleness bound

As the owner of IAM, I want every gateway pod to allow a request only while it holds a recent, quorum-backed proof that its snapshot contains every acknowledged change, so that staleness is bounded by `T_hard` and a frozen or partitioned partition leader cannot keep a pod allowing.
Covers FR-73, NFR-36.
Domain: `FreshnessRule` (allow only while `now_boot − last_proof ≤ FRESHNESS_HARD_BOUND` and the watchdog shows no gap above `FRESHNESS_READY_BOUND` since that proof), `FreshnessProof`, and the `PolicyLogProbe` and `PeerFreshnessClient` ports. Infrastructure: `KrafkaPolicyLogProbe`, which records `t_s` on the `BootClock` before sending anything, asks at least 2 of the 3 replica brokers for the partition metadata and accepts only the same leader and leader epoch, an epoch at least the highest seen and exactly one partition, then sends `ListOffsets` with isolation `READ_COMMITTED` and `current_leader_epoch` for every partition, so `HW(t_s)` is the last stable offset; `OFFSET_NOT_AVAILABLE`, `FENCED_LEADER_EPOCH`, `UNKNOWN_LEADER_EPOCH`, a regressed watermark or a nonzero watermark on another partition yields no proof. `LinuxBootClock` reads `CLOCK_BOOTTIME` through `rustix`. Application: the `FreshnessProber` task every `FRESHNESS_PROBE_INTERVAL` with a 1-second watchdog tick; the apply thread attaches a proof to a published snapshot only once that snapshot contains every complete version whose last record lies below `HW(t_s)`; the peer cross-check treats the proof as invalid and alerts when a peer reports a newer applied version for more than 1 second while the pod is fresh. Composition root: `/internal/freshness` (published version, proof age, digest and the configured `FRESHNESS_HARD_BOUND` as `hardBoundMs`) on the internal listener; the pipeline's snapshot step evaluates `FreshnessRule` and answers 503 `iam_stale` with `Retry-After: 1`. Until Story 15.1 wires `HyperPeerFreshnessClient`, the composition root passes an empty peer set, so the cross-check is inactive; this intermediate state never leaves the feature branch. Configuration: `FRESHNESS_PROBE_INTERVAL`; metric events `policy_proof_age_seconds` and `policy_fresh`. ADR 0024 (freshness contract: watermark proof, replica-quorum epoch check, `T_hard` and Sync-Fence) is added and states that the bound stays conditional until the results of Story 1.3 and test T15 confirm the replica-quorum argument.

**Acceptance Criteria:**
- **Given** a proof taken at `t_s` and paused time, **When** requests arrive at `t_s + FRESHNESS_HARD_BOUND` and 1 ms later, **Then** the first is allowed to proceed and the second gets 503 `iam_stale` with `Retry-After: 1`, proven in `make.integration_tests`.
- **Given** a `FakeBootClock` jump larger than `FRESHNESS_READY_BOUND` after a proof, **When** the watchdog ticks, **Then** the proof is invalid until a new proof is attached, proven in `make.unit_tests`.
- **Given** each probe error injected through `test-broker` (each KIP-207 and KIP-320 error, a regressed watermark, a nonzero watermark on a second partition, only one reachable replica broker, two brokers disagreeing on the leader epoch, an epoch lower than one already seen), **When** the probe runs, **Then** no proof is produced, proven in `make.integration_tests`.
- **Given** a probe whose `HW(t_s)` lies beyond the last complete version of the published snapshot, **When** the probe returns, **Then** the proof is attached only to the first later snapshot that contains every complete version below `HW(t_s)`, proven in `make.unit_tests`.
- **Given** an open relay transaction injected through `test-broker` that holds the records of version V, **When** the probe runs before and after the commit, **Then** the first proof stops at the last stable offset below V and covers no snapshot claim for V, and only a probe sent after the commit yields a proof that requires V, proven in `make.integration_tests`.
- **Given** a probe whose response is delayed by fault injection, **When** the proof is attached, **Then** its time is `t_s`, recorded before the request was sent, proven in `make.integration_tests`.
- **Given** a fake `PeerFreshnessClient` that reports a newer applied version for 1.5 seconds and another for 0.5 seconds, **When** the cross-check runs, **Then** the first invalidates the proof and alerts and the second does not, proven in `make.integration_tests`.
- **Given** a fresh pod, **When** `/internal/freshness` is read, **Then** it returns the published version, the proof age, the digest and `hardBoundMs`, and the metric events `policy_proof_age_seconds` and `policy_fresh` are recorded, proven in `make.integration_tests`.
- **Given** a zero or negative `FRESHNESS_PROBE_INTERVAL`, **When** `service check-config --mode gateway` runs, **Then** it exits 2 naming it, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.integration_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass and ADR 0024 is indexed.

**Depends on:** 1.1, 1.3, 9.4

### Story 9.6: Check derived state and export divergence metrics

As an operator, I want each pod to verify the structures its decisions read against the raw replicated records and to export its applied state, so that a bug in incremental maintenance stops the pod's allows at once instead of producing wrong decisions, and diverging pods are visible.
Covers FR-74.
Application: the `DerivedStateChecker`, which runs on the apply thread every `DERIVED_STATE_CHECK_INTERVAL`, rebuilds the derived structures (compiled role sets, the role-to-subject reverse index, interned assignment lists, routers) of a rotating 1/16 of the shards from the raw records, and compares a hash of the decision-relevant output (each subject's sorted effective-key set and the route-table hash) with the incremental structures. A mismatch means the published snapshot is wrong, so, unlike the log-level faults of Story 9.4, the pod stops allowing at once: it clears its proof, every request gets 503 `iam_stale` (decision API `deny`/`unavailable`), readiness fails, and the pod rebootstraps through the path of Stories 9.3 and 9.4. After each publication the pod emits the metric events `policy_applied_version`, `policy_digest_info` and `policy_derived_hash_info`; Prometheus rendering follows in Story 16.2. Configuration: `DERIVED_STATE_CHECK_INTERVAL` with its `docs/environment.md` row and local default.

**Acceptance Criteria:**
- **Given** a consistent snapshot, **When** 16 check intervals pass on the controlled clock, **Then** every shard was checked exactly once and the pod never fenced, proven in `make.integration_tests`.
- **Given** a derived structure corrupted by a test hook, **When** the interval that covers its shard runs, **Then** the pod fences, logs an error naming the mismatch and starts a rebootstrap, and `policy_derived_hash_info` changes, proven in `make.integration_tests`.
- **Given** a derived mismatch detected while the pod's proof is still younger than `FRESHNESS_HARD_BOUND`, **When** requests arrive before the rebootstrap has published a verified snapshot, **Then** none is allowed: the public listener answers 503 `iam_stale` and the decision API answers `deny` with reason `unavailable`, proven in `make.integration_tests`.
- **Given** two pods with the same history, **When** their metric events are compared, **Then** `policy_applied_version`, `policy_digest_info` and `policy_derived_hash_info` are equal, and they differ once one pod's derived structure is corrupted, proven in `make.integration_tests`.
- **Given** a check in progress, **When** a request is served, **Then** it reads the published snapshot without waiting for the check, proven in `make.integration_tests`.
- **Given** a zero `DERIVED_STATE_CHECK_INTERVAL`, **When** `service check-config --mode gateway` runs, **Then** it exits 2 naming it, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.integration_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass.

**Depends on:** 1.1, 9.4

### Story 9.7: Gate startup and readiness on policy freshness

As an operator, I want the gateway's probes to pass only on a verified, fresh snapshot, so that Kubernetes and the load balancer never send traffic to a pod that cannot decide correctly, and an outage never turns into a restart storm.
Covers FR-54.
Composition root: on the probe listener, `/internal/startup` passes once bootstrap is complete, the `__head` digest is verified, the configuration gates passed, the first freshness proof is attached to a published snapshot and the JWT key set is parsed; `/internal/ready` passes while the pod is started, not rebootstrapping, not fenced, with digest and derived-state checks passing and, until Story 15.1 replaces it with the peer-relative verdict, a proof no older than `FRESHNESS_READY_BOUND`; `/ping` (liveness) passes while a tokio watchdog that ticks every second is less than 10 seconds old, and never depends on Kafka, PostgreSQL, Valkey or upstreams. Requests on the public listener before startup completes get 503 `iam_stale`. Co-changes: the e2e world waits for `/internal/ready` of its in-process gateway before proxied scenarios start.

**Acceptance Criteria:**
- **Given** a gateway before its bootstrap finished, **When** the probes are read, **Then** `/internal/startup` and `/internal/ready` answer 503 and `/ping` answers 200, proven in `make.integration_tests`.
- **Given** a completed bootstrap with a verified digest, passed configuration gates and an attached proof, **When** the probes are read, **Then** `/internal/startup` and `/internal/ready` answer 200, proven in `make.unit_tests`.
- **Given** an unparsable JWT key file at start, **When** the gateway runs, **Then** `/internal/startup` never passes, proven in `make.integration_tests`.
- **Given** a fenced pod, **When** its probes are read, **Then** `/internal/ready` answers 503 until the rebootstrap completes and `/internal/startup` stays 200, proven in `make.integration_tests`.
- **Given** the compose broker stopped, **When** `FRESHNESS_READY_BOUND` passes, **Then** `/internal/ready` answers 503 and `/ping` stays 200, and after `FRESHNESS_HARD_BOUND` proxied requests get 503 `iam_stale`, proven in `make.integration_tests`.
- **Given** the tokio watchdog stalled by a test hook for more than 10 seconds of controlled time, **When** `/ping` is read, **Then** it answers 503, proven in `make.unit_tests`.
- **Given** the story's changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.integration_tests`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass and the template's health scenarios stay green.

**Depends on:** 1.1, 9.5, 9.6

## Epic 10: Request path for REST and GraphQL

This epic turns the gateway into the ingress for every service: zone-aware upstream discovery, the REST pipeline with authentication and authorization from the snapshot, principal propagation, upstream resilience, anonymous routes, the per-route enforcement mode, GraphQL proxying with coordinate authorization, edge hardening, read-your-writes, the decision API served from the snapshot on its own listener, CORS and CSRF rules, and the east-west listener for calls between services. Proxied upstream traffic is not an IAM capability and has no contract snapshot.

### Story 10.1: Discover upstream endpoints with zone-aware selection

As the gateway, I want to know every upstream endpoint with its readiness and zone and to prefer endpoints in my own zone, so that requests go to healthy endpoints and rarely cross availability zones.
Covers FR-87, NFR-43.
Domain: the `EndpointWatch` port, `UpstreamEndpoint` (address, port, zone, `ready`, `serving`, `terminating`) and `EndpointSelector`, a pure zone-aware power-of-two-choices rule on in-flight counts with the seeded `Rng`: it picks two endpoints of the pod's own zone and spills to other zones only when the zone has no healthy endpoint or its in-flight load per endpoint exceeds the threshold (CONFIG). Infrastructure: `KubernetesEndpointWatch` (watches EndpointSlices of the upstream Services and of `iam-gateway-peers` with read-only RBAC through a plain hyper client using the ServiceAccount token and the in-cluster CA; resumes from the last resource version and relists on 410) and `StaticEndpointWatch` (reads `UPSTREAM_STATIC_ENDPOINTS_FILE` for compose and e2e); DNS with fully qualified names and a trailing dot is the fallback. Application: the `EndpointWatcher` task. `GATEWAY_ZONE` is derived from the pod's own entry in the `iam-gateway-peers` slices, or set explicitly in static mode. Configuration: `UPSTREAM_DISCOVERY`, `UPSTREAM_STATIC_ENDPOINTS_FILE`, `UPSTREAM_ZONE_AWARE` and `GATEWAY_ZONE` with their `docs/environment.md` rows and local defaults (`static` in `.env` and `.env.test`). `tests/support`: `FakeEndpointWatch` and a fake Kubernetes API server.

**Acceptance Criteria:**
- **Given** a fake Kubernetes API serving EndpointSlices, **When** an endpoint is added, becomes not ready, becomes terminating or changes zone, **Then** the watched set reflects each change after one watch event, and only ready endpoints are offered for new requests, proven in `make.integration_tests`.
- **Given** a dropped watch connection and a 410 response, **When** the watch resumes, **Then** it continues from the last resource version, or relists after the 410, without losing an endpoint, proven in `make.integration_tests`.
- **Given** the requests the adapter sends, **When** the fake API records them, **Then** they use only `get`, `list` and `watch` on `endpointslices`, proven in `make.integration_tests`.
- **Given** healthy own-zone endpoints below the in-flight threshold, **When** a property test with a seeded `Rng` draws 100,000 selections, **Then** no selection crosses zones, and the cross-zone share stays at most 5% across random load patterns in which the own zone stays healthy (NFR-43), proven in `make.unit_tests`.
- **Given** two candidate endpoints with different in-flight counts, **When** the selector chooses, **Then** it picks the one with fewer in-flight requests; with no healthy own-zone endpoint it picks from the other zones, proven in `make.integration_tests`.
- **Given** `UPSTREAM_DISCOVERY=static` without a file, or an unparsable file, **When** `service check-config --mode gateway` runs, **Then** it exits 2 naming the variable, proven in `make.integration_tests`.
- **Given** the pod's own entry in the `iam-gateway-peers` slices and no `GATEWAY_ZONE`, **When** the gateway starts, **Then** its zone is taken from that entry; an explicit `GATEWAY_ZONE` overrides it in static mode, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.integration_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass.

**Depends on:** 1.1, 1.7, 9.2

### Story 10.2: Authorize REST requests in the gateway pipeline

As a customer of a VilnaCRM service, I want my REST request authenticated and authorized by the gateway from one policy snapshot, so that every service is protected by the same rules without implementing them itself.
Covers FR-4, FR-7, FR-13, FR-59.
Application: `RequestAuthorizer`, which, given one loaded snapshot, the matched route and the principal, resolves the REST template key through `RestOperationMatcher` on the route's service catalogue and decides through `AccessDecisionService` fed from `PolicyView`; for IAM's own routes (service `iam`) it applies the rule table of `IamAccessGuard` from the snapshot first (FR-4). Infrastructure: `SnapshotRevocationView` (the `RevocationView` over the loaded snapshot's revocation sets, used by `CachingTokenRepository` in gateway mode). Composition root: `bootstrap/gateway/pipeline.rs` in the order of FR-59: header and connection limits (template limits until Story 10.9); the read-your-writes slot (Story 10.10); one snapshot load and the freshness check; the route match on host, method and the path normalised by `PathNormalizer` (400 on a path-rule violation, 404 without a route); the CORS slot (Story 10.12); the rate-limit slot (Epic 12); authentication from the bearer token or the `__Host-auth_token` cookie (401 with `WWW-Authenticate: Bearer`); authorization (403 with a reason code that never discloses another service's operations); the header-rewrite slot (Story 10.4); forwarding of the canonical re-encoded path through the `UpstreamForwarder` port; the access-record slot (Story 14.1). The request drops its snapshot `Arc` before any await on the forwarder. In this story the forwarder is a recording stub in tests and a placeholder that answers 502 in the gateway; Story 10.3 replaces it, and this intermediate state never leaves the feature branch. Configuration: the JWT and token-memo variables in gateway mode.

**Acceptance Criteria:**
- **Given** a route and a subject holding the route's key, **When** the subject sends a REST request through the pipeline with a recording forwarder, **Then** the forwarder receives the request with the canonical re-encoded path, and a counting `PolicyView` shows exactly one snapshot load per request, taken after the read-your-writes slot, proven in `make.integration_tests`.
- **Given** a request matching no route, **When** it is sent, **Then** the gateway answers 404 and the forwarder receives nothing, proven in `make.integration_tests`.
- **Given** paths with `%252e%252e`, a `..` segment, an encoded `/`, a NUL byte or more than 2,048 bytes, **When** they are sent, **Then** each gets 400 and never reaches the forwarder, proven in `make.integration_tests`.
- **Given** missing, invalid, expired and revoked tokens, **When** each is sent, **Then** each gets 401 with `WWW-Authenticate: Bearer`, and a valid token in the `__Host-auth_token` cookie is accepted, proven in `make.integration_tests`.
- **Given** a subject without the route's key, **When** it sends the request, **Then** it gets 403 with `permission_missing`, and a unit test shows that the reason for an operation unknown in the route's service is the same whether or not another service has it, proven in `make.unit_tests` and `make.integration_tests`.
- **Given** a proof older than `FRESHNESS_HARD_BOUND`, an incomplete bootstrap, a fenced pod and the `failing()` `PolicyView`, **When** requests are sent, **Then** each gets 503 `iam_stale` or a denial and never an allow (FR-13), and a panic injected into a request task yields 500, proven in `make.integration_tests`.
- **Given** a request handed to the forwarder, **When** the forwarder starts, **Then** a test hook shows that the snapshot's strong count is back to its baseline, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.check_security`, `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.integration_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass.

**Depends on:** 1.1, 2.6, 6.4, 8.4, 9.7

### Story 10.3: Forward requests to upstreams with body limits

As a customer of a VilnaCRM service, I want my authorized request forwarded to a healthy endpoint of the right upstream and the response relayed as it arrives, so that the gateway adds protection without changing what the service returns.
Covers FR-59, FR-87.
Domain: `UpstreamTarget`, `ForwardError` and the associated `Request` and `Response` types of the `UpstreamForwarder` port (`architecture.md` section 4.4). Composition root: `bootstrap/gateway/upstream.rs` with `HyperUpstreamForwarder` in its first form, placed in the composition root under the ADR 0023 fallback for this adapter (pooled HTTP/1.1 keep-alive or one h2c connection per endpoint by the upstream's `protocol`, connect timeout 250 ms, endpoint from `EndpointSelector`, request body streamed with the route's body limit, 10 MiB by default, response relayed unbuffered, hop-by-hop headers stripped); the forwarder applies the connect timeout itself with `tokio::time`. The pipeline uses `HyperUpstreamForwarder` instead of the placeholder of Story 10.2 and maps a body above the limit to 413, a refused or reset connection to 502 and a connect or response timeout to 504. Co-changes: the e2e world proxies through its in-process gateway to a fake upstream with static endpoints and calls IAM's own API through the routes seeded by Story 8.7; scenarios in `features/iam_gateway_proxy.feature`.

**Acceptance Criteria:**
- **Given** a route, an upstream on the fake upstream and a subject holding the route's key, **When** the subject sends a REST request through the gateway, **Then** the upstream's response is relayed unchanged, proven in `make.e2e_tests`.
- **Given** a body above the route's limit, a refused upstream connection and an upstream that never answers the connect, **When** requests are sent, **Then** they get 413, 502 and 504, proven in `make.integration_tests`.
- **Given** a subject without the IAM key of an IAM route and the bootstrapped administrator, **When** each calls the IAM operation through the gateway, **Then** the first gets 403 from the gateway and `iam-control` receives nothing, and the second reaches `iam-control` and succeeds, proven in `make.e2e_tests`.
- **Given** PostgreSQL and `iam-control` stopped after the pod became fresh, **When** proxied requests continue, **Then** they are decided and forwarded from the snapshot while the proof stays fresh, proven in `make.integration_tests`.
- **Given** a streamed request body, **When** it is forwarded, **Then** the upstream receives the bytes as they arrive and the gateway never buffers more than the per-connection cap, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.check_security`, `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.integration_tests`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass.

**Depends on:** 1.1, 8.7, 10.1, 10.2

### Story 10.4: Propagate the principal and sanitise headers

As an upstream service, I want the gateway to tell me who the caller is through headers that a client can never forge, so that I can trust the identity without verifying tokens myself.
Covers FR-68.
Composition root: the header-rewrite step of the pipeline strips every client-supplied `X-IAM-*`, `Forwarded` and `X-Forwarded-*` header, then sets `X-IAM-Subject`, `X-IAM-Subject-Kind`, `X-IAM-Session`, `X-IAM-Policy-Version`, `X-Request-Id` (the template's request id) and `X-Forwarded-For` (the client address) on the upstream request; it forwards `Authorization` and the `__Host-auth_token` cookie unchanged only to upstreams with `forwardCredentials = true` (User service, whose routes re-check sessions, and `iam-control`) and strips both from every other upstream request, which relies on the `X-IAM-*` headers, so a compromised or header-logging upstream never sees a replayable token; it adds `X-IAM-Policy-Version` to every response. No internal token is signed per request.

**Acceptance Criteria:**
- **Given** a request carrying forged `X-IAM-Subject`, `X-IAM-Policy-Version`, `Forwarded` and `X-Forwarded-For` headers, **When** an echo upstream reports what it received, **Then** none of the forged values reaches it, proven in `make.integration_tests`.
- **Given** an authorized request, **When** the echo upstream reports its headers, **Then** `X-IAM-Subject`, `X-IAM-Subject-Kind`, `X-IAM-Session` and `X-IAM-Policy-Version` carry the decision's subject, kind, session and published version, `X-Request-Id` equals the response's request id, and `X-Forwarded-For` holds the client address, proven in `make.integration_tests`.
- **Given** an authorized request with a bearer token and a `__Host-auth_token` cookie next to another cookie, **When** it is forwarded to an upstream with `forwardCredentials = true` and to one without, **Then** the first receives `Authorization` and the cookie byte for byte, and the second receives neither while its other cookie is kept, proven in `make.integration_tests`.
- **Given** any response through the gateway, including 401, 403, 404 and 503 answers of the gateway itself, **When** it reaches the client, **Then** it carries `X-IAM-Policy-Version` with the version of the snapshot used, or of the published snapshot when none was loaded, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.integration_tests`, `make.tests_with_coverage` and `make.mutation_tests_diff` run, **Then** all pass.

**Depends on:** 1.1, 10.3

### Story 10.5: Apply upstream timeouts, retries, outlier ejection and concurrency limits

As an operator, I want the gateway to protect upstreams and clients from slow or failing endpoints with bounded timeouts, safe retries and load shedding, so that one bad endpoint never takes down a service or ties up the gateway.
Covers FR-66.
Domain: the pure rules `RetryRule`, `RetryBudget` and `OutlierRule`, unit-tested on their own. Composition root: `HyperUpstreamForwarder` gains the timeouts (connect 250 ms; response headers 10 seconds for REST and 30 seconds for GraphQL routes; whole request 60 seconds; none for streaming routes; each overridable per route and upstream), the retry rules (only when the request provably was not sent, meaning refused, closed before write, HTTP/2 `REFUSED_STREAM` or a GOAWAY above the last stream id, in which case the forwarder resends the request hyper hands back, or for idempotent methods on routes with `retryPolicy = idempotent` when the request has no body or a body buffered under 64 KiB; at most one retry, to another endpoint, within a retry budget of 10% per upstream; GraphQL mutations are never retried), passive outlier ejection (after `outlierConsecutiveErrors`, default 5, consecutive connect errors or 5xx responses, for 10 seconds, at most 50% of endpoints), and the per-upstream `concurrencyLimit` with fail-fast 503 `upstream_overloaded`. Upstream failures return 502 and upstream timeouts 504. All values are CONFIG. Timers, retries and the retry budget run inside the composition-root forwarder, which owns the streamed body and may use `tokio` directly; `iam-infrastructure` takes no direct `tokio` dependency. Tests use a hyper fake upstream that injects GOAWAY, `REFUSED_STREAM`, resets and slow bodies.

**Acceptance Criteria:**
- **Given** a fake upstream that delays the response headers, **When** REST and GraphQL requests are sent with paused time, **Then** they get 504 after 10 and 30 seconds, and a per-route override shortens the REST limit, proven in `make.integration_tests`.
- **Given** a connection refused by the first endpoint, **When** a POST is sent on a route with `retryPolicy = none`, **Then** it is retried once on another endpoint, because it provably was not sent, proven in `make.integration_tests`.
- **Given** a GET on a route with `retryPolicy = idempotent` whose first attempt returns a reset after the request was written, **When** it is sent, **Then** it is retried once on another endpoint; a GraphQL mutation under the same fault is never retried and gets 502, proven in `make.integration_tests`.
- **Given** a PUT with a streamed 1 MiB body on a route with `retryPolicy = idempotent` whose first attempt is reset after the body was written, and the same PUT with a 4 KiB buffered body, **When** each is sent, **Then** the streamed request is not retried and gets 502, and the buffered request is retried once on another endpoint, proven in `make.integration_tests`.
- **Given** the domain rules `RetryRule`, `RetryBudget` and `OutlierRule`, **When** their unit tests run over every retry case, budget boundary and ejection cap, **Then** each decision matches the rules above, proven in `make.unit_tests`.
- **Given** retries above 10% of the upstream's recent requests, **When** another retry would be needed, **Then** it is not made and the request gets 502, proven in `make.integration_tests`.
- **Given** an endpoint returning five consecutive 5xx responses, **When** further requests arrive within 10 seconds, **Then** that endpoint receives none, and with four of six endpoints failing no more than three are ejected, proven in `make.integration_tests`.
- **Given** an upstream with `concurrencyLimit` 2 and two requests in flight, **When** a third arrives, **Then** it gets 503 `upstream_overloaded` at once, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.integration_tests`, `make.tests_with_coverage` and `make.mutation_tests_diff` run, **Then** all pass.

**Depends on:** 1.1, 10.3

### Story 10.6: Serve anonymous routes under freshness fencing

As a visitor, I want to sign in, refresh tokens and reset my password through the gateway without a token, so that User service's public endpoints work, while a stale pod still never serves a route that has since become protected.
Covers FR-63.
Application: `RequestAuthorizer` returns an allow without required keys for routes flagged `anonymous`; the pipeline skips authentication and authorization on them but keeps the freshness check, body limits and, from Epic 12, rate limits; principal headers are still stripped and none is set. Co-changes: the reference route configuration for User service's public endpoints (`/api/signin`, `/api/signin/2fa`, `/api/token`, `/api/oauth/*`, `/api/reset-password*`, `POST /api/users`, `/api/users/confirm`, `/api/health`) in `deploy/kubernetes/routes/user-service.json`, in the request format of Story 8.6 (the User service upstream sets `forwardCredentials = true`), and its description in `docs/operations.md`. Rate limits on anonymous routes are proven in Story 12.2.

**Acceptance Criteria:**
- **Given** an anonymous route, **When** a request without a token and one with an invalid token are sent through the gateway, **Then** both are forwarded, no `X-IAM-Subject` reaches the upstream, and the invalid token is forwarded unchanged without being verified, proven in `make.integration_tests`.
- **Given** a proof older than `FRESHNESS_HARD_BOUND`, **When** a request reaches an anonymous route, **Then** it gets 503 `iam_stale`, proven in `make.integration_tests`.
- **Given** a body above the anonymous route's limit, **When** it is sent, **Then** it gets 413, proven in `make.integration_tests`.
- **Given** an anonymous route that a new version makes protected, **When** the pod has applied that version, **Then** a request without a token gets 401, proven in `make.integration_tests`.
- **Given** the reference route configuration, **When** it is applied in a dry run through the operation of Story 8.6 in an e2e scenario, **Then** it validates and lists exactly the public endpoints above as anonymous, proven in `make.e2e_tests`.
- **Given** the story's changes, **When** `make.integration_tests`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass.

**Depends on:** 1.1, 8.6, 10.3

### Story 10.7: Enforce the per-route enforcement mode

As a platform engineer, I want to put a route into audit mode during a rollout, so that I can see which requests the new rules would deny before I enforce them.
Covers FR-69.
Application: `RequestAuthorizer` applies the route's `enforcement`: in `enforce` (the default) a denial is a 403; in `audit` a would-deny decision is forwarded with reason `audit_mode_would_deny`. Authentication still applies in audit mode, so a request without a valid token still gets 401. The outcome carries the reason into the metric event `gateway_decisions_total` (by reason); Story 14.1 writes the same reason into the access record. Changing the mode needs `iam:route:anonymous` and is audited (Story 8.4).

**Acceptance Criteria:**
- **Given** a route in `audit` mode and a subject without its key, **When** the subject sends a request through the gateway, **Then** the request reaches the upstream and the decision outcome carries `audit_mode_would_deny`, recorded in `gateway_decisions_total`, proven in `make.integration_tests`.
- **Given** the same route in `enforce` mode, **When** the same request is sent, **Then** it gets 403 and the upstream receives nothing, proven in `make.integration_tests`.
- **Given** a route in `audit` mode, **When** a request without a token is sent, **Then** it gets 401, proven in `make.integration_tests`.
- **Given** a principal without `iam:route:anonymous`, **When** it switches the route to `audit` over REST and over GraphQL, **Then** both are refused and audited, and the gateway keeps enforcing, proven in `make.e2e_tests`.
- **Given** the story's changes, **When** `make.integration_tests`, `make.e2e_tests`, `make.tests_with_coverage` and `make.mutation_tests_diff` run, **Then** all pass.

**Depends on:** 1.1, 10.3

### Story 10.8: Proxy GraphQL requests with coordinate authorization

As a customer of a GraphQL service, I want my GraphQL request authorized on every field it selects and forwarded byte for byte, so that a document can never reach a field I may not use and the gateway and the upstream always read the same operation.
Covers FR-8, FR-60.
Domain: the `DocumentCache` port. Application: `GraphQlRequestAnalyzer` (envelope decode of `application/json` only, rejecting duplicate keys with 400; only the members `query`, `operationName`, `variables` and `extensions` are accepted, `query` must be a non-empty string, and `extensions.persistedQuery` or any document-id member (`documentId`, `queryId`, `id`) is rejected with 400, so no operation reaches an upstream without a document the gateway authorized; an empty coordinate set is `malformed_operation`, a denial; a JSON array is a batch of at most 10 operations, each authorized; `DocumentCache` lookup keyed by the `DocumentKey` of Story 6.6 with full-text confirmation; the per-subject parse budget of 20 cache misses per second and 1 MB of parsed text per second (CONFIG), 429 above it; coordinate extraction through `GraphQlDocumentAnalyzer` against the type graph in the snapshot; introspection only with `gql:{service}:__introspection`); `RequestAuthorizer` decides all-or-nothing over the coordinates. Infrastructure: `MokaDocumentCache` (values are coordinate sets and counts, never decisions). Composition root: routes flagged `graphql` accept `POST` only (405 with `Allow: POST` otherwise, so an operation never travels in a URL) and buffer the body up to the route limit (64 KiB default; the seeded IAM GraphQL route has 6 MiB), answer 413 above it and 415 for multipart or other content types; documents above 8 KB are parsed through `spawn_blocking` on the bounded blocking pool (`max_blocking_threads` 16), never on a request worker; the original bytes are forwarded unchanged. Metric event `graphql_document_cache_hit_ratio`.

**Acceptance Criteria:**
- **Given** a subject holding some of the coordinates a document selects, **When** it sends the document through the gateway, **Then** it gets 403 listing no coordinate of another service, and with all coordinates held the request reaches the upstream with the original bytes, proven in `make.integration_tests`.
- **Given** a body with duplicate `query` keys, a multipart body and a `text/plain` body, **When** they are sent, **Then** they get 400, 415 and 415, proven in `make.unit_tests`.
- **Given** a batch of 10 operations of which one is denied and a batch of 11, **When** they are sent, **Then** the first gets 403 and the second 400, proven in `make.unit_tests`.
- **Given** a body of 65 KiB on a default route and of 5 MiB on the IAM GraphQL route, **When** they are sent, **Then** the first gets 413 and the second is accepted, proven in `make.unit_tests`.
- **Given** a subject that sends 21 distinct uncached documents within one second of controlled time, **When** the 21st arrives, **Then** it gets 429 and cached documents of the same subject are still served, proven in `make.unit_tests`.
- **Given** an introspection query by a subject with and without `gql:{service}:__introspection`, **When** it is sent, **Then** only the holder's request is forwarded, proven in `make.integration_tests`.
- **Given** a 40 KB document, **When** it is parsed, **Then** a test hook shows that parsing ran on the blocking pool and not on a request worker, proven in `make.integration_tests`.
- **Given** the bootstrapped administrator, **When** it uploads a 5 MiB SDL through the gateway over REST and over GraphQL, **Then** both uploads succeed, proven in `make.e2e_tests`.
- **Given** a body carrying only `extensions.persistedQuery`, one with `documentId`, one with an empty `query` and one with an unknown top-level member, **When** they are sent, **Then** each gets 400 and the upstream receives nothing, proven in `make.integration_tests`.
- **Given** a `GET` request on a GraphQL route with the operation in the query string, **When** it is sent, **Then** it gets 405 with `Allow: POST` and the upstream receives nothing, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.integration_tests`, `make.e2e_tests`, `make.tests_with_coverage` and `make.mutation_tests_diff` run, **Then** all pass.

**Depends on:** 1.1, 6.6, 10.3

### Story 10.9: Harden the edge: smuggling rules, connection limits and Proxy Protocol

As the owner of IAM, I want the public listener to bound every connection and reject every ambiguous framing, so that slow clients, floods and request smuggling cannot exhaust the gateway or slip a request past authorization.
Covers FR-67, NFR-21, NFR-40.
Composition root: `bootstrap/gateway/listener.rs` reads the client address from Proxy Protocol v2 (`ppp`) when `GATEWAY_PROXY_PROTOCOL` is true and rejects a connection without a valid header; limits (all CONFIG): header block at most 16 KiB, header read timeout 10 seconds, HTTP/2 `max_concurrent_streams` 128 and `max_header_list_size` 16 KiB, buffered bytes at most 256 KiB per connection and 256 MB per pod, at most 64 connections per client IP and 32 per subject, keep-alive idle 120 seconds, connection age capped at 10 minutes plus or minus 20% (jitter through `Rng`) and ended with GOAWAY, and an earlier GOAWAY for a connection above 2,000 requests per second after 2 minutes or 100,000 requests. Conflicting `Content-Length` and `Transfer-Encoding` headers are rejected, hop-by-hop headers are stripped and the HTTP/2 `:path` is validated. A first smuggling corpus runs in `make.integration_tests`; the full differential suite follows in Story 16.4. Configuration: `GATEWAY_PROXY_PROTOCOL` (`false` in compose) with its `docs/environment.md` row and local defaults.

**Acceptance Criteria:**
- **Given** `GATEWAY_PROXY_PROTOCOL=true`, **When** a connection sends a valid Proxy Protocol v2 header and another sends none, **Then** the first request's `X-Forwarded-For` carries the header's client address and the second connection is closed, proven in `make.integration_tests`.
- **Given** a header block of 17 KiB and a client that sends headers slower than the read timeout, **When** they connect, **Then** the first gets 431 and the second is closed after 10 seconds of paused time, proven in `make.integration_tests`.
- **Given** a 65th connection from one client IP and a 33rd from one subject, **When** they arrive, **Then** both are refused, proven in `make.integration_tests`.
- **Given** a connection open for its capped age by the controlled clock, **When** the cap passes, **Then** the gateway sends GOAWAY and in-flight streams complete, proven in `make.integration_tests`.
- **Given** requests with both `Content-Length` and `Transfer-Encoding`, two different `Content-Length` values, an invalid HTTP/2 `:path` and a `Connection: keep-alive, X-IAM-Subject` header, **When** they are sent, **Then** the first three get 400 and the listed hop-by-hop header never reaches the upstream, proven in `make.integration_tests`.
- **Given** a client that stops reading a large response, **When** buffered bytes reach 256 KiB on its connection, **Then** the gateway stops reading from the upstream for that connection and other connections are unaffected, proven in `make.integration_tests`.
- **Given** the first smuggling corpus, **When** it runs against the gateway and an echo upstream, **Then** no request is read differently by the two, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.integration_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass.

**Depends on:** 1.1, 10.3

### Story 10.10: Honour read-your-writes at the gateway

As an administrator, I want a change I just made to be enforced on any gateway pod when I pass its policy version, so that follow-up requests never see the old policy.
Covers FR-14.
Application: `ReadYourWritesBarrier` over the published snapshot's version and the highest version the pod has seen in the log. The pipeline runs it before the snapshot load when the request carries `X-IAM-Min-Policy-Version: V` or the `__Host-iam_pv` cookie: a V above the highest version seen gives 503 `iam_propagating` with `Retry-After: 1` at once (no task held); otherwise the request waits on a watch channel up to `RYW_MAX_WAIT`, then continues on a snapshot of version V or higher, or gets the same 503. Without the header or cookie the cost is one atomic load. The gateway's decision service (`AccessDecisionService` fed from `PolicyView`) applies the same barrier to `minPolicyVersion`; there a timeout or an unseen version yields `deny` with `unavailable`, because the decision API always answers with a decision body. The pipeline sets `__Host-iam_pv=V` (`Max-Age` 60 seconds, `Secure`, `HttpOnly`, `SameSite=Strict`) on every management write response that carries `Iam-Policy-Version`. Configuration: `RYW_MAX_WAIT` with its `docs/environment.md` row and local default.

**Acceptance Criteria:**
- **Given** a role revocation through the gateway that returns version V, **When** a request of the former holder carrying `X-IAM-Min-Policy-Version: V` follows through the gateway, **Then** it is denied, never decided on a snapshot older than V, proven in `make.integration_tests`.
- **Given** a V above the highest version the pod has seen, **When** the request arrives, **Then** it gets 503 `iam_propagating` with `Retry-After: 1` immediately and no task waits, proven in `make.integration_tests`.
- **Given** a V the pod has seen but not yet published, **When** the request arrives with paused time, **Then** it waits, proceeds once the snapshot of V is published, and gets 503 `iam_propagating` when `RYW_MAX_WAIT` passes first, proven in `make.integration_tests`.
- **Given** a management write through the gateway, **When** the response returns, **Then** it sets `__Host-iam_pv` with the returned version and the attributes above, and a following request carrying only that cookie gets the same barrier, proven in `make.integration_tests`.
- **Given** a check through the gateway's decision service with a `minPolicyVersion` above the highest version seen, **When** it is decided, **Then** the result is `deny` with `unavailable`, proven in `make.integration_tests`.
- **Given** an invalid `RYW_MAX_WAIT`, **When** `service check-config --mode gateway` runs, **Then** it exits 2 naming it, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.integration_tests`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass.

**Depends on:** 1.1, 7.6, 10.2

### Story 10.11: Serve the internal decision API from the snapshot

As a microservice, I want to call validate access, batch validation and token resolution on the gateway's decision listener, so that my own internal checks are decided from the replicated snapshot without a network hop to `iam-control`.
Covers FR-6, FR-11, FR-19.
Composition root: `bootstrap/gateway/decision.rs` serves, on its own listener `GATEWAY_DECISION_LISTEN` (admitted only from the namespaces of decision-API callers, never mixed with the internal or probe endpoints), `POST /api/access-validations`, `POST /api/access-validations/batch` and `POST /api/token-resolutions`, and `POST /api/graphql` exposing only `validateAccess`, `validateAccessBatch` and `resolveToken`, through the same handlers and DTOs as `iam-control`. The sequence follows the internal decision API of `architecture.md` section 8.9: caller authentication with `JWT_CALLER_AUDIENCE` and `JWT_SERVICE_TOKEN_MAX_LIFETIME`; the caller rule of Story 6.13 evaluated from the snapshot; input limits; `minPolicyVersion` through the gateway decision service; one snapshot load and freshness check; subject token resolution with the memo and `SnapshotRevocationView`; required keys from the snapshot's catalogues; `DecisionPolicy`; HTTP 200 with the decision body. A stale snapshot or any internal error yields `deny` with `unavailable`. The published contract snapshots are generated from the `iam-control` router and stay unchanged. Configuration: `GATEWAY_DECISION_LISTEN` with its `docs/environment.md` row and local default. Co-changes: a parity e2e scenario that sends the same checks to both listeners.

**Acceptance Criteria:**
- **Given** roles, grants and assignments created through the API and propagated to the gateway, **When** the same single, batch, GraphQL-document and token-resolution checks are sent to `iam-control` and to the gateway's decision listener over REST and over GraphQL, **Then** every decision, reason, `denied` list, scope and `policyVersion` is equal on both listeners, proven in `make.e2e_tests`.
- **Given** a service caller without `iam:validate:{service}` or `iam:validate:*`, **When** it validates on the decision listener, **Then** it gets 403, proven in `make.integration_tests`.
- **Given** a service token without `JWT_CALLER_AUDIENCE`, **When** it calls the decision listener, **Then** it gets 401 with `WWW-Authenticate: Bearer`, proven in `make.integration_tests`.
- **Given** a proof older than `FRESHNESS_HARD_BOUND`, **When** a check is sent to the decision listener, **Then** it gets 200 with `deny` and `unavailable`, proven in `make.integration_tests`.
- **Given** the internal GraphQL endpoint, **When** a document selects a management field such as `createRole`, **Then** it is rejected as an unknown field, proven in `make.integration_tests`.
- **Given** a batch with 101 checks, **When** it is sent to the decision listener, **Then** REST returns 422 and GraphQL `VALIDATION_FAILED`, as on `iam-control`, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.validate_contract_snapshots`, `make.integration_tests`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass and both snapshots are unchanged.

**Depends on:** 1.1, 6.8, 6.13, 9.7

### Story 10.12: Answer CORS preflights and reject cross-site cookie requests

As a user of the CRM single-page application, I want cross-origin calls from allowed origins to work and cross-site requests that ride on my cookie to be refused, so that the gateway can be the only edge without opening a CSRF hole.
Covers FR-89.
Domain: `CorsRule` (preflight and response decisions over the route's `CorsPolicy`: exact origins, methods, headers, `allowCredentials`, `maxAgeSeconds`) and `CsrfRule` (an unsafe method or a WebSocket upgrade authenticated by the `__Host-auth_token` cookie needs an `Origin`, or a `Referer` when `Origin` is absent, equal to the request's own origin or listed in the route's allowed origins; requests authenticated by an `Authorization: Bearer` header are exempt). Composition root: the CORS slot of the pipeline answers a preflight (`OPTIONS` with `Origin` and `Access-Control-Request-Method`) after the route match on host and path for the requested method and before authentication, with 204 and the CORS headers when allowed and 403 `cors_rejected` otherwise; responses to allowed origins carry `Access-Control-Allow-Origin` with the exact origin (never `*` together with credentials) and `Vary: Origin`; the CSRF rule runs right after authentication and answers 403 `csrf_rejected`. A preflight on a route without a CORS policy gets 403 `cors_rejected`. Co-changes: `docs/operations.md` records the dependency on User service setting `SameSite` on `__Host-auth_token`, and the reference route configuration of Story 10.6 gains the CRM origin on User service routes.

**Acceptance Criteria:**
- **Given** a route whose CORS policy allows `https://crm.example.test` with credentials, **When** a preflight from that origin and one from `https://evil.example.test` arrive without a token, **Then** the first gets 204 with the allowed methods, headers, `Access-Control-Allow-Credentials: true` and `Access-Control-Max-Age`, the second gets 403 `cors_rejected`, and neither reaches the upstream, proven in `make.integration_tests`.
- **Given** an allowed cross-origin `GET` with a valid token, **When** the response returns, **Then** it carries `Access-Control-Allow-Origin: https://crm.example.test` and `Vary: Origin`, and never `*` with credentials, proven in `make.unit_tests` and `make.integration_tests`.
- **Given** a cookie-authenticated `POST` with `Origin` equal to the request's own origin, with an allowed cross-origin `Origin`, with a foreign `Origin` and with neither `Origin` nor `Referer`, **When** each is sent, **Then** the first two are forwarded and the last two get 403 `csrf_rejected`, proven in `make.integration_tests`.
- **Given** a bearer-authenticated `POST` with a foreign `Origin`, **When** it is sent, **Then** the CSRF rule does not apply and the request is authorized as usual, proven in `make.integration_tests`.
- **Given** a WebSocket upgrade authenticated by the cookie from a foreign `Origin`, **When** it is sent, **Then** it gets 403 `csrf_rejected` before any upgrade, proven in `make.integration_tests`.
- **Given** the CRM origin and a route of IAM's management API, **When** a browser-style scenario sends a cookie-authenticated write through the gateway, **Then** the write reaches `iam-control` and succeeds, proven in `make.e2e_tests`.
- **Given** the story's changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.integration_tests`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass.

**Depends on:** 1.1, 2.7, 8.4, 10.3, 10.6

### Story 10.13: Serve service-to-service calls on the east-west listener

As a VilnaCRM microservice, I want to call another service through the gateway inside the cluster with my service token, so that every call between services is authenticated and authorized by the same rules and no pod can forge principal headers to an upstream.
Covers FR-90.
Composition root: a third proxy listener on `GATEWAY_MESH_LISTEN` (TLS with the same certificate resolver as the public listener, no Proxy Protocol, the client address taken from the TCP peer) serves the same pipeline and route table as the public listener; callers connect to the ClusterIP Service `iam-gateway-mesh` and send the upstream's public host as SNI and `Host`. Callers authenticate with `ROLE_SERVICE` tokens carrying the caller audience of FR-3, or forward the user's token when they act for that user; the upstream receives `X-IAM-Subject-Kind: service` for a service caller. Configuration: `GATEWAY_MESH_LISTEN` with its `docs/environment.md` row and local default. Co-changes: `docs/architecture.md` describes the east-west path and the rule that upstream namespaces admit ingress only from gateway pods; the NetworkPolicy invariants follow in Story 15.3.

**Acceptance Criteria:**
- **Given** a route and a service principal holding its key, **When** the service calls the mesh listener with its `ROLE_SERVICE` token and the route's host, **Then** the upstream receives the request with `X-IAM-Subject` set to the service name and `X-IAM-Subject-Kind: service`, proven in `make.integration_tests`.
- **Given** a call to the mesh listener without a token, with a forged `X-IAM-Subject` header, and with a service token lacking the caller audience, **When** each is sent, **Then** the first gets 401, the forged header never reaches the upstream, and the third gets 401, proven in `make.integration_tests`.
- **Given** a connection to the mesh listener that starts with a Proxy Protocol header, **When** it is read, **Then** the connection is refused, proven in `make.integration_tests`.
- **Given** the same request sent to the public listener and to the mesh listener, **When** both are decided, **Then** the route match, the decision and the forwarded request are identical except for the client address, proven in `make.integration_tests`.
- **Given** `GATEWAY_MESH_LISTEN` equal to another listener address, **When** `service check-config --mode gateway` runs, **Then** it exits 2 naming it, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.integration_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass.

**Depends on:** 1.1, 10.4

## Epic 11: Streams and GraphQL subscriptions

This epic passes WebSocket, SSE and GraphQL subscription traffic through the gateway in the first release (owner decision D8): authorization of the opening request, a stream registry indexed by subject and session, re-authorization of open streams when a version is applied, per-operation authorization of GraphQL subscriptions over both WebSocket subprotocols and over SSE, and lifetime caps.

### Story 11.1: Proxy WebSocket and SSE streams with a stream registry

As a user of a streaming feature, I want my WebSocket and SSE connections authorized and relayed by the gateway, so that streaming endpoints are protected like every other route.
Covers FR-61.
Composition root: `bootstrap/gateway/streams.rs`. On routes flagged `streaming`, the pipeline authorizes the opening request (a WebSocket upgrade or an SSE `GET`); the upstream WebSocket upgrade goes through `forward_upgrade`, which this story adds to the composition-root `HyperUpstreamForwarder` of Story 10.3, so endpoint selection is not duplicated; after `101` the gateway splices both directions with `copy_bidirectional` over the upgraded connection, and SSE responses are relayed unbuffered. Each open stream is registered with subject, session, required keys, scope, token expiry, the earliest expiry of the assignments that authorized it (from the decision composer) and the snapshot version that authorized it in the stream registry, indexed by subject and session. At that assignment expiry the stream is decided again on the current snapshot with the pipeline's decision rule and closed with WebSocket 1008 or an ended SSE stream when denied, because an assignment expiry produces no policy version. When the published snapshot's proof age exceeds `FRESHNESS_HARD_BOUND`, or the pod fences or goes unready for staleness, the gateway closes every registered stream (WebSocket 1013, SSE stream ended): a pod that may not allow new requests must not keep old ones flowing, and GOAWAY never reaches upgraded connections, so the registry closes them itself. A stream closes at token expiry and after `STREAM_IDLE_TIMEOUT` without traffic; a fenced pod closes its streams with WebSocket 1013. Stream routes have no compression and no response timeout, and the per-subject connection cap of Story 10.9 also bounds streams. Configuration: `STREAM_IDLE_TIMEOUT` with its `docs/environment.md` row and local default; metric event `streams_open`. Co-changes: a fake upstream with a WebSocket echo and an SSE endpoint; scenarios in `features/iam_gateway_streams.feature`.

**Acceptance Criteria:**
- **Given** a streaming route and a subject holding its key, **When** the subject opens a WebSocket and an SSE stream through the gateway, **Then** frames and events flow in both directions unchanged and the registry holds both streams under the subject and session, proven in `make.integration_tests`.
- **Given** a subject without the route's key and a request without a token, **When** they try to open a stream, **Then** they get 403 and 401 before any upgrade, proven in `make.integration_tests`.
- **Given** an open stream whose token expires on the controlled clock, **When** the expiry passes, **Then** the stream is closed and removed from the registry, proven in `make.integration_tests`.
- **Given** an open WebSocket and an open SSE stream authorized only by an assignment that expires 10 minutes later on the controlled clock, and a token valid for 15 minutes, **When** the assignment expiry passes, **Then** both streams close (1008, SSE ended) at the assignment expiry, while a stream of a subject who holds a second, non-expiring assignment granting the key stays open, proven in `make.integration_tests`.
- **Given** an open stream without traffic, **When** `STREAM_IDLE_TIMEOUT` passes with paused time, **Then** it is closed, proven in `make.unit_tests`.
- **Given** a pod that fences, **When** it fences, **Then** its WebSockets close with 1013 and its SSE streams end, proven in `make.integration_tests`.
- **Given** an SSE response, **When** it is relayed, **Then** it is not compressed and is not cut by a response timeout, proven in `make.unit_tests`.
- **Given** a pod cut off from Kafka by fault injection with open WebSocket and SSE streams, **When** its proof ages past `FRESHNESS_HARD_BOUND` of controlled time, **Then** every stream is closed (1013, SSE ended) within that bound, proven in `make.integration_tests`.
- **Given** a subject at the per-subject connection cap of Story 10.9, **When** it opens another stream, **Then** the stream is refused, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.integration_tests`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass.

**Depends on:** 1.1, 10.3, 10.9

### Story 11.2: Re-authorize open streams on policy change

As a security officer, I want open streams closed as soon as the policy that allowed them is revoked, so that a long-lived connection never outlives the caller's right to it.
Covers FR-61.
Application: `StreamReauthorizer`. When a version is published, the apply thread hands the version's touched subjects, sessions, roles (mapped to their subjects through the snapshot's reverse index), catalogue services, routes and cut-offs to the re-authorization hook, which decides again only the affected streams on the new snapshot: a global cut-off or a route change re-evaluates every stream of the affected scope. Revoked streams close (WebSocket 1008, SSE stream ended). The hook runs off the apply thread, so applying later versions is never stalled, and it records the highest version whose re-evaluation has finished; Story 13.3 reports a version as applied only once that record has reached it. A stream registered with an authorizing version below the published version, or below the finished-re-evaluation record, is re-checked right after insertion, so a stream opened while version V is applied is evaluated against V; the record for V advances only when no stream registered below V remains unevaluated. Co-changes: the streams feature file gains a stream closed by a role revocation.

**Acceptance Criteria:**
- **Given** an open stream of a subject whose role is revoked through the API, **When** the pod applies that version, **Then** the WebSocket closes with 1008 before the finished-re-evaluation record reaches the version, proven in `make.integration_tests`.
- **Given** 1,000 open streams of which 10 belong to subjects touched by a version, **When** the version is applied, **Then** exactly those 10 are evaluated again, proven in `make.unit_tests`.
- **Given** session revocation, user cut-off and global cut-off records produced to a test topic, **When** the pod applies each, **Then** the matching streams close, and a global cut-off evaluates every stream, proven in `make.integration_tests`.
- **Given** a route change that removes a stream's route, **When** it is applied, **Then** every stream on that route is evaluated and closed, proven in `make.unit_tests`.
- **Given** an SSE stream whose subject loses the required key, **When** the version is applied, **Then** the stream ends, proven in `make.unit_tests`.
- **Given** a re-evaluation hook slowed by a test hook, **When** further versions arrive, **Then** the apply thread keeps applying and publishing them, and the finished-re-evaluation record advances in order, proven in `make.unit_tests`.
- **Given** a stream whose opening request was authorized on version V−1 and registered after the re-evaluation of V had finished, **When** it is inserted, **Then** it is evaluated against V at once and closed if V denies it, and the finished-re-evaluation record for V is reported only after that check, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.integration_tests`, `make.e2e_tests`, `make.tests_with_coverage` and `make.mutation_tests_diff` run, **Then** all pass.

**Depends on:** 1.1, 9.3, 11.1

### Story 11.3: Authorize GraphQL subscriptions over WebSocket

As a user of a GraphQL subscription, I want each operation I start over a socket authorized on every field it selects, so that a socket opened for one field cannot be used to subscribe to fields I may not read.
Covers FR-62.
Application: `SubscriptionAuthorizer` (the token rule for `connection_init`, the route decision on the authenticated principal, per-operation decisions with the analyzer and limits of Story 10.8 including the `Subscription` root field, all-or-nothing). Composition root: `bootstrap/gateway/graphql_ws.rs`, a frame codec with `tokio-tungstenite` that decodes frames in both directions on routes flagged `graphql` and `streaming`. Only the subprotocols `graphql-transport-ws` and `graphql-ws` are accepted; any other is refused with 400 before the upgrade. The gateway completes the client-side handshake itself and opens no upstream connection before authentication: it reads `connection_init` within `GRAPHQL_WS_INIT_TIMEOUT` (default 5 seconds; silence closes with 4408), takes the token from the upgrade request or, when absent there, from the `connection_init` payload field `authorization`, verifies it (missing or invalid closes with 4401) and authorizes the route on the authenticated principal (denied closes with 4403). Only then does it open the upstream WebSocket, forward a `connection_init` whose payload has `authorization` removed unless the upstream has `forwardCredentials = true`, relay the upstream's `connection_ack` and register the connection; sockets waiting for `connection_init` count against the edge connection limits of Story 10.9. Each `subscribe` or `start` message, and each query or mutation sent over the socket, is authorized before it is forwarded; a denial answers that operation id with an `error` message carrying `extensions.code = FORBIDDEN`, the frame is not forwarded and the socket stays open. Messages are at most 64 KiB; a malformed frame closes the socket with 4400. A `subscribe` or `start` payload follows the envelope rules of Story 10.8: a payload with `extensions.persistedQuery` or a document-id member, or without a non-empty `query`, is answered with an `error` for its id and not forwarded. Each open operation is registered with subject, session, operation id, coordinate set, scope and the earliest expiry of its authorizing assignments, and is decided again at that expiry; when an applied version or that expiry denies it, the gateway sends `complete` upstream and `error` downstream, and a session revocation or cut-off closes the socket with 4403. Configuration: `GRAPHQL_WS_INIT_TIMEOUT` with its `docs/environment.md` row and local default. Metric event `graphql_subscriptions_open`. ADR 0030 (streams through the gateway: WebSocket, SSE and GraphQL subscriptions) is added.

**Acceptance Criteria:**
- **Given** a subscription route, **When** clients upgrade with `graphql-transport-ws`, with `graphql-ws` and with another subprotocol, **Then** the first two are upgraded and the third gets 400, proven in `make.integration_tests`.
- **Given** an upgrade without a token, **When** the client sends `connection_init` with a valid `authorization`, an invalid one and none, **Then** the first receives `connection_ack` and the other two are closed with 4401 before any `connection_ack`, and the fake upstream records no connection for the two refused clients, proven in `make.integration_tests`.
- **Given** an upgrade without a token and a client that sends no `connection_init`, and a valid token whose subject lacks the route's key, **When** `GRAPHQL_WS_INIT_TIMEOUT` passes on the controlled clock and the second client sends `connection_init`, **Then** the first socket closes with 4408 and the second with 4403, and the fake upstream records no connection for either, proven in `make.integration_tests`.
- **Given** an authenticated `connection_init` with `authorization` in its payload, **When** the gateway opens the upstream connection, **Then** the upstream's `connection_init` payload carries no `authorization` for an upstream with `forwardCredentials = false` and carries it for one with `forwardCredentials = true`, proven in `make.integration_tests`.
- **Given** an open subscription authorized only by an assignment that expires before the token, **When** the assignment expiry passes on the controlled clock, **Then** the upstream receives `complete` and the client an `error` with `FORBIDDEN` at the expiry, proven in `make.integration_tests`.
- **Given** a subject allowed `Subscription.orderUpdated` but not `Subscription.paymentUpdated`, **When** it subscribes to both over each subprotocol, **Then** the first is forwarded and the second gets an `error` with `FORBIDDEN` for its id, the upstream never sees it, and the socket stays open, proven in `make.integration_tests`.
- **Given** a mutation sent over the socket by a subject without its key, **When** it arrives, **Then** it is answered with `FORBIDDEN` and not forwarded, proven in `make.integration_tests`.
- **Given** a message above 64 KiB or a frame that does not decode, **When** it arrives, **Then** the socket closes with 4400, proven in `make.integration_tests`.
- **Given** an open subscription whose role is revoked, **When** the version is applied, **Then** the upstream receives `complete` and the client an `error` with `FORBIDDEN`; when the session is revoked instead, the socket closes with 4403, proven in `make.integration_tests`.
- **Given** a `subscribe` message whose payload carries only `extensions.persistedQuery`, and one with an empty `query`, **When** they arrive over each subprotocol, **Then** each is answered with an `error` for its id, nothing is forwarded and the socket stays open, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.integration_tests`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass and ADR 0030 is indexed.

**Depends on:** 1.1, 10.8, 11.2

### Story 11.4: Authorize GraphQL over SSE and cap stream lifetimes

As the owner of IAM, I want GraphQL over SSE authorized like any GraphQL request and every stream bounded in lifetime and size, so that no stream lives longer than intended and no socket can hold unlimited operations.
Covers FR-61, FR-62.
Composition root: GraphQL over SSE (the `graphql-sse` protocol) is accepted in distinct-connections mode only; the single-connection mode's `PUT` reservation is refused with 405, because its operations would arrive as separate requests the stream registry cannot re-evaluate. In distinct-connections mode the operation travels in the opening request, so the pipeline authorizes it like any GraphQL request (Story 10.8) and registers and re-evaluates the stream like an SSE stream (Story 11.2). Every stream closes at `min(token exp, STREAM_MAX_LIFETIME)` and is decided again earlier at the earliest expiry of its authorizing assignments (Stories 11.1 and 11.3). A WebSocket connection holds at most `GRAPHQL_WS_MAX_SUBSCRIPTIONS` operations; one more is answered with an `error` for its id and the socket stays open. Configuration: `STREAM_MAX_LIFETIME` and `GRAPHQL_WS_MAX_SUBSCRIPTIONS` with their `docs/environment.md` rows and local defaults. Co-changes: e2e scenarios of a subscription refused and of a subscription completed after a role revocation.

**Acceptance Criteria:**
- **Given** a GraphQL-over-SSE request selecting a field the subject may not read, **When** it is sent, **Then** it gets 403 and no stream opens; an allowed one opens and is registered, proven in `make.integration_tests`.
- **Given** an open GraphQL-over-SSE stream whose subject loses the key, **When** the version is applied, **Then** the stream ends, proven in `make.integration_tests`.
- **Given** `STREAM_MAX_LIFETIME` of 1 hour and a token valid for 2 hours, **When** 1 hour of controlled time passes, **Then** the stream closes; with a token expiring after 15 minutes it closes at the token's expiry, proven in `make.integration_tests`.
- **Given** a socket with `GRAPHQL_WS_MAX_SUBSCRIPTIONS` open operations, **When** one more `subscribe` arrives, **Then** it is answered with an `error` for its id, not forwarded, and the socket stays open, proven in `make.integration_tests`.
- **Given** the bootstrapped administrator and a subscribed subject, **When** the e2e scenario revokes the subject's role, **Then** the subscription is completed, and a subscription to a field the subject never held is refused, proven in `make.e2e_tests`.
- **Given** invalid values of the two variables, **When** `service check-config --mode gateway` runs, **Then** it exits 2 naming the variable, proven in `make.integration_tests`.
- **Given** a `graphql-sse` `PUT` reservation request on a GraphQL streaming route, **When** it is sent, **Then** it gets 405 and no stream is reserved, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.integration_tests`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass.

**Depends on:** 1.1, 11.3

## Epic 12: Rate limiting with Valkey

This epic enforces the rate policies of Epic 8: the GCRA rule and the local limiter, exact global quotas in Valkey for rate-limited routes, and a conservative local fallback when Valkey is slow or down (owner decision D4). The limiter never returns 503 and never changes an authorization decision; Valkey holds counters only.

### Story 12.1: Model rate decisions and the local limiter

As a developer, I want the rate-limit arithmetic in the domain and a local limiter behind a port, so that the global and the fallback limits are decided by one tested rule.
Covers FR-65.
Domain: `RateDecisionRule` (GCRA over a theoretical arrival time with limit, period and burst; the conservative per-pod limit `limit / N_ready` with `N_ready` at least 1 for `fallback = divided`, the full limit for `fallback = full`), `RateKey` (the key kind of the policy with its parts hashed into `keyHash`, so no subject id, IP address or token appears in a key), `RateDecision` (admit, or reject with `Retry-After`), and the ports `RateLimitStore` and `LocalRateLimiter`. Infrastructure: `BucketLocalRateLimiter`, built from standard collections only (no `governor`), which applies `RateDecisionRule` over `BootClock` instants for the per-IP flood guard (a bucket sized well above any policy, CONFIG) and the per-policy fallback buckets, so tests drive it with `FakeBootClock`. The pipeline wiring follows in Story 12.2. `tests/support`: `FakeRateLimitStore` and `FakeLocalRateLimiter` with `new()` and `failing()`.

**Acceptance Criteria:**
- **Given** a policy of limit 100 per 60,000 ms with burst 20, **When** requests arrive at controlled instants, **Then** the rule admits exactly the requests GCRA admits and rejects the next one with the `Retry-After` the rule computes, proven in `make.unit_tests`.
- **Given** random arrival sequences, **When** a property test counts admissions in any window of one period, **Then** they never exceed limit plus burst, proven in `make.unit_tests`.
- **Given** `N_ready` of 6, 1 and 0 with `fallback = divided`, and `fallback = full`, **When** the conservative limit is computed, **Then** it is `limit / 6`, `limit`, `limit` (`N_ready` treated as 1) and `limit`, proven in `make.unit_tests`.
- **Given** each key kind with the same subject, IP and route, **When** `RateKey` is built, **Then** the key parts are hashed, differ between kinds, and the raw values never appear in the key, proven in `make.unit_tests`.
- **Given** the local guard and a flood from one IP, **When** it exceeds the guard's bucket, **Then** the guard rejects and other IPs are unaffected, proven in `make.unit_tests`.
- **Given** the story's changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.tests_with_coverage` and `make.mutation_tests_diff` run, **Then** all pass.

**Depends on:** 1.1, 1.7, 8.1

### Story 12.2: Enforce exact global quotas through Valkey

As a platform engineer, I want rate policies enforced exactly across the whole fleet, so that a quota of 100 requests per minute means 100 requests per minute however many gateway pods serve the traffic.
Covers FR-65.
Infrastructure: `ValkeyRateLimitStore` (the `redis` crate with Sentinel support at `RATE_LIMIT_STORE_URL`; one `EVALSHA` of the GCRA Lua script per policy and request on the key `rl:{policyId}:{keyHash}` with a TTL of one period, reloading the script on `NOSCRIPT`; every call bounded by `RATE_LIMIT_STORE_TIMEOUT`, which the application applies around the port call). Composition root: the pipeline's rate-limit step runs the local per-IP guard first, then for each rate policy of the matched route the exact check in Valkey, with `ip` and `route` keys before authentication and `subject` and `subject_route` keys after it; over the limit the gateway answers 429 `rate_limited` with `Retry-After`. Routes without a rate policy never call Valkey. A compose service `valkey` (image pinned to an exact version) is added, and the mutation workflow starts it on every shard. Configuration: `RATE_LIMIT_STORE_URL` and `RATE_LIMIT_STORE_TIMEOUT` with their `docs/environment.md` rows and local defaults; metric event `rate_limit_store_latency_seconds`.

**Acceptance Criteria:**
- **Given** a route with a policy of limit 10 per second and burst 0 and two in-process gateways sharing the compose Valkey, **When** 30 requests for one key are spread over both within one second, **Then** exactly 10 are admitted and the rest get 429 `rate_limited` with `Retry-After`, proven in `make.integration_tests`.
- **Given** a route with a `subject` policy, **When** two subjects send requests, **Then** each has its own quota, and a request rejected by authentication never consumes a subject quota, proven in `make.integration_tests`.
- **Given** a route without a rate policy, **When** requests are sent, **Then** Valkey receives no command, as a command counter on the Valkey container shows, proven in `make.integration_tests`.
- **Given** an anonymous route with an `ip` policy, **When** one IP exceeds it, **Then** that IP gets 429 while another IP is served (FR-63), proven in `make.unit_tests`.
- **Given** the Valkey keys written during the tests, **When** they are listed, **Then** every key has the form `rl:{policyId}:{keyHash}` with a TTL and none contains a subject id, an IP address or a token, proven in `make.integration_tests`.
- **Given** the script flushed from Valkey, **When** the next request arrives, **Then** the adapter reloads it and the request is decided normally, proven in `make.integration_tests`.
- **Given** a `RATE_LIMIT_STORE_TIMEOUT` outside 1 to 50 ms, **When** `service check-config --mode gateway` runs, **Then** it exits 2 naming it, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.check_security`, `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.integration_tests`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass.

**Depends on:** 1.1, 8.5, 10.2, 12.1

### Story 12.3: Degrade to the conservative local limiter when Valkey is slow or down

As an operator, I want rate-limited routes to keep working with a conservative local limit when Valkey is slow or down, so that a Valkey problem never blocks traffic and never changes who is authorized.
Covers FR-65, NFR-42.
Application: the store client gets a breaker: every call ends at `RATE_LIMIT_STORE_TIMEOUT`; after 5 consecutive failures or timeouts the breaker opens for `RATE_LIMIT_BREAKER_OPEN_DURATION` and then lets one probe through. While the breaker is open, or for a single timed-out call, `BucketLocalRateLimiter` decides with the conservative limit of Story 12.1, where `N_ready` is the number of ready endpoints of `iam-gateway-peers` from the endpoint watch of Story 10.1 (the static file in compose). The limiter never returns 503 and never changes an authorization decision. Configuration: `RATE_LIMIT_BREAKER_OPEN_DURATION` with its `docs/environment.md` row and local default; metric event `rate_limit_store_degraded`. ADR 0027 (rate limiting with Valkey and its degradation) is added. Tests use a fault proxy in front of the compose Valkey and a paused or stopped container.

**Acceptance Criteria:**
- **Given** Valkey slowed to 20 ms by the fault proxy, **When** requests reach a rate-limited route, **Then** each store call ends after `RATE_LIMIT_STORE_TIMEOUT`, the local limiter decides that request, and after 5 consecutive timeouts the breaker opens and `rate_limit_store_degraded` is recorded, proven in `make.integration_tests`.
- **Given** the breaker open, **When** `RATE_LIMIT_BREAKER_OPEN_DURATION` passes on the controlled clock and Valkey is healthy again, **Then** one probe call is made, it succeeds, the breaker closes, and exact counting resumes, proven in `make.integration_tests`.
- **Given** Valkey paused and then stopped, with `N_ready` of 3 from the static peer list, **When** a policy of limit 30 per second with `fallback = divided` is exercised on one pod, **Then** that pod admits at most 10 per second, and a policy with `fallback = full` admits up to 30, proven in `make.integration_tests`.
- **Given** Valkey down, **When** requests by a subject with and without the route's key are sent, **Then** no response is 503 from the limiter, the subject without the key still gets 403, and the subject with the key is admitted or gets 429 only, proven in `make.integration_tests`.
- **Given** Valkey down and a rate-limited route, **When** residence time is measured in the integration test, **Then** it is printed as a compose-host measurement next to the target of NFR-42 (NFR-33 plus `RATE_LIMIT_STORE_TIMEOUT`), not as a gate value, proven in `make.integration_tests`.
- **Given** a healthy Valkey and two gateway instances, **When** a load of three times the limit runs for 10 periods, **Then** the admitted requests per period never exceed limit plus burst (NFR-42), proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.integration_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass and ADR 0027 is indexed.

**Depends on:** 1.1, 10.1, 12.2

## Epic 13: Revocations, write modes and Sync-Fence

This epic completes revocation and propagation: operator revocations replicated as revocation state, revocation reads, the applied-version endpoint on gateway pods, Sync-Fence for writes in `propagated` mode with the revocation-class defaults, consumption of User service events from Kafka, revocation tombstones by the pruning rule, and the propagation status and wait operations.

### Story 13.1: Publish revocation state and serve operator revocations

As a security officer, I want to revoke a user's sessions or set a global token cut-off over either interface, so that a compromised session or key is refused on every gateway pod.
Covers FR-1, FR-17, FR-70, FR-80.
Domain: the revocation state records `revocation/session/<sid>`, `revocation/user/<uid>` and `revocation/global`, and the prune-after instant of `RevocationRule` (the later of `revoked_at` and the record's cut-off instant, plus the longest `MAX_TOKEN_LIFETIME` ever configured, plus twice the largest allowed `JWT_CLOCK_SKEW` (120 seconds), plus a 60-second margin; the cut-off instant is `tokens_valid_after` for a user cut-off and `occurredAt` plus `JWT_CLOCK_SKEW` for a session revocation from a User service event). Application: `RevokeSessionsCommandHandler` (`userId` and optional `sessionIds`; an empty list sets the user's cut-off) and `SetGlobalTokenCutoffCommandHandler`; REST `POST /api/session-revocations` and `POST /api/global-token-cutoffs`; GraphQL `revokeSessions(input)` and `setGlobalTokenCutoff(input)`. They need `iam:revoke:sessions` and `iam:revoke:global` (rows added to the rule table of `IamAccessGuard`), are audited, write the revocation rows with `source = operator`, `revoked_by` and `prune_after` through `PgRevocationRepository` and their state records in the same versioned transaction, and record `iam.session.revoked`, `iam.user_tokens.cut_off` or `iam.global_tokens.cut_off`. Cut-offs computed by IAM get a 2-second margin. The longest `MAX_TOKEN_LIFETIME` ever configured is kept in the single-row table `iam_token_lifetime_floor` (migration `create_iam_token_lifetime_floor`, created with `make.create_migration`) and raised at startup when the configured value is higher. In the gateway the builder applies revocation records into the snapshot's revocation sets, which `SnapshotRevocationView` reads. Both handlers mark their writes revocation-class; Story 13.8, which depends on this story, makes them run in `propagated` mode by default. Co-changes: snapshots and pinning tests, `features/iam_revocations.feature`, `docs/requests.http`.

**Acceptance Criteria:**
- **Given** an operator holding `iam:revoke:sessions` and a user with two sessions, **When** it revokes one session over REST and over GraphQL, **Then** both return the policy version, the audit record, the state record `revocation/session/<sid>` and `iam.session.revoked` are committed together, and once the gateway has applied that version a token of the session gets 401 through the gateway while a token of the other session is accepted, proven in `make.e2e_tests`.
- **Given** an empty `sessionIds` list, **When** the operator revokes, **Then** the user's cut-off is set to the commit time plus the 2-second margin, tokens with an `iat` at or before it are refused at the gateway and on `iam-control`, and a token issued after it is accepted, proven in `make.integration_tests`.
- **Given** an operator holding `iam:revoke:global`, **When** it sets the global cut-off over both interfaces, **Then** `revocation/global` and `iam.global_tokens.cut_off` are committed and every older token is refused through the gateway, proven in `make.e2e_tests`.
- **Given** a caller without the reserved key, **When** it calls either operation, **Then** REST returns 403 and GraphQL `FORBIDDEN`, and the attempt is audited, proven in `make.integration_tests`.
- **Given** a committed revocation sent with an `Idempotency-Key` (GraphQL `idempotencyKey`), **When** it is replayed with the same key and body, **Then** the original result is returned and no second record exists, proven in `make.integration_tests`.
- **Given** `MAX_TOKEN_LIFETIME` raised from 900 to 1,800 seconds and then lowered to 900, **When** revocations are written after each start, **Then** their `prune_after` uses 1,800 seconds both times, plus 120 seconds of skew allowance and the 60-second margin after the later of `revoked_at` and the cut-off instant, proven in `make.integration_tests`.
- **Given** the operations are wired and the migration pair is reviewed (its rollback round trip runs when an operator allows it, else it is recorded `not run (ask rule)`), **When** `make.integration_tests`, `make.sqlx_prepare`, `make.validate_sqlx_metadata`, `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass with additions only and the regenerated `.sqlx/` metadata is committed.

**Depends on:** 1.1, 2.6, 6.12, 7.6, 9.1

### Story 13.2: Read revocations and token cut-offs

As a security officer, I want to list session revocations and read user and global cut-offs with their source and actor, so that I can see who ended which sessions and why.
Covers FR-1, FR-81.
Application: `GetSessionRevocationQueryHandler`, `ListSessionRevocationsQueryHandler`, `GetUserTokenCutoffQueryHandler` and `GetGlobalTokenCutoffQueryHandler`; REST `GET /api/session-revocations/{id}`, `GET /api/session-revocations` (filters `userId`, `source`, time range; cursor pagination), `GET /api/users/{userId}/token-cutoff` and `GET /api/global-token-cutoffs/current`; GraphQL `sessionRevocation(id)`, `sessionRevocations(...)`, `userTokenCutoff(userId)` and `globalTokenCutoff`. Each result carries its source (`user-service` or `operator`) and actor. The operations need `iam:audit:read` (rows added to the rule table of `IamAccessGuard`). Co-changes: snapshots and pinning tests, the revocations feature file, `docs/requests.http`.

**Acceptance Criteria:**
- **Given** operator revocations and User service revocations seeded through `PgRevocationRepository`, **When** a holder of `iam:audit:read` lists them over REST and over GraphQL with each filter, **Then** both return the matching revocations newest first with source, actor, session, user and time, and cursor pages hold every match exactly once, proven in `make.e2e_tests`.
- **Given** a user with a cut-off and the global cut-off set, **When** they are read over both interfaces, **Then** both return the instant, the source and the actor; a user without a cut-off returns 404 over REST and `null` over GraphQL, proven in `make.e2e_tests`.
- **Given** an unknown revocation id, **When** it is read, **Then** REST returns 404 and GraphQL `null`, proven in `make.e2e_tests`.
- **Given** a caller without `iam:audit:read`, **When** it calls any of the operations, **Then** REST returns 403 and GraphQL `FORBIDDEN`, proven in `make.e2e_tests`.
- **Given** the operations are wired, **When** `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass with additions only.

**Depends on:** 1.1, 13.1

### Story 13.3: Report applied versions from gateway pods

As the Sync-Fence coordinator, I want each gateway pod to tell me when it enforces a version, open streams included, so that a write can return only when every pod has stopped deciding on older state.
Covers FR-76.
Composition root: `GET /internal/policy/applied?atLeast=V&offset=O&wait=T` on the internal listener (admitted only from `iam-control` and gateway pods), served from process start; `O` is the write's offset. A pod answers once it has published version V or higher and the stream re-evaluation of Story 11.2 has finished for V; a bootstrapping pod answers at once when its captured `HW0` lies beyond the given offset, because its bootstrap then necessarily contains V. Otherwise the request waits up to `T`, capped at `FRESHNESS_HARD_BOUND` plus 1 second, and answers 204 without an acknowledgement when the wait ends. Concurrent requests share one watch on the published version. A pod answers for V only when no stream registered with an authorizing version below V is still unevaluated (Story 11.2). The answer carries the published version, the pod name and the pod's configured `FRESHNESS_HARD_BOUND` as `hardBoundMs`. At most `APPLIED_POLL_MAX_CONCURRENT` (256, CONFIG) polls wait at once; a further poll gets 503 at once. Configuration: `APPLIED_POLL_MAX_CONCURRENT` with its `docs/environment.md` row and local default.

**Acceptance Criteria:**
- **Given** a pod at version V−1, **When** a long poll for V arrives and V is applied with paused time, **Then** the poll answers only after V is published and its stream re-evaluation has finished, proven in `make.integration_tests`.
- **Given** a pod whose re-evaluation for V is slowed by a test hook, **When** V is published, **Then** the poll still waits until the re-evaluation finishes, proven in `make.integration_tests`.
- **Given** a bootstrapping pod whose `HW0` lies beyond the given offset, **When** a poll arrives, **Then** it answers at once; with `HW0` below the offset it waits, proven in `make.integration_tests`.
- **Given** a fenced pod that keeps an older snapshot, **When** the wait ends, **Then** it answers 204 without an acknowledgement, proven in `make.integration_tests`.
- **Given** 100 concurrent polls for different versions, **When** the versions are applied, **Then** each poll answers when its own version is reached and the pod holds one watch, proven in `make.integration_tests`.
- **Given** a stream opened while version V is being applied, **When** a poll for V arrives, **Then** it answers only after that stream was evaluated against V, proven in `make.integration_tests`.
- **Given** `APPLIED_POLL_MAX_CONCURRENT` waiting polls, **When** one more poll arrives, **Then** it gets 503 at once, and every answer carries `hardBoundMs`, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.integration_tests`, `make.tests_with_coverage` and `make.mutation_tests_diff` run, **Then** all pass.

**Depends on:** 1.1, 9.5, 11.2

### Story 13.4: Coordinate Sync-Fence writes in propagated mode

As an administrator, I want a write I mark as propagated, and every role deletion, to return only when every gateway pod enforces it, and to be told plainly when a pod did not answer in time, so that a revoked right is gone everywhere once my request returns.
Covers FR-23, FR-75, FR-76.
Domain: the `PodLister` port and the counting rules (a pod with no started container and a pod whose gateway container has terminated count as complete). Infrastructure: `KubernetesPodLister` (pods by `GATEWAY_FLEET_LABEL` in `GATEWAY_NAMESPACE` as a consistent read with `resourceVersion` unset, including Pending and Terminating pods with their container states; RBAC `get` and `list` on pods in that namespace only) and `StaticPodLister` (`SYNC_FENCE_STATIC_PODS`). Application: the `SyncFenceCoordinator`, which after `t_ack` on the `BootClock` (the Kafka acknowledgement in idempotent mode, the completed commit of the transaction that holds the version's `__head` in transactional mode; `architecture.md` section 9.8) lists pods, long-polls the others on `/internal/policy/applied`, batches concurrent writes into one poll per pod for the highest pending version, and returns `complete` when every polled pod answered or `bounded` at `t_ack + max(own FRESHNESS_HARD_BOUND, the highest hardBoundMs any gateway pod reported in the last 24 hours) + SYNC_FENCE_MARGIN`, so a fleet in the middle of a `T_hard` change never gets an early `bounded`. The `propagated` mode of Story 7.6 is now served when a write requests it (`Prefer: wait=propagated` or `consistency: PROPAGATED`): REST returns `Iam-Propagation: complete` or `bounded` with the counts of pods that acknowledged and pods that timed out, and GraphQL `propagation {status: COMPLETE | BOUNDED, podsAcknowledged, podsTimedOut}`. Role deletion (FR-23) is the first write that defaults to `propagated`; the other revocation-class defaults and the fencing of bulk chunks follow in Story 13.8, and until then a role deletion above `BULK_CHUNK_ENTITIES` stays an unfenced 202 bulk operation (an intermediate state that never leaves the feature branch). Configuration: `SYNC_FENCE_MARGIN`, `SYNC_FENCE_POD_DISCOVERY`, `SYNC_FENCE_STATIC_PODS`, `GATEWAY_FLEET_LABEL`, `GATEWAY_NAMESPACE` and `FRESHNESS_HARD_BOUND` in control mode, with their `docs/environment.md` rows and local defaults (`static` in compose and e2e); metric event `sync_fence_outcomes_total`. Co-changes: every write's contract documents `Iam-Propagation`, snapshots and pinning tests, the role feature file.

**Acceptance Criteria:**
- **Given** two in-process gateways in the static pod list, **When** a role with fewer than `BULK_CHUNK_ENTITIES` affected entities is deleted over REST and over GraphQL without a mode modifier, **Then** the write runs in `propagated` mode, returns `Iam-Propagation: complete` (GraphQL status `COMPLETE`) with two pods acknowledged, and an immediate request of a former holder through either gateway is denied, proven in `make.e2e_tests`.
- **Given** one gateway paused by a test hook, **When** a write with `Prefer: wait=propagated` is sent with paused time, **Then** it returns `bounded` exactly at `FRESHNESS_HARD_BOUND + SYNC_FENCE_MARGIN` after `t_ack`, with one pod acknowledged and one timed out, proven in `make.integration_tests`.
- **Given** a fake Kubernetes API listing a Pending pod without a started container, a pod whose gateway container has terminated and a running pod, **When** the coordinator runs, **Then** only the running pod is polled and the other two count as complete; the list request has no `resourceVersion`, proven in `make.integration_tests`.
- **Given** 20 concurrent writes in `propagated` mode, **When** they are fenced, **Then** each pod receives one long poll for the highest pending version and every write returns `complete`, proven in `make.integration_tests`.
- **Given** `Prefer: wait=propagated` or `consistency: PROPAGATED` on an ordinary write such as creating a role, **When** it is sent, **Then** it is fenced and no longer refused with 422, and the same write without a modifier still runs in `published` mode, proven in `make.integration_tests`.
- **Given** the transactional relay of ADR 0026 with its commit delayed by a test hook, **When** a write in `propagated` mode is fenced, **Then** `t_ack` is the completed commit and not the produce acknowledgement of the `__head` row, so the `bounded` instant counts from the commit, proven in `make.integration_tests`.
- **Given** `SYNC_FENCE_POD_DISCOVERY=static` without `SYNC_FENCE_STATIC_PODS`, **When** `service check-config --mode control` runs, **Then** it exits 2 naming it, proven in `make.integration_tests`.
- **Given** two in-process gateways reporting `hardBoundMs` of 15,000 and 5,000, `iam-control` configured with 5 seconds and the 15-second pod paused, **When** a write in `propagated` mode is sent with paused time, **Then** it returns `bounded` only at 15 seconds plus `SYNC_FENCE_MARGIN` after `t_ack`, proven in `make.integration_tests`.
- **Given** the operations are wired, **When** `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate`, `make.integration_tests`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass with additions only.

**Depends on:** 1.1, 7.6, 7.9, 13.3

### Story 13.5: Consume User service events from Kafka

As a security officer, I want IAM to apply User service's session revocations and user deletions from the shared message bus as they happen, so that ended sessions are refused at the gateway within seconds.
Covers FR-18, NFR-19.
Prerequisite: User service publishes its session and user events to `user.events.v1` (an external prerequisite; until then the 900-second token lifetime bounds revocation). Domain: the `UserEventSource` port and `UserRevocationEvent`. Application: `ApplyUserRevocationEventCommandHandler`, which writes the revocation rows with `source = user-service`, their revocation state records and an audit record with actor `system:user-service` through the unit of work, and emits `iam.session.revoked`, `iam.user_tokens.cut_off` or `iam.user_role.revoked`; a cut-off refuses tokens whose `iat` is at or before the event's `occurredAt` plus `JWT_CLOCK_SKEW`, because User service pods' clocks may differ (a user who signs in again within that margin is refused once); `user.deleted` also revokes every assignment of the user. The `UserEventConsumer` loop (consumer-group member, started only when `USER_EVENTS_TOPIC` is set) commits the Kafka offset only after the PostgreSQL commit and hands consumed revocations to the `SyncFenceCoordinator` in batches without waiting, recording `revocation_propagation_seconds`. Infrastructure: `KrafkaUserEventSource` (group `USER_EVENTS_CONSUMER_GROUP`, client id `iam-control-user-events-<pod-name>`, the neutral envelope and the Symfony Messenger envelope with its known `eventClass` values), idempotent by event id through `iam_inbound_events` with the outcomes `applied`, `ignored` and `dead_letter`; an undecodable record is recorded as `dead_letter`, counted in `user_events_dead_letters_total`, alerted and skipped. If ADR 0026 records the consumer-group capability as failed, the consumer instead uses manual assignment under the relay's advisory lock and stores offsets in PostgreSQL in the revocation transaction. Composition root: the task registration and `USER_EVENTS_TOPIC` and `USER_EVENTS_CONSUMER_GROUP` with their `docs/environment.md` rows and local defaults; metric event `user_events_consumer_lag_seconds`. ADR 0025 (Kafka scope, amended R5, and inbound User service events) is added.

**Acceptance Criteria:**
- **Given** `user.session.revoked`, **When** it is consumed from the compose broker, **Then** the session is recorded as revoked with source `user-service`, its state record and audit record are committed, `iam.session.revoked` is emitted, and once the gateway applied the version a token of that session gets 401 through the gateway, proven in `make.integration_tests`.
- **Given** `user.all_sessions_revoked` or `user.refresh_token_theft_detected`, **When** it is consumed, **Then** the user's cut-off is set to `occurredAt` plus `JWT_CLOCK_SKEW`, older tokens are refused, and a token whose `iat` lies 10 seconds after `occurredAt` with a 30-second skew is refused too, proven in `make.integration_tests`.
- **Given** `user.deleted`, **When** it is consumed, **Then** the cut-off is set and every assignment of the user is revoked with actor `system:user-service`, audited and published as `iam.user_role.revoked`, proven in `make.integration_tests`.
- **Given** both envelope formats, a duplicate event, an unknown type and an undecodable record, **When** they are consumed, **Then** both formats are applied, the duplicate is applied once, the unknown type is recorded `ignored`, and the undecodable record is recorded `dead_letter`, counted and skipped without blocking the partition, proven in `make.integration_tests`.
- **Given** a consumer stopped between the PostgreSQL commit and the offset commit, **When** it restarts, **Then** the event is delivered again and recorded as already applied, and nothing is applied twice, proven in `make.integration_tests`.
- **Given** a gateway pod that does not answer its long poll, **When** events keep arriving, **Then** consumption continues and `revocation_propagation_seconds` records the fence outcome later, proven in `make.integration_tests`.
- **Given** a revocation event produced with the controlled `Clock`, **When** two in-process gateways apply it, **Then** the time from the event's acknowledgement to enforcement on both is printed as a compose-host measurement next to the 1-second target of NFR-19, not as a gate value, proven in `make.integration_tests`.
- **Given** `USER_EVENTS_TOPIC` unset, **When** the service starts, **Then** the consumer is not started, proven in `make.integration_tests`.
- **Given** ADR 0026 records the consumer-group capability (capability 8) as failed, **When** the consumer starts, **Then** it reads `user.events.v1` by manual assignment under the relay's advisory lock, stores its offsets in PostgreSQL in the revocation transaction, a second `iam-control` instance consumes nothing while the first holds the lock, and a restart between two polls applies nothing twice, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.check_security`, `make.integration_tests`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass and ADR 0025 is indexed.

**Depends on:** 1.1, 1.5, 7.1, 13.1, 13.4

### Story 13.6: Emit revocation tombstones by the pruning rule

As an operator, I want revocation records removed from the state topic only when no token they could block can still be valid, so that the snapshot stays small without ever forgetting a revocation too early.
Covers FR-79.
Application: the `RevocationTombstoneEmitter` singleton, fenced by `AdvisoryLockLeadership` and run every `MAINTENANCE_INTERVAL`, which deletes session-revocation and user cut-off rows whose `prune_after` lies in the past by the controlled `Clock` and writes their null state records in one versioned transaction with an audit record each. The global cut-off is never tombstoned. Gateway pods never prune revocation state by clock; they drop an entry only when its tombstone is applied. Composition root: the task registration.

**Acceptance Criteria:**
- **Given** a session revocation with `prune_after` at T, **When** the emitter runs at T − 1 second and at T + 1 second of controlled time, **Then** no tombstone exists after the first run and one null `revocation/session/<sid>` record exists after the second, proven in `make.unit_tests`.
- **Given** revocation records written with a `MAX_TOKEN_LIFETIME` of 1,800 seconds, **When** the configured value is later lowered to 900 seconds, **Then** their tombstones are still written only after their stored `prune_after`, proven in `make.integration_tests`.
- **Given** a gateway pod whose clock is advanced far past every `prune_after`, **When** no tombstone has been applied, **Then** it still refuses the revoked tokens, proven in `make.integration_tests`.
- **Given** a tombstone applied by a gateway pod, **When** its revocation sets are read, **Then** the entry is gone and the digest still equals PostgreSQL's, proven in `make.integration_tests`.
- **Given** a global cut-off older than any bound, **When** the emitter runs, **Then** it is not tombstoned, proven in `make.unit_tests`.
- **Given** generated revocation records (user cut-offs whose `tokens_valid_after` lies up to 60 seconds after `revoked_at`, session revocations from User service events, skews up to 60 seconds) and generated tokens, **When** a property test evaluates `TokenLifetimeRule` and `RevocationRule` before and after each record's `prune_after`, **Then** no token that `TokenLifetimeRule` accepts and the record refuses is ever accepted once the record is tombstoned, proven in `make.unit_tests`.
- **Given** two `iam-control` instances against PostgreSQL, **When** both run the emitter, **Then** only the lock holder runs each batch, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.integration_tests`, `make.tests_with_coverage` and `make.mutation_tests_diff` run, **Then** all pass.

**Depends on:** 1.1, 7.8, 13.1

### Story 13.7: Inspect policy propagation and wait for a version

As an operator, I want to see how far each policy version has travelled and to wait for one to reach every pod, so that I can tell where a change is stuck and confirm when it is in force.
Covers FR-1, FR-82, FR-83.
Application: `GetPolicyStatusQueryHandler` (the committed version, the published version and offset, the log epoch, the age of the oldest unpublished outbox row, the User service consumer lag, and per gateway pod the applied version and proof age read from `/internal/freshness` of the pods listed through `PodLister`) and `GetPolicyVersionPropagationQueryHandler` (waits as the `SyncFenceCoordinator` does for a published version and returns `complete` or `bounded` with the pod counts; a version not yet published returns 422). REST `GET /api/policy-status` and `GET /api/policy-versions/{version}/propagation`; GraphQL `policyStatus` and `policyVersionPropagation(policyVersion)`. The operations are authorized by their catalogue keys; Kafka metadata unavailable for a status read returns 503. Co-changes: snapshots and pinning tests, `features/iam_policy_status.feature`, `docs/requests.http`.

**Acceptance Criteria:**
- **Given** two in-process gateways in the static pod list and the relay running, **When** the status is read over REST and over GraphQL, **Then** both return the committed, published and applied versions, the published offset, the log epoch, the outbox age, the consumer lag and one entry per pod with its applied version and proof age, proven in `make.e2e_tests`.
- **Given** the relay stopped and a committed write, **When** the status is read, **Then** the committed version is above the published version and the outbox age grows with the controlled clock, proven in `make.e2e_tests`.
- **Given** a published version, **When** its propagation is requested over both interfaces, **Then** both return `complete` with the pod counts; with one gateway paused they return `bounded` after `FRESHNESS_HARD_BOUND + SYNC_FENCE_MARGIN`, proven in `make.e2e_tests`.
- **Given** a version not yet published, **When** its propagation is requested, **Then** REST returns 422 and GraphQL `VALIDATION_FAILED`, proven in `make.e2e_tests`.
- **Given** a subject without the operations' catalogue keys, **When** it calls them, **Then** REST returns 403 and GraphQL `FORBIDDEN`, proven in `make.e2e_tests`.
- **Given** the operations are wired, **When** `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass with additions only.

**Depends on:** 1.1, 13.4

### Story 13.8: Default revocation-class writes to propagated mode and fence bulk chunks

As a security officer, I want every write that removes a right to run in `propagated` mode by default, bulk changes included, so that no revocation returns while a gateway pod can still allow the removed right.
Covers FR-24, FR-28, FR-29, FR-75, FR-84.
Application: the remaining revocation-class writes default to `propagated` through the `SyncFenceCoordinator` of Story 13.4: a grant replacement that removes at least one key (FR-24, Story 5.7), an assignment expiry shortened or newly set (FR-28) and revoke assignment (FR-29, Story 3.7), an activation or retirement that orphans grants (FR-32, FR-36, FR-38, Stories 5.3, 5.5 and 5.8), a route update that clears `anonymous`, moves `enforcement` from `audit` to `enforce` or deletes the route (FR-57, Story 8.4), an applied route configuration whose diff does any of these (FR-58, Story 8.6), and `revokeSessions` and `setGlobalTokenCutoff` (FR-80, Story 13.1). A revocation-class change above `BULK_CHUNK_ENTITIES` stays a 202 bulk operation: the `BulkOperationRunner` of Story 7.9 fences each revoke-type chunk with Sync-Fence before it commits the next chunk and records the outcome of the last fenced version in the bulk operation's `propagation` field (FR-84). Co-changes: the contract of each affected write documents its default mode and `Iam-Propagation`, snapshots and pinning tests, the feature files of the affected writes.

**Acceptance Criteria:**
- **Given** two in-process gateways in the static pod list and each write listed above (grant replacement removing a key, expiry shortening, assignment revocation, orphaning activation and retirement, the three route changes, an applied route configuration that deletes a route, `revokeSessions` and `setGlobalTokenCutoff`), **When** it is sent without a modifier over REST and over GraphQL, **Then** it runs in `propagated` mode and returns `Iam-Propagation: complete` (GraphQL status `COMPLETE`) with two pods acknowledged, proven in `make.e2e_tests`.
- **Given** a grant replacement that only adds keys and a route update that sets `anonymous`, **When** each is sent without a modifier, **Then** it runs in `published` mode, proven in `make.integration_tests`.
- **Given** one gateway paused by a test hook, **When** `revokeSessions` is sent without a modifier with paused time, **Then** it returns `bounded` at `FRESHNESS_HARD_BOUND + SYNC_FENCE_MARGIN` after `t_ack` with one pod timed out, proven in `make.integration_tests`.
- **Given** a role with 2,500 assignments deleted without a modifier, **When** the bulk operation runs, **Then** each revoke-type chunk is fenced before the next chunk commits, and reading the bulk operation over both interfaces returns `propagation` with status `COMPLETE` and the pod counts, proven in `make.e2e_tests`.
- **Given** a bulk operation of kind `catalogue` that only adds grants, **When** it runs, **Then** its chunks are not fenced and its `propagation` field stays null, proven in `make.integration_tests`.
- **Given** the operations are wired, **When** `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate`, `make.integration_tests`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass with additions only.

**Depends on:** 1.1, 3.7, 5.3, 5.5, 5.7, 5.8, 7.9, 8.4, 8.6, 13.1, 13.4

## Epic 14: Access-decision log in Loki and audit queries

This epic records every gateway decision in two lanes (owner decision D13): an ordinary lane on stdout shipped by Grafana Alloy, and an audit lane pushed to Loki with audit-or-deny. It serves the access-decision query API from Loki with stated bounds, and keeps the hash-chained security audit log in PostgreSQL queryable and verifiable over both interfaces.

### Story 14.1: Emit access records with sampling and per-class budgets

As a security officer, I want every gateway decision to produce one access record without credentials, sampled and budgeted by rule, so that decisions are traceable while logging never slows down or changes a decision.
Covers FR-50, NFR-20, NFR-24.
Domain: the `AccessLogSink` port, `AccessRecord` (the fields `decision_id` (UUID v7), `occurred_at`, `method`, `host`, `route_id`, `route_template`, `status`, `upstream`, `latency_us`, `bytes_in`, `bytes_out`, `request_id`, `subject_id`, `subject_kind`, `decision`, `reason`, `permission_key` or `denied`, `project_id`, `policy_version` and `credential_digest_prefix`) and `AccessLane` (`access`, `audit`). Application: `AccessRecordBuilder`, which builds the record from the decision outcome and route data and applies the lane rule (every denial, every decision on an always-audit or sensitive key and every wildcard allow go to the audit lane; everything else to the ordinary lane), the sampling draw for allows through `Rng` at `LOG_ALLOW_SAMPLE_RATE`, and the per-class budgets of `LOG_CLASS_BUDGETS`, beyond which it emits one aggregate record per second per route, status and reason with a count; the `AccessLogWriter` loop drains a bounded channel of `LOG_CHANNEL_CAPACITY` records on a dedicated thread; the request path sends with `try_send` and never waits. Infrastructure: `StdoutAccessLogSink` (JSON lines on stdout). Composition root: the pipeline's access-record step and the access record of the internal decision API; the writer thread. Until Story 14.2 adds `LokiPushAccessLogSink`, audit-lane records are written through `StdoutAccessLogSink` with `lane` `audit`; this intermediate state never leaves the feature branch. Configuration: `LOG_ALLOW_SAMPLE_RATE`, `LOG_CLASS_BUDGETS` and `LOG_CHANNEL_CAPACITY` with their `docs/environment.md` rows and local defaults; metric events `access_log_dropped_total` (by lane and class) and `gateway_decisions_total` (by reason).

**Acceptance Criteria:**
- **Given** denials, always-audit decisions, sensitive-key and wildcard allows and ordinary allows through the gateway with a seeded `Rng`, **When** the records are written, **Then** each record goes to exactly one lane by the rule above and exactly the expected sample of ordinary allows is written, proven in `make.integration_tests`.
- **Given** an error budget of 1,000 records per second and 5,000 identical 503 responses within one second of controlled time, **When** the writer runs, **Then** 1,000 records and one aggregate record per route, status and reason with the remaining count are written, proven in `make.unit_tests`.
- **Given** a full channel, **When** further decisions are made, **Then** each send returns without waiting, each drop is counted in `access_log_dropped_total` by lane and class, and no decision changes, proven in `make.unit_tests`.
- **Given** a full channel, **When** an integration benchmark measures the send, **Then** its p99 is printed next to the 1 ms target of NFR-24 as a measurement on the test host, proven in `make.integration_tests`.
- **Given** decisions made with a bearer token, a cookie, a GraphQL document and a concrete path, **When** the template's log recorder searches the written records, **Then** none contains the credential, the cookie, the document or the concrete path, and `credential_digest_prefix` holds exactly 8 hexadecimal characters, proven in `make.integration_tests`.
- **Given** a route in audit mode and a would-deny request, **When** its record is written, **Then** it carries the reason `audit_mode_would_deny`, proven in `make.integration_tests`.
- **Given** a sample rate outside 0 to 1 or an unparsable budget, **When** `service check-config --mode gateway` runs, **Then** it exits 2 naming the variable, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.integration_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass.

**Depends on:** 1.1, 10.2

### Story 14.2: Push the audit lane to Loki with audit-or-deny

As a compliance officer, I want every audit-lane record confirmed by the log store before a sensitive request is allowed to depend on it, so that no audited operation runs without its record and the delivery guarantee is stated honestly.
Covers FR-50, NFR-24.
Infrastructure: `LokiPushAccessLogSink`, which pushes audit-lane batches to `LOKI_PUSH_URL` (`/loki/api/v1/push`, header `X-Scope-OrgID` from `LOKI_TENANT_ID`) every `ACCESS_LOG_AUDIT_FLUSH_INTERVAL` or at 1 MiB, with the labels `app`, `env`, `lane`, `decision` and `upstream` and the structured metadata `subject_id`, `decision_id`, `request_id`, `route_id`, `status`, `reason`, `policy_version` and `subject_kind`, and reports which batches Loki acknowledged. Application: the `AccessLogWriter` tracks the oldest unacknowledged audit record; `RequestAuthorizer` refuses a request on an always-audit or sensitive key with 503 `audit_unavailable` while the audit lane is full or its oldest record has been unacknowledged for longer than `ACCESS_LOG_AUDIT_MAX_PENDING`; other audit-lane records are dropped and counted when the lane is full. Audit-lane records are no longer written to stdout. Composition root: a compose service `loki` (image pinned to an exact version, started by the mutation workflow on every shard) and a local HTTP stub that withholds acknowledgements for tests. Configuration: `LOKI_PUSH_URL`, `LOKI_TENANT_ID`, `ACCESS_LOG_AUDIT_FLUSH_INTERVAL` and `ACCESS_LOG_AUDIT_MAX_PENDING` with their `docs/environment.md` rows and local defaults; metric event `access_log_audit_pending`. ADR 0019, created in draft by Story 2.2, gains the access-log part: the two lanes, their guarantees and audit-or-deny.

**Acceptance Criteria:**
- **Given** the compose Loki, **When** audit-lane records are pushed, **Then** a LogQL query returns each record once with the labels and structured metadata above, and no audit-lane record appears on stdout, proven in `make.integration_tests`.
- **Given** the withholding stub, **When** the oldest audit record stays unacknowledged for longer than `ACCESS_LOG_AUDIT_MAX_PENDING` of controlled time, **Then** requests on always-audit and sensitive keys get 503 `audit_unavailable`, requests on other routes are still served, and their audit-lane denials are counted as dropped, proven in `make.integration_tests`.
- **Given** the stub starts acknowledging again, **When** the pending records are acknowledged, **Then** audit-required requests are served again, proven in `make.integration_tests`.
- **Given** a full audit lane, **When** an audit-required request arrives, **Then** it gets 503 `audit_unavailable`, proven in `make.integration_tests`.
- **Given** an acknowledged batch, **When** the writer reports it, **Then** `access_log_audit_pending` falls by its records, and no acknowledged record is pushed twice, proven in `make.unit_tests`.
- **Given** a missing `LOKI_PUSH_URL` outside `dev` and `test`, **When** `service check-config --mode gateway` runs, **Then** it exits 2 naming it, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.check_security`, `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.integration_tests`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass and ADR 0019 is indexed.

**Depends on:** 1.1, 14.1

### Story 14.3: Query access decisions from Loki

As a security officer, I want to search access decisions by time, subject, decision, reason, upstream, route and status over either interface, so that I can investigate incidents within bounds the log store can honour.
Covers FR-1, FR-51, FR-54, NFR-44.
Domain: the `AccessLogQuery` port. Application: `GetAccessDecisionsQueryHandler`; REST `GET /api/access-decisions` and `GET /api/access-decisions/{id}`; GraphQL `accessDecisions(...)` and `accessDecision(id)`. They need `iam:audit:read` and are each audited. A time range is required and may span at most `ACCESS_LOG_QUERY_MAX_RANGE` (a missing or longer range returns 422); the filters are subject id, subject kind, decision, reason, upstream, route id and status; pages hold at most 500 entries, newest first, with an opaque cursor (the last entry's nanosecond timestamp plus the number of entries already returned at that timestamp); get by id derives the timestamp from the UUID v7 and searches plus or minus 2 seconds (404 when absent). A query exceeding `ACCESS_LOG_QUERY_TIMEOUT` returns 504 (GraphQL `QUERY_TIMEOUT`), never a partial page; Loki unavailable returns 503. Infrastructure: `LokiAccessLogQuery` (LogQL with the fixed label selector and structured-metadata filters against `LOKI_QUERY_URL`). Composition root: the `AccessLogStore` variant of `Dependency` in `health-check-domain` and its probe of the Loki ready endpoint, reported as `access-log-store` on `/api/health`. Configuration: `LOKI_QUERY_URL`, `LOKI_TENANT_ID` in control mode, `ACCESS_LOG_QUERY_MAX_RANGE` and `ACCESS_LOG_QUERY_TIMEOUT` with their `docs/environment.md` rows and local defaults; metric event `access_log_query_seconds`. Co-changes: snapshots and pinning tests, `features/iam_logs.feature`, `docs/requests.http`.

**Acceptance Criteria:**
- **Given** access records pushed to the compose Loki, **When** a holder of `iam:audit:read` queries them over REST and over GraphQL with each filter, **Then** both return the matching records newest first, the LogQL uses only the fixed labels plus structured-metadata filters, and the query itself is audited, proven in `make.e2e_tests`.
- **Given** 1,200 matching records, **When** they are paged, **Then** pages of at most 500 return every record exactly once, including records that share a timestamp, proven in `make.integration_tests`.
- **Given** a missing range or a range longer than `ACCESS_LOG_QUERY_MAX_RANGE`, **When** it is queried, **Then** REST returns 422 and GraphQL `VALIDATION_FAILED`, proven in `make.integration_tests`.
- **Given** a decision id, **When** it is read by id over both interfaces, **Then** the record is returned from the window around its UUID v7 timestamp; an absent id returns 404 over REST and `null` over GraphQL, proven in `make.e2e_tests`.
- **Given** a local HTTP stub that answers slower than `ACCESS_LOG_QUERY_TIMEOUT` and one that refuses connections, **When** queries are sent, **Then** they return 504 (GraphQL `QUERY_TIMEOUT`) with no partial page and 503, proven in `make.integration_tests`.
- **Given** a caller without `iam:audit:read`, **When** it queries, **Then** REST returns 403 and GraphQL `FORBIDDEN`, proven in `make.integration_tests`.
- **Given** the compose Loki running and then stopped, **When** `/api/health` is read, **Then** `access-log-store` is reported healthy and then unhealthy and the overall status follows the template's rule, proven in `make.integration_tests`.
- **Given** a 1-hour range on the compose Loki, **When** the integration test times the query, **Then** the duration is printed next to the NFR-44 target as a compose-host measurement, not as a gate value, proven in `make.integration_tests`.
- **Given** the operations are wired, **When** `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate`, `make.integration_tests`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass with additions only.

**Depends on:** 1.1, 6.12, 14.2

### Story 14.4: Query the security audit log

As a security officer, I want to search the security audit log by time, actor, action, target and outcome, so that I can review who changed what.
Covers FR-1, FR-52.
Application: `GetSecurityAuditEventsQueryHandler`; REST `GET /api/security-audit-events` and `GET /api/security-audit-events/{id}`; GraphQL `securityAuditEvents(...)` and `securityAuditEvent(id)`, requiring `iam:audit:read`; each query is audited. Co-changes: snapshots and pinning tests, `features/iam_security_audit.feature`, `docs/requests.http`.

**Acceptance Criteria:**
- **Given** an administrator who creates a role, changes it and is refused another operation, **When** the audit log is queried over both interfaces, **Then** the committed and rejected records are returned with actor, action, target, before and after summaries, outcome and `policyVersion`, proven in `make.e2e_tests`.
- **Given** a caller without `iam:audit:read`, **When** it queries, **Then** 403 is returned; every successful query is itself audited, proven in `make.e2e_tests`.
- **Given** the operations are wired, **When** `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass with additions only.

**Depends on:** 1.1, 1.7, 2.2, 6.12

### Story 14.5: Verify the audit hash chain

As a compliance officer, I want to verify the audit hash chain on demand, against external anchors when I have them, so that any tampering with the audit history is detected and located.
Covers FR-1, FR-52, NFR-23.
Application: `VerifySecurityAuditChainQueryHandler`; REST `GET /api/security-audit-events/chain-verification`; GraphQL `securityAuditChainVerification(...)`, requiring `iam:audit:read` and accepting optional `anchors` (`{seq, hash}` values published as `iam.security_audit.anchored`). Co-changes: snapshots and pinning tests, a final e2e step that verifies the chain after every run, `docs/requests.http`, and ADR 0019 extended with the threat model (external anchors, separate owner and runtime database roles) and the retention basis.

**Acceptance Criteria:**
- **Given** an untampered audit table, **When** the chain is verified over both interfaces, **Then** the result is `valid` with the number of records checked, proven in `make.e2e_tests`.
- **Given** a record altered by a test that disables the trigger, **When** the chain is verified, **Then** the result is `invalid` with the id of that record, proven in `make.integration_tests`.
- **Given** a chain rewritten and fully recomputed by a test after an anchor was published, **When** the chain is verified with that anchor, **Then** the result is `invalid` at the anchored record, proven in `make.integration_tests`.
- **Given** a complete e2e run, **When** its final step verifies the chain, **Then** the result is `valid`, proven in `make.e2e_tests`.
- **Given** the operations are wired, **When** `make.generate_openapi_spec`, `make.generate_graphql_spec`, `make.validate_contract_snapshots`, `make.validate_openapi_spec`, `make.openapi_diff`, `make.graphql_diff` (base `main`), `make.schemathesis_validate`, `make.integration_tests`, `make.e2e_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass with additions only.

**Depends on:** 1.1, 7.8, 14.2, 14.4

## Epic 15: Kubernetes deployment and operations

This epic makes the gateway a well-behaved Kubernetes workload on EKS (owner decisions D9, D14b, D15): AZ-aware peer-relative readiness with connection shedding, graceful drain, reference manifests for both Deployments, the platform resources for Strimzi, Valkey, Loki and Grafana Alloy with their invariants checked by Bats, and the operations runbooks.

### Story 15.1: Keep AZ-aware peer-relative readiness and shed connections

As an operator, I want a stale pod to leave the load balancer only when its peers are fresh, and an availability zone never to lose its last target, so that a local problem moves traffic away while a zone-wide or fleet-wide problem yields deterministic 503s instead of connection failures.
Covers FR-85, NFR-41.
Infrastructure: `HyperPeerFreshnessClient`, which reads `GET /internal/freshness` from peers taken, with their zones, from the ready endpoints of `iam-gateway-peers` in the endpoint watch of Story 10.1. Application: the `PeerReadinessChecker` task every 2 seconds: all peers while the fleet has fewer than 10 pods, otherwise 5 peers with 3 in the pod's own zone, sampled through `Rng`; `FreshnessRule` gives the local, AZ-shaped and fleet-wide verdicts. After 2 consecutive local verdicts the pod fails readiness and sends HTTP/2 GOAWAY, or `Connection: close` on the next HTTP/1.1 response; it becomes ready again after 3 consecutive fresh verdicts. The last `READINESS_AZ_FLOOR` ready pods of a zone never go unready for staleness. When staleness is fleet-wide, pods stay ready and fail closed per request. This replaces the interim local readiness rule of Story 9.7 and activates the peer cross-check of Story 9.5 with real peers. Configuration: `READINESS_AZ_FLOOR` with its `docs/environment.md` row and local default. EKS behaviour (tests T9, T16, T16b, T17, T25) is measured in Stories 16.7 and 16.8.

**Acceptance Criteria:**
- **Given** six pods in three zones with fake peers and one stale pod while the others are fresh, **When** two consecutive checks run with paused time, **Then** the stale pod fails readiness after the second, sends GOAWAY on its HTTP/2 connections and `Connection: close` on the next HTTP/1.1 response, and becomes ready again only after three consecutive fresh verdicts, proven in `make.integration_tests`.
- **Given** a zone whose two pods are stale while other zones are fresh and `READINESS_AZ_FLOOR` 1, **When** the checks run, **Then** exactly one pod of that zone goes unready, the last one stays ready, and its requests get 503 `iam_stale`, proven in `make.integration_tests`.
- **Given** every pod stale, **When** the checks run, **Then** every pod stays ready and requests get 503 `iam_stale` with `Retry-After: 1`, proven in `make.integration_tests`.
- **Given** a fleet of 12 fake peers, **When** peers are sampled with a seeded `Rng`, **Then** each check asks 5 peers with 3 in the pod's own zone; with 6 peers every peer is asked, proven in `make.integration_tests`.
- **Given** a peer that reports a newer applied version for more than 1 second while the pod is fresh, **When** the cross-check runs, **Then** the pod's proof is invalid, proven in `make.integration_tests`.
- **Given** an invalid `READINESS_AZ_FLOOR`, **When** `service check-config --mode gateway` runs, **Then** it exits 2 naming it, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.integration_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass.

**Depends on:** 1.1, 9.7, 10.1

### Story 15.2: Drain gracefully on shutdown

As an operator, I want a gateway pod to leave the load balancer, finish its requests and close its streams in order before it exits, so that rolling updates and scale-in fail no request.
Covers FR-86, NFR-41.
Composition root: `bootstrap/gateway/drain.rs`. The preStop hook is an `exec` of `service drain`, a new subcommand of the same binary (so it works in the distroless image), which calls `GET /internal/drain` on the probe listener over loopback; the endpoint answers only connections from `127.0.0.1` or `::1` and returns 403 to any other peer, so no other pod can drain the gateway. The drain flips readiness to false at once, sends GOAWAY and `Connection: close` on existing connections, keeps serving new connections that still arrive, and returns after `DRAIN_PROPAGATION_DELAY`. On SIGTERM the gateway stops accepting connections, sends GOAWAY again, finishes in-flight requests within `SHUTDOWN_GRACE_PERIOD` (20 seconds for the gateway), closes WebSockets with 1001, ends SSE streams and completes subscriptions jittered over 5 seconds through `Rng`, stops the Kafka tail (no offsets to commit), flushes both log lanes and exits. Composition root: the `drain` subcommand in `cli.rs` and `command.rs`. Configuration: `DRAIN_PROPAGATION_DELAY` with its `docs/environment.md` row and local default, and the gateway default of `SHUTDOWN_GRACE_PERIOD`.

**Acceptance Criteria:**
- **Given** a running pod, **When** `service drain` runs with paused time, **Then** `/internal/ready` answers 503 at once, existing connections receive GOAWAY or `Connection: close`, a new connection is still served, and the call returns after `DRAIN_PROPAGATION_DELAY`, proven in `make.integration_tests`.
- **Given** 50 requests in flight against a slow fake upstream, **When** SIGTERM arrives, **Then** no new connection is accepted, all 50 complete successfully within `SHUTDOWN_GRACE_PERIOD`, and the process exits 0, proven in `make.integration_tests`.
- **Given** open WebSockets, SSE streams and GraphQL subscriptions, **When** SIGTERM arrives, **Then** the WebSockets close with 1001, the SSE streams end and the subscriptions complete, spread over 5 seconds by the seeded `Rng`, proven in `make.integration_tests`.
- **Given** pending audit-lane records and ordinary records, **When** the process exits, **Then** both lanes were flushed, and the audit records were acknowledged by the compose Loki before exit, proven in `make.integration_tests`.
- **Given** an in-flight request that outlives `SHUTDOWN_GRACE_PERIOD`, **When** the grace period ends, **Then** the process exits with the template's exit code for an incomplete shutdown, proven in `make.integration_tests`.
- **Given** a request to `/internal/drain` from a non-loopback address, **When** it arrives, **Then** it gets 403 and readiness is unchanged, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.integration_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass.

**Depends on:** 1.1, 11.4, 15.1

### Story 15.3: Ship reference manifests for both Deployments on EKS

As a platform engineer, I want reviewed reference manifests for `iam-gateway`, `iam-control` and their Jobs, so that the deployment encodes the design's probes, resources, drain and isolation and cannot drift from them unnoticed.
Covers FR-88, NFR-39.
Co-changes: `deploy/kubernetes/` as plain, already-rendered YAML with no Kustomize overlays, because no renderer (`kustomize`, `kubectl`, `yq`) is in the protected `make/tool-versions.mk` and pinning one would be a second protected change, holding: the `iam-gateway` Deployment (6 to 9 replicas through the HPA, request 1 CPU with no CPU limit, 2 GiB memory with request equal to limit, `TOKIO_WORKER_THREADS=2`, the fleet label `app.kubernetes.io/part-of=iam-gateway`, `POD_NAME` and `POD_NAMESPACE` from the downward API, `FRESHNESS_HARD_BOUND` from the ConfigMap `iam-fleet`, the key that the `iam-control` Deployment reads too, the startup, readiness and liveness probes on the probe port 9092 with the settings of `architecture.md` section 17.5, the preStop `exec` of `service drain`, `terminationGracePeriodSeconds` 90, topology spread across zones and hosts, rolling update with `maxSurge` 3 and `maxUnavailable` 0, `minReadySeconds` 15, a toleration for the dedicated gateway node pool); the `iam-control` Deployment (2 to 3 replicas, 1 CPU and 512 MiB requests); the Services `iam-gateway` (LoadBalancer, 443 to 8443, AWS Load Balancer Controller annotations for an NLB with IP targets, internet-facing, Proxy Protocol v2, cross-zone off, health check on `/internal/ready` at port 9092, deregistration delay 120 seconds), `iam-gateway-decision` (ClusterIP 9091, the decision API), `iam-gateway-internal` (ClusterIP 9090, `/internal/freshness` and `/internal/policy/applied`), `iam-gateway-mesh` (ClusterIP 8444, east-west calls), `iam-gateway-peers` (headless 9090, `publishNotReadyAddresses: false`) and `iam-control` (ClusterIP 80 to `APP_PORT`); the HPA (CPU 50%, scale-up at most 3 pods per 60 seconds, scale-down at most 1 pod per 2 minutes with a 600-second window); PodDisruptionBudgets (`maxUnavailable: 1` for the gateway, `minAvailable: 1` for the control plane); default-deny NetworkPolicies with the allowances of `architecture.md` section 16.8; ServiceAccounts and RBAC (gateway: `get`, `list`, `watch` on `endpointslices` in upstream namespaces and in namespace `iam`, for `iam-gateway-peers`; control: `get`, `list` on pods in namespace `iam`); the Jobs `iam-migrate` and `iam-bootstrap` (with `--iam-host`); Secrets referenced and mounted as files, never committed with values. The Bats suite `tests/CLI/bats/deploy-manifests.bats` (`# bats file_tags=repository`, run by `make.bats` and by the existing `repository` group of the Bats matrix in `tests.yml`) checks the invariants with `grep` and `awk`; the repository's strict `yamllint` run covers the YAML. The file is new, so it is not yet protected (`tests/CLI/bats/` protects only files that exist on the base ref). No protected file changes. ADR 0028 (Kubernetes on EKS: NLB with TLS in the pod, probes, AZ-aware readiness, zone-aware routing) is added.

**Acceptance Criteria:**
- **Given** the gateway manifests under `deploy/kubernetes/`, **When** the Bats suite checks the gateway pods, **Then** they have a CPU request and no CPU limit, memory request equal to limit, the fleet label, the three probes on the probe port, the preStop `exec` drain hook and a termination grace of 90 seconds (NFR-39), proven in `make.bats`.
- **Given** the Services, **When** the suite checks them, **Then** `iam-gateway` carries the NLB annotations for IP targets, Proxy Protocol v2, cross-zone off and the `/internal/ready` health check on port 9092, `iam-gateway-decision`, `iam-gateway-internal` and `iam-gateway-mesh` expose only their own ports, and `iam-gateway-peers` is headless without not-ready addresses, proven in `make.bats`.
- **Given** the RBAC objects, **When** the suite checks them, **Then** the gateway may only `get`, `list` and `watch` EndpointSlices, in the upstream namespaces and in `iam`, and the control plane may only `get` and `list` pods in namespace `iam`, proven in `make.bats`.
- **Given** the NetworkPolicies, **When** the suite checks them, **Then** traffic is denied by default; `iam-control` admits ingress only from gateway pods and Jobs; gateway port 9090 admits only `iam-control` and gateway pods, and gateway egress to gateway pods on 9090 is allowed; port 9091 admits only decision-API caller namespaces; port 9092 admits only the NLB subnet CIDRs and monitoring; port 8444 admits only microservice namespaces; upstream namespaces admit ingress only from gateway pods; and gateway egress to PostgreSQL is denied, proven in `make.bats`.
- **Given** the HPA, PodDisruptionBudgets and rolling-update settings, **When** the suite checks them, **Then** they hold the values above, proven in `make.bats`.
- **Given** the manifests and the repository, **When** `make.secrets_scan` runs, **Then** no Secret value is committed.
- **Given** both Deployments and the Jobs, **When** the suite checks them, **Then** both Deployments read `FRESHNESS_HARD_BOUND` from the same ConfigMap key and the `iam-bootstrap` Job passes `--iam-host`, proven in `make.bats`.
- **Given** the new YAML files, **When** `make.lint_yaml` runs the repository's strict `yamllint`, **Then** it passes and no file under `deploy/` is a Kustomize overlay or needs a renderer.
- **Given** the story's changes, **When** `make.bats`, `make.lint_yaml`, `make.secrets_scan` and `make.docs_check` run, **Then** all pass, `deploy-manifests.bats` carries `# bats file_tags=repository`, and ADR 0028 is indexed.

**Depends on:** 1.1, 12.3, 13.4, 14.2, 15.2

### Story 15.4: Ship Strimzi, Valkey, Loki and Alloy platform resources

As a platform engineer, I want the Kafka, Valkey, Loki and log-shipping resources the gateway relies on expressed as reviewed manifests, so that the cluster is reconciled to the gated configuration and the startup gates only detect drift.
Covers FR-53, FR-72, FR-88, NFR-25.
Co-changes: `deploy/platform/strimzi/` (a KRaft `Kafka` with `KafkaNodePool`s of 3 brokers, one per zone with rack awareness, and 3 controllers; `default.replication.factor` 3, `min.insync.replicas` 2, `unclean.leader.election.enable` false, `auto.create.topics.enable` false, a TLS listener with `scram-sha-512`, `authorization.type: simple` with `allow.everyone.if.no.acl.found: false`; the `KafkaTopic` `iam.policy.state.v1` with 1 partition, 3 replicas and the full configuration of `architecture.md` section 9.1 (`cleanup.policy: compact`, `min.insync.replicas: 2`, `message.timestamp.type: LogAppendTime`, `min.compaction.lag.ms` 1 hour, `max.compaction.lag.ms` 1 day, `delete.retention.ms` 7 days, `max.message.bytes` 1 MiB, `segment.bytes` 64 MiB, `segment.ms` 1 hour, `min.cleanable.dirty.ratio` 0.1, `unclean.leader.election.enable: false`); the `KafkaTopic` `iam.events.v1` with `cleanup.policy: delete` and 7 days of retention; the `KafkaUser`s `iam-control`, `iam-gateway`, `iam-gateway-bootstrap` (the only one with a `consumerByteRate` quota) and `notification-service` with the ACLs of `architecture.md` section 17.11); `deploy/platform/valkey/` (one primary and two replicas with Sentinel, one per zone; the chart or operator stays an assumption); `deploy/platform/loki/` (retention per stream: `lane="access"` 90 days and `lane="audit"` 400 days, structured metadata enabled); `deploy/platform/alloy/` (a DaemonSet pipeline that parses the gateway's JSON lines and sets the labels `app`, `env`, `lane`, `decision` and `upstream`). `docs/operations.md` notes the raised `containerLogMaxSize` on the gateway node pool. All resources are plain, already-rendered YAML, like Story 15.3; a second Bats file, `tests/CLI/bats/deploy-platform.bats` (tag `repository`), holds the platform checks with `grep` and `awk`, because every file below `tests/CLI/bats/` that exists on the base ref is protected, so a story adds a new file there rather than editing one an earlier story merged. No protected file changes. ADR 0029 (Kafka on Strimzi and the configuration gates) is added.

**Acceptance Criteria:**
- **Given** the Strimzi resources, **When** the Bats suite checks them, **Then** the brokers have replication factor 3, `min.insync.replicas` 2, unclean leader election off, automatic topic creation off and simple authorization without the allow-everyone fallback, proven in `make.bats`.
- **Given** the state topic resource, **When** the suite checks it, **Then** it has exactly one partition, 3 replicas and each setting of `architecture.md` section 9.1, asserted one by one, matching every rule the configuration gates of FR-72 enforce, proven in `make.bats`.
- **Given** the `KafkaUser` resources, **When** the suite checks them, **Then** only `iam-control` may write the IAM topics, `iam-control` may also read the state topic (assign only, no group ACL) and holds `DescribeConfigs` on the cluster, both gateway principals may only read and describe the state topic, and only `iam-gateway-bootstrap` carries a quota, proven in `make.bats`.
- **Given** the Loki configuration, **When** the suite checks it, **Then** the `access` lane is retained for 90 days and the `audit` lane for 400 days (NFR-25), proven in `make.bats`.
- **Given** the Alloy pipeline, **When** the suite checks it, **Then** it sets only the five fixed labels, proven in `make.bats`.
- **Given** the story's changes, **When** `make.bats`, `make.lint_yaml`, `make.secrets_scan` and `make.docs_check` run, **Then** all pass, the platform YAML passes the strict `yamllint` run, and ADR 0029 is indexed.

**Depends on:** 1.1, 15.3

### Story 15.5: Write the operations runbooks

As an on-call operator, I want runbooks for the failures this design can meet, so that I can restore service from documented steps instead of guesswork.
Covers NFR-14, NFR-28, NFR-30.
Co-changes: `docs/operations.md` gains runbooks for a state topic ahead of PostgreSQL (stop the relay, resync to a new log epoch), a fleet or single-pod rebootstrap, Valkey degraded, Loki down (audit-or-deny engaged, queries unavailable), planned JWT key rotation and the emergency global cut-off, `T_hard` tuning (when `FRESHNESS_HARD_BOUND` may move from 15 to 5 seconds; it is changed through the one ConfigMap key both Deployments read, raised on `iam-control` first and lowered on the gateways first, while Sync-Fence also waits for the highest value any pod reports), and User service consumer lag; the availability targets of NFR-14 (99.95% monthly for the gateway, 99.9% for the management API, measured by synthetic checks in production); the recovery targets of NFR-28 (RPO at most 1 minute and RTO at most 15 minutes for PostgreSQL with synchronous replication); and the alert list with thresholds. Every figure is labelled as a target or an estimate until Story 16.7 measures it.

**Acceptance Criteria:**
- **Given** `docs/operations.md`, **When** it is read, **Then** each runbook above names its symptom, the metric or alert that shows it, the steps and the check that confirms recovery, proven in `make.docs_check`.
- **Given** the topic-ahead runbook, **When** its steps are followed in an e2e scenario against the compose world, **Then** a resync brings the shadow-bootstrap digest back to PostgreSQL's, proven in `make.e2e_tests`.
- **Given** the availability and recovery figures, **When** they are read, **Then** each is labelled as a target and names how it is measured, proven in `make.e2e_tests`.
- **Given** the story's changes, **When** `make.docs_check` and `make.e2e_tests` run, **Then** both pass.

**Depends on:** 1.1, 15.4

## Epic 16: Hardening, benchmarks and documentation

This epic completes configuration validation for both modes, observability, fault injection, the smuggling and parser-differential suite, contract hardening, the k6 gate, the benchmarks and Kafka fault tests on EKS outside `make ci`, and the decision records, operations guide and architecture model.

### Story 16.1: Validate the complete configuration for both modes

As an operator, I want every IAM variable of both run modes validated with clear errors at startup and in `check-config`, so that a misconfigured deployment fails fast instead of failing open.
Covers FR-55.
Composition root: the remaining ranges and cross-field rules in `config.rs` for every variable of FR-55 in both modes, a check that every variable has the local defaults in `.env` and `.env.test` added by the story that introduced it, a check that every template-synchronised file the plan changes (`command.rs`, `command/serve.rs`, `command/check_config.rs`, `command/healthcheck.rs`, `http/router.rs`, `graphql/handler.rs`, `tests/integration/main.rs`, `support.rs`, `check_config.rs` and `healthcheck.rs`, `docker-compose.yml`, the Dockerfile and the workflow files) is listed in `.templatesyncignore`, and the CLI integration tests per rule and per mode. Co-changes: `docs/environment.md` complete for every variable; the removed variables (`USER_SERVICE_BASE_URL`, `USER_SERVICE_TIMEOUT`, `JWT_PUBLIC_KEYS`, `TOKEN_CACHE_TTL`, `AUTHZ_CACHE_TTL`, `AUTHZ_CACHE_MAX_ENTRIES`, `POLICY_EPOCH_POLL_INTERVAL`, `POLICY_STALE_GRACE`, `RECONCILIATION_INTERVAL`, `IAM_EVENTS_QUEUE_URL`, `USER_EVENTS_QUEUE_URL`, `ACCESS_LOG_RETENTION`, `ACCESS_LOG_ALLOW_SAMPLE_RATE`, `ACCESS_LOG_BUFFER`) appear in none of `.env`, `.env.test` and `docs/environment.md`.

**Acceptance Criteria:**
- **Given** each variable of FR-55, **When** `service check-config --help` and the configuration tests are inspected, **Then** each is declared with `env` and a hidden value, has a documented default or requirement and its mode, and has a local default in `.env` and `.env.test`, proven in `make.integration_tests`.
- **Given** one violation per rule (key-file count and parsing, issuer and audience empty, service-token lifetime above 3,600 seconds or above `MAX_TOKEN_LIFETIME`, skew above 60 seconds, memo capacity and TTL bounds, `PLAINTEXT` or `relaxed` outside `dev` and `test`, missing Kafka or Loki URLs in their mode, a bulk chunk outside 1 to 1,000, a query range above 7 days, equal listener addresses, missing TLS files outside `dev` and `test`, `FRESHNESS_HARD_BOUND` outside 3 to 30 seconds or not above `FRESHNESS_READY_BOUND`, a `KAFKA_TRANSACTION_TIMEOUT` not below `FRESHNESS_HARD_BOUND` in control mode, a static discovery mode without its file or list, a rate-limit timeout outside 1 to 50 ms, a sample rate outside 0 to 1), **When** `service check-config` runs in the matching mode, **Then** it exits 2 with a message naming the variable, proven in `make.integration_tests`.
- **Given** a valid gateway configuration without database settings and a valid control configuration, **When** `service check-config --mode gateway` and `--mode control` run, **Then** both exit 0, proven in `make.integration_tests`.
- **Given** the repository, **When** a test searches `.env`, `.env.test` and `docs/environment.md`, **Then** none of the removed variables appears, proven in `make.docs_check`.
- **Given** the list of template-synchronised files above, **When** the seam check of Story 1.2 runs with the complete list, **Then** `.templatesyncignore` covers each file, proven in `make.integration_tests`.
- **Given** the story's changes, **When** `make.integration_tests`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass.

**Depends on:** 1.1, 12.3, 13.5, 14.3, 15.2

### Story 16.2: Emit operational metrics for both planes

As an operator, I want every gateway and control-plane metric exported in a standard format, so that I can see freshness, propagation, latency and log health at a glance and alert on them.
Covers NFR-20, NFR-27.
Composition root: `bootstrap/gateway/metrics.rs`, a registry of every metric of NFR-27 (gateway: `gateway_residence_seconds`, `gateway_decisions_total`, `policy_applied_version`, `policy_digest_info`, `policy_derived_hash_info`, `policy_proof_age_seconds`, `policy_fresh`, `policy_bootstrap_seconds`, `token_memo_hit_ratio`, `graphql_document_cache_hit_ratio`, `streams_open`, `graphql_subscriptions_open`, `rate_limit_store_degraded`, `rate_limit_store_latency_seconds`, `access_log_audit_pending`, `access_log_dropped_total`, `upstream_rtt_seconds`, `upstream_cross_zone_ratio`; control: `outbox_oldest_unpublished_seconds`, `relay_published_offset`, `user_events_consumer_lag_seconds`, `user_events_dead_letters_total`, `revocation_propagation_seconds`, `anti_entropy_repairs_total`, `sync_fence_outcomes_total`, `access_log_query_seconds`), fed by the `tracing` events with target `metrics` that the earlier stories emit, and rendered as Prometheus text with `prometheus-client` on the gateway's probe listener (`/metrics`) and on `GET /metrics` of `iam-control` (outside `/api`, not part of the contract snapshots). The gateway also emits `gateway_residence_seconds` (accept to upstream write, plus upstream first byte to last client byte), `token_memo_hit_ratio`, `upstream_rtt_seconds` by zone and `upstream_cross_zone_ratio`. Co-changes: `docs/operations.md` lists each metric with its labels and the alert thresholds.

**Acceptance Criteria:**
- **Given** each registered metric, **When** a test emits its `tracing` event through the template's log recorder, **Then** the rendered Prometheus text holds the metric with its labels, proven in `make.integration_tests`.
- **Given** proxied requests, **When** `/metrics` is read on the probe listener, **Then** `gateway_residence_seconds`, `token_memo_hit_ratio`, `upstream_rtt_seconds` by zone and `upstream_cross_zone_ratio` are present with plausible counts, proven in `make.integration_tests`.
- **Given** the rendered metrics of both planes, **When** their labels are inspected, **Then** no credential, cookie, document, concrete path, subject id or IP address appears, proven in `make.unit_tests`.
- **Given** an IAM request, **When** it is served, **Then** the template's request id, JSON log and trace span are preserved, proven in `make.integration_tests`.
- **Given** `GET /metrics` on `iam-control`, **When** the contract snapshots are generated, **Then** they are unchanged, proven in `make.unit_tests`.
- **Given** the story's changes, **When** `make.format`, `make.lint_code`, `make.unit_tests`, `make.architecture`, `make.complexity`, `make.integration_tests`, `make.validate_contract_snapshots`, `make.tests_with_coverage`, `make.mutation_tests_diff` and `make.docs_check` run, **Then** all pass.

**Depends on:** 1.1, 12.3, 13.4, 14.2

### Story 16.3: Prove fail-closed behaviour under injected faults

As a security officer, I want every dependency failure proven to end in a denial, a 503 or a 4xx, so that no outage can ever produce an allow.
Covers FR-13, NFR-14, NFR-15.
Tests: a compose-reproducible fault-injection suite in the composition root's integration tests for Kafka unreachable, a stale proof, a stalled relay, a zombie relay batch, duplicate records, digest and derived-state corruption, a second partition, a misconfigured topic, PostgreSQL down for `iam-control`, Loki down (audit-or-deny), Valkey down (limiter only, authorization unchanged), malformed and oversized input, and a panic in a handler; plus the gated part of NFR-14: the gateway keeps deciding and proxying from a fresh snapshot with PostgreSQL, `iam-control`, User service and Valkey stopped, and graceful shutdown and drain fail no in-flight request. Cases that need EKS run in Story 16.8.

**Acceptance Criteria:**
- **Given** each injected fault, **When** proxied requests, decision API checks and management calls are sent, **Then** 100% of results are `deny`, 503 or a 4xx response and none is an allow, proven in `make.integration_tests`.
- **Given** PostgreSQL, `iam-control` and Valkey stopped, with the fake upstream serving User service routes still running, while the proof stays fresh, **When** proxied requests continue, **Then** they are decided and forwarded from the snapshot, and rate-limited routes fall back to the local limiter, proven in `make.integration_tests`.
- **Given** a stalled relay, **When** administrative writes continue, **Then** they commit and return 202 with `committed_pending_propagation`, the gateway keeps serving the acknowledged state, and the writes are published after recovery, proven in `make.integration_tests`.
- **Given** SIGTERM and a drain while requests are in flight, **When** shutdown runs, **Then** every in-flight request completes and the process exits within `SHUTDOWN_GRACE_PERIOD`, proven in `make.integration_tests`.
- **Given** the suite, **When** `make.integration_tests`, `make.tests_with_coverage` and `make.mutation_tests_diff` run, **Then** all pass.

**Depends on:** 1.1, 13.5, 16.2

### Story 16.4: Run the smuggling and parser-differential suite

As the owner of IAM, I want a maintained corpus proving that the gateway and the upstream always read a request the same way, so that no encoding, framing or JSON trick can authorize one request and deliver another.
Covers NFR-21, NFR-40.
Tests: a corpus under the composition root's integration tests that sends each case through the gateway to an echo upstream that reports exactly what it parsed: double and mixed percent-encodings such as `%252e%252e`, encoded slashes and backslashes, conflicting `Content-Length` and `Transfer-Encoding`, obsolete line folding, HTTP/2 pseudo-header and `:path` abuses, duplicate JSON keys in GraphQL bodies, GraphQL batches at and above the cap, bodies with `extensions.persistedQuery`, `documentId`, `queryId` or an empty `query`, GraphQL `GET` requests, `graphql-sse` reservation `PUT` requests, malformed and oversized WebSocket frames on both subscription subprotocols. Every case is either rejected by the gateway or read identically by both sides.

**Acceptance Criteria:**
- **Given** each corpus case, **When** it is sent through the gateway, **Then** the gateway either rejects it with its documented status or the echo upstream reports exactly the method, path, headers and body the gateway authorized, with zero differentials, proven in `make.integration_tests`.
- **Given** a path that decodes to an allowed operation only after a second decode, **When** it is sent, **Then** it is rejected with 400 and never forwarded, proven in `make.integration_tests`.
- **Given** a GraphQL body with two `query` members, **When** it is sent, **Then** it is rejected with 400, proven in `make.integration_tests`.
- **Given** malformed WebSocket frames on `graphql-transport-ws` and `graphql-ws`, **When** they are sent, **Then** the socket closes with 4400 and nothing reaches the upstream, proven in `make.integration_tests`.
- **Given** a GraphQL body carrying only a persisted-query hash, **When** it is sent, **Then** it gets 400 and nothing reaches the upstream, proven in `make.integration_tests`.
- **Given** the suite, **When** `make.integration_tests`, `make.tests_with_coverage` and `make.mutation_tests_diff` run, **Then** all pass.

**Depends on:** 1.1, 10.8, 10.9, 11.3

### Story 16.5: Run Schemathesis with ephemeral credentials and harden inputs

As the owner of IAM, I want property-based contract testing to reach every protected IAM operation, so that malformed input never crashes or misleads the service.
Covers NFR-7, NFR-21.
Co-changes: a full Schemathesis pass over every operation of the API Surface Summary of `prd.md` against `iam-control`, with the credential target of Story 2.8 (which bootstraps its service principal since Story 6.10), and any DTO, limit or response fix the run reveals. No key or token is committed, and the template `Makefile` is unchanged.

**Acceptance Criteria:**
- **Given** the ephemeral credentials of the bootstrapped service principal, **When** `make.schemathesis_validate` runs, **Then** it reaches every IAM operation past the 401 and 403 and reports no failure.
- **Given** the generated OpenAPI document, **When** `make.validate_openapi_spec` runs, **Then** Spectral reports zero findings and every IAM operation documents 400, 401, 403, 413, 415, 422 and default problem responses.
- **Given** requests with unknown fields or validation errors naming operations of another service, **When** they are sent, **Then** unknown fields are rejected and no message reveals whether an operation exists elsewhere, proven in `make.schemathesis_validate`.
- **Given** the API Surface Summary of `prd.md`, **When** it is compared with both snapshots, **Then** every capability row has its REST operation and its GraphQL operation, proven in `make.validate_contract_snapshots`.
- **Given** the repository after the story, **When** `make.secrets_scan`, `make.docs_check`, `make.tests_with_coverage` and `make.mutation_tests_diff` run, **Then** all pass.

**Depends on:** 1.1, 7.10, 8.6, 13.2, 13.7, 14.3, 14.5

### Story 16.6: Gate the gateway with k6 scenarios

As the owner of IAM, I want load-test scenarios with thresholds for proxied traffic and for the management API, so that behaviour under load is checked in CI and the benchmark runs on EKS have a defined workload.
Covers NFR-29, NFR-34, NFR-41.
Co-changes: the k6 scenarios `gateway-proxy` (REST, GraphQL with document-cache hits and misses, anonymous and rate-limited routes, WebSocket and SSE streams that reconnect after a 1001 close, a revocation probe) and `iam-management` (administrative writes in both write modes, reads, a flood of 403 responses while write latency is measured) under `tests/Load/`, as `constant-arrival-rate` (open model) with their own thresholds, failing when `dropped_iterations` is above 0, plus smoke variants run by `make.smoke_load_tests`; parameters for the first-release workload (1,000 requests per second peak, 2,000 with headroom) used by Story 16.7; gateway e2e and smoke jobs in the workflow files, which call only the existing gate targets `e2e-tests` and `smoke-load-tests` of `make ci-list` with a gateway environment, so rule (d) of the protected invariant script holds without a change to `make/gates.mk`; the changed workflow files are added to `.templatesyncignore` and to the seam check of Story 1.2 in this story. The protected health budgets are unchanged. The smoke variants check correctness only; latency and capacity are gated in Story 16.7.

**Acceptance Criteria:**
- **Given** the smoke variants, **When** `make.smoke_load_tests` runs, **Then** both pass with checks above 99%, no dropped iterations, and the protected health budgets unchanged.
- **Given** the `gateway-proxy` scenario, **When** its streams are closed with 1001 by a drain in the smoke run, **Then** they reconnect and the checks still pass, proven in `make.smoke_load_tests`.
- **Given** the `iam-management` scenario, **When** a flood of refused requests runs beside administrative writes, **Then** write latency stays within the scenario's smoke threshold (a target, not a capacity gate) and the run's checks confirm that the refused requests were answered 403, proven in `make.smoke_load_tests`.
- **Given** the workflow files, **When** the seam check inspects them, **Then** a gateway e2e job and a smoke job exist, each calls only `make e2e-tests` or `make smoke-load-tests`, and `.templatesyncignore` covers the changed workflow files, proven in `make.integration_tests`.
- **Given** the changed workflow files, **When** `make.validate_invariants` runs, **Then** it passes, because every workflow still runs only gate targets of `make ci-list` (rule (d)).
- **Given** the story's changes, **When** `make.validate_invariants`, `make.integration_tests`, `make.smoke_load_tests` and `make.docs_check` run, **Then** all pass and both scenarios are documented with their thresholds labelled as targets.

**Depends on:** 1.1, 15.2, 16.2

### Story 16.7: Benchmark latency, capacity, propagation and bootstrap on reference nodes

As the owner of IAM, I want the latency, capacity, propagation, bootstrap, memory, Valkey and Loki estimates replaced by measurements on EKS reference nodes, so that the first release ships on measured numbers and every miss is known before production.
Covers FR-86, NFR-33, NFR-34, NFR-35, NFR-37, NFR-38, NFR-39, NFR-41, NFR-42, NFR-43, NFR-44.
Prerequisite: an EKS cluster with the AWS Load Balancer Controller, cert-manager, Strimzi, Valkey, Loki and Grafana Alloy (an external prerequisite); without it the story stops and reports. Runs outside `make ci` on dedicated nodes across 3 zones with the manifests of Stories 15.3 and 15.4, a hyper echo upstream (0 and 20 ms delay, 1 to 64 KB bodies), wrk2 and oha with coordinated-omission correction for latency, k6 scenarios of Story 16.6 for behaviour, and generators kept at or below 50% CPU. Tests at first-release scope: T1, T2, T3, T4, T6, T6b, T7, T8, T9, T10, T11, T12, T13 (at 100k and 1M subjects), T24, T25, T28, T29, T30 and T31, in the first-release configuration only (request 3 CPU, `TOKIO_WORKER_THREADS=2`, 6 pods, 12 for scale-out). The reference 5-CPU pod, T13 at 10M subjects, T23, T26, T27 and the Envoy `ext_authz` baseline are later-phase characterisation (`architecture.md` section 20.6). HdrHistogram artefacts are stored. Results replace the estimates in `docs/operations.md`, each labelled with the node type and date. A missed residence or capacity target triggers profiling and optimisation of the hyper pipeline before release (NFR-33). ADR 0031 (first-release sizing for 1,000 rps and deferred large-fleet mechanisms) is added with the measured results.

**Acceptance Criteria:**
- **Given** T2 at 50% fleet CPU on the first-release fleet, **When** it completes three repetitions, **Then** the residence p95 and p99 on the hottest pod, the requests per worker vCPU and the fleet's 2,000 rps run with zero gateway-caused 5xx responses are recorded against the targets of NFR-33 and NFR-34, and any miss is recorded with its profiling follow-up, recorded outside `make ci` and checked by `make.docs_check`.
- **Given** T3, T4, T11 and T12, **When** they run, **Then** the GraphQL, cold-token, forged-token and large-document results are recorded against their targets, recorded outside `make ci` and checked by `make.docs_check`.
- **Given** T6, T6b and T7, **When** they run, **Then** commit-to-applied propagation p99 and request p99 and p99.9 during bulk changes are recorded against NFR-35, and no serving pod's proof aged past `FRESHNESS_READY_BOUND`, recorded outside `make ci` and checked by `make.docs_check`.
- **Given** T8 and T13, **When** they run, **Then** single-joiner bootstrap time and snapshot memory are recorded against NFR-37 and NFR-38, and the bootstrapped digest equals PostgreSQL's, recorded outside `make ci` and checked by `make.docs_check`.
- **Given** T9, T10 and T25, **When** they run at 1,000 requests per second, **Then** scale-out, rolling update and pod kill complete with the failed-request count recorded against NFR-41, recorded outside `make ci` and checked by `make.docs_check`.
- **Given** the benchmark configuration, **When** T2 runs, **Then** the CFS-throttled period count of gateway pods is recorded as zero or reported as a miss (NFR-39), recorded outside `make ci` and checked by `make.docs_check`.
- **Given** T24, T30 and T31, **When** they run, **Then** the cross-zone share, the Valkey degradation behaviour and the Loki query durations are recorded against NFR-43, NFR-42 and NFR-44, recorded outside `make ci` and checked by `make.docs_check`.
- **Given** T1, **When** it ramps to the knee, **Then** the knee per worker vCPU is recorded against the 8,000 target of NFR-34, proven in `make.docs_check`.
- **Given** the results, **When** `docs/operations.md` and ADR 0031 are checked, **Then** every replaced figure is labelled as measured with node type and date, every unmeasured figure keeps its estimate or target label, and `make.docs_check` passes.

**Depends on:** 1.1, 15.4, 16.6

### Story 16.8: Run Kafka failover and zombie-leader fault tests on EKS

As the owner of IAM, I want the freshness guarantee tested against broker failover, a zombie partition leader and zone partitions, so that the `T_hard` value and the conditions of the bounded-staleness guarantee rest on evidence.
Covers FR-73, FR-85, NFR-15, NFR-19, NFR-35, NFR-36.
Prerequisite: the EKS environment of Story 16.7. Runs outside `make ci`: T14 (partition-leader broker kill and rolling broker restart), T15 (one zone isolated with its gateway pods and the old leader; one pod partitioned with the old leader), T16 and T16b (one pod and one zone cut off from Kafka), T17 (fleet-wide Kafka loss with NLB IP targets), T19 (Sync-Fence with terminating, pending and bootstrapping pods during a rollout), T20 (digest and derived-state corruption, gaps, topic recreation, relay duplicates, a zombie relay batch, a second partition), T32 (User service revocation end to end with a consumer killed mid-batch and a poison record) and T33 (GraphQL subscriptions under revocations and malformed frames). The story records the `T_hard` decision (tighten `FRESHNESS_HARD_BOUND` to 5 seconds only if T14 measures a proof gap of at most 2 seconds) and whether guarantees G4 and G8 hold unconditionally in the default mode; if T15 fails, it records that the liveness ticks or the later-phase strict mode need an owner decision. Results go to ADR 0024 and `docs/operations.md`.

**Acceptance Criteria:**
- **Given** T14, **When** the partition leader is killed and the brokers are restarted in turn, **Then** no false freshness proof is observed, and the proof gap and the fleet-wide 503 duration are recorded, recorded outside `make ci` and checked by `make.docs_check`.
- **Given** T15, **When** a zone is isolated with the old leader, **Then** no pod in the isolated zone allows a request on frozen state beyond `FRESHNESS_HARD_BOUND`, or the failure is recorded and the run stops for an owner decision on liveness ticks or strict mode, recorded outside `make ci` and checked by `make.docs_check`.
- **Given** T16, T16b and T17, **When** one pod, one zone and then the whole fleet lose Kafka, **Then** the stale pod sheds its connections, the zone keeps a registered target with 503 answers, and NLB targets stay registered with 503 and `Retry-After` fleet-wide, recorded outside `make ci` and checked by `make.docs_check`.
- **Given** T19 and T20, **When** they run, **Then** no new decision or open stream uses state older than a write that returned `complete` or `bounded`, and every corruption or duplicate case fences or is ignored as specified, with 100% of faults ending in a denial, 503 or 4xx (NFR-15), recorded outside `make ci` and checked by `make.docs_check`.
- **Given** T32 at 10 events per second and in bursts of 1,000, **When** the consumer pod is killed mid-batch and a poison record is produced, **Then** the p99 from the event's acknowledgement to enforcement on every healthy pod is recorded against the 1-second target of NFR-19, no event is lost or applied twice, and the poison record is dead-lettered without blocking, recorded outside `make ci` and checked by `make.docs_check`.
- **Given** T33, **When** it runs with 10,000 open subscriptions, **Then** denied operations never reach the upstream and revoked subscriptions complete before Sync-Fence returns, recorded outside `make ci` and checked by `make.docs_check`.
- **Given** the results, **When** ADR 0024 and `docs/operations.md` are checked, **Then** they record the `T_hard` decision and the status of G4 and G8, and `make.docs_check` passes.

**Depends on:** 1.1, 16.7

### Story 16.9: Complete the decision records, operations guide and architecture model

As a future maintainer, I want every IAM decision, risk mapping and operational procedure documented and the architecture model complete, so that the gateway can be operated and audited without tribal knowledge.
Covers NFR-5, NFR-22, NFR-28, NFR-30.
Co-changes: ADRs 0013 to 0031 completed and indexed in `docs/adr/README.md`, with ADR 0022 (security controls of IAM and the gateway edge) mapping API1 to API10 (2023), the IAM-specific risks (parser differential, confused deputy, cross-scope cache poisoning, reason-code disclosure, bootstrap) and the edge risks (request smuggling, header spoofing, stream re-authorization, rate-limit bypass) to requirements and tests; `docs/operations.md` completed with bootstrap and the break-glass procedure, the separate owner and runtime database roles, resync, key rotation and the emergency cut-off, RPO and RTO, and the measured results of Stories 16.7 and 16.8; `docs/architecture.md` describing the gateway and both planes; `workspace.dsl` with the system renamed "IAM API gateway", the containers `gateway`, `control`, `database`, `kafka`, `valkey`, `loki`, `loadBalancer` and `kubernetesApi`, the external systems and the relationships of `architecture.md` section 18, and `apiGateway` removed as an external system.

**Acceptance Criteria:**
- **Given** the ADR index, **When** it is read, **Then** ADRs 0013 to 0031 exist with status and context, and ADR 0022 maps each OWASP API risk, each IAM-specific risk and each edge risk to at least one requirement and one test, proven in `make.docs_check`.
- **Given** the model, **When** `make.validate_architecture_model` runs, **Then** it passes with the containers, external systems and relationships of section 18.
- **Given** the production image, **When** `make.image_scan` runs, **Then** it reports zero HIGH or CRITICAL findings.
- **Given** the documentation, **When** `make.docs_check` runs, **Then** it passes, and `docs/operations.md` states that a pod bootstrapped from the state topic reaches the PostgreSQL digest and decides the corpus as `iam-control` does, which NFR-28 relies on.

**Depends on:** 1.1, 16.3, 16.4, 16.5, 16.8
