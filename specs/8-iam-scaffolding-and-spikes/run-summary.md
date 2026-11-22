# Run Summary: IAM API Gateway and Authorization Service, Issue #8

| Field | Value |
| --- | --- |
| Bundle directory | `specs/8-iam-scaffolding-and-spikes/` |
| Issue | `#8` "Scaffold the IAM context and run the phase-0 spikes" (VilnaCRM-Org/api-gateway-service) |
| What this bundle is | The whole master plan `specs/0-iam-authorization-service/` (iam-service checkout, 2026-11-21, placeholder issue 0): 16 epics and 127 stories, with the Epic 1 section of the earlier Epic 1 bundle of this directory kept verbatim |
| Date | 2026-11-22 |
| Readiness | `Verdict: ready` in `implementation-readiness.md` |
| Self-check | The bundle verification script (N=8) printed no failure line; the stage dry run exited 0 |
| Next step | `/rs-sdlc-implement` for issue #8, starting with Story 1.1 (code already in the working tree, uncommitted) |

## Decision: One Pull Request for All 16 Epics

The owner decided on 2026-11-22 that all sixteen epics ship in one pull request for issue #8 ("we don't need one pr for each epic, you can work on the all epic in one pr"). This replaces the per-epic method of `handoff/HANDOFF.md`, under which this directory held only Epic 1 (stories 1.1 to 1.8) with the requirement ids those stories cover. The bundle now carries every epic, story, FR and NFR of the master plan, so the implementation workflow implements all 127 stories in that pull request and the FR/NFR review gate traces all 122 requirement ids of `prd.md` to test evidence in it. Story 1.1 runs first and alone; the other stories follow their `Depends on:` lines.

## Artifacts

| File | Content |
| --- | --- |
| `research.md` | The master research with the target-repository facts of the Epic 1 bundle (section 1.1 to 1.5), Story 1.1 in the working tree (section 1.6), the whole-product template view (sections 1.7, 1.8), the approved ADR 0023 change (section 9) and the owner decisions including ADR 0023, Story 1.8 and the one-pull-request decision (section 19) |
| `product-brief.md` | The master brief with the current state of the target repository, the delivery in one pull request and a risk row for it |
| `prd.md` | All 85 FRs and 37 NFRs of the master, nineteen of them with the "Epic 1 slice" paragraph of the Epic 1 bundle; delivery paragraph in the executive summary; product scope with the delivery and protected-change note; API surface summary, event catalogue, traceability |
| `architecture.md` | The master architecture with a rewritten `## Constraints` (3,845 bytes), section 3.1 and section 6 describing the approved delta applied in Story 2.3, the Epic 1 wiring of `api-gateway-service` as section 7.5, the one-pull-request note in section 23 and updated assumptions in section 24 |
| `epics.md` | New preamble (one pull request, profile, owner decisions, changes against the master), coverage table regenerated from the 127 `Covers` lines, Epic 1 verbatim from the Epic 1 bundle, Epics 2 to 16 from the master with `(#8)` and the edits listed below |
| `implementation-readiness.md` | Inventory, coverage, alignment, story quality, review disposition of this rewrite, risks, open decisions, prerequisites, verdict |
| `run-summary.md` | This file |

## Edits to Epics 2 to 16 Against the Master

| Story | Edit | Reason |
| --- | --- | --- |
| 2.3 | Prerequisite sentence and two criteria rewritten: the story applies the approved ADR 0023 delta to `architecture.toml` and `make.validate_configuration` reports it as the only protected change | ADR 0023 approved 2026-11-21, applied in Story 2.3 |
| 2.5, 2.6 | "not merged" read as "not applied on the branch (Story 2.3)" | One pull request: no separate merge |
| 2.5, 7.3 | Story 2.3 added to `Depends on:` | They use crates of the delta and did not depend on Story 2.3 transitively |
| 2.8 | One criterion added: the four items Story 1.1 defers (schema merge, `.data(iam_state)`, `iam` tag, `bearerAuth`) are present and pinned | The master story text omitted `.data(iam_state)` |
| 7.3 | One criterion added: the `allow.everyone.if.no.acl.found` fallback recorded by Story 1.3 | Story 1.7 names it; the master criteria did not prove it |
| 13.5 | One criterion added: manual assignment under the advisory lock with offsets in PostgreSQL when capability 8 failed | Story 1.7 names it; the master criteria did not prove it |

## Counts

| Item | Count |
| --- | --- |
| Epics | 16 |
| Stories | 127 |
| Given/When/Then criteria | 863 (master 860, plus one each in Stories 2.8, 7.3 and 13.5) |
| Functional requirements | 85 (FR-1 to FR-90; FR-16, FR-40, FR-41, FR-42 and FR-44 retired in the master) |
| Non-functional requirements | 37 (NFR-1 to NFR-44; NFR-10 to NFR-13, NFR-17, NFR-18 and NFR-32 retired in the master) |
| Requirement ids defined in `prd.md` and covered by a `Covers` line | 122 of 122 |
| Requirements with an "Epic 1 slice" paragraph | 19 (FR-15, FR-18, FR-46, FR-60, FR-71, FR-72, FR-73, NFR-1, NFR-2, NFR-3, NFR-4, NFR-5, NFR-8, NFR-9, NFR-30, NFR-31, NFR-33, NFR-36, NFR-37) |
| Ids the Epic 1 bundle defined that the master lacks | 0 |
| `## Constraints` size | 3,845 bytes (limit 4,500) |
| ADRs planned | 0013 to 0031 |

## Owner Decisions (binding)

| Decision | Date | Effect on the plan |
| --- | --- | --- |
| All 16 epics ship in one pull request for issue #8 | 2026-11-22 | This bundle covers the whole plan; Story 1.1 first and alone |
| The protected allow-list change of ADR 0023 (`architecture.toml`, `architecture.md` section 3.1) is APPROVED | 2026-11-21 | Applied in Story 2.3 with `ALLOW_PROTECTED_CONFIG_EDIT=1` and the `approved-config-change` label set by a maintainer |
| Story 1.8: the push step of the mutation shard job runs `make mutation-tests-diff` | 2026-11-22 | Story 1.8 implements it |
| Story 1.8: the protected mutation-matrix resize is NOT approved | 2026-11-22 | Story 1.8 records the request in `docs/operations.md`; the 15-second suite budget stays |
| Standing instruction: do not stop to ask; take the recommended option, record it, continue | 2026-11-22 | Open decisions keep their defaults; protected changes beyond the approved ones still stop |
| `approved-config-change` is applied only for protected changes the plan covers and the owner approved | 2026-11-21 | Only the ADR 0023 change qualifies |
| Merging is allowed once CI, the FR/NFR gate and review threads are green | 2026-11-22 | Applies to the one pull request |
| Design decisions D1, D2, D3, D4, D6 (part), D7, D8, D9, D13, D14a, D14b, D15 (`handoff/design/gw-owner-decisions.md`): Kafka on Strimzi, IAM consumes `user.events.v1`, krafka with a spike first and `rdkafka` as fallback, Valkey rate limits, Loki access log, TLS in the pod, all stream types in phase 1, EKS, 1,000 rps first release, REST and GraphQL parity | 2026-11-21 | As planned in the master |

## Protected-File Changes the Plan Needs

| Change | Files | Story | Approval state |
| --- | --- | --- | --- |
| Allow-list delta of ADR 0023 (infrastructure `external` and `dev_external` additions, application dev-only `criterion`) | `architecture.toml` | 2.3 | Approved 2026-11-21; applied with the `approved-config-change` label |
| Mutation-matrix resize to 16 shards of 60 mutants | `tests/CLI/bats/ci_scripts.bats` (protected directory), with `scripts/ci/mutation-plan.sh` | 1.8 | NOT approved; request recorded only, both files unchanged |
| `rdkafka` fallback (librdkafka build change and an `openssl-sys` exception), only if Story 1.7 records a failed must-pass capability | `deny.toml` (`openssl-sys` exception), `architecture.toml` (infrastructure `external`: add `rdkafka`), build configuration (Dockerfile, librdkafka) | 1.7 outcome | NOT approved; the run stops for the owner before Epic 7 |
| A direct `tokio` dependency of `iam-infrastructure`, only if the spikes show krafka's or redis's API exposes `tokio` types | `architecture.toml` | 1.7 outcome, then 2.3 or later | NOT approved; stop for the owner |
| Advisory ignores for `krafka`, `criterion` or another new crate tree that fails `unmaintained = "all"` or an advisory | `deny.toml` | 1.2, 1.6, 2.3 or later | NOT approved; stop for the owner |
| Pingora dependency-policy exceptions (D21) | `deny.toml` | none planned | NOT approved (default: no) |

Changes the plan avoids by design (no protected file touched): Bats checks of Stories 15.3 and 15.4 use new files under `tests/CLI/bats/`; no renderer is added to `make/tool-versions.mk` (Story 15.3); the gateway e2e and smoke jobs call existing gate targets, so `make/gates.mk` stays unchanged (Story 16.6); the protected health budgets of `tests/Load/config.json.dist` stay unchanged (Story 16.6); no key is committed, so `.gitleaksignore` stays unchanged; `.cargo/mutants.toml`, `clippy.toml` and the `workspace.lints` table stay unchanged; Story 2.8 passes the ephemeral Schemathesis token by overriding `SCHEMATHESIS_FLAGS` on the `make schemathesis-validate` command line while keeping `--checks all --phases=examples,coverage`, so the workflow runs only that gate target (invariant rule (d)) and `make/gates.mk`, `scripts/check-invariants.sh` and the template Makefile stay unchanged; if that proves impossible, the story stops for the owner as an unapproved protected change.

## Assumptions

> Assumption: The service is named "VilnaCRM API Gateway" (profile `project.description`; repository `VilnaCRM-Org/api-gateway-service`); the master's product name `iam-service` describes the same product.

> Assumption: The profile `.claude/rust-sdlc.yml` resolves every `make.*` key to the target of the same name; `make.bench_spikes` (added by Story 1.6 in `make/service.mk`) and `make.bats` (existing target `bats`) are not profile keys and resolve by the same naming rule; stories pass `base_ref=main` as written while the profile and the `Makefile` default to `origin/main`.

> Assumption: The Epic 1 section is kept verbatim from the earlier Epic 1 bundle because it matches the Story 1.1 code in the working tree; it differs from the master only by the commit literal and the recorded Story 1.8 agreement.

> Assumption: Where a later story says the approved allow-list change must be "merged", it means applied on the branch by Story 2.3.

> Assumption: Each story's `make.mutation_tests_diff` with `base_ref=main` covers every change since `main`; a story whose full diff run exceeds the shard budget narrows the run to its own commits and records the base it used.

> Assumption: `deny.toml` already holds time-boxed exceptions for RUSTSEC-2026-0543 (chrono) and RUSTSEC-2026-0542 (humantime), accepted on 2026-11-21 until 2027-02-21; this plan adds no exception.

> Assumption: Host ports 8080, 8081 and 18081 are taken on the developer machine, so local runs set `APP_PORT=28081`, `STRUCTURIZR_PORT=28080` and a free `LOAD_TEST_APP_PORT`.

> Assumption: The rollback target is an `ask` rule; an unattended run records each migration story's rollback round trip as `not run (ask rule)`.

> Assumption: The tests that need Amazon EKS (Stories 16.7 and 16.8) run outside `make ci` and are recorded through `make.docs_check`; the one pull request can close without an EKS cluster, with those measurements recorded as pending where the cluster is missing.

> Assumption: The removal of the template's example context is not a story of this plan.

## Warnings

- Uncovered requirement ids: none. Every one of the 122 ids defined in `prd.md` appears in at least one story's `Covers` line.
- The pull-request mutation job runs `make mutation-tests-diff` against `main` over the whole IAM code of 127 stories; with the resize not approved its capacity stays at 8 shards of at most 150 mutants within 45 minutes each, which the full diff may exceed. The owner may need to revisit the resize request of Story 1.8 before the pull request can turn green.
- Story 1.1 C12 runs six of the seven `make ci` stages (`make.ci_cli` is absent); Bats still runs in CI and in Story 1.8.
- `docs/architecture.md` (Story 1.1) and `docs/operations.md` (Story 1.8 and later runbooks) are template-synchronised files not listed in `.templatesyncignore`; a later template sync may conflict with their IAM edits.
- Story 1.6 must add `docs/make-targets-service.md` with the `bench-spikes` row for `make.docs_check`; Story 2.8 extends it with the Schemathesis token target.
- krafka's and criterion's dependency trees are unverified against `deny.toml` (`unmaintained = "all"`); Stories 1.2 and 1.6 stop and report if no exact version passes.
- The FR/NFR gate spent four runs on pull request #7 while the plugin caps it at three per pull request; with 122 ids in one pull request each gate run is long, so evidence should be complete before the first run.

## Self-Check

Run from the repository root on 2026-11-22 with `bash /home/kravtsov/Projects/iam-service/handoff/verify.sh` (N=8, `SPECS_DIR=specs/8-iam-scaffolding-and-spikes`): no missing file, heading, constraint key or order failure; 127 stories, 127 `Depends on:` lines and 127 criteria blocks; no duplicate story id; the readiness verdict is ready with no blocking phrase; every story has Given, When and Then and depends only on earlier stories; the dry run of `stage-planning-artifacts.sh` exited 0. A traceability script confirmed that the 122 ids defined in `prd.md` equal the ids of the coverage table and of the union of the `Covers` lines, that no placeholder-issue commit literal of the master remains, and that the Epic 1 section equals the Epic 1 section of the earlier bundle.

SPECS_DIR: specs/8-iam-scaffolding-and-spikes
