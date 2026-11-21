# Run Summary: Scaffold the IAM Context and Run the Phase-0 Spikes

| Field | Value |
| --- | --- |
| Bundle directory | `specs/8-iam-scaffolding-and-spikes/` |
| Issue | `#8` "Scaffold the IAM context and run the phase-0 spikes" (VilnaCRM-Org/api-gateway-service) |
| What this bundle is | The Epic 1 slice of the master plan `specs/0-iam-authorization-service/` (seven files, 16 epics, 127 stories, placeholder issue 0) held in the `iam-service` checkout (`/home/kravtsov/Projects/iam-service/specs/0-iam-authorization-service/`) |
| Date | 2026-11-22 |
| Readiness | `Verdict: ready` in `implementation-readiness.md` |
| Self-check | Round 1 of 5: the bundle verification script (N=8) and the traceability checks passed |
| Next step | `/rs-sdlc-implement` for issue #8 |

## Why a Per-Epic Bundle

The implementation workflow implements every story of a bundle's `epics.md` in one pull request, and the FR/NFR review gate traces every requirement id defined in the bundle's `prd.md` to test evidence in that pull request. The master bundle defines 85 FRs and 37 NFRs over 127 stories, so it cannot be one pull request. This bundle therefore holds Epic 1 only and defines only the requirement ids its stories cover, each scoped to what Epic 1 can prove.

## Artifacts

| File | Content |
| --- | --- |
| `research.md` | Target-repository facts re-checked on 2026-11-22, layer rules and allow-lists, naming rules (section 2.5), datastore summary for ADR 0014 (section 5), dependency and protected-change rules (section 9), krafka capabilities and the `rdkafka` fallback (section 15), benchmark targets (section 17), owner decisions, product summary |
| `product-brief.md` | Product in brief, the problem Epic 1 solves, users, goals, scope, success criteria S1 to S8, risks |
| `prd.md` | 7 FRs and 12 NFRs with the master ids; 16 of the 19 are labelled "(Epic 1 slice)"; an "Out of scope for this feature" note naming the completing epic for each; product scope (Epic 1 in, Epics 2 to 16 out) |
| `architecture.md` | Tech Stack, Constraints (3,428 bytes), context map, crates, the policy-epoch slice per layer, wiring, data model, model changes, test strategy with the mutation budget, spike plan and decision rule, ADRs 0013, 0014, 0026, target architecture (later epics), assumptions |
| `epics.md` | Epic 1 with stories 1.1 to 1.8 copied from the master, `(#8)` commit literal, coverage table from the `Covers` lines |
| `implementation-readiness.md` | Inventory, coverage, alignment, story quality with four advisory notes, prerequisites, risks, owner decisions, verdict |
| `run-summary.md` | This file |

## Counts

| Item | Count |
| --- | --- |
| Epics | 1 |
| Stories | 8 |
| Given/When/Then criteria | 56 |
| Functional requirements | 7 (FR-15, FR-18, FR-46, FR-60, FR-71, FR-72, FR-73) |
| Non-functional requirements | 12 (NFR-1, NFR-2, NFR-3, NFR-4, NFR-5, NFR-8, NFR-9, NFR-30, NFR-31, NFR-33, NFR-36, NFR-37) |
| Requirements scoped to an Epic 1 slice | 16: FR-15, FR-18, FR-46, FR-60, FR-71, FR-72, FR-73, NFR-2, NFR-4, NFR-5, NFR-9, NFR-30, NFR-31, NFR-33, NFR-36, NFR-37 |
| Requirements delivered in full | 3: NFR-1, NFR-3, NFR-8 (restated for the crates of this feature) |
| ADRs written by this feature | 3 (0013, 0014, 0026) |
| Migrations | 1 (`create_iam_policy_epoch`) |

## Owner Decisions (binding)

| Decision | Date | Effect on this feature |
| --- | --- | --- |
| The owner APPROVED the protected allow-list change of ADR 0023 (`architecture.toml`, the delta of `architecture.md` section 3.1) | 2026-11-21 | None of the Epic 1 stories needs or applies it; it is applied in a later feature before Story 2.3 of the master plan |
| Protected files still need the `approved-config-change` label on the pull request, applied by a maintainer | 2026-11-21 | Epic 1 plans no protected-file change; if Story 1.8's resize is later approved, its pull request needs that label |
| krafka is the Kafka client with a spike first; `rdkafka` stays the fallback (D14a) | 2026-11-21 | Stories 1.2 to 1.7 |
| The gateway code lives as modules inside the `authorization/iam` crates (D19, default) | 2026-11-21 | Story 1.1, ADR 0013 |

## Assumptions

> Assumption: The service is named "VilnaCRM API Gateway" (profile `project.description`; repository `VilnaCRM-Org/api-gateway-service`).

> Assumption: `deny.toml` already holds time-boxed exceptions for RUSTSEC-2026-0543 (chrono, test-utility path of the AWS SDK) and RUSTSEC-2026-0542 (humantime), accepted on 2026-11-21 until 2027-02-21; this feature adds no exception.

> Assumption: Host ports 8080, 8081 and 18081 are taken on the developer machine, so local runs set `APP_PORT=28081` and `STRUCTURIZR_PORT=28080`. Port 18081 is also the `Makefile` default of `LOAD_TEST_APP_PORT`, so local runs of targets that start the isolated load-test stack (`make.ci_delivery`, Schemathesis, smoke load tests) also need a free `LOAD_TEST_APP_PORT` (an inference from the `Makefile`, flagged for the implementer).

> Assumption: This bundle plans Epic 1 only, derived from the master plan on 2026-11-22; story text, acceptance criteria and `Depends on:` lines are the master's, with the master's placeholder issue literal replaced by `(#8)` everywhere.

> Assumption: The profile `.claude/rust-sdlc.yml` resolves every `make.*` key to the target of the same name; `make.bench_spikes` (added by Story 1.6 in `make/service.mk`) and `make.bats` (existing target `bats`) are not profile keys and resolve by the same naming rule.

> Assumption: Stories pass `base_ref=main` as written; the profile and the `Makefile` default to `origin/main`.

> Assumption: The scaffold story exposes no public operation; the `iam` tag, the `bearerAuth` scheme and the GraphQL root merge wait for the first operation of a later feature.

> Assumption: The rollback target is an `ask` rule; an unattended run records Story 1.1's rollback round trip as `not run (ask rule)`.

> Assumption: The phase-0 outcome gates every Kafka-dependent later feature; a failed must-pass capability stops the run for an owner decision.

> Owner decision (2026-11-22, standing instruction to take the recommended option): the owner agrees to the push-step change of the mutation shard job, so Story 1.8 implements it. The protected matrix resize (`scripts/ci/mutation-plan.sh`, `tests/CLI/bats/ci_scripts.bats`) is NOT approved in this feature: the story takes the no-approval branch, leaves both files unchanged and records the request in `docs/operations.md`.

> Assumption: `make.integration_tests` reaches the compose `kafka` service through a `DEPS` assignment in the service-owned `make/service.mk`, because the template `Makefile` is not edited (`architecture.md` section 7.1).

> Assumption: The benches use `async-graphql`'s `parser` re-export; a separate parser dev-dependency is added to `crates/service` only if the re-export is insufficient.

## Warnings

- Story 1.1 C12 runs six of the seven `make ci` stages (`make.ci_cli` is absent); Bats still runs in CI and in Story 1.8.
- `docs/architecture.md` (Story 1.1) and `docs/operations.md` (Story 1.8) are template-synchronised files not listed in `.templatesyncignore`; a later template sync may conflict with their IAM edits.
- Story 1.6 must add `docs/make-targets-service.md` with the `bench-spikes` row for `make.docs_check`; the story text implies it but does not name the file.
- krafka's and criterion's dependency trees are unverified against `deny.toml` (`unmaintained = "all"`); Stories 1.2 and 1.6 stop and report if no exact version passes.

## Self-Check

Round 1 of 5, run from the repository root: the adapted bundle verification script (N=8, `SPECS_DIR=specs/8-iam-scaffolding-and-spikes`) printed only its info lines; a traceability script confirmed that the set of ids defined in `prd.md` equals the union of the stories' `Covers` lines (19 ids), that no placeholder issue literal of the master remains, that no story depends on an unknown or later story, and that Story 1.1 has `Depends on: none` and criteria C1 to C12.

SPECS_DIR: specs/8-iam-scaffolding-and-spikes
