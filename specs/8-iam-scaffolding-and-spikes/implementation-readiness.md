# Implementation Readiness: Scaffold the IAM Context and Run the Phase-0 Spikes

| Field | Value |
| --- | --- |
| Bundle | `specs/8-iam-scaffolding-and-spikes/` |
| Issue | `#8` "Scaffold the IAM context and run the phase-0 spikes" (VilnaCRM-Org/api-gateway-service) |
| Date | 2026-11-22 |
| Scope of this check | `research.md`, `product-brief.md`, `prd.md`, `architecture.md`, `epics.md` of this bundle (Epic 1 of the master plan, stories 1.1 to 1.8), checked against the target repository `api-gateway-service` |

## 1. Document Inventory

| File | Content | Status |
| --- | --- | --- |
| `research.md` | Target-repository facts re-checked on 2026-11-22, layer rules, naming, datastore summary, dependency and protected-change rules, krafka capabilities and the `rdkafka` fallback, benchmark targets, owner decisions, product summary | Current |
| `product-brief.md` | Problem, users, goals, scope, success criteria S1 to S8, risks for Epic 1 | Current |
| `prd.md` | 7 functional requirements (FR-15, FR-18, FR-46, FR-60, FR-71, FR-72, FR-73) and 12 non-functional requirements (NFR-1, 2, 3, 4, 5, 8, 9, 30, 31, 33, 36, 37), master ids kept, each partial one labelled "(Epic 1 slice)"; an out-of-scope note that defines no id; product scope | Current |
| `architecture.md` | `## Tech Stack`, `## Constraints` (part (a) before part (b), under 4,500 bytes), context map, crates, the policy-epoch slice per layer, composition-root wiring, data model, model changes, test strategy and mutation budget, spike plan and decision rule, ADR list, target architecture (later epics, not part of this feature), assumptions | Current |
| `epics.md` | 1 epic, 8 stories copied from the master with their criteria and `Depends on:` lines, commit literal `(#8)`, coverage table from the `Covers` lines | Current |
| `implementation-readiness.md` | This file | Current |
| `run-summary.md` | What the bundle is, counts, assumptions, owner decisions, next step | Current |

## 2. Requirement Coverage

| Check | Result |
| --- | --- |
| Every FR defined in `prd.md` is named by a story's `Covers` line | Yes, 7 of 7: FR-15 (1.6), FR-18 (1.5), FR-46 (1.4), FR-60 (1.6), FR-71 (1.2), FR-72 (1.3), FR-73 (1.3) |
| Every NFR defined in `prd.md` is named by a story's `Covers` line | Yes, 12 of 12: NFR-1, 3, 4, 5, 8, 31 (1.1); NFR-2 (1.1, 1.8); NFR-9 (1.1, 1.2); NFR-30 (1.1, 1.7); NFR-33 (1.6); NFR-36 (1.3); NFR-37 (1.5) |
| Every id named by a `Covers` line is defined in `prd.md` | Yes; the union of the eight `Covers` lines equals the 19 ids defined |
| Every requirement is evidenced by the stories of this feature | Yes: each partial requirement is scoped to its Epic 1 slice, and each slice statement restates what the covering story's criteria prove (integration tests, benches through `make.bench_spikes`, recorded results through `make.docs_check`) |
| Every story traces to at least one requirement | Yes, all eight |
| The brief's success criteria map to requirements | S1 to NFR-1/3/4/5/31; S2 to NFR-8; S3 to FR-18/46/71/72/73; S4 to NFR-30; S5 to FR-15/60, NFR-33; S6 to NFR-37; S7 to NFR-2; S8 to NFR-1 to NFR-5 |

## 3. Architecture Alignment

| Check | Result |
| --- | --- |
| `## Tech Stack` names only the Rust toolchain and crates | Yes |
| `## Constraints` holds part (a) with `(#8)` and `story N.M`, then part (b) with the ten keys and both dispatch branches, no fenced block | Yes |
| Story-1 rule | Applied: no member path starts with `crates/authorization/iam/`, so Story 1.1 is "Scaffold authorization/iam" with criteria C1 to C12 and `Depends on: none` |
| Every component of Story 1.1 is placed in a layer | Yes, sections 3 to 7 and 13 of `architecture.md` |
| Spike crates need no allow-list change | Yes: dev-dependencies of `crates/service` (`external = ["*"]`) |
| Section citations of `epics.md` (`architecture.md` sections 3.1, 5.6, 19, 20) resolve | Yes, the master numbers are kept |
| Every `make.*` key a story names exists | Yes, with two notes in section 4 |

## 4. Story Quality

| Check | Result |
| --- | --- |
| Format | 8 `### Story 1.M:` headings, 8 `**Acceptance Criteria:**` lines, 8 `**Depends on:**` lines, unique ids, every criterion in Given/When/Then form naming a `make.*` gate |
| Dependency order | No forward reference and no unknown id: 1.1 none; 1.2 on 1.1; 1.3, 1.4, 1.5, 1.6 and 1.8 on 1.1, 1.2; 1.7 on 1.1 to 1.6 |
| Make keys versus the target repository | Every key maps to an existing target in the `Makefile` and `docs/make-targets.md`, except `make.bench_spikes`, which Story 1.6 adds to `make/service.mk` |
| Note A (advisory) | `make.bench_spikes` and `make.bats` are not keys of `.claude/rust-sdlc.yml`; `bats` exists as a target (gate G16), `bench-spikes` is created by Story 1.6. The naming rule of `epics.md` resolves both |
| Note B (advisory) | Story 1.1 C12 runs six of the seven `make ci` stages; `make.ci_cli` (Bats) is not in its list. Bats still runs in the CI workflow and in Story 1.8 (`make.bats`) |
| Note C (advisory) | Story 1.6 must document `bench-spikes` in `docs/make-targets-service.md` for `make.docs_check`, and Story 1.2 must make `make.integration_tests` start the compose `kafka` service (through `make/service.mk`, see `architecture.md` section 7.1); the story texts leave both implicit |
| Note D (advisory) | Story 1.8 mentions recording the resize request "next to ADR 0023"; ADR 0023 is written in a later feature, so the request goes to the protected-change list of `docs/operations.md`, as its own criterion states |

The notes are advisory: each criterion is satisfiable as written, and none needs a story change before implementation starts.

## 5. Prerequisites

| Prerequisite | Gates | Status |
| --- | --- | --- |
| The owner-approved allow-list change of ADR 0023 | Not needed by this feature (later feature, before Story 2.3) | Approved 2026-11-21; not applied here |
| Owner agreement to the push-step change of the mutation shard job | Story 1.8 | Recorded on 2026-11-22: agreed |
| Owner approval of the protected mutation-matrix resize (`tests/CLI/bats/ci_scripts.bats`) and the `approved-config-change` label applied by a maintainer | Story 1.8 resize branch only | Not approved; the criterion for the unapproved case applies |
| Docker with Compose on the developer machine and the CI runner | Stories 1.2 to 1.5 (compose broker) | Available per the template |
| Free local ports: `APP_PORT=28081`, `STRUCTURIZR_PORT=28080`, a free `LOAD_TEST_APP_PORT` | Local runs of the delivery stage and `make start` | Host ports 8080, 8081 and 18081 are taken |

## 6. Risks

| Risk | Effect | Mitigation in the plan |
| --- | --- | --- |
| A must-pass krafka capability fails | Kafka-dependent features cannot start | Story 1.7 records it and the run stops for an owner decision; `rdkafka` fallback documented |
| krafka or criterion pulls a crate that fails `deny.toml` (`unmaintained = "all"`, licence list, `openssl-sys` ban) | `make.check_security` fails in Story 1.2 or 1.6 | Choose an exact version that passes (krafka with `default-features = false` and a rustls feature, as the organisation's precedent does) or stop and report; no `deny.toml` change is planned |
| The spike suite pushes `crates/service` over the 15-second budget | Mutation shards exceed their limit | `test-broker` first; spike modules removed in Story 1.7; fallback of `architecture.md` section 19 |
| Template sync overwrites `docs/architecture.md` (Story 1.1) or `docs/operations.md` (Story 1.8), which `.templatesyncignore` does not list | Documentation edits lost or conflicting in a sync pull request | Reviewer checks the sync pull request; adding the files to `.templatesyncignore` is a follow-up decision for the owner |
| krafka's public API exposes `tokio` types | A direct `tokio` dependency in infrastructure would need a further protected change | ADR 0026 records it; requested from the owner before the adapter epics |

## 7. Open Owner Decisions

None blocks the start of this feature.

1. **Story 1.8 CI change:** agreed on 2026-11-22: pushes run `make mutation-tests-diff` instead of the whole-workspace mutation run.
2. **Mutation-matrix resize:** Do you approve the protected change to 16 shards of 60 mutants (it alters `tests/CLI/bats/ci_scripts.bats`)? Default: not approved; recorded as a request.
3. **Kafka client:** After Story 1.7, accept krafka, or choose the `rdkafka` fallback or value framing with strict mode if a must-pass capability failed.

## 8. Verdict

Every cross-check in sections 2 to 4 passes. The notes of section 4 are advisory and the items of sections 5 and 7 are owner decisions or prerequisites that gate Story 1.8 only; a story that reaches an unmet prerequisite stops and reports. The feature may start with Story 1.1.

Verdict: ready
