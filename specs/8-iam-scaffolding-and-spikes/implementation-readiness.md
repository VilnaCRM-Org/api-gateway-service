# Implementation Readiness: IAM API Gateway and Authorization Service

| Field | Value |
| --- | --- |
| Bundle | `specs/8-iam-scaffolding-and-spikes/` |
| Issue | `#8` "Scaffold the IAM context and run the phase-0 spikes" (VilnaCRM-Org/api-gateway-service); one pull request delivers all 16 epics (owner decision, 2026-11-22) |
| Date | 2026-11-22 |
| Design assessed | IAM is the API gateway: `iam-gateway` (data plane) and `iam-control` (control plane) from one image on AWS EKS, an in-process policy snapshot replicated from one ordered Kafka topic, a freshness proof that fails closed, Sync-Fence for revocation-class writes |
| Scope of this check | `research.md`, `product-brief.md`, `prd.md`, `architecture.md`, `epics.md` of this bundle, all 16 epics, after the rewrite from the Epic 1 bundle to the whole plan |

This file cross-checks the brief, the PRD, the architecture and the epics of the bundle for issue #8. The owner decided on 2026-11-22 that all sixteen epics ship in one pull request, so this bundle replaces the earlier Epic 1 bundle of this directory: it carries the whole master plan (`specs/0-iam-authorization-service/`, iam-service checkout, 2026-11-21, readiness verdict ready after its fourth review round) with the Epic 1 section of the earlier bundle kept verbatim, because that text matches the Story 1.1 code already in the working tree.

## 1. Document Inventory

| File | Size (bytes) | Content | Status |
| --- | --- | --- | --- |
| `research.md` | about 141,000 | Target-repository facts re-checked on 2026-11-22 and Story 1.1 in the working tree (section 1); the Miro board, surrounding services, datastore, gateway, Kafka, cache, capacity and Kubernetes research; owner decisions (D1 to D15 decided part, ADR 0023, Story 1.8, one pull request); open decisions with defaults | Current |
| `product-brief.md` | about 23,000 | Product, current state of the target repository, delivery in one pull request, problem, users, goals, scope, success criteria S1 to S15, risks, open decisions | Current |
| `prd.md` | about 165,000 | 85 functional requirements (FR-1 to FR-90 with retired gaps) and 37 non-functional requirements (NFR-1 to NFR-44 with retired gaps), nineteen of them with an "Epic 1 slice" paragraph; product scope, API surface summary (48 capabilities on both interfaces), event catalogue, traceability to the owner's scope | Current |
| `architecture.md` | about 264,000 | `## Tech Stack`, `## Constraints` (3,845 bytes, part (a) before part (b)), topology, crates, the allow-list delta (section 3.1, owner-approved, applied in Story 2.3), domain, application, infrastructure, composition root with the Epic 1 wiring in `api-gateway-service` (section 7.5), request path, replication and freshness, Kafka scope, rate limiting, logs, data model, API surface, events, security, Kubernetes, test strategy, performance plan, ADRs 0013 to 0031, open items | Current |
| `epics.md` | about 427,000 | 16 epics, 127 stories, 863 Given/When/Then criteria, one `Depends on:` line per story, the requirement coverage table built from the `Covers` lines | Current |
| `implementation-readiness.md` | this file | Cross-checks, review disposition, risks, open decisions, prerequisites, verdict | Current |
| `run-summary.md` | about 13,000 | The one-pull-request decision, counts, owner decisions, protected-file changes with their approval state, assumptions, warnings, self-check | Current |

## 2. Requirement Coverage

| Check | Result |
| --- | --- |
| Every FR of `prd.md` is covered by at least one story | Yes: 85 of 85 FRs appear in a `Covers` line |
| Every NFR of `prd.md` is covered by at least one story | Yes: 37 of 37 NFRs; the Epic 1 bundle defined no id that the master lacks |
| Every story traces to at least one requirement | Yes: 127 of 127 stories carry exactly one `Covers` line |
| Coverage table in `epics.md` matches the `Covers` lines | Yes: regenerated from the `Covers` lines of the 127 stories on 2026-11-22; the set of ids in the table equals the set of ids defined in `prd.md` (122) |
| Epic 1 slices stay consistent with the whole requirements | Yes: each "Epic 1 slice" paragraph of `prd.md` (FR-15, FR-18, FR-46, FR-60, FR-71, FR-72, FR-73, NFR-1, NFR-2, NFR-3, NFR-4, NFR-5, NFR-8, NFR-9, NFR-30, NFR-31, NFR-33, NFR-36, NFR-37) states what Stories 1.1 to 1.8 prove; the full requirement above it is completed by the later stories that its coverage row lists |
| Brief success criteria trace to requirements | Yes, unchanged from the master: S2 to NFR-33, S3 and S4 to NFR-34, S5 to NFR-35, S6 to NFR-19, S7 to NFR-36, S8 to NFR-15, S9 to FR-75 and FR-76, S10 to NFR-23, S11 to NFR-24, S12 to NFR-20, S13 to FR-1, S14 to FR-61 and FR-62, S15 to FR-65 and NFR-42 |
| REST and GraphQL parity | Yes: each of the 48 rows of the API Surface Summary names a REST operation and a GraphQL operation served by one handler |
| Retired requirement ids | FR-16, FR-40, FR-41, FR-42, FR-44, NFR-10, NFR-11, NFR-12, NFR-13, NFR-17, NFR-18 and NFR-32 are retired in the master; no story or requirement of this bundle references them as active |

## 3. Architecture Alignment

| Check | Result |
| --- | --- |
| `## Tech Stack` names only the toolchain and crates | Yes |
| `## Constraints` holds part (a) with `(#8)` and `story N.M` before part (b) with the ten `make.*` keys, at most 4,500 bytes | Yes: 3,845 bytes measured as the bundle verification script measures it |
| Scope line of the constraints | All 16 epics in one pull request for issue #8, Story 1.1 first and alone |
| Protected allow-list delta is identical in `research.md` section 9, `prd.md` NFR-6 and `architecture.md` section 3.1 | Yes, and all three now describe it as approved by the owner on 2026-11-21 and applied in Story 2.3 with the `approved-config-change` label |
| Stories that use the delta cannot start before Story 2.3 | Yes: Stories 2.5 and 7.3 gained Story 2.3 in their `Depends on:` lines; every other story that uses a crate of the delta depends on Story 2.3 transitively (checked over the dependency graph: the stories outside that closure are domain-only or use standard collections, plus Story 4.6, whose infrastructure fallback is stated to run after Story 2.3) |
| Story 1.1 deferrals land in a later story's criteria | Yes: the merge of `IamQuery` and `IamMutation`, the `.data(iam_state)` call, the `iam` tag and the `bearerAuth` scheme are criteria of Story 2.8 (one criterion added for `.data(iam_state)`, which the master story text omitted) |
| Story 1.7 fallbacks land in later stories' criteria | Yes: the relay-epoch-only branch for capability 7 is a criterion of Story 7.4; the `allow.everyone.if.no.acl.found` fallback recorded by Story 1.3 is now a criterion of Story 7.3; the manual-assignment branch for capability 8 is now a criterion of Story 13.5 |
| Decisions fail closed | Yes, unchanged from the master: stale proof, incomplete bootstrap, fence, gap, digest or derived-state mismatch give 503 or deny; an empty GraphQL coordinate set is a denial; persisted-query envelopes are refused |
| Guarantees G1 to G9 numbered alike in `research.md` section 15.5 and `architecture.md` section 9.6 | Yes |
| Network isolation, Kafka ACLs, data model and names agree between files | Yes, unchanged from the master's fourth-round check |
| Epic 1 wiring matches the working tree | Yes: `architecture.md` section 7.5 lists the files Story 1.1 changed (`Cargo.toml`, `crates/service/Cargo.toml`, `bootstrap.rs`, the three `Adapters { .. }` literals, `http.rs`, `openapi.rs`) and leaves `graphql/schema.rs` unchanged until Story 2.8 |
| Mutation gate is attainable for loop-heavy code | Yes, as planned: pure step functions with branch-free shells and bounded waits, the mutation workflow starts Kafka, Valkey and Loki, crate integration suites within 15 seconds (the 30-second budget needs the resize, which is not approved), the spike modules removed in Story 1.7, push runs changed to diff runs in Story 1.8; one-pull-request effect in section 6 |

## 4. Story Quality

| Check | Result |
| --- | --- |
| Format | Every story has `### Story N.M: Title`, a user-story description, one `Covers` line, an exact `**Acceptance Criteria:**` line, Given/When/Then criteria and one `**Depends on:**` line; ids are unique and numbered in order |
| Story-1 rule | Story 1.1 scaffolds `authorization/iam` with criteria C1 to C12 and `Depends on: none`; every other story lists 1.1 |
| Dependency order | No story depends on a later story or an unknown id (checked by the bundle verification script) |
| Every criterion names its proving gate | Yes: 863 of 863 criteria name a `make.*` key; criteria of Stories 16.7 and 16.8 run outside `make ci` and are recorded through `make.docs_check` |
| Story size | Unchanged from the master: Stories 7.4 and 10.8 are the largest (11 criteria each) and stay single stories because their parts share one adapter |
| Migration stories | Each names `make.create_migration` for its reversible pair; Story 1.1's migration already exists in the working tree |
| Intermediate states | Each intermediate state (for example the 502 placeholder forwarder between Stories 10.2 and 10.3, IAM operations without IAM key checks until Stories 6.11 and 6.12) is stated; with one pull request none of them reaches `main` |
| Shared files | ADR 0019 is created by Story 2.2 and extended by Stories 14.2 and 14.5 in sequence; synchronised files go into `.templatesyncignore` in the story that first changes them, proven by the seam check of Story 1.2; Bats checks of Stories 15.3 and 15.4 use new files, so no file under the protected `tests/CLI/bats/` that exists on `main` changes |

## 5. Review Disposition

The master plan closed its fourth review round with every blocker and major finding applied or recorded with a reason (master readiness section 5). This rewrite raised the following items, each applied:

| Item | Disposition |
| --- | --- |
| The master treated ADR 0023 as an external prerequisite awaiting approval, while the owner approved it and placed it in Story 2.3 | Applied: Story 2.3 applies the delta (prerequisite sentence and two criteria rewritten), Stories 2.5 and 2.6 read "not applied on the branch (Story 2.3)", and the research, PRD, architecture and brief describe the approval |
| Stories 2.5 and 7.3 could be dispatched before Story 2.3 although they use crates of the delta | Applied: Story 2.3 added to their `Depends on:` lines |
| Story 1.1 defers `.data(iam_state)` to Story 2.8, whose criteria did not name it | Applied: one criterion added to Story 2.8 |
| Story 1.7 names fallbacks for Stories 7.3 and 13.5 that their criteria did not prove | Applied: one criterion added to each |
| The Story 1.8 owner decision differed between the master (open) and the Epic 1 bundle (push step agreed, resize not approved) | Applied: the Epic 1 bundle text is kept and the decision is recorded in every file |
| One pull request makes each story's diff mutation run grow with the branch | Applied as an assumption in `epics.md` and a risk below: a story narrows its diff run to its own commits when the full diff exceeds the shard budget, and records the base it used |

## 6. Risks

| Risk | Effect | Mitigation in the plan |
| --- | --- | --- |
| krafka lacks a must-pass capability (headers on tombstones, no-group assign, leader epochs, transactions, SCRAM with a custom CA) | The freshness guarantee cannot be declared | Phase-0 spikes 1.2 to 1.6 and the decision record of Story 1.7 run before any Kafka code; the run stops for the owner before Epic 7; `rdkafka` needs an owner-approved build change and `openssl-sys` exception, which is not approved |
| The replica-quorum argument behind G4 fails test T15 | Bounded staleness is conditional | G4 and G8 are labelled conditional until Story 1.3 and test T15; liveness ticks (D17) or the strict mode are the fallbacks |
| One pull request carries 127 stories | A long-lived branch, a large review, and a pull-request mutation diff that covers the whole IAM code | Stories close one by one on their own gate sets; diff runs narrowed to a story's own commits when needed; the pull-request-level mutation job may exceed the 8-shard capacity, recorded in `run-summary.md` warnings for the owner |
| A crate of the approved delta fails `make.check_security` | Story 2.3 or a later story cannot use it | The story stops and reports; the composition-root fallback behind the same ports is recorded in ADR 0023 |
| A story needs a protected change beyond ADR 0023 (for example a `deny.toml` exception) | The story cannot close | It stops and reports to the owner; no such change is approved |
| Latency or capacity targets are missed | Release delayed | All figures are targets or estimates; Story 16.7 measures them on EKS; the fallback is profiling the hyper pipeline |
| User service does not publish its events to Kafka | Revocations from User service wait for token expiry (at most 900 seconds) | Operator revocations and cut-offs work without it; NFR-19 states the bound honestly |
| The 15-second suite budget proves too tight for PostgreSQL- and broker-backed suites | Stories stop for an owner decision | Most broker tests on `test-broker`; split the story; the resize request of Story 1.8 stays open with the owner |
| Running Kafka on Strimzi without prior Kafka operations experience | Operational load | Strimzi resources, Bats invariants, runbooks in Story 15.5 |

## 7. Open Owner Decisions

Each has a default that the plan uses until the owner answers, following the owner's standing instruction to take the recommended option and record it. None blocks the start of the pull request.

1. **Story 1.8 resize:** approve the protected resize of the mutation matrix to 16 shards of 60 mutants (it changes `tests/CLI/bats/ci_scripts.bats`)? Default: not approved; the request is recorded in `docs/operations.md` and the 15-second budget applies.
2. **D27:** keep peer-relative readiness, the peer cross-check and zone-aware upstream selection? Default: keep them.
3. **D28:** calls between services through the gateway's east-west listener (FR-90)? Default: yes.
4. **D5:** fence anonymous routes during a Kafka outage longer than `T_hard`? Default: fence.
5. **D6 (rest):** real cardinalities and traffic shape? Default: 2 GiB pods and a 200,000-entry token memo.
6. **D9 (WAF), D10, D11, D12, D15 (rest), D16 to D26:** defaults as stated in `research.md` section 20.
7. **Governance items:** separate owner and runtime database roles; an external pipeline that keeps the audit anchors; the log-retention basis; the follow-up issue that removes the template's example context.

Decided since the master readiness check: ADR 0023 approved (2026-11-21, applied in Story 2.3); the Story 1.8 push-step change agreed (2026-11-22); all 16 epics in one pull request (2026-11-22).

## 8. Prerequisites

| Prerequisite | Gates | Status |
| --- | --- | --- |
| Story 1.1 committed first, alone | Every other story | Code in the working tree, uncommitted |
| The owner-approved allow-list change (ADR 0023) applied with the `approved-config-change` label set by a maintainer | Story 2.3 and every story that uses a crate of the delta | Approved 2026-11-21; applied in Story 2.3 |
| Phase-0 spikes 1.2 to 1.6 and the krafka decision of Story 1.7 | Epic 7 onward, encoded in the `Depends on:` lines | Planned as Epic 1 |
| An EKS cluster with the AWS Load Balancer Controller, cert-manager, Strimzi, Valkey, Loki and Grafana Alloy | Stories 16.7 and 16.8 (outside `make ci`), and production | Not available yet; those criteria are recorded through `make.docs_check` |
| User service publishes its four session and user events to `user.events.v1` | FR-18 and NFR-19 end to end in production | Not available (SQS only today); compose tests produce the events |
| Production minting of `ROLE_SERVICE` tokens with the IAM caller audience | FR-3 and FR-90 in production | Needs a User service change |
| Notification service tails `iam.events.v1` | FR-48 consumer side | Outside this repository |

## 9. Verdict

Every cross-check in sections 2 to 4 passes, the items of section 5 are applied, and the bundle verification script reports no failure. The open decisions of section 7 have recorded defaults, and the prerequisites of section 8 gate only the named stories; a story that reaches an unmet prerequisite or a protected change that is not approved stops and reports. The pull request for issue #8 may start with Story 1.1.

Verdict: ready
