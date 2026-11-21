# Product Brief: Scaffold the IAM Context and Run the Phase-0 Spikes

| Field | Value |
| --- | --- |
| Bundle | `specs/8-iam-scaffolding-and-spikes/` |
| Issue | `#8` "Scaffold the IAM context and run the phase-0 spikes" (VilnaCRM-Org/api-gateway-service) |
| Date | 2026-11-22 |
| Source of scope | Epic 1 of the master plan `specs/0-iam-authorization-service/` (iam-service checkout, 2026-11-21), which follows the owner's decisions on the Miro C4 board and of 2026-11-21 (IAM is the API gateway; Kafka carries policy updates; krafka with a spike first, D14a) |

## Product (the whole plan, in brief)

The VilnaCRM API Gateway becomes VilnaCRM's single entry point with identity and access management built in. For every request it terminates TLS, verifies the User service token offline, decides from its own in-memory policy snapshot whether the caller may use the requested REST operation or GraphQL fields, and proxies the request to the owning service. A control plane (`iam-control`) owns PostgreSQL, serves the management API over REST and GraphQL with parity, and replicates policy to every gateway pod through one ordered Kafka topic; a pod allows only while it can prove its snapshot is fresh. Authentication stays in User service. The full plan has sixteen epics; this brief covers the first.

## Problem (for this feature)

The repository is a fresh template copy with no IAM code, and the gateway design rests on an unproven dependency:

- Every later epic adds behaviour to the `authorization/iam` bounded context, which does not exist yet. Without a scaffolded, gate-green context and its first persisted table (the policy epoch, whose row lock will order every policy change), no later story can start.
- The replication and freshness design depends on krafka, a pure-Rust, pre-1.0, single-author Kafka client that breaks in minor releases. Twelve capabilities the design relies on (headers on tombstones, group-less `read_committed` tails, leader epochs in metadata and `ListOffsets`, configuration and ACL reads, idempotent and transactional producing, consumer groups, SCRAM over TLS with a custom CA, fault injection, read rate) are unverified. The fallback, `rdkafka`, needs an owner-approved build change and an `openssl-sys` exception, so the owner must learn of a failure before code depends on the client.
- The latency estimates of the gateway have no measured reference for the two costliest per-request operations, RS256 verification and GraphQL parsing.
- Broker-backed integration suites rerun for every mutant and threaten the 45-minute mutation-shard limit as the gateway grows.

## Users

| User | What they need from this feature |
| --- | --- |
| **The IAM team (implementers of Epics 2 to 16)** | A scaffolded context that passes every gate, a migration and repository pattern to copy, and verified ground under the Kafka design |
| **The owner** | A recorded, evidence-based Kafka client decision (ADR 0026) before any Kafka-dependent work starts, and a clear request for any protected change |
| **Operators and reviewers** | Spike results labelled as host measurements, no secrets committed, and a mutation gate that stays attainable |

## Goals

1. **A gate-green bounded context.** `authorization/iam` exists with its three crates, the policy-epoch slice, the composition-root wiring, the architecture model and the documentation, and every repository bar holds.
2. **Verified Kafka ground.** Every krafka capability the later replication and freshness design needs is proven or recorded as failed, and the client decision is recorded with its fallback rule.
3. **A first measured reference.** RS256 verification and GraphQL parsing are measured on a known host, labelled as such.
4. **An attainable mutation gate.** The integration-suite budget is stated and measured, the spike modules leave once recorded, and pushes run diff mutation runs with the owner's agreement.
5. **Template conformity.** No protected file changes; seam files are added to `.templatesyncignore` when first changed.

## Scope

### In scope

The eight stories of Epic 1: scaffold `authorization/iam` (1.1); spikes for the group-less tail (1.2), metadata, leader epochs and configuration reads (1.3), idempotent and transactional producing (1.4), consumer groups, SCRAM over TLS and read rate (1.5); token-verify and GraphQL parser benchmarks (1.6); the phase-0 outcome and Kafka client decision (1.7); fitting the mutation gate (1.8).

### Out of scope

- Epics 2 to 16 of the master plan (policy core and token authentication, roles, specifications, permission catalogue, decision core, replication, gateway management API, gateway runtime, request path, streams, rate limiting, revocations and Sync-Fence, access log, Kubernetes, hardening and benchmarks).
- Applying the owner-approved allow-list change of ADR 0023 (a later feature).
- Any public IAM operation, authentication middleware or contract change.
- The removal of the template's example context; every platform prerequisite (EKS, Strimzi, Valkey, Loki).

## Success Criteria

| # | Criterion | Measure | Goal |
| --- | --- | --- | --- |
| S1 | The context is scaffolded and wired | Checklist C1 to C12 of Story 1.1 done; every `make ci` stage it runs passes; 0 protected files changed | 1, 5 |
| S2 | The policy epoch is persisted correctly | `iam_policy_epoch` with its seeded row, reversible migration and current `.sqlx/` metadata; repository integration tests pass | 1 |
| S3 | Every krafka capability has an outcome | `docs/spikes/phase-0.md` records pass or fail for capabilities 1 to 12 with the krafka version; each proven capability has an integration test | 2 |
| S4 | The client decision is recorded | ADR 0026 accepted (every must-pass capability passed) or proposed with the owner's options (the run stops) | 2 |
| S5 | Benchmarks give a reference, not a gate | Median and p99 for RS256 verify (one and three keys) and parsing (1, 5, 8, 64 KiB), with the CPU model; no key committed | 3 |
| S6 | Read rate measured | Group-less read rate of a 200 MB topic recorded next to the 100 MB/s target as a compose-host figure | 3 |
| S7 | Mutation gate attainable | `crates/service` integration suite within 15 s after Story 1.7 (measured); mutation workflow starts `kafka`; push diff runs or a recorded stop-and-report | 4 |
| S8 | Repository bars | 100% line and function coverage, zero surviving mutants on changed code, complexity, lint, architecture, contract, security and documentation gates green | 1, 5 |

## Risks

| Risk | Effect | Handling |
| --- | --- | --- |
| A must-pass krafka capability fails | The freshness guarantee cannot be declared; Kafka-dependent features cannot start | Story 1.7 stops the run for an owner choice: `rdkafka` (build change and exception) or value framing with strict mode |
| Spike suites push `crates/service` over the 15-second budget | Mutation shards approach 45 minutes | `test-broker` first, compose broker only for real log semantics; spike modules removed in Story 1.7 |
| The owner agreed to the Story 1.8 CI change on 2026-11-22; the matrix resize is not approved | Story 1.8 implements the push-step change and records the resize request | The 15-second budget and its fallback stay in force |
| krafka's or criterion's dependency tree meets an advisory or licence rule of `deny.toml` | `make.check_security` fails in Stories 1.2 or 1.6 | Pick the exact version that passes, or stop and report; no `deny.toml` edit is planned |
| Template sync overwrites seam files | Lost wiring | `.templatesyncignore` entries and the seam-check test |
