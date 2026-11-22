# 0026. krafka as the Kafka client: phase-0 spike results and rdkafka fallback

Status: accepted. Every must-pass capability (1 to 6 and 9) passed; Epic 7 may start.

Planning decisions: section 20.4 of `specs/8-iam-scaffolding-and-spikes/architecture.md` (phase-0 spikes and decision rules) and requirement NFR-30 of its `prd.md`. The detailed results, findings and procedures are in [the phase-0 spikes](../spikes/phase-0.md).

## Context

The replication design of IAM (the fenced relay of ADR 0017, the tail without a consumer group, the freshness proof and the Kafka configuration gates) rests on Kafka client capabilities that no gateway code may assume before they are shown. The template bans `openssl-sys` (`deny.toml`), which rules out `rdkafka` with TLS, so the pure-Rust client `krafka` was checked first. Stories 1.2 to 1.5 exercised it against the compose broker (`apache/kafka` 4.3.2, KRaft) and against krafka's in-process `test-broker`, and the serialized verify step of the implementation round ran those tests through `make integration-tests` on 2026-11-22 (261 tests passed, 2 ignored by design: the 3-broker leader-change observation and the bootstrap read rate). Story 1.6 added the token-verify and GraphQL parser benches, which do not bear on the client choice.

## Decision

`krafka` 0.32.0, pinned exactly, without default features and with `rustls-aws-lc-rs`, is the Kafka client of IAM. The spike stories carried it as a dev-dependency of `crates/service` only; Story 1.7 removed it from the workspace together with the spike modules, and the first story of Epic 7 that needs it adds it again to the infrastructure layer, where ADR 0023 already allows it.

| Capability | Story | Must pass | Outcome |
| --- | --- | --- | --- |
| (1) Headers on null-value records | 1.2 | yes | pass: every header of a tombstone comes back byte-identical, the value stays null |
| (2) No-group `assign`, `read_committed` and the last stable offset, out-of-range detection, reseek after reconnect | 1.2 | yes | pass: the tail stops at the last stable offset, an out-of-range position fails the poll without a reset, a reseek after a dropped connection reads every record once |
| (3) Metadata to a chosen broker with the leader epoch | 1.3 | yes | pass, with a limit: krafka cannot address a Metadata request to a broker the caller picks, so the replica-quorum check uses one client seeded with each broker; the 3-broker compose observation is not a gate and was not run |
| (4) `ListOffsets` with the current leader epoch and the KIP-207/KIP-320 errors | 1.3 | yes | pass: `FENCED_LEADER_EPOCH`, `UNKNOWN_LEADER_EPOCH` and `OFFSET_NOT_AVAILABLE` are distinct typed errors on the consumer path |
| (5) `DescribeConfigs` and `DescribeAcls` | 1.3 | yes | pass: every topic value and the ACLs are readable; `allow.everyone.if.no.acl.found` is not returned as a value, so the fallback below applies |
| (6) Idempotent producing with `acks=all`, one request in flight, explicit partition, headers | 1.4 | yes | pass: 10,000 records under injected faults land exactly once and in order with lz4 batches |
| (7) Transactional producer `iam-relay` with epoch fencing | 1.4 | no | pass: a second `iam-relay` fences the first, aborted and timed-out transactions stay invisible to `read_committed` readers |
| (8) Consumer group with commit after processing and rebalance | 1.5 | no | pass: with the KIP-848 protocol and auto-commit off, uncommitted records move to the remaining member once each |
| (9) SASL SCRAM-SHA-512 over TLS with a custom CA | 1.5 | yes | pass: a wrong password and an untrusted CA fail with distinguishable typed errors |
| (10) Fault injection through `test-broker` | 1.2 | no | pass, with a limit: `NOT_LEADER_OR_FOLLOWER` and timeouts on `Fetch` are retried inside krafka and reach the reader only on the `ListOffsets` watermark lookup |
| (11) Bootstrap read rate (target at least 100 MB/s, compose host only) | 1.5 | no | recorded only, not a gate: not measured on a recorded host before the spike modules were removed |
| (12) Follower fetching (KIP-392) | 1.5 | no | recorded only: available in the client API (`client_rack`), not exercised |

The spike tests needed no `tokio` type to call krafka, so no direct `tokio` dependency of the infrastructure layer is requested from them.

### Fallback rule

The rule of section 20.4 stays the decision rule for any later change of the client or of its version:

- If capability 1, 2, 3, 4, 5, 6 or 9 fails, the freshness guarantee is not declared, this record stays proposed, and the run stops before Epic 7 for an owner choice between the `rdkafka` fallback (a build change and an `openssl-sys` exception) and value framing with strict mode.
- If capability 7 fails, the relay-epoch header is the only relay fencing, and Story 7.4 implements the relay-epoch fencing only.
- If `DescribeConfigs` does not return `allow.everyone.if.no.acl.found`, Story 7.3 uses the fallback recorded by Story 1.3: a negative probe with a principal that holds no ACL on the state topic, which must be refused with `TOPIC_AUTHORIZATION_FAILED`, plus the static check of the Strimzi `Kafka` resource in Story 15.4.
- If capability 8 fails, `iam-control` consumes `user.events.v1` by manual assignment under the relay's advisory lock and stores offsets in PostgreSQL in the revocation transaction, and Story 13.5 implements that manual-assignment fallback.

### Outcome of the rule for this release

| Rule | Applies | Consequence |
| --- | --- | --- |
| A must-pass capability failed | no | Epic 7 may start; the freshness guarantee can be declared |
| Capability 7 failed | no | Story 7.4 may use transactional fencing of `iam-relay` together with the relay-epoch header of ADR 0017 |
| `allow.everyone.if.no.acl.found` not returned | yes | Story 7.3 uses the negative probe and the static Strimzi check |
| Capability 8 failed | no | Story 13.5 uses the consumer group (KIP-848 protocol, commit after the revocation transaction) |

| Option | Outcome | Reason |
| --- | --- | --- |
| `krafka` 0.32.0 with rustls | Chosen | Every must-pass capability passed; pure Rust, no `openssl-sys`, typed errors and an in-process test broker |
| `rdkafka` | Fallback | Needs a C toolchain build change and an `openssl-sys` exception from the owner; not needed while krafka passes |
| Value framing with strict mode | Fallback | Only if headers on null values or the freshness capabilities fail |

## Consequences

The findings of the phase-0 spikes bind the Kafka stories: the tail treats `KrafkaError::NoOffset` as the rebootstrap signal, the freshness probe uses the consumer path for `ListOffsets` and a client per broker for the quorum check, the relay sets `acks=all` and idempotence explicitly and stops on a fatal fencing error, and `iam-control` sets `GroupProtocol::Consumer` and polls again on retriable errors. A krafka upgrade is a new decision: it re-runs the phase-0 capabilities (the spike modules can be restored from the history of Story 1.6, commit 136aa9e) and amends this record. The spike modules no longer run in the `crates/service` integration suite, so they no longer run for every `crates/service` mutant.
