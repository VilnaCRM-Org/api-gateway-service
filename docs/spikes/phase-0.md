# Phase-0 spikes

The phase-0 spikes check, before any gateway code depends on them, the client capabilities that the replication design of issue #8 rests on. Each spike story adds integration tests under `crates/service/tests/integration/` and records its results here. No production crate depends on a spike crate; the spike modules leave in Story 1.7, which also records the Kafka client decision (ADR 0026).

## Kafka client

| Item | Value |
| --- | --- |
| Client | `krafka` 0.32.0, a dev-dependency of `crates/service` only, with the `test-broker` feature and without default features |
| Compose broker | `apache/kafka` 4.3.2, the single-node KRaft service `kafka` of `docker-compose.yml`, PLAINTEXT, development and test only |
| How to run | `make start-deps DEPS=kafka`, then `make integration-tests`; the tests read `KAFKA_BOOTSTRAP_SERVERS` from `.env.test` |

## Story 1.2: tail without a consumer group

Tests: `crates/service/tests/integration/kafka_spike/`. Capabilities (1), (2) and (10) of `architecture.md` section 20.4 of the planning bundle. The tests against the compose broker prove what a real broker does; the fault tests use krafka's in-process `test-broker` (`krafka::testing::FakeBroker`), which speaks the Kafka wire protocol and injects errors, silences and dropped connections per API.

The verdicts below come from the tests and from reading the krafka 0.32.0 source. The serialized verify step of the implementation round runs `make integration-tests` and confirms them; a test that fails there turns its verdict into fail, and the result of that run replaces the "verify step" column.

| Capability | Test | Verdict | Verify step |
| --- | --- | --- | --- |
| (1) Headers on a null-value record: the eight `iam-*` framing headers of a tombstone come back byte-identical (values with a zero byte and bytes that are not UTF-8) and the value is reported as null | `headers.rs`, compose broker | pass | pending |
| (2) `assign` of partition 0 without a group, `read_committed`: with an open transaction of `iam-relay` the tail returns only the committed record, the broker and the client's lag both report the last stable offset at the first open record, and the open records arrive in order once the transaction commits | `read_committed.rs`, `test-broker` | pass | pending |
| (2) Out-of-range detection: a position below the log start offset (after `DeleteRecords`) fails the poll with `KrafkaError::NoOffset` naming the partition, the position stays where it was on every further poll, and a reseek to the log start reads the retained records | `out_of_range.rs`, compose broker | pass | pending |
| (2) Reseek after reconnect: the broker connection is dropped while the tail is in progress (`FakeBroker::crash`, then `restart`); the tail reseeks to its in-memory position and reads every record exactly once, in order | `reconnect.rs`, `test-broker` | pass | pending |
| (10) Fault injection: `OFFSET_OUT_OF_RANGE`, `NOT_LEADER_OR_FOLLOWER` and a request timeout each reach the reader as a distinguishable typed error | `typed_errors.rs`, `test-broker` | pass, with the limit below | pending |

### Findings that shape the design

- **No automatic reset.** With `AutoOffsetReset::None` krafka never moves a position on `OFFSET_OUT_OF_RANGE`; it fails the poll with `KrafkaError::NoOffset`. This is the rebootstrap signal of FR-71.
- **Where the faults surface.** `OFFSET_OUT_OF_RANGE` on a `Fetch` fails the poll. `NOT_LEADER_OR_FOLLOWER` and a request timeout on a `Fetch` do not: krafka refreshes the metadata, backs the partition off and retries, so the poll returns no records and no error until the fault clears, and no record is lost or repeated. The reader meets both as typed errors on its `ListOffsets` watermark lookup (`Consumer::fetch_watermarks`): `KrafkaError::Broker` with `ErrorCode::NotLeaderForPartition`, and `KrafkaError::Timeout`. The tail therefore cannot learn of a leader change or an outage from its long poll alone; it relies on the probe's `ListOffsets` and metadata requests, as section 9.3 of the architecture already assumes (the tail reseeks after a reconnect or when the probe sees the watermark move while the tail is idle).
- **Headers and null values.** krafka keeps a null value distinct from an empty one and keeps every header, so the framing of section 9.2 works for tombstones; the value-framing fallback is not needed.
- **Position in memory.** `Consumer::seek` drops buffered records of the partition, so a reseek to the in-memory position never repeats a record that was already handed out.

### Integration suite wall time

Section 19 of the architecture budgets 15 s for the integration suite of `crates/service`. `make integration-tests` runs `cargo nextest`, which prints the time of every test and of the whole run, but not a total per crate; a per-crate total needs a change of the integration recipe, which the Makefile (synchronised with the template) and `make/gates.mk` (protected) own. The CI figure is recorded here once that change is approved and a CI run has measured it.

| Suite | Budget | Measured in CI |
| --- | --- | --- |
| `crates/service` integration tests, with the spike module | 15 s | pending |
