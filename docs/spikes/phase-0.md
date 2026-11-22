# Phase-0 spikes

The phase-0 spikes check, before any gateway code depends on them, the client capabilities that the replication design of issue #8 rests on. Each spike story added integration tests to the `crates/service` integration suite and recorded its results here. No production crate depends on a spike crate. Story 1.7 recorded the outcome and the Kafka client decision in [ADR 0026](../adr/0026-krafka-as-the-kafka-client.md) and removed the spike module `kafka_spike` of that suite together with the krafka dev-dependency; the last commit that holds the module is 136aa9e (Story 1.6), from which it can be restored to re-run a spike.

## Outcome

Every must-pass capability (1 to 6 and 9) passed, and so did capabilities 7, 8 and 10; capability 11 was not measured and capability 12 is recorded only. The serialized verify step of the implementation round ran every spike test through `make integration-tests` on 2026-11-22: 261 tests passed, and the 2 ignored ones are the hand-run compose-host observations of capabilities 3 and 11. ADR 0026 is accepted, and Epic 7 may start.

## Kafka client

| Item | Value |
| --- | --- |
| Client | `krafka` 0.32.0, during the spikes a dev-dependency of `crates/service` only, with the `test-broker` feature and without default features; removed from the workspace in Story 1.7 until Epic 7 adds it to the infrastructure layer (ADR 0023, ADR 0026) |
| Compose broker | `apache/kafka` 4.3.2, the single-node KRaft service `kafka` of `docker-compose.yml`, PLAINTEXT, development and test only |
| How to run | the spike tests no longer exist in the working tree; restored from commit 136aa9e they ran with `make start-deps DEPS=kafka`, then `make integration-tests`, and read `KAFKA_BOOTSTRAP_SERVERS` from `.env.test` |

## Story 1.2: tail without a consumer group

Tests: the module `kafka_spike` of the `crates/service` integration suite (removed in Story 1.7). Capabilities (1), (2) and (10) of `architecture.md` section 20.4 of the planning bundle. The tests against the compose broker prove what a real broker does; the fault tests use krafka's in-process `test-broker` (`krafka::testing::FakeBroker`), which speaks the Kafka wire protocol and injects errors, silences and dropped connections per API.

The verdicts below come from the tests and from reading the krafka 0.32.0 source. The serialized verify step of the implementation round ran `make integration-tests` on 2026-11-22 and confirmed every verdict; its result is the "verify step" column.

| Capability | Test | Verdict | Verify step |
| --- | --- | --- | --- |
| (1) Headers on a null-value record: the eight `iam-*` framing headers of a tombstone come back byte-identical (values with a zero byte and bytes that are not UTF-8) and the value is reported as null | `headers.rs`, compose broker | pass | pass |
| (2) `assign` of partition 0 without a group, `read_committed`: with an open transaction of `iam-relay` the tail returns only the committed record, the broker and the client's lag both report the last stable offset at the first open record, and the open records arrive in order once the transaction commits | `read_committed.rs`, `test-broker` | pass | pass |
| (2) Out-of-range detection: a position below the log start offset (after `DeleteRecords`) fails the poll with `KrafkaError::NoOffset` naming the partition, the position stays where it was on every further poll, and a reseek to the log start reads the retained records | `out_of_range.rs`, compose broker | pass | pass |
| (2) Reseek after reconnect: the broker connection is dropped while the tail is in progress (`FakeBroker::crash`, then `restart`); the tail reseeks to its in-memory position and reads every record exactly once, in order | `reconnect.rs`, `test-broker` | pass | pass |
| (10) Fault injection: `OFFSET_OUT_OF_RANGE`, `NOT_LEADER_OR_FOLLOWER` and a request timeout each reach the reader as a distinguishable typed error | `typed_errors.rs`, `test-broker` | pass, with the limit below | pass |

### Findings that shape the design

- **No automatic reset.** With `AutoOffsetReset::None` krafka never moves a position on `OFFSET_OUT_OF_RANGE`; it fails the poll with `KrafkaError::NoOffset`. This is the rebootstrap signal of FR-71.
- **Where the faults surface.** `OFFSET_OUT_OF_RANGE` on a `Fetch` fails the poll. `NOT_LEADER_OR_FOLLOWER` and a request timeout on a `Fetch` do not: krafka refreshes the metadata, backs the partition off and retries, so the poll returns no records and no error until the fault clears, and no record is lost or repeated. The reader meets both as typed errors on its `ListOffsets` watermark lookup (`Consumer::fetch_watermarks`): `KrafkaError::Broker` with `ErrorCode::NotLeaderForPartition`, and `KrafkaError::Timeout`. The tail therefore cannot learn of a leader change or an outage from its long poll alone; it relies on the probe's `ListOffsets` and metadata requests, as section 9.3 of the architecture already assumes (the tail reseeks after a reconnect or when the probe sees the watermark move while the tail is idle).
- **Headers and null values.** krafka keeps a null value distinct from an empty one and keeps every header, so the framing of section 9.2 works for tombstones; the value-framing fallback is not needed.
- **Position in memory.** `Consumer::seek` drops buffered records of the partition, so a reseek to the in-memory position never repeats a record that was already handed out.

### Integration suite wall time

Section 19 of the architecture budgets 15 s for the integration suite of `crates/service`. `make integration-tests` runs `cargo nextest`, which prints the time of every test and of the whole run, but not a total per crate; a per-crate total needs a change of the integration recipe, which the Makefile (synchronised with the template) and `make/gates.mk` (protected) own. The CI figure is recorded here once that change is approved and a CI run has measured it.

| Suite | Budget | Measured in CI |
| --- | --- | --- |
| `crates/service` integration tests, with the spike module (Stories 1.2 to 1.6) | 15 s | not measured; the three slowest spike tests alone took 16.2 s, 13.3 s and 8.4 s in the verify step |
| `crates/service` integration tests, without the spike module (from Story 1.7) | 15 s | pending |

## Story 1.3: metadata, leader epochs and configuration reads

Tests: `broker_metadata.rs`, `leader_epoch.rs`, `configuration.rs` and `multi_broker.rs` of the module `kafka_spike` (removed in Story 1.7). Capabilities (3), (4) and (5) of `architecture.md` section 20.4 of the planning bundle (FR-72, FR-73, NFR-36). The compose broker `kafka` now runs the KRaft ACL authorizer `org.apache.kafka.metadata.authorizer.StandardAuthorizer` (the successor of the `simple` authorizer, which Kafka 4 no longer ships) with `allow.everyone.if.no.acl.found=false`; the anonymous PLAINTEXT principal is its only super user. A broker container started before this change keeps running without the authorizer, because `make start-deps` never recreates a running service: recreate it once with `docker compose up --detach --wait --force-recreate kafka`.

As for Story 1.2, the verdicts come from the tests and from reading the krafka 0.32.0 source; the serialized verify step ran `make integration-tests` on 2026-11-22, and its result is the "verify step" column.

| Capability | Test | Verdict | Verify step |
| --- | --- | --- | --- |
| (3) A Metadata request addressed to the compose broker names the leader (node 1), a leader epoch and the partition count (1) of a new topic | `broker_metadata.rs`, compose broker | pass | pass |
| (3) Addressing a chosen broker: a client seeded with one broker of a 3-node cluster sends its Metadata request to that broker only, and its answer matches the cluster's leader and epoch | `broker_metadata.rs`, `test-broker` | pass, with the limit below | pass |
| (3) After a leader change, each of the three brokers asked on its own reports the new leader and the epoch one higher | `broker_metadata.rs`, `test-broker` | pass | pass |
| (4) `ListOffsets` with the current leader epoch returns the log start and the high watermark, on the `test-broker` and on the compose broker | `leader_epoch.rs` | pass | pass |
| (4) A stale epoch (the broker moved past the client's cached epoch) surfaces as `KrafkaError::Broker` with `ErrorCode::FencedLeaderEpoch`, a future epoch (the broker behind the client) as `ErrorCode::UnknownLeaderEpoch`, an injected `OFFSET_NOT_AVAILABLE` as `ErrorCode::OffsetNotAvailable`; the three codes are distinct and retriable; after a stale epoch the next lookup succeeds, while a future epoch persists (the refresh keeps the newer cached epoch, KIP-320) until the broker catches up, and the next lookup then succeeds | `leader_epoch.rs`, `test-broker` | pass | pass |
| (5) `DescribeConfigs` on a topic created with `cleanup.policy=compact`, `min.insync.replicas=2`, `unclean.leader.election.enable=false` and `message.timestamp.type=LogAppendTime` returns each value; `DescribeTopics` returns the partition count and the replication factor | `configuration.rs`, compose broker | pass | pass |
| (5) `DescribeConfigs` on the broker returns its configuration, `authorizer.class.name` included | `configuration.rs`, compose broker | pass | pass |
| (5) `DescribeAcls` lists the write ACL of `User:iam-control` on a topic after `CreateAcls` | `configuration.rs`, compose broker | pass | pass |
| (5) `allow.everyone.if.no.acl.found` from `DescribeConfigs` on the broker: never readable as `true`; expected not returned as a value (see below) | `configuration.rs`, compose broker | not returned as a value; fallback chosen | not returned as a value; fallback chosen |

### The authorizer setting and its fallback

`allow.everyone.if.no.acl.found` is a property of the authorizer, outside the broker configuration definition. Kafka reports a key it has no definition for as sensitive, without a value (krafka's `ConfigValue::Sensitive`), or omits it; the broker test accepts both and fails only on a readable value other than `false`. The gates therefore cannot rely on `DescribeConfigs` for this setting, and the fallback that Story 7.3 uses, to be carried into ADR 0026 by Story 1.7, is:

1. **Negative probe** (the runtime check of `iam-control`): a dedicated probe principal that holds no ACL on the state topic tries to describe it; the broker must answer `TOPIC_AUTHORIZATION_FAILED`. An answer with data means an implicit allow and blocks publishing.
2. **Static check**: the Bats check of Story 15.4 asserts `allow.everyone.if.no.acl.found: "false"` in the Strimzi `Kafka` resource, so a misconfiguration is caught before deployment.

If the verify step shows the value as readable `false`, the gate reads it directly and keeps the negative probe as a second check.

### Findings that shape the design

- **No per-broker Metadata call.** krafka's public API cannot send a Metadata request to a broker the caller picks; its metadata writer chooses the broker. A fresh client seeded with one broker's address sends its bootstrap Metadata request (for every topic) to that broker, and `Consumer::fetch_metadata(None)` reads the answer from the cache without another request. The replica-quorum check of FR-73 therefore needs one short-lived client per broker per probe, or a long-lived client per broker that forces a refresh with that broker as its only seed; the cost of a connection per probe is an input to the freshness-probe stories, not measured here.
- **Epoch errors only on the consumer path.** `Consumer::fetch_watermarks` sends `ListOffsets` with the leader epoch of its cached metadata, returns the broker's code unchanged and refreshes the metadata afterwards; the refresh never lowers a cached leader epoch (KIP-320), so `UNKNOWN_LEADER_EPOCH` repeats until the broker reaches the client's epoch. The admin `list_offsets` call also sends the cached epoch, but treats `FENCED_LEADER_EPOCH`, `UNKNOWN_LEADER_EPOCH` and `OFFSET_NOT_AVAILABLE` as retriable: it refreshes the metadata and retries until its deadline, and the caller sees the error only if it persists. The freshness probe must use the consumer path, so that every epoch error ends the probe without a proof.
- **The caller cannot choose the epoch.** Both paths send the epoch from krafka's metadata cache; there is no parameter for it. The probe gets KIP-320 checking by refreshing the metadata from the quorum first; it cannot send an epoch it confirmed with the brokers itself, so a refresh between the quorum check and `ListOffsets` can move the epoch the request carries.
- **Configuration reads.** Every topic value of FR-72 comes back as a plain value; the replication factor and the partition count come from `DescribeTopics`, not from `DescribeConfigs`.

### The 3-broker compose profile (outside `make ci`)

The profile `kafka-cluster` of `docker-compose.yml` runs three combined KRaft nodes, `kafka-cluster-1` to `kafka-cluster-3`, reachable only inside the compose network. No make target starts it. The observation test `after_the_leader_stops` left with the spike module in Story 1.7; to run the observation, restore the module from commit 136aa9e first (for example with `git restore --source=136aa9e` on its directory and its module line), then run by hand, from the checkout, with the development stack up:

1. `docker compose --profile kafka-cluster up --detach --wait kafka-cluster-1 kafka-cluster-2 kafka-cluster-3`
2. `docker compose exec -T app scripts/with-env.sh .env .env.test -- cargo nextest run -p service --test integration --no-run` (build first, so that the next step starts at once)
3. In one terminal: `docker compose exec -T app scripts/with-env.sh .env .env.test -- cargo nextest run -p service --test integration --run-ignored only -E 'test(after_the_leader_stops)'`. The test creates a topic on brokers 1, 2 and 3 (broker 1 leads it) and waits until all three report the same leader.
4. About 20 seconds later, in a second terminal: `docker compose --profile kafka-cluster stop kafka-cluster-1`. The test waits up to 180 seconds from its start for at least 2 of 3 brokers to report the same new leader with a higher epoch, then prints one `compose-host observation:` line with every broker's report before and after, the quorum, and the brokers that still named an older leader or epoch after the quorum agreed (run with `--no-capture` to see it).
5. `docker compose --profile kafka-cluster down` when done (the profile has no volumes).

Whether a broker's Metadata answer was older than the leader epoch its own replica fetcher used (the point behind guarantee G4) is not visible through krafka: the replica fetcher's epoch is broker state with no client API. The run records instead whether any reachable broker still named the old leader or epoch after the quorum had agreed on the new one.

| Observation (compose host only, not a gate value) | Result |
| --- | --- |
| At least 2 of 3 brokers report the same new leader and epoch after broker 1 stops | not run on the compose host before Story 1.7 removed the test; not a gate value (ADR 0026) |
| A reachable broker still named the old leader or epoch after the quorum agreed | not run on the compose host before Story 1.7 removed the test; not a gate value (ADR 0026) |
| A broker's Metadata answer older than its replica fetcher's epoch | not observable through krafka |

## Story 1.4: idempotent and transactional producing

Tests: `idempotent.rs`, `fencing.rs`, `aborted.rs` and `stable_offset.rs` of the module `kafka_spike` (removed in Story 1.7). Capabilities (6) and (7) of `architecture.md` section 20.4 of the planning bundle (FR-46). The relay's producer is configured with `acks=all`, idempotence on, lz4 compression, an explicit partition 0 and the `iam-*` framing headers; the transactional producer uses the transactional id `iam-relay` (on the compose broker a unique `iam-relay-<topic>` id, because that broker outlives the run and tests run beside each other).

As for Story 1.2, the verdicts come from the tests and from reading the krafka 0.32.0 source; the serialized verify step ran `make integration-tests` on 2026-11-22, and its result is the "verify step" column.

| Capability | Test | Verdict | Verify step |
| --- | --- | --- | --- |
| (6) Idempotent producing: 10,000 records to partition 0 with every fifth `Produce` request faulted (an applied write whose answer is lost, `NOT_LEADER_OR_FOLLOWER`, an applied write answered with `REQUEST_TIMED_OUT`) land exactly once and in order, the returned offsets are contiguous from 0, the `iam-seq` header of every record survives, and every stored batch carries the lz4 codec | `idempotent.rs`, `test-broker` | pass | pass |
| (6) lz4 batches of the idempotent producer with headers are accepted and returned by a real broker, at consecutive offsets | `idempotent.rs`, compose broker | pass | pass |
| (7) Fencing: a second producer that initialises `iam-relay` while the first has an open transaction gets the same producer id with a higher epoch; the first producer's commit fails with a fatal fencing error (`KrafkaError::Fenced`, or `PRODUCER_FENCED` / `INVALID_PRODUCER_EPOCH`), and a `read_committed` reader returns only the successor's record | `fencing.rs`, `test-broker` and compose broker | pass | pass |
| (7) Aborted transaction: a `read_committed` reader returns the records committed before and after an aborted transaction and none of the aborted ones | `aborted.rs`, `test-broker` and compose broker | pass | pass |
| (7) `ListOffsets` with `READ_COMMITTED`: with a transaction open the answer is the offset of its first record (the last stable offset), while the high watermark lies beyond its last record; after the commit the answer lies beyond its last record | `stable_offset.rs`, compose broker | pass | pass |
| (7) Transaction timeout: a relay with `transaction.timeout.ms` 10 s that stops without committing has its transaction aborted by the broker; its records never become visible and its late commit fails | `stable_offset.rs`, compose broker | pass, with the bound below | pass |

### Findings that shape the design

- **One request in flight.** krafka has no `max.in.flight.requests.per.connection` setting. Its send engine keeps at most one batch per partition on the wire (and at most five requests per broker, each for other partitions), so the state topic's single partition always has at most one `Produce` request in flight; the ordering of FR-46 does not depend on a setting the relay could get wrong.
- **Idempotence is the default.** `ProducerBuilder::idempotent` defaults to on and requires `Acks::All`; the relay sets both explicitly so that a later default change cannot weaken it. A retry after a lost answer is de-duplicated by the broker and returns the original offset.
- **Fencing surfaces on commit.** A fenced relay learns of its successor only on its next coordinator or `Produce` call; the error is fatal (`KrafkaError::is_fatal`), so the relay must drop the producer and stop instead of retrying.
- **Commit markers are asynchronous.** A real broker answers `EndTxn` before the commit markers are written, so the last stable offset passes the transaction shortly after `commit()` returns, not at the same moment; the probe of section 9.3 must not treat a stable offset that lags a fresh commit as a fault.
- **Timeout bound.** The broker checks for timed-out transactions every `transaction.abort.timed.out.transaction.cleanup.interval.ms` (10 s by default, unchanged on the compose broker), so an abandoned transaction is aborted between `transaction.timeout.ms` and `transaction.timeout.ms` plus that interval; the test allows a further 5 s for the abort markers and its own polling. The in-process `test-broker` never expires a transaction, which is why this test needs the compose broker.

## Story 1.5: consumer group, SCRAM over TLS with a custom CA, and bootstrap read rate

Tests: `consumer_group.rs`, `sasl_ssl.rs` and `read_rate.rs` of the module `kafka_spike` (removed in Story 1.7). Capabilities (8), (9), (11) and (12) of `architecture.md` section 20.4 of the planning bundle (FR-18, NFR-37).

The SCRAM listeners are two SASL_SSL listeners of the compose broker, `SCRAM_HOST` (`localhost:${KAFKA_SASL_SSL_PORT}`, 9094) and `SCRAM_DOCKER` (`kafka:19094` inside the compose network), both with the mechanism SCRAM-SHA-512. Their TLS material comes from `scripts/kafka-tls-fixture.sh`, which the one-shot compose service `kafka-tls` runs as the host user before the broker starts: a root CA standing in for the Strimzi cluster CA, a broker certificate it signs for `localhost`, `kafka` and 127.0.0.1, and an unrelated CA for the untrusted case, all under the git-ignored `target/kafka-tls/` (`KAFKA_TLS_DIR` of `.env.test`). No key or password is committed: the fixture generates the keys, and the test creates its SCRAM user with a password generated for the run (`AlterUserScramCredentials` through the PLAINTEXT super-user listener, the salted password computed with `aws-lc-rs`). The fixture keeps a set that is still valid for a day; once it regenerates the set (for example after `target/` was deleted), the running broker must be recreated with `docker compose up --detach --force-recreate kafka` to load the new certificate.

As for the earlier stories, the verdicts come from the tests and from reading the krafka 0.32.0 source; the serialized verify step ran `make integration-tests` on 2026-11-22, and its result is the "verify step" column.

| Capability | Test | Verdict | Verify step |
| --- | --- | --- | --- |
| (8) Consumer group with a manual commit after processing: two members of one group (KIP-848 protocol, `GroupProtocol::Consumer`, auto-commit off) split a three-partition topic and each record is delivered once; when member B leaves (`close`, which leaves the group without committing) after processing records it did not commit, member A is given B's partitions, both rebalance callbacks report the move, and A receives exactly B's uncommitted records again, each once, and no committed record | `consumer_group.rs`, compose broker | pass | pass |
| (9) SASL SCRAM-SHA-512 over TLS trusting a custom root CA (`TlsConfig::with_ca_cert`, the CA file only): the right password connects and reads the cluster metadata; a wrong password fails with `KrafkaError::Auth` carrying the broker's `SaslAuthenticationFailed` and no cause; an untrusted CA fails the TLS handshake with `KrafkaError::Auth` whose cause is the TLS error (an `InvalidData` I/O error), so the two failures are told apart by type and cause | `sasl_ssl.rs`, compose broker | pass | pass |
| (11) Bootstrap read rate: a reader without a group reads a 200 MiB one-partition topic from offset 0 | `read_rate.rs`, compose broker, ignored by `make ci` | recorded below, not a gate | not run by the verify step |
| (12) Follower fetching (KIP-392) | none (recorded only) | available in the client API (`ConsumerBuilder::client_rack` sends the rack in every `Fetch`, and the fetcher follows a preferred read replica the broker names); not exercised, because it needs several brokers with racks and `replica.selector.class`; a later phase | not applicable |

### Bootstrap read rate (compose host, not a gate)

The measurement ran outside `make ci`, by hand, against the compose broker. The test left with the spike module in Story 1.7; restored from commit 136aa9e, it runs as:

```sh
make start-deps DEPS=kafka
scripts/with-env.sh .env .env.test -- cargo nextest run -p service --test integration \
    --run-ignored only kafka_spike::read_rate --no-capture
```

The test prints the rate in MB/s (10^6 bytes per second) with the bytes read and the elapsed time. The figure is a compose-host measurement for orientation next to the 100 MB/s target of NFR-37, never a gate value; the rate on the Strimzi cluster is measured by the EKS stories.

| Item | Target | Measured on the compose host |
| --- | --- | --- |
| Read of 200 MiB (12,800 records of 16 KiB, no compression) from offset 0, no group, `read_committed`, one partition | ≥ 100 MB/s (NFR-37), not a gate | not measured on a recorded host before Story 1.7 removed the test; recorded only, not a gate (ADR 0026) |

### Findings that shape the design

- **Commit after processing.** With auto-commit off, `Consumer::close` reports the assigned partitions to `on_partitions_revoked` and leaves the group without committing, so a member that stops between processing and committing hands its partitions over at the last committed offset: the records it processed are delivered again (at least once), and a committed record never is. `iam-control` must therefore make the handling of a `user.events.v1` record idempotent and commit only after the revocation transaction committed.
- **Protocol.** krafka's default is still the classic protocol, which Apache Kafka 4.3 deprecates (KIP-1274); `iam-control` sets `GroupProtocol::Consumer` explicitly. A commit under the classic protocol fails with `REBALANCE_IN_PROGRESS` during a join round and must be retried after the next poll.
- **Retriable poll errors.** Under the KIP-848 protocol `Consumer::poll` returns the coordinator's `NOT_COORDINATOR` (for example while a fresh broker still loads `__consumer_offsets`) instead of retrying it; krafka drops the cached coordinator, and the next poll re-discovers it. The `iam-control` consume loop must poll again on `KrafkaError::is_retriable` and fail only on the other errors. Revocations while the group converges on its first split are normal and are not a hand-over.
- **Custom CA only.** `TlsConfig::with_ca_cert` replaces the default WebPKI roots, so the client trusts the Strimzi cluster CA and nothing else; `KAFKA_CA_FILE` maps onto it directly. A TLS failure is fatal (`KrafkaError::Auth`), like a rejected password, and neither is retried by the client.
- **Advertised listeners.** The client connects to the advertised address of the listener it bootstrapped on, so every SASL_SSL listener needs a certificate valid for its advertised host name; on Strimzi the cluster CA signs the broker certificates for their service names.

## Story 1.6: token-verify backend and GraphQL parser benchmarks

Benches: `crates/service/benches/spikes/main.rs` and its modules beside it, run by `make bench-spikes` and never by `make ci`. FR-15, FR-60 and NFR-33 of the planning bundle. `jsonwebtoken` (with the `aws_lc_rs` backend), `aws-lc-rs`, `async-graphql-parser`, `pem` and `criterion` are dev-dependencies of `crates/service` only.

| Item | Value |
| --- | --- |
| Token verify | `jsonwebtoken` 10.4.0 with the `aws_lc_rs` backend; RS256, RSA-2048, issuer, audience and `exp` validated; cases: one trusted key, three keys with the newest signing (one signature check), three keys with the oldest signing (two failed signature checks, then the match), keys tried newest first |
| Key generation | `aws-lc-rs` `KeyPair::generate(KeySize::Rsa2048)` when the bench starts; the private half is handed to `jsonwebtoken` as an in-memory PEM and never written; never the `rsa` crate (RUSTSEC-2023-0071) |
| GraphQL parse | `async-graphql-parser` 7.2.1 `parse_query` on generated documents of exactly 1, 5, 8 and 64 KiB: one named query with variables, aliased selections with object arguments, nested connections, inline fragments and fragment spreads, and four named fragments |
| Statistic | criterion's estimates, then a latency pass of 10 000 individually timed calls per operation that prints the median and the p99 (nearest rank) per operation |
| Committed secrets | none: no private key and no token is stored in the repository; both are generated at bench start |

### Measurements

Every figure below is a measurement of the host named in the table, taken by `make bench-spikes`; none is a gate value, and the NFR-33 figures stay targets. The serialized verify step of the implementation round runs the target and replaces each "pending" cell with the figure that `target/reports/bench-spikes/spikes.txt` reports, and the CPU model with the line `host CPU model:` of that report.

| Item | Value |
| --- | --- |
| Host CPU model | pending; every figure below was measured on this host and is not a gate value |

| Operation | Median per operation | p99 per operation |
| --- | --- | --- |
| `rs256_verify/one_key` | pending | pending |
| `rs256_verify/three_keys_newest_signs` | pending | pending |
| `rs256_verify/three_keys_oldest_signs` | pending | pending |
| `graphql_parse/1KiB` | pending | pending |
| `graphql_parse/5KiB` | pending | pending |
| `graphql_parse/8KiB` | pending | pending |
| `graphql_parse/64KiB` | pending | pending |

### Dependency and advisory check

| Check | Result |
| --- | --- |
| `openssl-sys` in the dependency graph | banned by the dependency policy; `make check-security` fails if it enters, verify step: pending |
| `aws-lc-rs` key generation against the advisory database | verify step: pending (`make check-security`); the test-key crate of ADR 0023 is `aws-lc-rs` and never `rsa` while RUSTSEC-2023-0071 is open |
