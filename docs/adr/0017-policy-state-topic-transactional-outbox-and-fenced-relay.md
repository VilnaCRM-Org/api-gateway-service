# 0017. Policy state topic, transactional outbox and fenced Kafka relay

Status: draft. Story 2.3 adds the unit of work and the outbox with event rows only; Story 7.2 adds the state rows, the policy digest and the `__head` row, Story 7.4 adds the relay and its wake-up, and spike Stories 1.2 and 1.4 decide the fencing layer.

Planning decisions: sections 6.1, 9.1 to 9.3 and 15.1 of `specs/8-iam-scaffolding-and-spikes/architecture.md` (unit of work, topics, framing, relay and fencing, event envelope) and requirements FR-2, FR-46, FR-47, FR-49 and FR-70 of its `prd.md`.

## Context

Every administrative change must reach the gateway fleet and the event consumers exactly in commit order, and no change may be visible without its audit record and its event. A direct write to Kafka from a command handler can succeed while the database transaction rolls back, or the reverse; and two relays that both believe they lead can write out of order.

## Decision

- **One transaction per change.** `PgIamUnitOfWork::commit` locks the single `iam_policy_epoch` row with `SELECT ... FOR UPDATE`, increments `version` by one when the change affects decisions (gap-free and commit-ordered under the lock), runs the aggregate statements and guards, inserts the outbox rows, appends the audit record to the hash chain of ADR 0019 through `PgSecurityAuditLog::append_within`, and inserts the change receipt and the idempotency record. A failing step rolls everything back. A change that does not affect decisions keeps the version, and its receipt has no policy version.
- **Transactional outbox.** `iam_outbox` holds state rows (`kind = 'state'`, one per changed entity, framed by `policy_version`, `seq`, `count` and `digest_after`, a null payload for a tombstone) and event rows (`kind = 'event'`, topic `iam.events.v1`, record key the aggregate id, payload the envelope). The identity column `position` orders the rows; a partial index on `position` where `published_at IS NULL` keeps the relay's scan small. Check constraints keep the two shapes apart. Every row carries the policy version of its own transaction and the log epoch.
- **Event envelope.** `{id, type, occurredAt, data}` with a UUID v7 id, a type of the form `iam.<aggregate>.<verb>` (dotted lower-case words, the pattern `^[a-z][a-z0-9]*([._-][a-z0-9]+)*$`), an RFC 3339 UTC time with six fractional digits, and `data` holding `aggregateId`, `entityVersion`, `actor` and `policyVersion` before the event's own fields. The domain describes `data` as an abstract tree (`EventData`) that refuses field names of credentials and specification bodies and text values with a control character, a token-shaped word or a bearer credential; the infrastructure encodes it with `serde_json` from private DTOs and refuses an encoding above 64 KiB.
- **State rows and the digest (Story 7.2).** A transaction that affects decisions reads the state of every entity its statements may change before they run and again after they ran, so each state row carries the full new state (or a null tombstone) and the digest moves by `h_old ^ h_new` for exactly what changed. The state is canonical JSON with `schemaVersion` (`JsonStateRecordCodec`); the entity hash is the first 16 bytes of the SHA-256 of the printed key followed by the canonical state (`Sha256PolicyDigest`); an entity whose encoding does not change writes no row. The rows follow the order of the keys, `seq` runs from 1 to `count` without a gap, each row carries the running digest as `digest_after`, and the `__head` row `{version, digest}` is the last row of the version. A subject record holds the full list of its assignments that are not revoked, and a subject without assignment is a tombstone. A catalogue is a manifest plus chunks of at most 1 MiB, addressed by the hash of their content: the `<catVer>` segment of a chunk key is the chunk format version (1), so a chunk whose entries do not change keeps its key and is not written again, while the manifest names the chunks and the catalogue epoch. A transaction that does not affect decisions, or that fails, writes no state row and no head row.
- **Policy state topic** `iam.policy.state.v1`: one partition, compacted, keyed by state key; the relay publishes state rows there and event rows to `iam.events.v1` (Story 7.4).
- **Fenced relay.** One active relay per fleet under an advisory lock; a transactional producer when spike Story 1.4 passes, and always the `iam-relay-epoch` header with every key resolved by highest version, so a zombie relay's late batch cannot win (section 9.3).

| Option | Outcome | Reason |
| --- | --- | --- |
| Transactional outbox in PostgreSQL with a fenced relay | Chosen | The change, its audit record and its events commit together; the relay can retry without loss and the order is the commit order |
| Direct produce from the command handler | Rejected | A produce and a commit cannot be atomic; a rollback after a produce publishes a change that never happened |
| Change data capture from the write-ahead log | Rejected | Needs a connector and a replication slot outside the service, and loses the domain framing of state records |
| Sequence or identity column for the policy version | Rejected | A rolled-back transaction leaves a gap, and the order of sequence values is not the commit order |

## Consequences

Every versioned write serialises on the `iam_policy_epoch` row lock and on the audit chain-head lock, which bounds the write rate (about 500 policy writes per second, an estimate) but gives one total order. The outbox grows until the relay marks rows published and prunes them after seven days (Story 7.4). The 64 KiB bound on an envelope is checked when the change commits, so an oversized event fails the change instead of the relay.
