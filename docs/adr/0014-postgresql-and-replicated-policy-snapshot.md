# 0014. PostgreSQL as system of record and an in-process replicated policy snapshot instead of DynamoDB and DAX

Planning decisions: section 13 of `specs/8-iam-scaffolding-and-spikes/architecture.md` (data model and migrations) and section 5 of its `research.md` (datastore decision).

## Context

The planning board names DynamoDB with DAX as the store of the authorization data. The template ships PostgreSQL through `sqlx`, with compile-time checked queries, reversible migrations and integration tests that run against a real database in every pipeline. An authorization decision is made on every request that passes the gateway, so its read path must not wait for a network round trip, and a revoked permission must stop being honoured within a stated bound.

## Decision

PostgreSQL 16 is the system of record of IAM. Reads on the request path will not query it and will not use a shared cache: every gateway instance will hold the whole policy as an in-process snapshot that is replicated from a Kafka topic fed by the control plane. Nothing uses DynamoDB, DAX or a shared cache for authorization data; Valkey is planned for rate-limit counters only.

The first table is `iam_policy_epoch`: one row, enforced by `CHECK (id = 1)`, that holds the gap-free policy version, the 16-byte digest of the policy state and the log, relay and catalogue epochs. Later changes will lock this row in the transaction that writes a policy change, so versions are assigned in commit order.

The options compared:

| Option | Outcome | Reason |
| --- | --- | --- |
| PostgreSQL | Chosen | One transaction covers a change with its outbox and audit rows; one locked counter row gives a gap-free, commit-ordered version; conditional writes, consistent reverse lookups, constraints and documents of several MiB; it runs locally and in the pipeline, so the coverage and mutation gates hold |
| DynamoDB with DAX | Rejected | DAX runs only inside a VPC, so it cannot be tested locally or in the pipeline, and its query cache is not invalidated by writes, so no revocation bound can be guaranteed |
| DynamoDB without DAX | Rejected | No gap-free global version and no atomic change across many items; it would also replace protected PostgreSQL-specific configuration |
| A shared cache for policy | Rejected | A cache round trip costs far more than an in-process decision, and asynchronous replication or eviction can lose a revocation |

## Consequences

Every policy write goes through one row lock, which bounds the administrative write rate; the estimate is 100 to 500 writes per second and has not been measured. The gateway needs a replication path with a freshness proof before it may allow a request, and the Kafka client that carries it is verified by the phase-0 spikes before any gateway code depends on it. Memory use on a gateway instance grows with the size of the policy.

The decision is revisited when the administrative write rate approaches the ceiling of the single counter row, or when a requirement appears that PostgreSQL cannot meet.
