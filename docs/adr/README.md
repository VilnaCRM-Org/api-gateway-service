# Architecture decision records

These records explain why the structure of the template is what it is. Each one has the same parts: the context that forced a decision, the decision, and its consequences. Each names the planning decisions it summarises, so a reader can trace a record back to the planning bundle (`AD-nn` are the core architecture decisions, `DD-nn` the delivery decisions). The [architecture overview](../architecture.md) shows how the decisions fit together.

| Record | Title | Planning decisions |
| --- | --- | --- |
| [0001](0001-workspace-and-layers.md) | Workspace and layers | AD-01, AD-02 |
| [0002](0002-architecture-gate.md) | Architecture gate | AD-03, AD-25 |
| [0003](0003-error-model.md) | Error model | AD-06 |
| [0004](0004-configuration.md) | Configuration | AD-07 |
| [0005](0005-persistence-and-migrations.md) | Persistence and migrations | AD-08, AD-20 |
| [0006](0006-health-and-liveness.md) | Health and liveness | AD-11, AD-12 |
| [0007](0007-api-contracts.md) | API contracts | AD-16, AD-17, AD-18, AD-19, DD-10 |
| [0008](0008-tests-coverage-mutation.md) | Tests, coverage and mutation | AD-23, AD-24, DD-09 |
| [0009](0009-make-execution-model.md) | Make execution model | DD-01, DD-02 |
| [0010](0010-workflow-layout.md) | Workflow layout | DD-08, DD-13 |
| [0011](0011-release-flow.md) | Release flow | DD-11, DD-12 |
| [0012](0012-container-images.md) | Container images | DD-19, DD-20 |
| [0013](0013-iam-bounded-context.md) | IAM bounded context `authorization/iam`, with the gateway as modules inside it | IAM architecture section 3, research section 2.5 (owner item D19) |
| [0014](0014-postgresql-and-replicated-policy-snapshot.md) | PostgreSQL as system of record and an in-process replicated policy snapshot instead of DynamoDB and DAX | IAM architecture section 13, research section 5 |
| [0015](0015-iam-is-the-api-gateway-split-planes-one-image-two-run-modes.md) | IAM is the API gateway: split planes, one image, two run modes | IAM architecture sections 3 and 20, FR-45, FR-54, FR-55, FR-67, NFR-31 |
| [0016](0016-token-validation-without-persistence-or-liveness-calls.md) | Token validation at the gateway without token persistence or liveness calls | IAM architecture sections 4.2, 7 and 16.1, FR-15, FR-55, NFR-6, NFR-20 |
| [0017](0017-policy-state-topic-transactional-outbox-and-fenced-relay.md) | Policy state topic, transactional outbox and fenced Kafka relay (draft) | IAM architecture sections 6.1, 9.1 to 9.3 and 15.1, FR-2, FR-46, FR-47, FR-70 |
| [0018](0018-permission-catalogue-generated-from-specifications.md) | Permission catalogue generated from OpenAPI and GraphQL specifications | IAM architecture section on the catalogue, FR-1, FR-2, FR-32, FR-36, FR-38 |
| [0019](0019-security-audit-log-and-access-decision-log.md) | Security audit log in PostgreSQL and access-decision log in Loki (draft) | IAM architecture sections 12 to 13, FR-49, FR-50, FR-52, NFR-24 |
| [0020](0020-effective-permissions-composed-at-check-time.md) | Effective permissions composed at check time | IAM architecture section 6, FR-1, FR-39, NFR-16 |
| [0021](0021-rest-and-graphql-parity.md) | REST and GraphQL parity for IAM operations | IAM architecture sections 5.5 and 8, FR-1, FR-19, NFR-7 |
| [0023](0023-allow-list-additions-for-the-gateway.md) | Allow-list additions for the gateway | IAM architecture section 3.1, NFR-6 |
| [0024](0024-freshness-contract.md) | Freshness contract: watermark proof, replica-quorum epoch check, `T_hard` and Sync-Fence (proposed) | IAM architecture sections 9.5 to 9.8, FR-73, NFR-36 |
| [0026](0026-krafka-as-the-kafka-client.md) | krafka as the Kafka client: phase-0 spike results and rdkafka fallback | IAM architecture section 20.4, NFR-30 |
| [0027](0027-rate-limiting-with-valkey-and-its-degradation.md) | Rate limiting with Valkey and its degradation: GCRA script, store timeout, breaker and conservative local limit | IAM architecture section on rate limiting, FR-63, FR-65, NFR-42 |

A downstream service keeps its own records in this directory next to the twelve of the template. To add one, copy the form of an existing record, number it with the next free four-digit prefix and add a row to the table above.
