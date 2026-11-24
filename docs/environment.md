# Environment variables

This is the reference of every variable the template reads: the service settings, the compose and Make variables, and the two test seeds. Each row names the default, the consumer and the name the PHP service template used (empty when there was none). The document-drift check (`make docs-check`, rule 5) keeps this file equal to the sources: the help of `service serve`, `service migrate` and `service healthcheck`, the variables of the four compose files, the names in `.env` and `.env.test`, the variables the `Makefile` and its fragments declare with `?=`, and the keys of `[env]` in `.cargo/config.toml`.

A service that adds variables for its own adapters adds their rows here. The sync never overwrites this file.

## Service settings

"Required" means the command fails with exit status 2 when the variable is missing. Durations use the `humantime` syntax (`500ms`, `2s`, `1m`).

| Name | Type | Default | Required | Consumer | PHP name |
| --- | --- | --- | --- | --- | --- |
| `APP_ENV` | `dev`, `test` or `prod` | `prod` | no | `service` (the GraphQL explorer is on in `dev` only); compose | `APP_ENV` |
| `APP_HOST` | IP address | `0.0.0.0` | no | `service serve`; `service healthcheck` (probes this address, or the loopback address when this one is `0.0.0.0` or `::`) | none (Caddy) |
| `APP_PORT` | integer 0 to 65535 (0 = any free port, for tests) | `8081` | no | `service serve`, `service healthcheck`; compose | listener `:8081` in the Caddyfile |
| `LOG_LEVEL` | `tracing` filter directives | `info` | no | `service serve` (the other commands write plain text) | none |
| `DATABASE_URL` | `postgres://` or `postgresql://` URL | none | yes for `serve`, `migrate`, `migrate revert`, `check-config`, `iam-bootstrap` | `service`; `sqlx-cli`; `#[sqlx::test]`; the end-to-end world | `DB_URL` |
| `DATABASE_LISTEN_URL` | `postgres://` or `postgresql://` URL | `DATABASE_URL` (`.env`: the URL of the compose database, `.env.test`: the test database) | no | `service serve`: the direct, not pooled, connection that holds `LISTEN iam_outbox` of the outbox relay while this replica leads it (Story 7.4); a notification only starts the next relay batch early, because the relay also polls every 100 ms; `check-config` exits 2 for a value that is no PostgreSQL URL | none |
| `DATABASE_MAX_CONNECTIONS` | integer 1 to 100 | `10` | no | `service` | none |
| `DATABASE_ACQUIRE_TIMEOUT` | duration | `2s` | no | `service` | none |
| `DATABASE_STATEMENT_TIMEOUT` | duration, `1ms` to `24d` (`0`, a value below `1ms` and a value above `24d` are rejected) | `5s` | no | `service`, including `service migrate` (see [Migrations and rollback](operations.md#migrations-and-rollback)) | none |
| `DATABASE_WAIT_TIMEOUT` | duration | `30s` | no | `service migrate` (one attempt per second until it elapses) | entrypoint loop, 60 tries |
| `AWS_REGION` | string | none | yes for `serve`, `check-config` | `service` | `AWS_SQS_REGION` |
| `AWS_ENDPOINT_URL_SQS` | `http://` or `https://` URL | unset (regional AWS endpoint) | no | `service` | `AWS_SQS_ENDPOINT_BASE` + `LOCALSTACK_PORT` |
| `AWS_ACCESS_KEY_ID` | string | unset (the provider's default credential chain: role credentials) | no; both keys set or both unset | validated as a pair by `service serve` and `check-config`; the AWS SDK credential chain reads the value | `AWS_SQS_KEY` |
| `AWS_SECRET_ACCESS_KEY` | string | unset (the provider's default credential chain: role credentials) | no; both keys set or both unset | validated as a pair by `service serve` and `check-config`; the AWS SDK credential chain reads the value | `AWS_SQS_SECRET` |
| `SQS_CONNECT_TIMEOUT` | duration | `500ms` | no | `service` | none |
| `SQS_OPERATION_TIMEOUT` | duration | `2s` | no | `service` (attempt and operation timeout) | none |
| `SQS_MAX_ATTEMPTS` | integer 1 to 5 | `1` | no | `service` | none |
| `HEALTH_PROBE_TIMEOUT` | duration | `3s` | no | `service` | none |
| `HTTP_REQUEST_TIMEOUT` | duration | `10s` | no | `service` | none |
| `HTTP_MAX_BODY_BYTES` | integer 1 024 to 10 485 760 | `65536` | no | `service` | none |
| `SHUTDOWN_GRACE_PERIOD` | duration | `10s` | no | `service` | none |
| `JWT_PUBLIC_KEYS_FILE` | path of a file of 1 to 3 PEM RSA public keys, newest last | none (`.env`: the development key file `config/jwt/dev-public-keys.pem`, whose private half is not committed) | yes for `serve`, `check-config` | `service`: `JwtAccessTokenVerifier` tries the keys newest first and reloads the file within 5 s of a change, keeping the last valid key set when a reload fails; `check-config` exits 2 for a file with no key, more than three keys or an unparsable key | none |
| `JWT_ISSUER` | non-empty string | `vilnacrm-user-service` | no | `service`: the required `iss` of every access token | none |
| `JWT_AUDIENCE` | non-empty string | `vilnacrm-api` | no | `service`: the value every access token's `aud` must contain | none |
| `JWT_CLOCK_SKEW` | duration, at most `60s` | `30s` | no | `service`: tolerance of the `exp`, `nbf` and `iat` checks against the `Clock` port | none |
| `MAX_TOKEN_LIFETIME` | duration, at least `1s` | `900s` | no | `service`: a token whose `exp - iat` exceeds it is `token_invalid` | none |
| `TOKEN_MEMO_CAPACITY` | integer, at least `1000` | `200000` | no | `service`: the largest number of verified token identities `MokaTokenMemo` keeps, keyed by the SHA-256 digest of the credential; failed verifications are kept apart, at most 10 000 for 5 s; `check-config` exits 2 below 1000 | none |
| `TOKEN_MEMO_MAX_TTL` | duration, at most `MAX_TOKEN_LIFETIME` | `900s` (capped at `MAX_TOKEN_LIFETIME` when unset) | no | `service`: an identity is memoized for `min(exp - now, TOKEN_MEMO_MAX_TTL)` on the `Clock` port; the revocation state is still checked on every request, and both memos are flushed when the key set of `JWT_PUBLIC_KEYS_FILE` changes; `check-config` exits 2 above `MAX_TOKEN_LIFETIME` | none |
| `JWT_CALLER_AUDIENCE` | non-empty string | `vilnacrm-iam` | no | `service`: the audience a service principal's token must contain in `aud` to call IAM's own API, so that a token issued for calls between other services cannot be replayed to IAM; user tokens are checked against the revocation state instead | none |
| `JWT_SERVICE_TOKEN_MAX_LIFETIME` | duration, at least `1s`, at most `3600s` and at most `MAX_TOKEN_LIFETIME` | `900s` (capped at `MAX_TOKEN_LIFETIME` when unset) | no | `service`: a service principal's token whose `exp - iat` exceeds it is refused with 401 on IAM's own API, because service tokens cannot be revoked by session; `check-config` exits 2 above `3600s` or above `MAX_TOKEN_LIFETIME` | none |
| `MAINTENANCE_INTERVAL` | duration, longer than `0s` | `10m` (`.env`: `10m`) | no | `service serve`: how often the `PolicyMaintenance` singleton runs a pass (Story 7.8). The task polls at the shorter of this value and the 10-second retry interval of a singleton, and a poll that finds the last committed pass younger than this value ends without running anything; `check-config` exits 2 for an unparsable or zero value | none |
| `ORPHANED_GRANT_RETENTION` | duration, longer than `0s` | `90d` (`.env`: `90d`) | no | `service serve`: how long a grant that stayed orphaned (`orphaned_at` set) is kept; a pass purges the grants orphaned strictly longer ago than this, with an audit record each; `check-config` exits 2 for an unparsable or zero value | none |
| `ANTI_ENTROPY_HEAD_INTERVAL` | duration, longer than `0s` | `5s` (`.env`: `5s`) | no | `service serve`: how often the `AntiEntropyChecker` singleton (Story 7.7) runs a head check: it compares the newest `__head` of `POLICY_TOPIC` with PostgreSQL, verifies that the offsets stored for the recent outbox rows still hold the expected versions, and compares the last record by offset of every key written since the previous check with the newest PostgreSQL version of the key; a lost or lower record is published again by clearing `published_at` of its outbox row. The task polls at the shorter of this value and the 10-second retry interval of a singleton; a topic above PostgreSQL raises the topic-ahead alert and holds the relay (see `docs/operations.md`); `check-config` exits 2 for an unparsable or zero value | none |
| `ANTI_ENTROPY_FULL_INTERVAL` | duration, at least `ANTI_ENTROPY_HEAD_INTERVAL` | `10m` (`.env`: `10m`) | no | `service serve`: how often the `AntiEntropyChecker` runs the shadow bootstrap (Story 7.7): it rebuilds the state from the whole topic (highest version per key, tombstones delete, lower relay epochs ignored) and compares the digest with the newest `__head` and with PostgreSQL; a mismatch raises an alert and calls for the resync of Story 7.10; `check-config` exits 2 for an unparsable or zero value, or one shorter than `ANTI_ENTROPY_HEAD_INTERVAL` | none |
| `BULK_CHUNK_ENTITIES` | integer from `1` to `1000` | `1000` (`.env`: `1000`) | no | `service serve`: the most entities one policy version of a bulk change may change (Story 7.9); a change of more changed entities takes the bulk path, which records a pending bulk operation, answers 202 with `Location: /api/bulk-operations/{id}` and lets the `BulkOperationRunner` commit it in chunks of at most this many entities, every revoke-type chunk before every grant-type chunk; `check-config` exits 2 for a value outside 1 to 1000 | none |
| `BULK_MAX_RECORDS_PER_SECOND` | integer of at least `1` | `2000` (`.env`: `2000`) | no | `service serve`: the most records per second the `BulkOperationRunner` commits (Story 7.9); after each chunk the runner waits for the share of a second that the chunk's records use, so a revocation-class write commits between two chunks; `check-config` exits 2 for zero or an unparsable value | none |
| `KAFKA_BOOTSTRAP_SERVERS` | comma-separated `host:port` pairs | none (`.env` and `.env.test`: `${KAFKA_HOST}:${KAFKA_PORT}`, the compose broker) | yes for `serve`, `gateway`, `check-config` | `service`: the control-plane Kafka connection of `KrafkaTopicInspector` (Story 7.3) and of the relay of Story 7.4, and the bootstrap connection of a gateway pod (Story 9.3); the tests of the Kafka adapters read it against the compose broker | none |
| `KAFKA_SECURITY_PROTOCOL` | `SASL_SSL` or `PLAINTEXT` | `SASL_SSL` (`.env`: `PLAINTEXT`, the compose broker) | no | `service`: `PLAINTEXT` is refused unless `APP_ENV` is `dev` or `test` (`check-config` exits 2 naming the variable) | none |
| `KAFKA_SASL_MECHANISM` | `SCRAM-SHA-512` or `SCRAM-SHA-256` | `SCRAM-SHA-512` | no | `service`: read with `SASL_SSL` only | none |
| `KAFKA_SASL_USERNAME` | non-empty string | none | yes with `SASL_SSL` | `service`: the principal of the control plane, `iam-control` in production; ignored with `PLAINTEXT` | none |
| `KAFKA_SASL_PASSWORD` | non-empty string, secret | none | yes with `SASL_SSL` | `service`: the password of the principal; the help, the configuration problems, the spans and the log lines never print it; ignored with `PLAINTEXT` | none |
| `KAFKA_BOOTSTRAP_SASL_USERNAME` | non-empty string | none (`.env`: unset, `PLAINTEXT` needs none) | yes with `SASL_SSL` for `service gateway` and `check-config --mode gateway` | `service gateway`: the principal `iam-gateway-bootstrap` under which a pod reads the state topic from offset 0 (Story 9.3), with the client id of the same name; the gateway does not read `KAFKA_SASL_USERNAME` or `KAFKA_CLIENT_ID`; ignored with `PLAINTEXT`; `check-config --mode gateway` exits 2 naming the variable when it is missing | none |
| `KAFKA_BOOTSTRAP_SASL_PASSWORD` | non-empty string, secret | none (`.env`: unset, `PLAINTEXT` needs none) | yes with `SASL_SSL` for `service gateway` and `check-config --mode gateway` | `service gateway`: the password of `iam-gateway-bootstrap`; the help, the configuration problems, the spans and the log lines never print it; ignored with `PLAINTEXT` | none |
| `KAFKA_CA_FILE` | path of a PEM file | unset (the system roots) | no | `service`: the certificate authority of the Strimzi cluster that the TLS connection trusts; read with `SASL_SSL` only | none |
| `KAFKA_CLIENT_ID` | non-empty string | `iam-control` | no | `service`: the client id of the connection | none |
| `KAFKA_CONNECT_TIMEOUT` | duration | `1s` | no | `service`: the timeout of opening a Kafka connection | none |
| `KAFKA_REQUEST_TIMEOUT` | duration, not shorter than `KAFKA_CONNECT_TIMEOUT` | `2s` | no | `service`: the timeout of one Kafka request, and of an inspection attempt including its retries; `check-config` exits 2 naming the variable when it is shorter than the connect timeout | none |
| `KAFKA_RETRY_DELAY` | duration | `100ms` | no | `service`: the pause between two attempts of a retried Kafka request | none |
| `KAFKA_CONFIG_GATES` | `enforce` or `relaxed` | `enforce` (`.env` and `.env.test`: `relaxed`, the single-node compose broker) | no | `service`: `relaxed` accepts any replication factor and any `min.insync.replicas` of at least 1 and skips the ACL checks, with a warning on every check; it is refused unless `APP_ENV` is `dev` or `test` | none |
| `KAFKA_TRANSACTION_TIMEOUT` | duration from `1s` to `10s` | `10s` (`.env`: `10s`) | no | `service serve`: `transaction.timeout.ms` of the transactional producer `iam-relay` of the outbox relay (Story 7.4); a transaction that does not commit within it is aborted by the broker and its rows are sent again; `check-config` exits 2 for an unparsable value or one outside 1 to 10 seconds (the rule that it stays below `FRESHNESS_HARD_BOUND` is completed in Story 16.1) | none |
| `PUBLISH_WAIT_TIMEOUT` | duration from `100ms` to `30s` | `5s` (`.env`: `5s`) | no | `service serve`: how long a REST or GraphQL write waits, after its commit, for the relay's stored offset of the `__head` row of its policy version (the Kafka acknowledgement with the idempotent relay, the completed commit with the transactional relay); a write whose version is not acknowledged in time returns `202` with `committed_pending_propagation` (REST) or the status `COMMITTED_PENDING` (GraphQL); `check-config` exits 2 naming the variable for an unparsable value or one outside `100ms` to `30s` | none |
| `POLICY_TOPIC` | Kafka topic name | `iam.policy.state.v1` | no | `service`: the state topic whose configuration `KrafkaTopicInspector` checks, the relay publishes to and a gateway pod bootstraps from (Story 9.3); compose (the topic that `kafka-topics` creates) | none |
| `EVENTS_TOPIC` | Kafka topic name, different from `POLICY_TOPIC` | `iam.events.v1` | no | `service`: the topic that every event row of the outbox names, so the relay publishes the IAM events there (Story 7.5); compose (the topic that `kafka-topics` creates); the end-to-end suite sets a topic of its own per scenario | none |
| `GATEWAY_LISTEN` | socket address `host:port` | `0.0.0.0:8443` (`.env`: `0.0.0.0:8443`) | no | `service gateway`: the public listener, TLS when `GATEWAY_TLS_CERT_FILE` and `GATEWAY_TLS_KEY_FILE` are set (TLS 1.3 and 1.2, ALPN `h2` and `http/1.1`), plain HTTP only in `APP_ENV` `dev` and `test` without them; until the pipeline of Story 10.2 exists it answers every request with 503 `iam_stale`; `check-config --mode gateway` exits 2 for an unparsable address or one equal to another listener's (port 0 never clashes) | none |
| `GATEWAY_INTERNAL_LISTEN` | socket address `host:port`, different from the other listeners | `0.0.0.0:9090` (`.env`: `0.0.0.0:9090`) | no | `service gateway`: the internal listener for `iam-control` and the gateway pods (the network policy admits nothing else); it serves `/internal/freshness` and `/internal/policy/applied` from Stories 9.5 and 13.3 | none |
| `GATEWAY_PROBE_LISTEN` | socket address `host:port`, different from the other listeners | `0.0.0.0:9092` (`.env`: `0.0.0.0:9092`) | no | `service gateway`: the probe listener (`/ping`); `service healthcheck --mode gateway` probes `/ping` on it, on the loopback address when its host is `0.0.0.0` or `::` | none |
| `GATEWAY_TLS_CERT_FILE` | path of a PEM certificate chain | none | yes for `gateway` and `check-config --mode gateway` outside `APP_ENV` `dev` and `test`; with `GATEWAY_TLS_KEY_FILE` | `service gateway`: the certificate of the public listener, compared with the file every second and replaced by a new valid pair through an `ArcSwap` certificate resolver; a pair that does not parse is logged (`gateway certificate reload failed`) and the last valid pair stays in force; `check-config --mode gateway` exits 2 when only one of the two files is set, when the pair is unusable or when a file is missing in `prod`; `docker-compose.prod.yml` mounts it from `GATEWAY_TLS_HOST_DIR` | none |
| `GATEWAY_TLS_KEY_FILE` | path of a PEM private key | none | yes for `gateway` and `check-config --mode gateway` outside `APP_ENV` `dev` and `test`; with `GATEWAY_TLS_CERT_FILE` | `service gateway`: the private key that matches `GATEWAY_TLS_CERT_FILE`; read and reloaded with it, and never printed | none |
| `POD_NAME` | text | none (`.env`: `iam-gateway-local`) | no | `service gateway`: the name of the pod, from the Kubernetes downward API, logged in the `listening` entry | none |
| `POD_NAMESPACE` | text | none (`.env`: `local`; compose: `local`) | no | `service gateway`: the namespace of the pod, from the Kubernetes downward API, logged in the `listening` entry; compose | none |
| `UPSTREAM_DISCOVERY` | `kubernetes` or `static` | `kubernetes` (`.env` and `.env.test`: `static`; compose: `static`) | no | `service gateway`: how the gateway learns the endpoints of its upstreams; `kubernetes` watches the EndpointSlices of the Services through the Kubernetes API (read-only `get`, `list` and `watch` on `endpointslices`, the ServiceAccount token and the in-cluster CA, resuming from the last resource version and listing again after a 410), `static` reads `UPSTREAM_STATIC_ENDPOINTS_FILE`; with `kubernetes` the CA file of the ServiceAccount must exist, otherwise the gateway does not start; `check-config --mode gateway` exits 2 naming the variable for another value | none |
| `UPSTREAM_STATIC_ENDPOINTS_FILE` | path of a JSON file mapping a Service name to a list of `{address, port, zone?, pod?, ready?, serving?, terminating?}` | none (`.env`: `config/upstream/dev-static-endpoints.json`; compose: `/etc/service/upstream-endpoints.json`) | yes with `UPSTREAM_DISCOVERY=static` | `service gateway`: the endpoints of every Service, read again every second (a change of the file is a watch event); `ready` and `serving` default to `true`, `terminating` to `false`; the Services of the file are watched in the namespace of `POD_NAMESPACE` (`default` without it); `check-config --mode gateway` exits 2 naming the variable when the file is missing, is not valid JSON of that shape or holds an entry without an address or with an invalid zone | none |
| `UPSTREAM_ZONE_AWARE` | `true` or `false` | `true` | no | `service gateway`: when `true`, a request goes to a ready endpoint of the gateway's own zone, and spills to other zones only when the own zone has no ready endpoint or its in-flight requests per endpoint exceed the spill threshold (`EndpointSelector`, power of two choices on the in-flight counts); `false` chooses among every ready endpoint | none |
| `GATEWAY_ZONE` | 1 to 63 ASCII letters, digits, `-`, `_` or `.` | none | no | `service gateway`: the availability zone of this pod; when unset it is taken from the pod's own entry (matched by `POD_NAME`) in the EndpointSlices of the `iam-gateway-peers` Service in `POD_NAMESPACE`, and stays unknown (no zone preference) while that entry is missing; when set it overrides the peers slices, which is how static mode names its zone | none |
| `TOKIO_WORKER_THREADS` | integer, at least 1 | the number of CPU cores (compose: `2`) | no | tokio, not the service: the multi-thread runtime of `service gateway` reads it when it starts and runs that many worker threads, with at most 16 blocking threads (the `runtime started` entry reports both); compose | none |

Cross-field rules checked at start-up: `HEALTH_PROBE_TIMEOUT >= DATABASE_ACQUIRE_TIMEOUT`; `HEALTH_PROBE_TIMEOUT >= SQS_OPERATION_TIMEOUT`; `HTTP_REQUEST_TIMEOUT > HEALTH_PROBE_TIMEOUT`; the two AWS key variables are both set or both unset (the error names the missing one). `TOKEN_MEMO_MAX_TTL <= MAX_TOKEN_LIFETIME` (the error names `TOKEN_MEMO_MAX_TTL`). A configuration problem never prints the value of a variable. The Kafka rules: `KAFKA_REQUEST_TIMEOUT >= KAFKA_CONNECT_TIMEOUT`; `KAFKA_SECURITY_PROTOCOL=PLAINTEXT` and `KAFKA_CONFIG_GATES=relaxed` only when `APP_ENV` is `dev` or `test` (the error names the variable); `KAFKA_SASL_USERNAME` and `KAFKA_SASL_PASSWORD` with `SASL_SSL`; `POLICY_TOPIC` and `EVENTS_TOPIC` name two different topics. The gateway rules (`service gateway`, `service check-config --mode gateway`, which read no database or queue variable; the Kafka variables they read are `KAFKA_BOOTSTRAP_SERVERS`, `KAFKA_SECURITY_PROTOCOL`, `KAFKA_SASL_MECHANISM`, `KAFKA_CA_FILE`, the timeouts, `KAFKA_CONFIG_GATES`, `POLICY_TOPIC` and `EVENTS_TOPIC` with the rules above, and `KAFKA_BOOTSTRAP_SASL_USERNAME` and `KAFKA_BOOTSTRAP_SASL_PASSWORD`, both required with `SASL_SSL`, so a gateway outside `APP_ENV` `dev` and `test` without them exits 2 naming the variable): `GATEWAY_LISTEN`, `GATEWAY_INTERNAL_LISTEN` and `GATEWAY_PROBE_LISTEN` are three different addresses (the error names the later variable; port 0 never clashes); `GATEWAY_TLS_CERT_FILE` and `GATEWAY_TLS_KEY_FILE` are set together and name a usable pair, and outside `APP_ENV` `dev` and `test` they are required; `JWT_PUBLIC_KEYS_FILE` is required; `UPSTREAM_DISCOVERY=static` needs `UPSTREAM_STATIC_ENDPOINTS_FILE`, which must name a readable, valid endpoints file (the error names `UPSTREAM_STATIC_ENDPOINTS_FILE`); `UPSTREAM_ZONE_AWARE` is `true` or `false`; `GATEWAY_ZONE` is a valid zone label.

## Compose and local stack

| Name | Type | Default | Required | Consumer | PHP name |
| --- | --- | --- | --- | --- | --- |
| `DB_VERSION` | string | `16` | no | compose | `DB_VERSION` |
| `DB_HOST` | host name | `localhost` | no | `.env` interpolation; compose sets `database` inside containers | host part of `DB_URL` |
| `DB_PORT` | integer | `5432` | no | compose (the host port of `database`); `.env` interpolation; compose sets `5432`, the port inside the compose network, in the `app` and `migrate` containers, so a changed host port does not change their URL | `DB_PORT` |
| `DB_NAME` | string | `app` | no | compose; `.env` interpolation | `DB_NAME` |
| `DB_USER` | string | `app` | no | compose; `.env` interpolation | `DB_USER` |
| `DB_PASSWORD` | string | `local-dev-only` | no | compose; `.env` interpolation | `DB_PASSWORD` |
| `LOCALSTACK_HOST` | host name | `localhost` | no | `.env` interpolation; compose sets `localstack` inside containers | `AWS_SQS_ENDPOINT_BASE` |
| `LOCALSTACK_PORT` | integer | `4566` | no | compose (the host port of `localstack`); `.env` interpolation; compose sets `4566`, the port inside the compose network, in the `app` container | `LOCALSTACK_PORT` |
| `KAFKA_HOST` | host name | `localhost` | no | `.env` interpolation of `KAFKA_BOOTSTRAP_SERVERS`; compose sets `kafka` inside the `app` container | none |
| `KAFKA_PORT` | integer | `9092` | no | compose (the host port of `kafka`, and the port its `PLAINTEXT` listener advertises); `.env` interpolation; compose sets `19092`, the in-network listener, in the `app` container | none |
| `KAFKA_SASL_SSL_PORT` | integer | `9094` | no | compose (the host port of the `SCRAM_HOST` listener of `kafka`, SASL SCRAM-SHA-512 over TLS, and the port it advertises); `.env` interpolation of `KAFKA_SASL_SSL_BOOTSTRAP_SERVERS`; compose sets `19094`, the in-network `SCRAM_DOCKER` listener, in the `app` container | none |
| `STRUCTURIZR_PORT` | integer | `8080` | no | compose | `STRUCTURIZR_PORT` |
| `GATEWAY_PORT` | integer | `8443` | no | compose (the loopback host port of the public listener of `iam-gateway`, which listens on `8443` inside the container) | none |
| `GATEWAY_TLS_HOST_DIR` | path on the host | none (required by `docker-compose.prod.yml` for `iam-gateway`) | no | compose: the directory with `tls.crt` and `tls.key`, mounted read-only at `/etc/service/tls` and named by `GATEWAY_TLS_CERT_FILE` and `GATEWAY_TLS_KEY_FILE` | none |
| `UPSTREAM_ENDPOINTS_HOST_FILE` | path on the host | `./config/upstream/dev-static-endpoints.json` (required by `docker-compose.prod.yml` for `iam-gateway`) | no | compose: the endpoints file mounted read-only at `/etc/service/upstream-endpoints.json` and named by `UPSTREAM_STATIC_ENDPOINTS_FILE` | none |
| `JWT_PUBLIC_KEYS_HOST_FILE` | path on the host | `./config/jwt/dev-public-keys.pem` (required by `docker-compose.prod.yml`) | no | compose: mounted read-only as the `JWT_PUBLIC_KEYS_FILE` of the `app` container built from the production image | none |
| `GITHUB_TOKEN` | token | unset | no | compose: the source of the build secret `github_token` of the development image; raises the rate limit of the tool downloads | none |

## Test seeds

The two seeds are test settings, not service settings. Cargo passes them to every test process from `[env]` of `.cargo/config.toml`, and a value set by the caller wins. `make` forwards both into the development container. The other two rows are build settings from the same `[env]` table. `KAFKA_SASL_SSL_BOOTSTRAP_SERVERS` and `KAFKA_TLS_DIR` are test settings of `.env.test`, which the test targets export; since Story 1.7 removed the krafka spike tests no test reads them until the SCRAM tests of Epic 7.

| Name | Type | Default | Required | Consumer | PHP name |
| --- | --- | --- | --- | --- | --- |
| `TEST_SEED` | unsigned 64-bit integer | `20261110`, the seed recorded in `.cargo/config.toml` | no | `test_support::seed::TestRng` | none (the PHP data was unseeded) |
| `PROPTEST_RNG_SEED` | unsigned 64-bit integer | `20261110`, recorded in `.cargo/config.toml` | no | property tests (`proptest` reads it) | none |
| `KAFKA_SASL_SSL_BOOTSTRAP_SERVERS` | `host:port` | `${KAFKA_HOST}:${KAFKA_SASL_SSL_PORT}` from `.env.test` | no | no test reads it since Story 1.7 removed the SCRAM spike test (Story 1.5); kept for the Kafka adapter tests of Epic 7 against the SASL_SSL listener of the compose broker | none |
| `KAFKA_TLS_DIR` | absolute path | `${PWD}/target/kafka-tls` from `.env.test` | no | the directory where the compose service `kafka-tls` writes the TLS material of the broker with `scripts/kafka-tls-fixture.sh` before the broker starts (Story 1.5); no test reads it since Story 1.7 removed the SCRAM spike test, and it is kept for the Kafka adapter tests of Epic 7 | none |
| `SQLX_OFFLINE` | `true` | `true` from `.cargo/config.toml` | no | sqlx macros at build time | none |
| `SWAGGER_UI_DOWNLOAD_URL` | `vendored-only` | `vendored-only` from `.cargo/config.toml` | no | the build script of `utoipa-swagger-ui`: with the `vendored` feature it uses the embedded assets and ignores the value; without the feature the build stops instead of downloading Swagger UI (FR8) | none |

## Make variables

Every variable a caller may set, except `PROJECT_NAME` (see below the table), is declared with `?=` in the `Makefile` or in one of its two fragments, so the caller's value always wins. Pass them on the command line (`make start BUILD_IMAGE=0`) or through the environment. `TEST_SEED` and `PROPTEST_RNG_SEED` are not Make variables; see the seeds above.

| Name | Default | Consumer | PHP name |
| --- | --- | --- | --- |
| `COMPOSE_PROJECT_NAME` | `$(PROJECT_NAME)`; a value set by the caller is kept | exported to Compose | none |
| `RUN_IN_CONTAINER` | empty | `1` or `true`: targets of class TOOL run in the `app` container | none |
| `CI` | from the environment | non-empty: native mode is forced, `COMPOSE_PROFILES` defaults to empty and `CARGO_BUILD_WARNINGS=deny` is exported | `CI` |
| `IN_DEV_CONTAINER` | from the environment (`1` in the `app` container of the development environment) | native mode is forced; `ensure-deps` and `ensure-database` start nothing | none |
| `CARGO_BUILD_WARNINGS` | `deny` when `CI` is set and inside `make ci`; otherwise from the environment | Cargo's `build.warnings`; unset again for cargo-mutants | none |
| `DOCKER` | `docker` | exported; container engine command, also used by the scripts | `DOCKER` |
| `DOCKER_COMPOSE` | `docker compose` | exported; Compose command, also used by the scripts | `DOCKER_COMPOSE` |
| `HOST_UID` | `$(shell id -u)` | exported; user of the development container and of `docker run` tools | none |
| `HOST_GID` | `$(shell id -g)` | exported; group of the development container and of `docker run` tools | none |
| `COMPOSE_PROFILES` | `docs` (empty when `CI` is set) | exported; `docs` starts the Structurizr viewer | none |
| `APP_IMAGE` | `$(PROJECT_NAME)-app:prod` | exported; image name used by the compose files | none |
| `DEV_IMAGE` | `$(PROJECT_NAME)-app:dev` | exported; image name used by the compose files | none |
| `BUILD_IMAGE` | `1` | exported; `0`: `start`, `build-prod-image` and the isolated-environment wrapper use images that are already built and pass `--no-build` | none |
| `DEPS` | `database localstack` | compose services that `start-deps` starts | none |
| `base_ref` | `origin/main` | base of `validate-configuration`, `openapi-diff`, `graphql-diff` and `mutation-tests-diff` | `base_ref` |
| `CONFIG_CHANGE_APPROVED` | empty | `true` waives the approval of a protected-configuration change (set by CI from the label) | none |
| `BREAKING_CHANGE_APPROVED` | empty | `true` waives the approval of a breaking API change (set by CI from the label) | none |
| `LOAD_TEST_PROJECT` | `$(PROJECT_NAME)-load` | exported; compose project of the isolated production-image environment | none |
| `LOAD_TEST_APP_PORT` | `18081` | exported; host port of the service in that environment | none |
| `SCHEMATHESIS_URL` | `http://localhost:$(LOAD_TEST_APP_PORT)` | target of Schemathesis; when the caller sets it nothing is started | `SCHEMATHESIS_URL` |
| `scenario` | empty | parameter of `execute-load-tests-script` | `scenario` |
| `runSmoke` | `true` | parameter of `execute-load-tests-script` | `runSmoke` |
| `runAverage` | `true` | parameter of `execute-load-tests-script` | `runAverage` |
| `runStress` | `true` | parameter of `execute-load-tests-script` | `runStress` |
| `runSpike` | `true` | parameter of `execute-load-tests-script` | `runSpike` |
| `LOCAL_MODE_ENV` | `false` | `true`: the AWS load scripts talk to LocalStack | none |
| `region` | empty (the script default applies) | `aws-load-tests`, passed as `-r` | none |
| `ami` | empty (the script default applies) | `aws-load-tests`, passed as `-a` | none |
| `instance_type` | empty (the script default applies) | `aws-load-tests`, passed as `-t` | none |
| `instance_tag` | empty (the script default applies) | `aws-load-tests`, passed as `-i` | none |
| `role` | empty (the script default applies) | `aws-load-tests`, passed as `-o` | none |
| `branch` | empty (the script default applies) | `aws-load-tests`, passed as `-b` | none |
| `repo_url` | empty (the `origin` remote is used) | `aws-load-tests`, passed as `-u` | none |
| `security_group` | empty (the script default applies) | `aws-load-tests`, passed as `-s` | none |
| `load_target` | empty (the script default applies) | `aws-load-tests`, passed as `-l` | none |
| `name` | empty | parameter of `create-migration` (snake_case description) | none |
| `group` | empty | parameter of `new-context` | none |
| `context` | empty | parameter of `new-context` | none |
| `MUTANTS_SHARD` | empty | `k/n`: adds `--shard k/n` to `mutation-tests` and `mutation-tests-diff` | none |
| `MUTANTS_IN_PLACE` | empty | set by CI only: exactly `1` adds `--in-place` to `mutation-tests` and `mutation-tests-diff`, so cargo-mutants builds in the checkout and reuses the restored `target/` (NFR40); any other value adds nothing. Leave it unset locally: in place, cargo-mutants rewrites source files of the working tree while it runs | none |
| `ARCH_ARGS` | empty | test hook of the negative Bats tests (`architecture`) | none |
| `DENY_ARGS` | empty | test hook of the negative Bats tests (`check-security`) | none |
| `BATS_PATH` | `tests/CLI/bats` | test hook: the suite `bats` runs | none |
| `BATS_ARGS` | empty | extra arguments of `bats`, for example a tag filter | none |
| `DOCKERFILES` | `Dockerfile` | test hook: the files `lint-docker` checks | none |
| `IMAGE_TO_SCAN` | empty | test hook: the image `image-scan` scans instead of the production image | none |
| `OPENAPI_DIFF_IMAGE` | the pinned oasdiff image | overrides the image of `openapi-diff`; the PHP variable name is kept | `OPENAPI_DIFF_IMAGE` |
| `CI_STAGES` | the seven stages of `make ci` | stages run by `ci`; lets Bats test the aggregate without running it | none |
| `BMALPH_PLATFORM` | `claude-code` | parameter of the bmalph targets (`claude-code` or `codex`) | none |
| `BMALPH_DRY_RUN` | `false` | `true`: the bmalph targets preview without changing files | none |

Four names that the `Makefile` computes are not rows of the table, because the drift check keeps the table equal to the `?=` declarations. `PROJECT_NAME` is the Compose project name and the prefix of the image names: the caller's `COMPOSE_PROJECT_NAME` when set, else the checkout directory name, lower-cased with characters outside `a-z0-9_-` replaced by `-`; a value from the command line or the environment wins. `EXEC` is the prefix of every class TOOL command: empty, or `docker compose exec -T --user <uid>:<gid> -e … app`; it is computed and not meant to be set. `EXEC_ENV` lists the variables that `EXEC` forwards into the container (`TEST_SEED PROPTEST_RNG_SEED CONFIG_CHANGE_APPROVED CARGO_BUILD_WARNINGS DATABASE_STATEMENT_TIMEOUT`; the last one lets `DATABASE_STATEMENT_TIMEOUT=30m make migrate` reach the container). `TEST_ENV` is the prefix of commands that need the test configuration (`env -u DATABASE_URL scripts/with-env.sh .env .env.test --`): the caller's `DATABASE_URL` is removed first, so the test targets always use the database of `.env.test` (see "Committed environment files").

## PHP-to-Rust name mapping

| PHP name | Rust name | Note |
| --- | --- | --- |
| `DB_URL` | `DATABASE_URL` | the URL is built from the `DB_*` parts in `.env` |
| `AWS_SQS_REGION` | `AWS_REGION` | the standard AWS name |
| `AWS_SQS_KEY`, `AWS_SQS_SECRET` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | the standard AWS names; both or neither |
| `AWS_SQS_ENDPOINT_BASE` and `LOCALSTACK_PORT` | `AWS_ENDPOINT_URL_SQS` | one URL; in `.env` it is built from `LOCALSTACK_HOST` and `LOCALSTACK_PORT` |
| `APP_ENV`, `DB_VERSION`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `LOCALSTACK_PORT`, `STRUCTURIZR_PORT` | same names | kept |

PHP variables that are not carried over: `APP_SECRET`, `AWS_SQS_VERSION`, `EMAIL_QUEUE_NAME`, `MESSENGER_TRANSPORT_DSN`, `CADDY_MERCURE_JWT_SECRET`, `SERVER_NAME`, `APP_RUNTIME_HTTP_ENV`, `XDEBUG_MODE`, `KERNEL_CLASS`, `PANTHER_*`, `SYMFONY_DEPRECATIONS_HELPER`, `LOAD_TEST_CONFIG`, `HTTP_PORT`, `HTTPS_PORT` and `HTTP3_PORT`. The framework, the mail queue, Mercure, the Caddy server and the PHP debugger have no counterpart in the Rust service.

## Committed environment files

`.env` and `.env.test` are tracked and are not git-ignored. They hold placeholders for the local compose stack only: nothing in them is a secret, and a value must never be reused outside a developer machine.

- `.env` holds the development defaults, for the compose stack and for `cargo run -p service -- serve`.
- `.env.test` holds only the values that differ from `.env` (`APP_ENV=test`, `LOG_LEVEL=warn` and a `DATABASE_URL` that ends in `_test`), so each value is defined in one place. It is always read after `.env`.
- `${NAME}` references are resolved by the service (`dotenvy`), by Docker Compose and by `scripts/with-env.sh`, and in all three a value already present in the process environment wins. That is how the same file works on a host (`localhost`) and inside a container, where compose sets `DB_HOST=database` and `LOCALSTACK_HOST=localstack` and the in-network ports `DB_PORT=5432` and `LOCALSTACK_PORT=4566`, so a host port changed in `.env` changes only what compose publishes.
- The test targets run with the variables of `.env` and then of `.env.test` exported (`env -u DATABASE_URL scripts/with-env.sh .env .env.test --`); a variable the caller has already set overrides both, with one exception: `DATABASE_URL` is removed from the caller's environment first, so the test targets always use the `_test` database of `.env.test` and never the database that a `DATABASE_URL` exported in the shell names (for `sqlx-cli`, for example). To move the test database, set `DB_PORT`, `DB_HOST` or `DB_NAME`: the URL of `.env.test` is built from them. `scripts/setup-test-db.sh`, which drops and recreates its database, additionally refuses with status 2 any database whose name does not end in `_test`. The `Makefile` includes neither file.
- `scripts/with-env.sh` reads a value like the service and Compose do, for the forms the three read the same way: `NAME=value`, a value in double quotes (`\"`, `\\` and `\n` are unescaped) or in single quotes (literal), and an inline comment after whitespace (`NAME=value # comment`). It refuses with status 2 the forms they read differently: an unquoted value that holds whitespace, a quote or a backslash, a `$` that does not start `${NAME}`, an unknown escape, a quote that does not close on its line, and a comment right after the `=`. Write such a value in quotes.
- Sourcing a file in a shell (`set -a; . ./.env`) overrides the caller's values and must not be used.
- The production image contains no env file. Supply every required variable at run time: `DATABASE_URL` and `AWS_REGION` have no default.
