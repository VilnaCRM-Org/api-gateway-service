# Service targets

The targets that api-gateway-service adds to the template's Makefile. They are defined in make/service.mk, which the `Makefile` loads with `-include`, so a template sync never changes them. The template's targets are documented in [make-targets.md](make-targets.md); the documentation check requires every target of make/service.mk to have a row here.

## All service targets

| Target | Class | Needs | In `make ci` | Help text |
| --- | --- | --- | --- | --- |
| `bench-spikes` | TOOL | none | no | Run the phase-0 spike benches (RS256 verify, GraphQL parse); never part of make ci |
| `schemathesis-iam` | TOOL | Docker | no | Run Schemathesis with an ephemeral ROLE_SERVICE token so it reaches the IAM operations past the 401; never part of make ci |

## `bench-spikes`

Runs the criterion benches of `crates/service/benches/spikes/main.rs` with `cargo bench --locked -p service --bench spikes` and copies the output to `target/reports/bench-spikes/spikes.txt`. It measures RS256 verification with one and with three trusted keys tried newest first, and `async-graphql-parser` on generated documents of 1, 5, 8 and 64 KiB. After criterion's own estimates, a latency pass times 10 000 calls of every operation one by one and prints the median and the p99 per operation, together with the CPU model of the host.

The RSA key pairs are generated through `aws-lc-rs` when the bench starts and the tokens are signed then; no key and no token is stored in the repository. The figures are measurements of the host that ran the bench and are recorded as such in [spikes/phase-0.md](spikes/phase-0.md); they are never gate values, which is why the target is not part of `make ci`.

## `schemathesis-iam`

Runs `make schemathesis-validate` with credentials for IAM's own operations, which require a bearer token (`bearerAuth`) and answer 401 without one. `scripts/schemathesis-iam.sh` generates an RSA key pair with `openssl` in a temporary directory, signs a ten-minute `ROLE_SERVICE` token with RS256 that names the audiences `JWT_AUDIENCE` and `JWT_CALLER_AUDIENCE` (the caller rule of FR-3), mounts the public half as the key file of the service under test through `JWT_PUBLIC_KEYS_HOST_FILE`, and passes the token to Schemathesis as an `Authorization` header through `SCHEMATHESIS_FLAGS`. Schemathesis therefore reaches the token-resolution operation past the 401 and checks its documented responses.

No key and no token is committed or kept: the temporary directory is removed on every exit path, and the template `Makefile` and `make/gates.mk` are unchanged. The plain `make schemathesis-validate` of `make ci` keeps running without a token, so it checks the 401 path of the IAM operations only.
