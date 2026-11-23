# 0015. IAM is the API gateway: split planes, one image, two run modes

Status: accepted. Story 9.2 of the pull request of issue #8 implements the run modes; the pipeline of the public listener follows in Story 10.2.

Planning decisions: the decision table of `specs/8-iam-scaffolding-and-spikes/architecture.md` (record 0015, which replaces the earlier plan of invalidation workers as tasks of the single binary), requirements FR-45, FR-54, FR-55 and FR-67 and NFR-31 of its `prd.md`.

## Context

IAM decides every request that reaches the platform, so the component that enforces the decision sits on the request path of every service. Two kinds of work have opposite needs. The control plane (administrative writes, the policy log, the outbox relay, the audit log) needs PostgreSQL, Kafka credentials with write access and the management API. The data plane (TLS termination, token verification, the decision, the forwarding) needs only a replicated, read-only snapshot, must keep serving while PostgreSQL is down, and is the part that faces the network. A compromised data-plane pod must not be able to write the policy or reach the database.

## Decision

IAM is the API gateway, and it runs as two planes of one build:

- `iam-control` runs `service serve`: the management API, PostgreSQL and the Kafka producer.
- `iam-gateway` runs `service gateway`: the data plane. It has no database setting, never creates a PostgreSQL pool, and parses the JWT key set when it starts.
- Both are run modes of the same image. `service check-config --mode gateway|control` and `service healthcheck --mode gateway|control` select the mode (`control` is the default and keeps the template behaviour).
- The gateway opens three listeners: the public listener on `GATEWAY_LISTEN` (rustls with TLS 1.3 and 1.2, ALPN `h2` and `http/1.1`, a certificate pair hot-reloaded through an `ArcSwap` certificate resolver that keeps the last valid pair when a reload fails; plain HTTP only in `APP_ENV` `dev` and `test` without the files), the internal listener on `GATEWAY_INTERNAL_LISTEN` (reached only from `iam-control` and the gateway pods) and the probe listener on `GATEWAY_PROBE_LISTEN`, whose `/ping` never depends on Kafka, PostgreSQL or an upstream.
- The isolation of the planes is by credentials (the gateway holds no database credential and a read-only Kafka identity) and by network policy (the internal listener admits only `iam-control` and gateway pods).
- Until the pipeline of Story 10.2 exists, the public listener answers every request with 503 `iam_stale` and `Retry-After: 1`: no snapshot is published, and the gateway fails closed.
- The gateway runtime is built by `command/gateway.rs` with at most 16 blocking threads; tokio reads `TOKIO_WORKER_THREADS` for the worker count.

| Option | Outcome | Reason |
| --- | --- | --- |
| One image, two run modes | Chosen | One build, one supply chain and one set of scans; the planes still differ in credentials, ports and network policy |
| One binary that serves both planes in one process | Rejected | The data-plane pod would hold the database and write credentials, and a fault of the control plane would take the data plane down |
| Two images | Rejected | Two builds to keep identical for the shared domain and token code, with no isolation gain over two run modes |
| Envoy with `ext_authz` | Rejected | Every request would pay a network hop to the decision service, and the decision needs the in-process snapshot |
| Pingora | Rejected | A second runtime and a second language of extension for logic that the Rust service already holds |
| TLS terminated at the network load balancer | Rejected | The gateway must see the client's TLS parameters and rotate its own certificate; the load balancer balances connections, the gateway balances requests |

## Consequences

The Dockerfile, `command/check_config.rs`, `command/healthcheck.rs` and their tests and integration tests are seam files: they are listed in `.templatesyncignore`, and the seam check of Story 1.2 covers them. The sockets of the gateway are owned by `command/gateway.rs`, named in the socket-owner list of `docs/architecture.md`. The container health check of the gateway is `service healthcheck --mode gateway`. A later story that adds a listener (the decision API of Story 12.1, the mesh listener of Story 15.1) adds a variable, a row of `docs/environment.md` and an owner here.
