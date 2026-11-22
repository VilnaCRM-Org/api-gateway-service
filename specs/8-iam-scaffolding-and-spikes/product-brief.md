# Product Brief: The VilnaCRM API Gateway with IAM

| Field | Value |
| --- | --- |
| Bundle | `specs/8-iam-scaffolding-and-spikes/` |
| Issue | `#8` "Scaffold the IAM context and run the phase-0 spikes" (VilnaCRM-Org/api-gateway-service); one pull request delivers all 16 epics (owner decision, 2026-11-22) |
| Date | 2026-11-22 (derived from the master plan of 2026-11-21) |
| Source of scope | Owner decisions on the Miro C4 board (IAM frames): plan everything in IAM's system context, including REST/OpenAPI permissions and security and access logs; expose every capability over REST and GraphQL. Owner decisions of 2026-11-21: IAM is the API gateway itself, Kafka carries the updates, Kubernetes on AWS EKS, and the decided items D1, D2, D3, D4, D6 (part), D7, D8, D9, D13, D14a, D14b and D15 recorded in `research.md` section 19 (D5, D10, D11, D12 and D16 to D28 stay open with defaults); owner decision of 2026-11-22: all 16 epics ship in one pull request for issue #8 |
| Supersedes | The first version of this brief, which described IAM as a decision service called by a separate gateway |

## Product

IAM is the VilnaCRM API gateway with identity and access management built in. Every request from the website, the CRM front end and partner integrations enters through IAM. For each request IAM terminates TLS, verifies the User service token, decides whether the caller may use the requested REST operation or GraphQL fields, and proxies the request to the owning service. The decision is made in the gateway's own memory from a policy snapshot that every gateway pod keeps up to date from one ordered Kafka topic. IAM also provides the management API (roles, permissions, assignments, routes, rate limits, revocations, logs) over REST and GraphQL with full parity.

Authentication stays in User service. IAM verifies the tokens that User service issues; it never signs in a user.

IAM runs on Kubernetes (AWS EKS) as one image in two run modes: `iam-gateway`, the data plane, and `iam-control`, the control plane, which owns PostgreSQL, the management API and the Kafka relay.

## Current State of the Target Repository

The product is built in `api-gateway-service` (VilnaCRM-Org/api-gateway-service), a fresh copy of the Rust service template whose service is named "VilnaCRM API Gateway" (`research.md` section 1):

- A Rust 1.99.1 workspace (edition 2024) with thirteen members: the template's example context `company-subdomain/some-module`, `internal/health-check`, the `shared` kernel, the composition root `crates/service`, and `tests/e2e`, `tests/support`, `xtask`. No IAM code exists on `main`.
- Story 1.1 ("Scaffold authorization/iam") is already implemented in the working tree of branch `feat/8-iam-scaffolding-and-spikes`, uncommitted: the three IAM crates under `crates/authorization/iam/` with the policy-epoch slice, the migration `create_iam_policy_epoch`, ADRs 0013 and 0014, the IAM smoke scenario and the composition-root wiring of `service serve`, with no public operation yet.
- `architecture.toml` (protected) allows no Kafka, HTTP-client, JWT or JSON crate in the infrastructure layer today; the owner-approved ADR 0023 delta that adds them is applied in Story 2.3. The composition root accepts any crate, so the phase-0 spikes add `krafka`, `jsonwebtoken`, `criterion` and `aws-lc-rs` as dev-dependencies of `crates/service` without a protected change.
- `deny.toml` bans `openssl-sys` and `native-tls` and sets `unmaintained = "all"`; `aws-lc-rs` is already in `Cargo.lock`.
- The profile `.claude/rust-sdlc.yml` maps every `make.*` key to the target of the same name; `make ci` has seven stages (`ci-preflight`, `ci-static-analysis`, `ci-tests`, `ci-contracts`, `ci-mutation`, `ci-delivery`, `ci-cli`).
- The mutation matrix is 8 shards of at most 150 mutants with a 45-minute timeout; the push step runs the whole workspace until Story 1.8 changes it to a diff run.
- On the developer machine host ports 8080, 8081 and 18081 are taken, so local runs set `APP_PORT=28081`, `STRUCTURIZR_PORT=28080` and a free `LOAD_TEST_APP_PORT`.

## Delivery

All sixteen epics (127 stories, 85 functional and 37 non-functional requirements) ship in one pull request for issue #8 (owner decision, 2026-11-22). Story 1.1 runs first and alone; the phase-0 spikes of Epic 1 and the Kafka client decision of Story 1.7 come before any Kafka-dependent epic; Story 2.3 applies the owner-approved allow-list change; the FR/NFR review gate traces every requirement to test evidence in the one pull request.

## Problem

VilnaCRM is a set of microservices, and nothing in front of them decides centrally who may call which operation:

- User service authenticates people and issues signed access tokens, but its users have no roles or permissions beyond a hard-coded `ROLE_USER` or `ROLE_SERVICE` claim.
- Core service has no authentication or authorization configuration at all, so whatever sits in front of it is its only enforcement point.
- The organisation's gateway repository is an empty infrastructure template. The planned design was a managed AWS API Gateway with a WAF and an internal load balancer; it has no authorizer and no per-operation policy.
- Each service that wants access control would have to invent its own rules, its own role storage and its own way to read tokens, which leads to inconsistent decisions, duplicated security code and no single place to answer "who can do what" or "who did what".
- A separate gateway that calls a separate authorization service on every request adds a network hop and a second point of failure to every call. At gateway traffic that hop and its per-request lookups do not scale.

The Miro board assigns the authorization responsibility to an IAM microservice that "provides auth cache and authorization management, security and access logs". The owner has decided that this service is also the gateway. The `iam-service` repository is an unmodified copy of the Rust service template and contains none of it yet.

## Users

| User | What they need from the gateway and IAM |
| --- | --- |
| **Customers and their client applications** (the public website, the protected CRM front end, partner integrations) | A fast, single entry point. Public routes (sign-in, token refresh, registration) stay open; every other route is protected. A request they are not allowed to make is denied with a clear status, and a revoked session stops working within seconds. WebSocket, SSE and GraphQL subscriptions work through the same entry point |
| **CRM administrators** | Create and maintain roles, choose which REST operations and GraphQL fields each role may use, assign roles to users globally or per project, see a user's effective permissions, revoke sessions, and see the effect of a change at once. Everything is available over REST and over GraphQL |
| **Service teams** (Core, Notification, Payment, Analytics and the rest) | Register their upstream, routes and OpenAPI and GraphQL contracts so that their operations become permissions; see which permissions a new specification version adds or orphans; rely on the identity headers the gateway adds instead of parsing tokens; receive IAM change events (Notification service tails `iam.events.v1`) |
| **Security and compliance staff** | A tamper-evident record of every administrative change and rejected attempt; a queryable record of access decisions (all denials, sampled allows, always-audited operations); evidence that tokens and personal data are not leaked into logs |
| **Operators** | Health that reflects real freshness, not just liveness; bounded and observable policy propagation; a way to resync policy state and to revoke sessions in an incident; reference manifests for Kubernetes, Kafka, Valkey and Loki; a single image that deploys like every other template-based service |

## Goals

1. **One entry point that authenticates, authorizes and proxies.** Every protected REST operation and GraphQL field of every registered service is denied by default and allowed only through roles that administrators manage and permissions generated from each service's own published contract.
2. **A hot path fast enough to sit on every request.** The decision uses only the pod's own memory: no database, no Kafka call, no cross-pod lock and no external cache on the warm path. No path allows on error.
3. **Bounded staleness that fails closed.** A gateway pod allows a request only while it can prove that its snapshot contains every policy change Kafka acknowledged more than a hard bound earlier. A revocation reaches every healthy pod in under a second typically and is never allowed past the hard bound, `T_hard` (15 s now, 5 s target).
4. **Complete, trustworthy logs.** No administrative change without an audit record in PostgreSQL; denials and always-audited operations recorded in Loki; no raw tokens or request contents in any log.
5. **Interface parity.** Every IAM management capability, including routes, upstreams, rate policies, revocations and log queries, is available over REST and over GraphQL with the same behaviour.
6. **Horizontal scale on Kubernetes.** The first release is sized for 1,000 rps at peak with a small fleet chosen for zone availability; adding pods adds capacity in proportion, and mechanisms needed only at tens of pods are documented for later.
7. **Template conformity.** The service meets every repository bar as shipped (100% coverage, zero surviving mutants, complexity limits, layer boundaries, contract gates) and stays compatible with template synchronisation.

## Scope

### In scope

- **Gateway data plane.** Route matching by host and path, upstream registry, TLS termination in the pod behind an AWS Network Load Balancer, a pooled proxy to upstream services with zone-aware endpoint selection, timeouts, retries only where safe, body limits, circuit breaking and load shedding, request ids, identity headers to upstreams, and WebSocket, SSE and GraphQL subscription pass-through with per-subscription authorization, re-evaluation on policy change, lifetime caps and drain on shutdown.
- **Authentication.** Offline RS256 verification of User service tokens with configured public keys, a per-pod token memo, and an anonymous-route mechanism for public routes.
- **Authorization.** Decisions for REST operations (method and path) and GraphQL documents (field coordinates, all-or-nothing), with reason codes, scopes and the policy version; a decision API for single checks, batches and token resolution on the internal listener; GraphQL and OpenAPI specification ingestion, permission generation, retirement, diffs and orphaned-grant handling; scoped RBAC with deny by default.
- **Management API with REST and GraphQL parity.** Roles and grants; user-role assignments at global or project scope; effective permissions; upstreams, routes and route configuration with dry run; rate policies; session revocations and global token cut-offs; policy propagation status and write fences; policy resync; bulk operations.
- **Replication and freshness.** Transactional outbox in PostgreSQL, a fenced relay to the compacted Kafka state topic, group-less tails and snapshot bootstrap in every gateway pod, digest checks, a freshness proof, read-your-writes through a policy-version header, and Sync-Fence writes that return when every pod has applied the change.
- **Kafka.** IAM produces `iam.policy.state.v1` and `iam.events.v1` and consumes the User service topic `user.events.v1` in the control plane (session revoked, all sessions revoked, refresh-token theft, user deleted).
- **Rate limiting.** Local limits in every pod and exact global quotas through Valkey on routes that carry a rate policy, with a bounded timeout and a per-pod fallback.
- **Logs.** Hash-chained security audit log in PostgreSQL (write, query, integrity verification, retention); access-decision log in Loki with a query API served by the control plane.
- **Kubernetes operations.** Reference manifests for the two Deployments, probes gated on policy freshness, autoscaling, disruption budgets, topology spread, graceful shutdown, network policies; platform resources for Strimzi Kafka, Valkey, Loki and Grafana Alloy.
- **Phase-0 proof.** Spike stories that verify every Kafka client capability the freshness guarantee relies on, and the benchmark that replaces every estimate in this bundle with a measurement.
- **Housekeeping.** Authentication of IAM's own API, the first-administrator bootstrap, idempotency and optimistic concurrency for administrative writes, health probes, configuration, documentation, contract snapshots, end-to-end and load tests.

### Out of scope

- **Authentication itself** (sign-in, registration, OAuth, 2FA, cookies, token issuance): owned by User service.
- **The changes to other services.** User service must publish its four session and user events to Kafka; Notification service must tail `iam.events.v1`. They are external prerequisites that IAM's plan states; they are not work in this repository.
- **Object-level authorization** (may this user read record 42): stays in the owning service, using the identity and scopes the gateway supplies.
- **Large-fleet mechanisms** for tens or hundreds of pods: upstream subsetting, peer snapshot bootstrap, bulk-egress pacing beyond a simple cap, token-memo dilution work, follower fetching, per-AZ autoscaling and 200-pod rollout targets. They are documented as later-phase items with their triggers.
- **A WAF or DDoS layer** in front of the load balancer (open owner decision).
- **A strict freshness mode** that counts from the PostgreSQL commit, a separate gateway binary without database code, persisted queries and a first-party allow-list mode: later-phase items.
- **Explicit deny rules, attribute- or relationship-based policies, partial GraphQL responses, a tenant scope level and OpenAPI YAML uploads.**
- **League OAuth2 tokens** issued by User service's OAuth sub-context, which no VilnaCRM resource server accepts today. This narrows the owner's system-context scope, so it is recorded as a deviation from the board and left for the owner to confirm.
- **DynamoDB, DAX** and an external cache for authorization data. Valkey holds rate-limit counters only.
- **Removal of the template's example context** and of the template's own planning bundle.

## Success Criteria

Each criterion is measurable and traced to a goal. The PRD turns them into numbered requirements. Every performance figure below is a **target** that a phase-0 benchmark must confirm; nothing has been measured on VilnaCRM code or hardware, and the supporting figures in `research.md` section 17 are estimates.

| # | Criterion | Measure and target | Goal |
| --- | --- | --- | --- |
| S1 | Every request to a protected operation of a registered service gets an allow or deny decision, and an operation absent from the service's active specifications is denied | End-to-end scenarios over REST and GraphQL; zero false allows on the maintained decision corpus and the fault suite | 1 |
| S2 | **Latency.** Gateway residence time for a warm REST request (time inside the gateway, measured server side, hottest pod at most 60% CPU) | Target: p95 at most 0.5 ms and p99 at most 1 ms; end-to-end added latency p99 at most 2 ms with zone-aware upstream routing (the extra round trip to a same-AZ upstream is reported separately). Warm GraphQL adds at most 0.1 ms. First-seen token: residence p99 at most 1.2 ms | 2 |
| S3 | **Throughput.** Planned load per worker vCPU at 50% CPU on the production protocol mix | Target: at least 5k rps per worker vCPU, with the saturation knee at least 1.6 times the planned rate. Estimated expected value 6.25k, conservative 2.5k, optimistic 8.3k | 2, 6 |
| S4 | **First-release capacity.** Peak traffic of the first release | CONFIG: 1,000 rps at peak (owner decision), served by a fleet of 6 pods, 2 per zone, so about 170 rps per pod; load-tested at that peak and at a multiple of it | 6 |
| S5 | **Policy propagation.** A policy change reaches every healthy gateway pod | Target: p99 at most 500 ms from PostgreSQL commit to every healthy pod on the first-release fleet of 6 to 9 pods (estimate 150 to 300 ms); larger fleets are a later-phase estimate; a request carrying the returned policy version sees the change on any pod | 3 |
| S6 | **Revocation.** A session revoked in User service is enforced on every healthy pod | Target: p99 at most 1 s from the Kafka acknowledgement of the User service event (estimate 0.2 to 0.5 s); lag alerts at 2 s and 10 s; the 900 s token lifetime is the absolute backstop | 3 |
| S7 | **Freshness bound.** No allow on state that misses a change acknowledged more than `T_hard` earlier | CONFIG: `T_hard` 15 s now, 5 s after the broker-failover test shows a proof gap of at most 2 s; conditional on the Kafka configuration gates, relay fencing and the replica-quorum check passing the phase-0 spike | 3 |
| S8 | **No allow on error** | 100% of injected faults (Kafka outage, stale proof, broken record, upstream failure, Valkey failure, malformed input, parser disagreement) yield a denial, a 503 or a client error, never an allow | 2 |
| S9 | Write fences | A revocation-class write in `propagated` mode returns `complete` when every pod has applied it, or `bounded` after `T_hard` + 0.5 s | 3 |
| S10 | Administrative changes are audited | 100% of committed changes and rejected attempts have an audit record; the hash chain verifies | 4 |
| S11 | Denials and always-audit operations are logged | Every denial is recorded in the audit lane, summarised in a per-class aggregate within the budgets, or counted as dropped; an always-audit or sensitive-key operation is refused when Loki cannot acknowledge its record (NFR-24) | 4 |
| S12 | No secrets in logs or storage | Zero raw tokens, cookies, GraphQL documents or concrete paths in logs or tables, asserted by tests | 4 |
| S13 | Interface parity | Every management capability has a REST operation and a GraphQL operation; both contract snapshots pinned and regenerated; end-to-end scenarios cover both | 5 |
| S14 | Streams | WebSocket, SSE and GraphQL subscriptions authorize at subscribe time, close when no longer allowed, respect lifetime caps and drain on shutdown | 1, 2 |
| S15 | Rate limiting | Exact global quota on routes with a rate policy while Valkey is healthy; with Valkey slow or down, a conservative per-pod limit applies and authorization is unaffected | 2 |
| S16 | Zero failed requests on scale-out and rolling update in the reference test | Readiness, draining and zone-aware connection handling hold | 6 |
| S17 | Repository bars | 100% line and function coverage, zero surviving mutants, all complexity, lint, architecture, contract, security and documentation gates green | 7 |
| S18 | Administrators see their change at once | A request carrying the returned policy version reflects the change on any pod | 3 |

## Risks

| Risk | Effect | Handling |
| --- | --- | --- |
| Every performance figure is an estimate | Gates may be missed | A phase-0 benchmark replaces every figure; if the conservative case is the truth, profile and optimise rather than relax the gates |
| krafka is pre-1.0, single-author and breaks in minor releases, and several capabilities the freshness guarantee needs are unverified | Freshness of every pod and revocation delivery depend on it | Exact pin behind a port; phase-0 spike stories; fault-injection with the test broker; 72 h soak before each bump; `rdkafka` as the documented fallback with an owner-approved build change |
| The freshness guarantee is conditional until the replica-quorum check and the zombie-leader test pass | A pod isolated with a stale Kafka leader could allow on frozen policy for the partition's duration | Spike and test before the guarantee is called unconditional; strict mode or liveness ticks if the check cannot be built |
| A fleet-wide Kafka outage beyond `T_hard` is a full API outage, by design | Loss of availability to protect correctness | `T_hard` 15 s first, three zones, replication factor 3, tuned Strimzi failover, an open decision on exempting anonymous routes |
| User service does not yet publish its events to Kafka | A revoked session can keep working at upstreams that do not check sessions (Core service) for up to 900 s | Release prerequisite tracked in the readiness file; operator revocation API; 900 s token lifetime |
| New platform: AWS EKS, Strimzi Kafka, Valkey, Loki and metrics do not exist in the organisation | Schedule and operations load depend on platform work | Phase-0 dependency; reference manifests and runbooks; owner decisions already taken |
| Edge duties move to the gateway team (TLS rotation, HTTP/2 hardening, DoS posture) and there is no WAF in the first release | Security exposure | Hardening test suite, rate limits and connection caps; WAF decision open |
| One protected allow-list change is needed (HTTP stack, Kafka client, TLS, Valkey, hashing, JWT) | Epics that use the new crates depend on it | A single change, approved by the owner on 2026-11-21 and applied in Story 2.3; composition-root fallback with its own ADR if a crate fails the dependency policy |
| Loki has no secondary index and limited query performance; its outage blocks always-audit operations | Access-log queries can be slow; audit-or-deny can return 503 | Bounded ranges and pages, fixed labels, replication across zones, an owner option to relax audit-or-deny per route class |
| GraphQL subscription frames add a codec and per-message parsing to the data plane | A bug could let a frame through unauthorized | Authorize before forwarding, fail closed on any decode error, fuzzing in the parser-differential suite |
| Parser differences between IAM and upstream services | IAM authorizes one operation and the service executes another | Authorize the same bytes that are forwarded, reject ambiguous requests, parser-differential tests |
| Template-sync conflicts | Sync pull requests overwrite IAM wiring | `.templatesyncignore` entries for the seam files; new files elsewhere |
| One pull request carries all 127 stories | A long-lived branch; the changed-code mutation run and the review load grow with every story | Story order by `Depends on:` lines, every story closes on its own gate set, the 15-second suite budget, diff mutation runs narrowed to a story's own commits when the full diff exceeds the shard budget |

## Open Decisions for the Owner

Each has a stated default in `research.md` section 20 and does not block planning. The most consequential: behaviour of anonymous routes during a Kafka outage (D5); user, tenant and session cardinality (D6, rest); WAF in front of the load balancer (D9); JWKS and `kid` from User service and which token families pass the gateway (D11, D12); crate placement of the gateway code (D19); Valkey and Loki deployment choices (D23, D24, D26); the name and payload of the User service topic (D25).
