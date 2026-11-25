# 0027. Rate limiting with Valkey and its degradation

Status: accepted.

Planning decisions: the rate-limiting sections of `specs/8-iam-scaffolding-and-spikes/architecture.md` and requirements FR-63, FR-65 and NFR-42 of its `prd.md`. Stories 12.1 to 12.3 implement it.

## Context

A rate policy must hold across the whole gateway fleet: the requests admitted for one policy key in one period never exceed the limit plus the burst, whichever pod receives them. That needs a counter that every pod shares. The counter must also never become a reason to refuse traffic: a slow, paused or stopped store may not answer 503, may not slow a request beyond a bounded time and may not change who is authorized.

## Decision

1. **Exact quotas in Valkey.** The policy limit, period and burst are decided by one GCRA script that runs inside Valkey (`ValkeyRateLimitStore`, Story 12.2). The key is `rl:<policyId>:<keyHash>`, the hash being a SHA-256 of the key parts, so no client address or subject appears in Valkey. Time comes from the boot clock, never from the wall clock.
2. **Bounded calls.** Every call of the `RateLimitStore` port is bounded by `RATE_LIMIT_STORE_TIMEOUT` (1 ms to 50 ms, default 10 ms), measured on the boot clock. A call that fails or times out is decided locally.
3. **Conservative local limit.** The local decision is made by the in-process `BucketLocalRateLimiter` under a rule of the same period and burst and a conservative limit: `limit / N_ready` (at least 1) for a policy with `fallback = divided`, the full limit for `fallback = full`. `N_ready` is the number of ready endpoints of the `iam-gateway-peers` Service from the endpoint watch of Story 10.1 (the static endpoints file in compose); an empty list counts as one pod. The fleet as a whole then admits about the policy limit when all pods degrade together, and a `full` policy accepts up to `N_ready` times its limit in exchange for never refusing a legitimate caller.
4. **Breaker.** After 5 consecutive failures or timeouts the breaker of the store opens for `RATE_LIMIT_BREAKER_OPEN_DURATION` (1 s to 5 m, default 5 s). While it is open no call reaches the store and the local limiter decides every request, so a dead store does not cost `RATE_LIMIT_STORE_TIMEOUT` per request. When the duration has passed, exactly one probe call is let through while the other requests stay local; a probe that answers closes the breaker and exact counting resumes, a probe that fails opens it again for a full duration. A probe whose request is cancelled is replaced one duration later. The breaker is a pure state machine over boot instants (`StoreBreaker` in the domain), so tests drive it with a controlled clock. An answer from the store, admit or reject alike, counts as success.
5. **Never 503, never a changed authorization.** The limiter decides only admit or reject (429 with `Retry-After`). The pipeline authenticates and authorizes before it counts by subject, and a degraded store changes only which limiter counts, never whether a subject holds the key of the route.
6. **Observability.** Every call of the store is reported as `rate_limit_store_latency_seconds`; every decision made locally because of the store is reported as the metric event `rate_limit_store_degraded` with a `reason` of `unavailable`, `timed_out`, `breaker_open` (a request skipped by the open breaker) or `breaker_opened` (the failure that opened it).

## Consequences

- A Valkey failover may lose recent increments and briefly over-admit; this is stated and accepted (NFR-42).
- During a degradation each pod counts alone, so per-key accuracy is lost and the fleet limit is approximate: exact for `divided` only when traffic is spread evenly across the ready pods.
- A pod that does not know its peers (no watch result yet) treats `N_ready` as 1 and applies the full limit, which keeps traffic flowing at the cost of over-admission until the watch fills.
- Residence time of a rate-limited route while Valkey is down stays within NFR-33 plus `RATE_LIMIT_STORE_TIMEOUT`; the integration test prints the measurement of the compose host next to that target and does not gate on it.

## Alternatives considered

| Option | Outcome | Reason |
| --- | --- | --- |
| Refuse with 503 when the store is down | rejected | a Valkey problem would take every rate-limited route down |
| Admit everything while the store is down | rejected | one outage removes every limit, including those that protect upstreams |
| Retry the store inside the request | rejected | multiplies the latency a degraded store already adds; the breaker bounds the cost instead |
| A separate probe task for the breaker | rejected | a probe by the next request needs no task and tests the real call path |
