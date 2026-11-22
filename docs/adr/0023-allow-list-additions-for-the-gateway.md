# 0023. Allow-list additions for the gateway

Status: accepted. The owner approved the change on 2026-11-21; Story 2.3 applies it to `architecture.toml` in the pull request of issue #8, with the `approved-config-change` label.

Planning decisions: section 3.1 of `specs/8-iam-scaffolding-and-spikes/architecture.md` (allow-list delta) and requirement NFR-6 of its `prd.md`.

## Context

The architecture gate (ADR 0002) allows each layer only the third-party crates that `architecture.toml` lists. The IAM gateway needs adapters for Kafka, Valkey, JSON Web Tokens, the upstream HTTP client, the route matcher, the boot clock and the seeded random generator, and the unit of work encodes events as JSON. These adapters implement domain ports, so they belong in the infrastructure layer. `architecture.toml` is protected configuration (ADR 0002, `protected-config.toml`), so the change needs the owner's approval and the label on the pull request.

## Decision

`architecture.toml` changes by exactly this delta and nothing else:

- Application layer, `dev_external`: add `criterion`.
- Infrastructure layer, `external`: add `arc-swap`, `bytes`, `http`, `http-body-util`, `hyper`, `hyper-rustls`, `hyper-util`, `jsonwebtoken`, `krafka`, `matchit`, `rand`, `redis`, `rustix`, `rustls`, `rustls-pki-types`, `serde`, `serde_json`, `sha2`.
- Infrastructure layer, `dev_external`: add `aws-lc-rs`, `criterion`, `krafka`.

Unchanged: the domain layer (`async-trait`, `thiserror`, `uuid`), the application layer's `external` list, every `forbidden_transitive` list and the `[contexts]` table.

| Option | Outcome | Reason |
| --- | --- | --- |
| Add the crates to the infrastructure layer | Chosen | Adapters of domain ports belong in infrastructure under the template's layering; each crate passes the security gate |
| Put the adapters in the composition root (`external = ["*"]`) | Fallback | Keeps `architecture.toml` unchanged but mixes adapters with wiring; `HyperUpstreamForwarder` takes this path in any case, so `tokio` stays out of the infrastructure list |
| Add `tokio`, `governor`, `ppp`, `tokio-rustls` or `reqwest` | Not requested | Task loops and timers live in the application layer; the listeners live in the composition root; the local limiter uses the domain rule over the boot clock |
| Add `rsa` for test keys | Not requested | It carries RUSTSEC-2023-0071 with no patched release, which `deny.toml` refuses; `aws-lc-rs` provides the test keys |

## Consequences

Every added crate must pass `make check-security` (licences, advisories, bans) when it is first used; `openssl-sys` stays banned. A further crate in any layer needs another approved change of `architecture.toml` and a new record. Stories that use these crates depend on Story 2.3.
