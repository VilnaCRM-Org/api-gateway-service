# 0016. Token validation at the gateway without token persistence or liveness calls

Status: accepted. Story 2.5 adds the offline verifier; Story 2.6 adds the identity memo and the revocation checks.

Planning decisions: sections 4.2, 7 and 16.1 of `specs/8-iam-scaffolding-and-spikes/architecture.md` (tokens, `JwtAccessTokenVerifier`, caller authentication) and requirements FR-15, FR-55, NFR-6 and NFR-20 of its `prd.md`.

## Context

Every request through the gateway, and every call to IAM's own API, carries a User service access token. The original design stored tokens through a cache and a database and asked User service whether a session was still alive. That puts a network call, or a lookup, on every request, and it makes IAM hold copies of credentials.

## Decision

- **Offline verification.** `JwtAccessTokenVerifier` (infrastructure, `jsonwebtoken` with the `aws_lc_rs` backend) implements the domain port `AccessTokenVerifier`. It accepts only a compact JWS signed with RS256 that verifies against one of the PEM public keys of `JWT_PUBLIC_KEYS_FILE` (1 to 3 keys, newest last in the file, tried newest first), with `iss` equal to `JWT_ISSUER` and `aud` containing `JWT_AUDIENCE`.
- **Strict header.** Any other algorithm (`none`, every HMAC variant, any other asymmetric algorithm) and any of the header parameters `jwk`, `jku`, `x5u`, `x5c` and `crit` make the token invalid, so a token can never choose its own key.
- **Claims.** `sub` and `jti` are required, `sid` whenever `roles` is present; a `ROLE_SERVICE` token's `sub` must match the service-name pattern and names the service principal, any other token's `sub` must be a user UUID.
- **Time through the `Clock` port.** `jsonwebtoken`'s own `exp` and `nbf` checks are off. The domain rule `TokenLifetimeRule` checks integer `iat`, `nbf` and `exp` against the injected time with `JWT_CLOCK_SKEW` (at most 60 seconds) and rejects `exp − iat` above `MAX_TOKEN_LIFETIME` (900 seconds), the absolute backstop of revocation.
- **Outcomes.** A blank credential is `token_missing`, an expiry beyond the skew is `token_expired`, everything else is `token_invalid` (`TokenRejection`).
- **Key rotation.** The key file is watched; a changed file is read again and its keys put in force. A reload that fails keeps the last valid set and logs an error; a missing or invalid file at startup stops the service.
- **No persistence, no liveness call.** No token is stored. The raw credential lives only in request memory: `Credential` prints nothing through `Debug` and has no `Display`. Revocations arrive as replicated state over Kafka (Story 2.6), not through a call to User service.

| Option | Outcome | Reason |
| --- | --- | --- |
| Offline RS256 verification with a watched key file | Chosen | Verifying costs less than any lookup; no dependency sits on the request path; keys rotate without a restart |
| Token persistence with a cache and a database | Rejected | Holds copies of credentials and adds a lookup to every request |
| Session-liveness call to User service per request or per cache miss | Rejected | Couples availability of every request to User service; revocations are replicated instead |
| JWKS endpoint fetched at runtime | Rejected | Adds an outbound dependency and a header-driven key choice; the keys are mounted as a Kubernetes Secret |

## Consequences

A revoked session's token keeps working until the revocation reaches the pod (Story 2.6) and never beyond its expiry, at most `MAX_TOKEN_LIFETIME` after issue. Rotating keys needs the new public key in the file before User service signs with it, which the three-key limit allows. League OAuth2 tokens fail the issuer check.
