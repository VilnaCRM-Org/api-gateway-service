# 0021. REST and GraphQL parity for IAM operations

Status: accepted. Story 2.8 applies it to the first IAM operation, the token resolution.

Planning decisions: functional requirements FR-1 and FR-19 and non-functional requirement NFR-7 of `specs/8-iam-scaffolding-and-spikes/prd.md`, and the API surface table of its section on operations.

## Context

IAM's management and decision capabilities are offered over REST and over GraphQL. Two handlers per capability would let the two interfaces drift: a rule checked on one side, forgotten on the other, a field answered differently. The review of the IAM plan therefore treats a capability on one interface only as a defect.

## Decision

- **One use case, two adapters.** Each operation has one query or command, one handler and one set of wire shapes. The REST handler and the GraphQL resolver call the same function of the application layer (`resolve_credential` for the token resolution), validate through the same REST DTO (`TokenResolutionRequest`) and build their answer from the same response value (`TokenResolutionResponse`), so a rule or a limit is written once.
- **Same errors.** Every failure is a `Problem` first. REST answers it as `application/problem+json`; GraphQL converts it with `iam_problem_to_graphql_error`, which maps 401 to `UNAUTHENTICATED`, 403 to `FORBIDDEN`, 404 to `NOT_FOUND`, 409 to `CONFLICT`, 412 to `PRECONDITION_FAILED`, 428 to `PRECONDITION_REQUIRED`, 422 to `VALIDATION_FAILED` with its violations and every other status to `INTERNAL_SERVER_ERROR` without detail.
- **Same authentication.** The authentication middleware resolves the bearer token of the caller before either interface runs. REST refuses a missing or rejected token with the 401 problem and `WWW-Authenticate: Bearer`; GraphQL resolves the token without refusing the request, because its HTTP status is always 200, and every IAM field checks the principal itself and answers `UNAUTHENTICATED`.
- **A refusal that is an answer.** The token resolution reports an expired, revoked, missing or invalid credential as data (`resolved = false` with the reason code `token_missing`, `token_invalid`, `token_expired` or `token_revoked`), identically on both interfaces. Only a failure to read the revocation state is an error (500). The credential is never echoed and never printed: its `Debug` output prints nothing.
- **Proof.** Each end-to-end scenario of an operation sends the same request over both interfaces and asserts that the two answers are equal; the contract snapshots of both interfaces are regenerated in the same story, and the pinning tests of the composition root assert the operation, its tag and its security scheme.

| Option | Outcome | Reason |
| --- | --- | --- |
| One use case, two thin adapters | Chosen | A rule is written once; the end-to-end parity scenario catches drift |
| GraphQL implemented on top of the REST API | Rejected | Adds an in-process HTTP hop and loses typed errors |
| Two independent implementations | Rejected | The interfaces drift; every rule has to be written and tested twice |

## Consequences

A new IAM operation adds its use case, one REST handler, one resolver, its DTOs and one scenario that compares both answers. The empty `IamMutation` root joins the schema with the first IAM mutation, because GraphQL does not allow an object type without fields. The same operation is served from the policy snapshot on the gateway's decision listener in Story 10.11, through the same handlers and DTOs.
