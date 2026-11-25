# 0019. Security audit log in PostgreSQL and access-decision log in Loki

Status: draft. Story 2.2 records the security audit log; Story 14.2 records the access-log part (the two lanes, their guarantees and audit-or-deny) and Story 14.5 adds the chain verification, the threat model and the retention basis.

Planning decisions: sections 12.4 and 13 of `specs/8-iam-scaffolding-and-spikes/architecture.md` (security audit log, data model), section 12 (access log) and requirements FR-49, FR-50, FR-52 and NFR-24 of its `prd.md`.

## Context

Every committed administrative change and every refused administrative attempt must leave a record that an operator cannot alter or remove without the change being detected. The records hold identifiers, role names and permission keys, never a token, a specification body or a person's name or email. The access decisions of the gateway are far more numerous and are kept elsewhere: in Loki, through the two lanes described under "The access log".

## Decision

The security audit log is one append-only PostgreSQL table, `iam_security_audit_events`, written only by `iam-control`:

- Every record carries a gap-free sequence number `seq`, the hash of the previous record `prev_hash` and its own `hash = sha256(prev_hash || canonical_form)`. The first record links to 32 zero bytes.
- The digest is computed in SQL by the built-in `sha256` function, inside the inserting statement, while the transaction holds the row lock of the single-row table `iam_security_audit_chain_head` (`CHECK (id = 1)`). The sequence number is the head's sequence number plus one, not an identity column, so a rolled-back transaction leaves no gap.
- The canonical form is built by the domain entity `SecurityAuditEvent`: a version line `iam.security_audit.v1`, then one `name=value` line per value in a fixed order, an absent value written as nothing. Times are whole microseconds since 1970, the precision of the column, so a record read back has the same form.
- A trigger rejects `UPDATE` and `DELETE` of any row and `TRUNCATE` of the table.
- Records of committed changes are appended in the change's transaction through `PgSecurityAuditLog::append_within` (the unit of work of Story 2.3); buffered refused attempts are appended through `SecurityAuditLog::append_batch` in one transaction (Story 6.11).
- After the commit, every record is also emitted as one `tracing` event with target `audit`, which the JSON log layer renders as one JSON object.
- Summaries are validated by `AuditSummary`: one line of printable characters of at most 4,096 bytes and no word shaped like a JSON Web Token.

| Option | Outcome | Reason |
| --- | --- | --- |
| Hash chain computed in SQL under a chain-head row lock | Chosen | One transaction covers the change and its record; the lock orders records in commit order and keeps the sequence gap-free; no hashing crate is needed in the service |
| Hash computed in Rust | Rejected for now | Needs a hashing crate on the allow-list, and two writers could still interleave without the lock |
| Identity column for `seq` | Rejected | A rolled-back transaction consumes identity values, so the sequence would have gaps |

## The access log

Every gateway decision produces one access record (Story 14.1), which goes to exactly one of two lanes. The ordinary lane holds the sampled allows and the errors; its guarantee is best effort: the record is written to stdout by a writer thread, a full channel drops it and counts the drop (`access_log_dropped_total`), and no decision changes. The audit lane holds every denial, every decision on an always-audit or sensitive key and every wildcard allow; its guarantee is stronger and is stated honestly (Story 14.2, NFR-24): a record of the audit lane is delivered to Loki at least once while Loki is reachable and keeps up, and an operation whose record cannot be delivered is not performed.

- **Delivery.** `LokiPushAccessLogSink` queues the audit-lane entries and a worker thread pushes them to `LOKI_PUSH_URL` every `ACCESS_LOG_AUDIT_FLUSH_INTERVAL`, or at once when the queue holds 1 MiB, with `X-Scope-OrgID` from `LOKI_TENANT_ID`. The labels are `app`, `env`, `lane`, `decision` and `upstream`; the structured metadata are `subject_id`, `decision_id`, `request_id`, `route_id`, `status`, `reason`, `policy_version` and `subject_kind`. A batch counts as acknowledged only when Loki answers with a 2xx status; a batch that failed goes back to the front of the queue and is pushed again, and an acknowledged batch is never pushed twice. The push is plain HTTP: a TLS-terminating proxy or the in-cluster address carries it.
- **Acknowledgement.** The writer asks the sink how many audit entries Loki has acknowledged and keeps the write times of the others in order, so the oldest unacknowledged record is always known. The metric event `access_log_audit_pending` carries how many wait and falls by the records of each acknowledged batch.
- **Audit-or-deny.** `RequestAuthorizer` refuses a request that the decision would allow on an always-audit or sensitive key with 503 `audit_unavailable` while the audit lane is full (the channel dropped an audit record, or as many audit records wait for Loki as `LOG_CHANNEL_CAPACITY`) or the oldest unacknowledged record has waited longer than `ACCESS_LOG_AUDIT_MAX_PENDING`. A refused request is a denial and so is itself an audit-lane record. Requests on other keys are still served; while the lane is closed in either way the writer drops the audit-lane records that arrive (a denial, a wildcard allow, the record of a refused request) and counts them, and an acknowledgement from Loki opens the lane again. Audit-lane records are no longer written to stdout.
- **Limits of the guarantee.** A record that is queued when a pod is killed is lost, and a record that Loki acknowledged but could not store is outside the gateway's knowledge: the bound `ACCESS_LOG_AUDIT_MAX_PENDING` limits how many operations can run on unconfirmed records, it does not remove the window. An allow on a key without the flags is not audit-required and is sampled.

| Option | Outcome | Reason |
| --- | --- | --- |
| Push the audit lane to Loki and refuse audited operations while unacknowledged records are too old | Chosen | The guarantee is stated and bounded, and the request path never waits for Loki |
| Write the audit lane to stdout and let a collector ship it | Rejected for the audit lane | Nothing tells the gateway that the record arrived, so an audited operation could run without a record |
| Wait for Loki on the request path | Rejected | A slow Loki would slow every audited request and break the latency budget |

## Verifying the chain

`GET /api/security-audit-events/chain-verification` and the GraphQL query `securityAuditChainVerification(anchors: ...)` recompute the whole chain on demand; both need `iam:audit:read`, and every verification is itself recorded as `security_audit.verify` once it has run, so a verification that cannot be audited is not served and never checks its own record (Story 14.5, FR-52).

- **What is checked.** `PgSecurityAuditLog::verify_chain` reads the records in pages of 1,000 from the first one and walks them in order: the sequence number follows the previous one (`gap`), the stored values read back as a valid record (`unreadable`), `prev_hash` is the hash of the previous record (`link`), and `hash` equals `sha256(prev_hash || canonical_form)` of the stored values (`digest`). The canonical form is built by the same domain entity that built it at insert time, and the digest is computed by the same SQL function, over a page at a time. The walk stops at the first break; the result is `valid` with the number of records checked, or `invalid` with the id and sequence number of that record and the cause.
- **Anchors.** The caller may pass up to 100 `{seq, hash}` values that an external audit pipeline kept from the `iam.security_audit.anchored` events. The chain is `invalid` with cause `anchor` at an anchored record whose stored hash differs, and `anchor_missing` when an anchor names a sequence number beyond the newest record. A chain that an attacker rewrote and fully recomputed passes every internal check, so only an anchor published before the rewrite exposes it.
- **Reads are consistent per page, not per walk.** Appends continue during a verification; a record appended after the walk read its page is simply not counted, and the count is the number of records the walk saw.

| Option | Outcome | Reason |
| --- | --- | --- |
| Rebuild the canonical form in Rust and digest it in SQL, a page at a time | Chosen | One definition of the canonical form, the digest function that wrote the chain, and no hashing crate in the service |
| Recompute the digest with a second SQL expression of the canonical form | Rejected | Two definitions of the form could drift apart and report a false break |
| Hold the chain-head lock during the walk | Rejected | It would block every administrative write for the length of a scan |

## Threat model

The chain protects the history against an actor with some access, and is honest about who it does not stop.

| Actor | Can do | Detected by |
| --- | --- | --- |
| An administrator of the API | Nothing to existing records: the API has no operation that updates or deletes an audit record | Not applicable |
| A database user without owner rights, such as the service's runtime role | Read and append; `UPDATE`, `DELETE` and `TRUNCATE` are rejected by the trigger and, in production, not granted | The trigger; the role grants |
| A user who can disable the trigger or alter the table and changes one record | Alter or delete a record | `verify_chain`: `digest`, `link` or `gap` at that record, without any anchor |
| A user who rewrites the chain from some record on and recomputes every later hash | Make the whole chain consistent again | Only an external anchor published before the rewrite: `anchor` at the anchored record |
| A user who also controls the external anchors | Rewrite the history undetected | Nothing inside this design |

Consequences of the model, which operations must provide:

- **External anchors.** The maintenance task publishes the chain head as `iam.security_audit.anchored` on `iam.events.v1` (FR-43). An external audit pipeline, outside the database owner's control, keeps those `seq` and `hash` values and passes them to the verification. Without kept anchors the verification detects accidental corruption and single-record tampering, not a full rewrite.
- **Separate database roles.** Production runs migrations under an owner role and the service under a runtime role that holds only `INSERT` and `SELECT` on the audit tables, with no `UPDATE`, `DELETE`, `TRUNCATE`, `ALTER` or trigger rights, so that disabling the trigger needs the owner role, which the running service never holds. Setting up the two roles is an operational prerequisite (an open owner item).
- **Verification on a schedule.** The end-to-end suite verifies the chain of every scenario's database as its last step; production operators verify with their anchors on a schedule they choose.

## Retention basis

The PostgreSQL security audit log keeps its records for at least 400 days and IAM never deletes them (NFR-25, FR-53): the records are the evidence for the security of the service and the legitimate interest of its operator in detecting misuse, and they hold pseudonymous identifiers, role names and permission keys, never a person's name or email, so that keeping them does not require rewriting them when a user is deleted. The Loki lanes age out on their own: `lane="access"` after 90 days and `lane="audit"` after 400 days in the reference configuration. A longer period for the table is a decision of the operator, not of the service.

## Consequences

Every audited write takes the chain-head lock, which serialises administrative writes together with the policy-version lock of `iam_policy_epoch`. The in-database chain detects accidental corruption and tampering by anyone who cannot rewrite the whole chain; anchoring the chain head outside the database, the verification and the threat model are described above. Production runs the service under a database role that holds only `INSERT` and `SELECT` on the audit tables (an operational prerequisite).
