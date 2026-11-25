# 0019. Security audit log in PostgreSQL and access-decision log in Loki

Status: draft. Story 2.2 records the security audit log; Story 14.2 records the access-log part (the two lanes, their guarantees and audit-or-deny) and Story 14.5 adds the threat model.

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

## Consequences

Every audited write takes the chain-head lock, which serialises administrative writes together with the policy-version lock of `iam_policy_epoch`. The in-database chain detects accidental corruption and tampering by anyone who cannot rewrite the whole chain; anchoring the chain head outside the database and the threat model are added by Story 14.5. Production runs the service under a database role that holds only `INSERT` and `SELECT` on the audit tables (an operational prerequisite).
