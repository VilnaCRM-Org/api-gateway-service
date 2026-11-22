# 0019. Security audit log in PostgreSQL and access-decision log in Loki

Status: draft. Story 2.2 records the security audit log; Story 14.2 adds the Loki parts and Story 14.5 adds the threat model.

Planning decisions: sections 12.4 and 13 of `specs/8-iam-scaffolding-and-spikes/architecture.md` (security audit log, data model) and requirements FR-49 and FR-52 of its `prd.md`.

## Context

Every committed administrative change and every refused administrative attempt must leave a record that an operator cannot alter or remove without the change being detected. The records hold identifiers, role names and permission keys, never a token, a specification body or a person's name or email. The access decisions of the gateway are far more numerous and are kept elsewhere (Story 14.2).

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

## Consequences

Every audited write takes the chain-head lock, which serialises administrative writes together with the policy-version lock of `iam_policy_epoch`. The in-database chain detects accidental corruption and tampering by anyone who cannot rewrite the whole chain; anchoring the chain head outside the database and the threat model are added by Story 14.5. Production runs the service under a database role that holds only `INSERT` and `SELECT` on the audit tables (an operational prerequisite).
