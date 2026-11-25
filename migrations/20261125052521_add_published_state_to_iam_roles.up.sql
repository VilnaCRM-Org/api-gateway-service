-- The canonical state record of the role as `iam.policy.state.v1` last published it. A role that
-- no versioned transaction has written yet (a role created or renamed by a change that does not
-- affect decisions) has none, so the digest of the next versioned transaction takes away exactly
-- what was published and the head digest stays the digest of the records on the topic.
ALTER TABLE iam_roles ADD COLUMN published_state TEXT;

-- Roles whose newest state row is still in the outbox keep it; older rows were pruned after they
-- were published, and a role without one counts as not published.
UPDATE iam_roles AS role
SET published_state = newest.payload
FROM (
    SELECT DISTINCT ON (record_key) record_key, payload
    FROM iam_outbox
    WHERE kind = 'state' AND record_key LIKE 'role/%'
    ORDER BY record_key, position DESC
) AS newest
WHERE newest.record_key = 'role/' || role.id::text;
