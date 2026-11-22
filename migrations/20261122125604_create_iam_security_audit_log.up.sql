CREATE TABLE iam_security_audit_events (
    seq BIGINT NOT NULL,
    id UUID NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    actor TEXT NOT NULL,
    caller_service TEXT,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    scope TEXT,
    before_summary TEXT,
    after_summary TEXT,
    idempotency_key TEXT,
    outcome TEXT NOT NULL,
    reason TEXT,
    policy_version BIGINT,
    request_id TEXT,
    prev_hash BYTEA NOT NULL,
    hash BYTEA NOT NULL,
    CONSTRAINT iam_security_audit_events_pkey PRIMARY KEY (seq),
    CONSTRAINT iam_security_audit_events_id_key UNIQUE (id),
    CONSTRAINT iam_security_audit_events_seq_check CHECK (seq >= 1),
    CONSTRAINT iam_security_audit_events_outcome_check CHECK (outcome IN ('committed', 'rejected')),
    CONSTRAINT iam_security_audit_events_policy_version_check CHECK (policy_version >= 0),
    CONSTRAINT iam_security_audit_events_prev_hash_check CHECK (octet_length(prev_hash) = 32),
    CONSTRAINT iam_security_audit_events_hash_check CHECK (octet_length(hash) = 32)
);

CREATE INDEX iam_security_audit_events_occurred_at_idx ON iam_security_audit_events (occurred_at);
CREATE INDEX iam_security_audit_events_actor_occurred_at_idx ON iam_security_audit_events (actor, occurred_at);
CREATE INDEX iam_security_audit_events_target_idx ON iam_security_audit_events (target_type, target_id);

CREATE TABLE iam_security_audit_chain_head (
    id SMALLINT NOT NULL,
    seq BIGINT NOT NULL,
    hash BYTEA NOT NULL,
    CONSTRAINT iam_security_audit_chain_head_pkey PRIMARY KEY (id),
    CONSTRAINT iam_security_audit_chain_head_id_check CHECK (id = 1),
    CONSTRAINT iam_security_audit_chain_head_seq_check CHECK (seq >= 0),
    CONSTRAINT iam_security_audit_chain_head_hash_check CHECK (octet_length(hash) = 32)
);

INSERT INTO iam_security_audit_chain_head (id, seq, hash) VALUES (1, 0, decode(repeat('00', 32), 'hex'));

CREATE FUNCTION iam_security_audit_events_reject_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'iam_security_audit_events is append-only: % is not allowed', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER iam_security_audit_events_append_only
    BEFORE UPDATE OR DELETE ON iam_security_audit_events
    FOR EACH ROW EXECUTE FUNCTION iam_security_audit_events_reject_change();

CREATE TRIGGER iam_security_audit_events_no_truncate
    BEFORE TRUNCATE ON iam_security_audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION iam_security_audit_events_reject_change();
