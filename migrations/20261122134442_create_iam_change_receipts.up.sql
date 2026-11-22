CREATE TABLE iam_change_receipts (
    change_id UUID NOT NULL,
    actor TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    entity_version BIGINT NOT NULL,
    policy_version BIGINT,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT iam_change_receipts_pkey PRIMARY KEY (change_id),
    CONSTRAINT iam_change_receipts_entity_version_check CHECK (entity_version >= 1),
    CONSTRAINT iam_change_receipts_policy_version_check CHECK (policy_version >= 0)
);

CREATE INDEX iam_change_receipts_created_at_idx ON iam_change_receipts (created_at);
