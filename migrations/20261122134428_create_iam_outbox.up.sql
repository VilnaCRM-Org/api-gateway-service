CREATE TABLE iam_outbox (
    id UUID NOT NULL,
    position BIGINT GENERATED ALWAYS AS IDENTITY,
    kind TEXT NOT NULL,
    topic TEXT NOT NULL,
    record_key TEXT NOT NULL,
    payload TEXT,
    policy_version BIGINT NOT NULL,
    seq INTEGER,
    count INTEGER,
    digest_after BYTEA,
    log_epoch BIGINT NOT NULL,
    event_type TEXT,
    aggregate_id TEXT,
    occurred_at TIMESTAMPTZ NOT NULL,
    published_at TIMESTAMPTZ,
    published_offset BIGINT,
    relay_epoch BIGINT,
    CONSTRAINT iam_outbox_pkey PRIMARY KEY (id),
    CONSTRAINT iam_outbox_position_key UNIQUE (position),
    CONSTRAINT iam_outbox_kind_check CHECK (kind IN ('state', 'event')),
    CONSTRAINT iam_outbox_policy_version_check CHECK (policy_version >= 0),
    CONSTRAINT iam_outbox_log_epoch_check CHECK (log_epoch >= 0),
    CONSTRAINT iam_outbox_relay_epoch_check CHECK (relay_epoch >= 0),
    CONSTRAINT iam_outbox_digest_after_check CHECK (octet_length(digest_after) = 16),
    CONSTRAINT iam_outbox_state_framing_check CHECK (
        kind <> 'state'
        OR (
            seq IS NOT NULL AND count IS NOT NULL AND seq >= 1 AND count >= seq
            AND digest_after IS NOT NULL AND event_type IS NULL
        )
    ),
    CONSTRAINT iam_outbox_event_shape_check CHECK (
        kind <> 'event'
        OR (
            payload IS NOT NULL AND event_type IS NOT NULL AND aggregate_id IS NOT NULL
            AND seq IS NULL AND count IS NULL AND digest_after IS NULL
        )
    ),
    CONSTRAINT iam_outbox_published_check CHECK (
        (published_at IS NULL AND published_offset IS NULL AND relay_epoch IS NULL)
        OR (
            published_at IS NOT NULL AND published_offset IS NOT NULL AND published_offset >= 0
            AND relay_epoch IS NOT NULL
        )
    )
);

CREATE INDEX iam_outbox_unpublished_idx ON iam_outbox (position) WHERE published_at IS NULL;
CREATE INDEX iam_outbox_policy_version_seq_idx ON iam_outbox (policy_version, seq);
