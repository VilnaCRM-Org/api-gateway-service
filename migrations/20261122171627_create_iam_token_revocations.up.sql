CREATE TABLE iam_revoked_sessions (
    session_id TEXT NOT NULL,
    id UUID NOT NULL,
    user_id UUID NOT NULL,
    source TEXT NOT NULL,
    revoked_by TEXT NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL,
    prune_after TIMESTAMPTZ NOT NULL,
    CONSTRAINT iam_revoked_sessions_pkey PRIMARY KEY (session_id),
    CONSTRAINT iam_revoked_sessions_id_key UNIQUE (id),
    CONSTRAINT iam_revoked_sessions_source_check CHECK (source IN ('user-service', 'operator'))
);

CREATE INDEX iam_revoked_sessions_user_id_revoked_at_idx ON iam_revoked_sessions (user_id, revoked_at);
CREATE INDEX iam_revoked_sessions_prune_after_idx ON iam_revoked_sessions (prune_after);

CREATE TABLE iam_user_token_validity (
    user_id UUID NOT NULL,
    tokens_valid_after TIMESTAMPTZ NOT NULL,
    source TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    prune_after TIMESTAMPTZ NOT NULL,
    CONSTRAINT iam_user_token_validity_pkey PRIMARY KEY (user_id),
    CONSTRAINT iam_user_token_validity_source_check CHECK (source IN ('user-service', 'operator'))
);

CREATE INDEX iam_user_token_validity_prune_after_idx ON iam_user_token_validity (prune_after);

CREATE TABLE iam_global_token_cutoff (
    id SMALLINT NOT NULL,
    tokens_valid_after TIMESTAMPTZ NOT NULL,
    set_by TEXT NOT NULL,
    set_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT iam_global_token_cutoff_pkey PRIMARY KEY (id),
    CONSTRAINT iam_global_token_cutoff_id_check CHECK (id = 1)
);

CREATE TABLE iam_inbound_events (
    event_id UUID NOT NULL,
    topic TEXT NOT NULL,
    partition INTEGER NOT NULL,
    "offset" BIGINT NOT NULL,
    event_type TEXT NOT NULL,
    outcome TEXT NOT NULL,
    error TEXT,
    processed_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT iam_inbound_events_pkey PRIMARY KEY (event_id),
    CONSTRAINT iam_inbound_events_outcome_check CHECK (outcome IN ('applied', 'ignored', 'dead_letter'))
);

CREATE INDEX iam_inbound_events_processed_at_idx ON iam_inbound_events (processed_at);
