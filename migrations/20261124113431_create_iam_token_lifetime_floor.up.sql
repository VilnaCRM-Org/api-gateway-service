CREATE TABLE iam_token_lifetime_floor (
    id SMALLINT NOT NULL,
    longest_lifetime_seconds BIGINT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT iam_token_lifetime_floor_pkey PRIMARY KEY (id),
    CONSTRAINT iam_token_lifetime_floor_id_check CHECK (id = 1),
    CONSTRAINT iam_token_lifetime_floor_lifetime_check CHECK (longest_lifetime_seconds > 0)
);
