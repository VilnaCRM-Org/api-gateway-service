CREATE TABLE iam_idempotency_keys (
    actor TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_digest BYTEA NOT NULL,
    change_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT iam_idempotency_keys_pkey PRIMARY KEY (actor, idempotency_key),
    CONSTRAINT iam_idempotency_keys_request_digest_check CHECK (octet_length(request_digest) = 32)
);

CREATE INDEX iam_idempotency_keys_created_at_idx ON iam_idempotency_keys (created_at);
