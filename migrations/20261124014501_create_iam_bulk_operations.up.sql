CREATE TABLE iam_bulk_operations (
    id UUID NOT NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    total_records BIGINT NOT NULL,
    applied_records BIGINT NOT NULL,
    first_version BIGINT,
    last_version BIGINT,
    requester TEXT NOT NULL,
    error TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT iam_bulk_operations_pkey PRIMARY KEY (id),
    CONSTRAINT iam_bulk_operations_kind_check CHECK (kind IN ('role_deletion', 'catalogue', 'resync', 'other')),
    CONSTRAINT iam_bulk_operations_status_check CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    CONSTRAINT iam_bulk_operations_total_check CHECK (total_records >= 1),
    CONSTRAINT iam_bulk_operations_applied_check CHECK (applied_records BETWEEN 0 AND total_records),
    CONSTRAINT iam_bulk_operations_versions_check CHECK (
        (first_version IS NULL AND last_version IS NULL)
        OR (first_version IS NOT NULL AND last_version IS NOT NULL AND first_version >= 0 AND first_version <= last_version)
    ),
    CONSTRAINT iam_bulk_operations_error_check CHECK (error IS NULL OR char_length(error) <= 500),
    CONSTRAINT iam_bulk_operations_requester_check CHECK (char_length(requester) BETWEEN 1 AND 200)
);

CREATE INDEX iam_bulk_operations_unfinished_idx ON iam_bulk_operations (id) WHERE status IN ('pending', 'running');
