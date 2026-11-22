CREATE TABLE iam_policy_epoch (
    id SMALLINT NOT NULL,
    version BIGINT NOT NULL,
    digest BYTEA NOT NULL,
    log_epoch BIGINT NOT NULL,
    relay_epoch BIGINT NOT NULL,
    catalog_epoch BIGINT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT iam_policy_epoch_pkey PRIMARY KEY (id),
    CONSTRAINT iam_policy_epoch_id_check CHECK (id = 1),
    CONSTRAINT iam_policy_epoch_version_check CHECK (version >= 0),
    CONSTRAINT iam_policy_epoch_digest_check CHECK (octet_length(digest) = 16),
    CONSTRAINT iam_policy_epoch_log_epoch_check CHECK (log_epoch >= 0),
    CONSTRAINT iam_policy_epoch_relay_epoch_check CHECK (relay_epoch >= 0),
    CONSTRAINT iam_policy_epoch_catalog_epoch_check CHECK (catalog_epoch >= 0)
);

INSERT INTO iam_policy_epoch (id, version, digest, log_epoch, relay_epoch, catalog_epoch, updated_at)
VALUES (1, 0, decode(repeat('00', 16), 'hex'), 0, 0, 0, CURRENT_TIMESTAMP);
