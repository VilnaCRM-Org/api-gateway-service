CREATE TABLE iam_roles (
    id UUID NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    kind TEXT NOT NULL,
    grant_count INTEGER NOT NULL,
    version BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    deleted_at TIMESTAMPTZ,
    CONSTRAINT iam_roles_pkey PRIMARY KEY (id),
    CONSTRAINT iam_roles_name_length_check CHECK (char_length(name) BETWEEN 1 AND 100),
    CONSTRAINT iam_roles_description_length_check CHECK (char_length(description) <= 1000),
    CONSTRAINT iam_roles_kind_check CHECK (kind IN ('system', 'custom')),
    CONSTRAINT iam_roles_grant_count_check CHECK (grant_count BETWEEN 0 AND 5000),
    CONSTRAINT iam_roles_version_check CHECK (version >= 1)
);

CREATE UNIQUE INDEX iam_roles_name_key ON iam_roles (lower(name)) WHERE deleted_at IS NULL;

CREATE TABLE iam_role_permissions (
    role_id UUID NOT NULL,
    permission_key TEXT NOT NULL,
    key_kind TEXT NOT NULL,
    service TEXT NOT NULL,
    is_wildcard BOOLEAN NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    orphaned_at TIMESTAMPTZ,
    granted_by TEXT NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT iam_role_permissions_pkey PRIMARY KEY (role_id, permission_key),
    CONSTRAINT iam_role_permissions_role_id_fkey FOREIGN KEY (role_id) REFERENCES iam_roles (id),
    CONSTRAINT iam_role_permissions_key_kind_check CHECK (key_kind IN ('rest', 'gql', 'iam'))
);

CREATE INDEX iam_role_permissions_permission_key_idx ON iam_role_permissions (permission_key);
CREATE INDEX iam_role_permissions_service_active_idx ON iam_role_permissions (service, active);
