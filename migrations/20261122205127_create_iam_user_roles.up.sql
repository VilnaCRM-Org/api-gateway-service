CREATE TABLE iam_user_roles (
    id UUID NOT NULL,
    subject_kind TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    role_id UUID NOT NULL,
    scope_kind TEXT NOT NULL,
    project_id UUID,
    expires_at TIMESTAMPTZ,
    version BIGINT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    CONSTRAINT iam_user_roles_pkey PRIMARY KEY (id),
    CONSTRAINT iam_user_roles_role_id_fkey FOREIGN KEY (role_id) REFERENCES iam_roles (id),
    CONSTRAINT iam_user_roles_subject_kind_check CHECK (subject_kind IN ('user', 'service')),
    CONSTRAINT iam_user_roles_user_subject_check CHECK (
        subject_kind <> 'user'
        OR subject_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    ),
    CONSTRAINT iam_user_roles_service_subject_check CHECK (
        subject_kind <> 'service'
        OR (char_length(subject_id) <= 63 AND subject_id ~ '^[a-z][a-z0-9]*(-[a-z0-9]+)*$')
    ),
    CONSTRAINT iam_user_roles_scope_kind_check CHECK (scope_kind IN ('global', 'project')),
    CONSTRAINT iam_user_roles_scope_project_check CHECK (
        (scope_kind = 'project') = (project_id IS NOT NULL)
    ),
    CONSTRAINT iam_user_roles_version_check CHECK (version >= 1)
);

CREATE UNIQUE INDEX iam_user_roles_active_key ON iam_user_roles (
    subject_kind,
    subject_id,
    role_id,
    scope_kind,
    coalesce(project_id, '00000000-0000-0000-0000-000000000000'::uuid)
) WHERE revoked_at IS NULL;

CREATE INDEX iam_user_roles_subject_idx ON iam_user_roles (subject_kind, subject_id)
    WHERE revoked_at IS NULL;

CREATE INDEX iam_user_roles_role_id_idx ON iam_user_roles (role_id);
