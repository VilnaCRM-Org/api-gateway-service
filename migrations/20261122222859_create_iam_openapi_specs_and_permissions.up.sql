CREATE TABLE iam_openapi_specs (
    id UUID NOT NULL,
    service TEXT NOT NULL,
    content_hash BYTEA NOT NULL,
    document TEXT NOT NULL,
    status TEXT NOT NULL,
    uploaded_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    activated_at TIMESTAMPTZ,
    retired_at TIMESTAMPTZ,
    CONSTRAINT iam_openapi_specs_pkey PRIMARY KEY (id),
    CONSTRAINT iam_openapi_specs_service_hash_key UNIQUE (service, content_hash),
    CONSTRAINT iam_openapi_specs_service_check CHECK (
        char_length(service) <= 63 AND service ~ '^[a-z][a-z0-9]*(-[a-z0-9]+)*$'
    ),
    CONSTRAINT iam_openapi_specs_content_hash_check CHECK (
        content_hash = sha256(convert_to(document, 'UTF8'))
    ),
    CONSTRAINT iam_openapi_specs_status_check CHECK (status IN ('draft', 'active', 'retired'))
);

CREATE INDEX iam_openapi_specs_service_status_idx ON iam_openapi_specs (service, status);

CREATE FUNCTION iam_openapi_specs_immutable_content() RETURNS trigger AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.service IS DISTINCT FROM OLD.service
        OR NEW.content_hash IS DISTINCT FROM OLD.content_hash
        OR NEW.document IS DISTINCT FROM OLD.document THEN
        RAISE EXCEPTION 'the content of an OpenAPI specification version never changes';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER iam_openapi_specs_immutable_content BEFORE UPDATE ON iam_openapi_specs
    FOR EACH ROW EXECUTE FUNCTION iam_openapi_specs_immutable_content();

CREATE TABLE iam_openapi_spec_operations (
    spec_id UUID NOT NULL,
    method TEXT NOT NULL,
    path_template TEXT NOT NULL,
    label TEXT,
    sensitive BOOLEAN NOT NULL,
    audit_always BOOLEAN NOT NULL,
    CONSTRAINT iam_openapi_spec_operations_pkey PRIMARY KEY (spec_id, method, path_template),
    CONSTRAINT iam_openapi_spec_operations_spec_id_fkey FOREIGN KEY (spec_id)
        REFERENCES iam_openapi_specs (id),
    CONSTRAINT iam_openapi_spec_operations_method_check CHECK (
        method IN ('GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS')
    )
);

CREATE TABLE iam_rest_permissions (
    id UUID NOT NULL,
    permission_key TEXT NOT NULL,
    service TEXT NOT NULL,
    method TEXT NOT NULL,
    path_template TEXT NOT NULL,
    label TEXT,
    sensitive BOOLEAN NOT NULL,
    audit_always BOOLEAN NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    orphaned_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT iam_rest_permissions_pkey PRIMARY KEY (id),
    CONSTRAINT iam_rest_permissions_permission_key_key UNIQUE (permission_key),
    CONSTRAINT iam_rest_permissions_method_check CHECK (
        method IN ('GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS')
    )
);

CREATE INDEX iam_rest_permissions_service_active_idx ON iam_rest_permissions (service, active);
