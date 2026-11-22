CREATE TABLE iam_graphql_specs (
    id UUID NOT NULL,
    service TEXT NOT NULL,
    content_hash BYTEA NOT NULL,
    sdl TEXT NOT NULL,
    status TEXT NOT NULL,
    uploaded_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    activated_at TIMESTAMPTZ,
    retired_at TIMESTAMPTZ,
    CONSTRAINT iam_graphql_specs_pkey PRIMARY KEY (id),
    CONSTRAINT iam_graphql_specs_service_hash_key UNIQUE (service, content_hash),
    CONSTRAINT iam_graphql_specs_service_check CHECK (
        char_length(service) <= 63 AND service ~ '^[a-z][a-z0-9]*(-[a-z0-9]+)*$'
    ),
    CONSTRAINT iam_graphql_specs_content_hash_check CHECK (
        content_hash = sha256(convert_to(sdl, 'UTF8'))
    ),
    CONSTRAINT iam_graphql_specs_status_check CHECK (status IN ('draft', 'active', 'retired'))
);

CREATE INDEX iam_graphql_specs_service_status_idx ON iam_graphql_specs (service, status);

CREATE FUNCTION iam_graphql_specs_immutable_content() RETURNS trigger AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.service IS DISTINCT FROM OLD.service
        OR NEW.content_hash IS DISTINCT FROM OLD.content_hash
        OR NEW.sdl IS DISTINCT FROM OLD.sdl THEN
        RAISE EXCEPTION 'the content of a GraphQL specification version never changes';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER iam_graphql_specs_immutable_content BEFORE UPDATE ON iam_graphql_specs
    FOR EACH ROW EXECUTE FUNCTION iam_graphql_specs_immutable_content();

CREATE TABLE iam_graphql_spec_fields (
    spec_id UUID NOT NULL,
    type_name TEXT NOT NULL,
    field_name TEXT NOT NULL,
    return_type TEXT NOT NULL,
    sensitive BOOLEAN NOT NULL,
    audit_always BOOLEAN NOT NULL,
    CONSTRAINT iam_graphql_spec_fields_pkey PRIMARY KEY (spec_id, type_name, field_name),
    CONSTRAINT iam_graphql_spec_fields_spec_id_fkey FOREIGN KEY (spec_id)
        REFERENCES iam_graphql_specs (id)
);

CREATE TABLE iam_graphql_spec_possible_types (
    spec_id UUID NOT NULL,
    abstract_type TEXT NOT NULL,
    possible_type TEXT NOT NULL,
    CONSTRAINT iam_graphql_spec_possible_types_pkey PRIMARY KEY (
        spec_id, abstract_type, possible_type
    ),
    CONSTRAINT iam_graphql_spec_possible_types_spec_id_fkey FOREIGN KEY (spec_id)
        REFERENCES iam_graphql_specs (id)
);

CREATE TABLE iam_graphql_permissions (
    id UUID NOT NULL,
    permission_key TEXT NOT NULL,
    service TEXT NOT NULL,
    type_name TEXT NOT NULL,
    field_name TEXT NOT NULL,
    sensitive BOOLEAN NOT NULL,
    audit_always BOOLEAN NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    orphaned_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT iam_graphql_permissions_pkey PRIMARY KEY (id),
    CONSTRAINT iam_graphql_permissions_permission_key_key UNIQUE (permission_key)
);

CREATE INDEX iam_graphql_permissions_service_active_idx ON iam_graphql_permissions (service, active);
