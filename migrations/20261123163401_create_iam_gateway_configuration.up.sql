CREATE TABLE iam_upstreams (
    id UUID NOT NULL,
    name TEXT NOT NULL,
    namespace TEXT NOT NULL,
    service_name TEXT NOT NULL,
    catalog_service TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    forward_credentials BOOLEAN NOT NULL DEFAULT FALSE,
    system BOOLEAN NOT NULL DEFAULT FALSE,
    connect_timeout_ms BIGINT NOT NULL,
    response_timeout_ms BIGINT NOT NULL,
    concurrency_limit BIGINT NOT NULL,
    retry_budget_percent INTEGER NOT NULL,
    outlier_threshold BIGINT NOT NULL,
    version BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    deleted_at TIMESTAMPTZ,
    CONSTRAINT iam_upstreams_pkey PRIMARY KEY (id),
    CONSTRAINT iam_upstreams_port_check CHECK (port BETWEEN 1 AND 65535),
    CONSTRAINT iam_upstreams_protocol_check CHECK (protocol IN ('http1', 'h2c')),
    CONSTRAINT iam_upstreams_connect_timeout_check CHECK (connect_timeout_ms > 0),
    CONSTRAINT iam_upstreams_response_timeout_check CHECK (response_timeout_ms > 0),
    CONSTRAINT iam_upstreams_concurrency_limit_check CHECK (concurrency_limit > 0),
    CONSTRAINT iam_upstreams_retry_budget_check CHECK (retry_budget_percent BETWEEN 0 AND 100),
    CONSTRAINT iam_upstreams_outlier_threshold_check CHECK (outlier_threshold > 0),
    CONSTRAINT iam_upstreams_version_check CHECK (version >= 1)
);

CREATE UNIQUE INDEX iam_upstreams_name_key ON iam_upstreams (name) WHERE deleted_at IS NULL;

CREATE TABLE iam_rate_policies (
    id UUID NOT NULL,
    name TEXT NOT NULL,
    key_kind TEXT NOT NULL,
    request_limit BIGINT NOT NULL,
    period_seconds BIGINT NOT NULL,
    burst BIGINT NOT NULL,
    fallback TEXT NOT NULL,
    version BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    deleted_at TIMESTAMPTZ,
    CONSTRAINT iam_rate_policies_pkey PRIMARY KEY (id),
    CONSTRAINT iam_rate_policies_name_length_check CHECK (char_length(name) BETWEEN 1 AND 100),
    CONSTRAINT iam_rate_policies_key_kind_check CHECK (
        key_kind IN ('ip', 'subject', 'subject_route', 'route')
    ),
    CONSTRAINT iam_rate_policies_limit_check CHECK (request_limit > 0),
    CONSTRAINT iam_rate_policies_period_check CHECK (period_seconds > 0),
    CONSTRAINT iam_rate_policies_burst_check CHECK (burst >= 0),
    CONSTRAINT iam_rate_policies_fallback_check CHECK (fallback IN ('divided', 'full')),
    CONSTRAINT iam_rate_policies_version_check CHECK (version >= 1)
);

CREATE UNIQUE INDEX iam_rate_policies_name_key ON iam_rate_policies (name) WHERE deleted_at IS NULL;

CREATE TABLE iam_routes (
    id UUID NOT NULL,
    host TEXT NOT NULL,
    methods TEXT[] NOT NULL,
    path_pattern TEXT NOT NULL,
    service TEXT NOT NULL,
    upstream_id UUID NOT NULL,
    graphql BOOLEAN NOT NULL DEFAULT FALSE,
    streaming BOOLEAN NOT NULL DEFAULT FALSE,
    anonymous BOOLEAN NOT NULL DEFAULT FALSE,
    enforcement TEXT NOT NULL,
    body_limit BIGINT NOT NULL,
    request_timeout_ms BIGINT NOT NULL,
    idle_timeout_ms BIGINT NOT NULL,
    retry TEXT NOT NULL,
    cors JSONB,
    system BOOLEAN NOT NULL DEFAULT FALSE,
    version BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    deleted_at TIMESTAMPTZ,
    CONSTRAINT iam_routes_pkey PRIMARY KEY (id),
    CONSTRAINT iam_routes_upstream_id_fkey FOREIGN KEY (upstream_id) REFERENCES iam_upstreams (id),
    CONSTRAINT iam_routes_methods_check CHECK (cardinality(methods) >= 1),
    CONSTRAINT iam_routes_enforcement_check CHECK (enforcement IN ('enforce', 'audit')),
    CONSTRAINT iam_routes_retry_check CHECK (retry IN ('none', 'idempotent')),
    CONSTRAINT iam_routes_body_limit_check CHECK (body_limit > 0),
    CONSTRAINT iam_routes_request_timeout_check CHECK (request_timeout_ms > 0),
    CONSTRAINT iam_routes_idle_timeout_check CHECK (idle_timeout_ms > 0),
    CONSTRAINT iam_routes_version_check CHECK (version >= 1)
);

CREATE INDEX iam_routes_host_path_pattern_idx ON iam_routes (host, path_pattern);
CREATE INDEX iam_routes_upstream_id_idx ON iam_routes (upstream_id);

CREATE TABLE iam_route_rate_policies (
    route_id UUID NOT NULL,
    rate_policy_id UUID NOT NULL,
    position INTEGER NOT NULL,
    CONSTRAINT iam_route_rate_policies_pkey PRIMARY KEY (route_id, rate_policy_id),
    CONSTRAINT iam_route_rate_policies_route_id_fkey FOREIGN KEY (route_id) REFERENCES iam_routes (id),
    CONSTRAINT iam_route_rate_policies_rate_policy_id_fkey
        FOREIGN KEY (rate_policy_id) REFERENCES iam_rate_policies (id),
    CONSTRAINT iam_route_rate_policies_position_check CHECK (position >= 1)
);

CREATE INDEX iam_route_rate_policies_rate_policy_id_idx ON iam_route_rate_policies (rate_policy_id);
