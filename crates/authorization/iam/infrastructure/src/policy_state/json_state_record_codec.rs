//! Canonical JSON encoding of the policy state records.
//!
//! Every object lists its fields in alphabetical order and every list is in canonical order, so the
//! same state always encodes to the same bytes. Each record carries its `schemaVersion`.

use iam_domain::{
    AssignmentScope, AssignmentState, CatalogueChunk, CatalogueEntryState, CatalogueManifest,
    ChunkId, CorsDraft, CorsPolicy, EnforcementMode, EntityVersion, GlobalRevocationState,
    GrantState, HttpMethod, InvalidStateRecord, PolicyDigestValue, PolicyHead, PolicyState,
    PolicyVersion, ProjectId, RateFallback, RateKeyKind, RatePolicyDraft, RatePolicyFields,
    RatePolicyId, RatePolicyState, RetryPolicy, RoleId, RoleKind, RoleState, RouteDraft,
    RouteFields, RouteFlag, RouteFlags, RouteId, RouteState, ServiceName, SessionId,
    SessionRevocationState, StateKey, StateRecordCodec, SubjectKind, SubjectRef, SubjectState,
    UpstreamFields, UpstreamId, UpstreamProtocol, UpstreamSettingsDraft, UpstreamState,
    UserRevocationState,
};
use serde_json::{Map, Value};
use shared_domain::Uuid;

/// The schema version that this release writes and reads.
pub const SCHEMA_VERSION: i64 = 1;

type Fields = Map<String, Value>;

/// Encodes and decodes the policy state records as canonical JSON.
#[derive(Debug, Default, Clone, Copy)]
pub struct JsonStateRecordCodec;

/// The JSON object of `fields`, which the caller lists in alphabetical order.
fn object<const N: usize>(fields: [(&str, Value); N]) -> Value {
    Value::Object(
        fields
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect(),
    )
}

fn optional_text(value: Option<&str>) -> Value {
    value.map_or(Value::Null, |text| Value::String(text.to_owned()))
}

fn encode_role(role: RoleState) -> Value {
    let role = role.canonical();
    let grants = role
        .grants
        .iter()
        .map(|grant| {
            object([
                ("active", Value::Bool(grant.active)),
                ("key", Value::String(grant.key.clone())),
            ])
        })
        .collect();
    object([
        ("description", optional_text(role.description.as_deref())),
        ("grants", Value::Array(grants)),
        ("id", Value::String(role.id.to_string())),
        ("kind", Value::String(role.kind.as_str().to_owned())),
        ("name", Value::String(role.name)),
        ("schemaVersion", Value::from(SCHEMA_VERSION)),
        ("version", Value::from(role.version.value())),
    ])
}

fn encode_assignment(assignment: &AssignmentState) -> Value {
    object([
        (
            "expiresAt",
            assignment
                .expires_at_micros
                .map_or(Value::Null, Value::from),
        ),
        (
            "project",
            optional_text(
                assignment
                    .scope
                    .project_id()
                    .map(|project| project.to_string())
                    .as_deref(),
            ),
        ),
        ("role", Value::String(assignment.role.to_string())),
        ("scope", Value::String(assignment.scope.kind().to_owned())),
    ])
}

fn encode_subject(state: SubjectState) -> Value {
    let state = state.canonical();
    object([
        (
            "assignments",
            Value::Array(state.assignments.iter().map(encode_assignment).collect()),
        ),
        ("schemaVersion", Value::from(SCHEMA_VERSION)),
        (
            "subject",
            object([
                ("id", Value::String(state.subject.id().to_string())),
                (
                    "kind",
                    Value::String(state.subject.kind().as_str().to_owned()),
                ),
            ]),
        ),
    ])
}

fn encode_entry(entry: &CatalogueEntryState) -> Value {
    object([
        ("auditAlways", Value::Bool(entry.audit_always)),
        ("key", Value::String(entry.key.clone())),
        ("sensitive", Value::Bool(entry.sensitive)),
    ])
}

fn encode_chunk(chunk: &CatalogueChunk) -> Value {
    object([
        (
            "entries",
            Value::Array(chunk.entries.iter().map(encode_entry).collect()),
        ),
        ("schemaVersion", Value::from(SCHEMA_VERSION)),
        ("service", Value::String(chunk.service.to_string())),
    ])
}

fn encode_manifest(manifest: &CatalogueManifest) -> Value {
    object([
        ("catalogEpoch", Value::from(manifest.catalog_epoch)),
        (
            "chunks",
            Value::Array(
                manifest
                    .chunks
                    .iter()
                    .map(|chunk| Value::String(chunk.to_string()))
                    .collect(),
            ),
        ),
        ("schemaVersion", Value::from(SCHEMA_VERSION)),
        ("service", Value::String(manifest.service.to_string())),
    ])
}

fn encode_upstream(upstream: &UpstreamState) -> Value {
    let settings = &upstream.settings;
    object([
        (
            "catalogService",
            Value::String(settings.catalog_service().to_string()),
        ),
        (
            "concurrencyLimit",
            Value::from(settings.concurrency_limit()),
        ),
        (
            "connectTimeoutMs",
            Value::from(settings.connect_timeout_ms()),
        ),
        (
            "forwardCredentials",
            Value::Bool(settings.forward_credentials()),
        ),
        ("id", Value::String(upstream.id.to_string())),
        ("name", Value::String(upstream.name.to_string())),
        ("namespace", Value::String(settings.namespace().to_owned())),
        (
            "outlierThreshold",
            Value::from(settings.outlier_threshold()),
        ),
        ("port", Value::from(settings.port())),
        (
            "protocol",
            Value::String(settings.protocol().as_str().to_owned()),
        ),
        (
            "responseTimeoutMs",
            Value::from(settings.response_timeout_ms()),
        ),
        (
            "retryBudgetPercent",
            Value::from(settings.retry_budget_percent()),
        ),
        ("schemaVersion", Value::from(SCHEMA_VERSION)),
        (
            "serviceName",
            Value::String(settings.service_name().to_owned()),
        ),
        ("system", Value::Bool(upstream.system)),
        ("version", Value::from(upstream.version.value())),
    ])
}

fn method_texts(methods: &[HttpMethod]) -> Value {
    Value::Array(
        methods
            .iter()
            .map(|method| Value::String(method.as_str().to_owned()))
            .collect(),
    )
}

fn text_list(values: &[String]) -> Value {
    Value::Array(values.iter().cloned().map(Value::String).collect())
}

fn encode_cors(cors: &CorsPolicy) -> Value {
    object([
        ("allowCredentials", Value::Bool(cors.allow_credentials())),
        ("headers", text_list(cors.headers())),
        ("maxAgeSeconds", Value::from(cors.max_age_seconds())),
        ("methods", method_texts(cors.methods())),
        ("origins", text_list(cors.origins())),
    ])
}

fn encode_route(route: &RouteState) -> Value {
    let fields = &route.fields;
    let flags = fields.flags();
    object([
        ("bodyLimit", Value::from(fields.body_limit().bytes())),
        ("cors", fields.cors().map_or(Value::Null, encode_cors)),
        (
            "enforcement",
            Value::String(fields.enforcement().as_str().to_owned()),
        ),
        (
            "flags",
            object([
                ("anonymous", Value::Bool(flags.anonymous())),
                ("graphql", Value::Bool(flags.graphql())),
                ("streaming", Value::Bool(flags.streaming())),
            ]),
        ),
        ("host", Value::String(fields.host().as_str().to_owned())),
        ("id", Value::String(route.id.to_string())),
        ("idleTimeoutMs", Value::from(fields.timeouts().idle_ms())),
        ("methods", method_texts(fields.methods())),
        (
            "pathPattern",
            Value::String(fields.path_pattern().as_str().to_owned()),
        ),
        (
            "ratePolicies",
            Value::Array(
                fields
                    .rate_policies()
                    .iter()
                    .map(|policy| Value::String(policy.to_string()))
                    .collect(),
            ),
        ),
        (
            "requestTimeoutMs",
            Value::from(fields.timeouts().request_ms()),
        ),
        ("retry", Value::String(fields.retry().as_str().to_owned())),
        ("schemaVersion", Value::from(SCHEMA_VERSION)),
        ("service", Value::String(fields.service().to_string())),
        ("system", Value::Bool(route.system)),
        (
            "upstreamId",
            Value::String(fields.upstream_id().to_string()),
        ),
        ("version", Value::from(route.version.value())),
    ])
}

fn encode_rate_policy(policy: &RatePolicyState) -> Value {
    let fields = &policy.fields;
    object([
        ("burst", Value::from(fields.burst())),
        (
            "fallback",
            Value::String(fields.fallback().as_str().to_owned()),
        ),
        ("id", Value::String(policy.id.to_string())),
        (
            "keyKind",
            Value::String(fields.key_kind().as_str().to_owned()),
        ),
        ("limit", Value::from(fields.limit())),
        ("name", Value::String(fields.name().to_owned())),
        ("periodSeconds", Value::from(fields.period_seconds())),
        ("schemaVersion", Value::from(SCHEMA_VERSION)),
        ("version", Value::from(policy.version.value())),
    ])
}

fn encode_session_revocation(state: &SessionRevocationState) -> Value {
    object([
        ("pruneAfterMicros", Value::from(state.prune_after_micros)),
        ("revokedAtMicros", Value::from(state.revoked_at_micros)),
        ("schemaVersion", Value::from(SCHEMA_VERSION)),
        ("session", Value::String(state.session.to_string())),
        ("user", Value::String(state.user.to_string())),
    ])
}

fn encode_user_revocation(state: &UserRevocationState) -> Value {
    object([
        ("pruneAfterMicros", Value::from(state.prune_after_micros)),
        ("schemaVersion", Value::from(SCHEMA_VERSION)),
        (
            "tokensValidAfterMicros",
            Value::from(state.tokens_valid_after_micros),
        ),
        ("user", Value::String(state.user.to_string())),
    ])
}

fn encode_global_revocation(state: &GlobalRevocationState) -> Value {
    object([
        ("schemaVersion", Value::from(SCHEMA_VERSION)),
        (
            "tokensValidAfterMicros",
            Value::from(state.tokens_valid_after_micros),
        ),
    ])
}

fn encode_head(head: &PolicyHead) -> Value {
    object([
        ("digest", Value::String(head.digest.to_hex())),
        ("schemaVersion", Value::from(SCHEMA_VERSION)),
        ("version", Value::from(head.version.value())),
    ])
}

const fn field_error(field: &'static str) -> InvalidStateRecord {
    InvalidStateRecord::Field { field }
}

fn get<'a>(fields: &'a Fields, name: &'static str) -> Result<&'a Value, InvalidStateRecord> {
    fields.get(name).ok_or_else(|| field_error(name))
}

fn text(fields: &Fields, name: &'static str) -> Result<String, InvalidStateRecord> {
    get(fields, name)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| field_error(name))
}

fn flag(fields: &Fields, name: &'static str) -> Result<bool, InvalidStateRecord> {
    get(fields, name)?
        .as_bool()
        .ok_or_else(|| field_error(name))
}

fn number(fields: &Fields, name: &'static str) -> Result<i64, InvalidStateRecord> {
    get(fields, name)?.as_i64().ok_or_else(|| field_error(name))
}

fn nullable<'a, T>(
    fields: &'a Fields,
    name: &'static str,
    read: impl FnOnce(&'a Value) -> Option<T>,
) -> Result<Option<T>, InvalidStateRecord> {
    let value = get(fields, name)?;
    if value.is_null() {
        return Ok(None);
    }
    read(value).map(Some).ok_or_else(|| field_error(name))
}

fn member<'a>(value: &'a Value, name: &'static str) -> Result<&'a Fields, InvalidStateRecord> {
    value.as_object().ok_or_else(|| field_error(name))
}

fn members<'a>(
    fields: &'a Fields,
    name: &'static str,
) -> Result<Vec<&'a Fields>, InvalidStateRecord> {
    get(fields, name)?
        .as_array()
        .ok_or_else(|| field_error(name))?
        .iter()
        .map(|value| member(value, name))
        .collect()
}

fn decode_role(fields: &Fields) -> Result<PolicyState, InvalidStateRecord> {
    let grants = members(fields, "grants")?
        .into_iter()
        .map(|grant| {
            Ok(GrantState {
                key: text(grant, "key")?,
                active: flag(grant, "active")?,
            })
        })
        .collect::<Result<Vec<_>, InvalidStateRecord>>()?;
    Ok(PolicyState::Role(
        RoleState {
            id: RoleId::parse(&text(fields, "id")?).map_err(|_error| field_error("id"))?,
            name: text(fields, "name")?,
            description: nullable(fields, "description", |value| {
                value.as_str().map(str::to_owned)
            })?,
            kind: RoleKind::parse(&text(fields, "kind")?).map_err(|_error| field_error("kind"))?,
            version: EntityVersion::new(number(fields, "version")?)
                .map_err(|_error| field_error("version"))?,
            grants,
        }
        .canonical(),
    ))
}

fn decode_assignment(fields: &Fields) -> Result<AssignmentState, InvalidStateRecord> {
    let project = nullable(fields, "project", Value::as_str)?
        .map(ProjectId::parse)
        .transpose()
        .map_err(|_error| field_error("project"))?;
    Ok(AssignmentState {
        role: RoleId::parse(&text(fields, "role")?).map_err(|_error| field_error("role"))?,
        scope: AssignmentScope::from_parts(&text(fields, "scope")?, project)
            .map_err(|_error| field_error("scope"))?,
        expires_at_micros: nullable(fields, "expiresAt", Value::as_i64)?,
    })
}

fn decode_subject(fields: &Fields) -> Result<PolicyState, InvalidStateRecord> {
    let subject = member(get(fields, "subject")?, "subject")?;
    let kind = SubjectKind::parse(&text(subject, "kind")?).map_err(|_error| field_error("kind"))?;
    let assignments = members(fields, "assignments")?
        .into_iter()
        .map(decode_assignment)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PolicyState::Subject(
        SubjectState {
            subject: SubjectRef::new(kind, &text(subject, "id")?)
                .map_err(|_error| field_error("id"))?,
            assignments,
        }
        .canonical(),
    ))
}

fn service(fields: &Fields) -> Result<ServiceName, InvalidStateRecord> {
    ServiceName::new(&text(fields, "service")?).map_err(|_error| field_error("service"))
}

fn decode_manifest(fields: &Fields) -> Result<PolicyState, InvalidStateRecord> {
    let chunks = get(fields, "chunks")?
        .as_array()
        .ok_or_else(|| field_error("chunks"))?
        .iter()
        .map(|chunk| {
            chunk
                .as_str()
                .ok_or_else(|| field_error("chunks"))
                .and_then(ChunkId::new)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PolicyState::Manifest(CatalogueManifest {
        service: service(fields)?,
        catalog_epoch: number(fields, "catalogEpoch")?,
        chunks,
    }))
}

fn decode_chunk(fields: &Fields) -> Result<PolicyState, InvalidStateRecord> {
    let entries = members(fields, "entries")?
        .into_iter()
        .map(|entry| {
            Ok(CatalogueEntryState {
                key: text(entry, "key")?,
                sensitive: flag(entry, "sensitive")?,
                audit_always: flag(entry, "auditAlways")?,
            })
        })
        .collect::<Result<Vec<_>, InvalidStateRecord>>()?;
    Ok(PolicyState::Chunk(CatalogueChunk {
        service: service(fields)?,
        entries,
    }))
}

fn version(fields: &Fields) -> Result<EntityVersion, InvalidStateRecord> {
    EntityVersion::new(number(fields, "version")?).map_err(|_error| field_error("version"))
}

fn identifier<T>(
    fields: &Fields,
    name: &'static str,
    parse: impl FnOnce(&str) -> Result<T, iam_domain::InvalidIamValue>,
) -> Result<T, InvalidStateRecord> {
    parse(&text(fields, name)?).map_err(|_error| field_error(name))
}

/// The value of a closed set that the text of the field names.
fn variant<T>(
    fields: &Fields,
    name: &'static str,
    parse: impl FnOnce(&str) -> Option<T>,
) -> Result<T, InvalidStateRecord> {
    parse(&text(fields, name)?).ok_or_else(|| field_error(name))
}

fn decode_upstream(fields: &Fields) -> Result<PolicyState, InvalidStateRecord> {
    let draft = UpstreamSettingsDraft {
        namespace: text(fields, "namespace")?,
        service_name: text(fields, "serviceName")?,
        catalog_service: text(fields, "catalogService")?,
        port: number(fields, "port")?,
        protocol: variant(fields, "protocol", UpstreamProtocol::parse)?,
        forward_credentials: flag(fields, "forwardCredentials")?,
        connect_timeout_ms: number(fields, "connectTimeoutMs")?,
        response_timeout_ms: number(fields, "responseTimeoutMs")?,
        concurrency_limit: number(fields, "concurrencyLimit")?,
        retry_budget_percent: number(fields, "retryBudgetPercent")?,
        outlier_threshold: number(fields, "outlierThreshold")?,
    };
    let (name, settings) = UpstreamFields::new(&text(fields, "name")?, &draft)
        .map_err(|_violations| field_error("settings"))?
        .into_parts();
    Ok(PolicyState::Upstream(UpstreamState {
        id: identifier(fields, "id", UpstreamId::parse)?,
        name,
        settings,
        system: flag(fields, "system")?,
        version: version(fields)?,
    }))
}

fn texts(fields: &Fields, name: &'static str) -> Result<Vec<String>, InvalidStateRecord> {
    get(fields, name)?
        .as_array()
        .ok_or_else(|| field_error(name))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| field_error(name))
        })
        .collect()
}

fn methods(fields: &Fields) -> Result<Vec<HttpMethod>, InvalidStateRecord> {
    texts(fields, "methods")?
        .iter()
        .map(|method| HttpMethod::parse(method).ok_or_else(|| field_error("methods")))
        .collect()
}

fn decode_cors(value: &Value) -> Result<CorsDraft, InvalidStateRecord> {
    let fields = member(value, "cors")?;
    Ok(CorsDraft {
        origins: texts(fields, "origins")?,
        methods: methods(fields)?,
        headers: texts(fields, "headers")?,
        allow_credentials: flag(fields, "allowCredentials")?,
        max_age_seconds: number(fields, "maxAgeSeconds")?,
    })
}

/// The canonical JSON text of a CORS policy, as the state record and the `cors` column hold it.
pub(crate) fn cors_to_json(cors: &CorsPolicy) -> String {
    encode_cors(cors).to_string()
}

/// The unvalidated CORS policy that the canonical JSON text holds.
///
/// # Errors
///
/// [`InvalidStateRecord::Field`] when the text is not the JSON of a CORS policy.
pub(crate) fn cors_from_json(text: &str) -> Result<CorsDraft, InvalidStateRecord> {
    let value: Value = serde_json::from_str(text).map_err(|_error| field_error("cors"))?;
    decode_cors(&value)
}

fn decode_flags(fields: &Fields) -> Result<RouteFlags, InvalidStateRecord> {
    let flags = member(get(fields, "flags")?, "flags")?;
    Ok(RouteFlags::default()
        .with(RouteFlag::Graphql, flag(flags, "graphql")?)
        .with(RouteFlag::Streaming, flag(flags, "streaming")?)
        .with(RouteFlag::Anonymous, flag(flags, "anonymous")?))
}

fn decode_route(fields: &Fields) -> Result<PolicyState, InvalidStateRecord> {
    let rate_policies = texts(fields, "ratePolicies")?
        .iter()
        .map(|id| RatePolicyId::parse(id).map_err(|_error| field_error("ratePolicies")))
        .collect::<Result<Vec<_>, _>>()?;
    let cors = nullable(fields, "cors", Some)?
        .map(decode_cors)
        .transpose()?;
    let draft = RouteDraft {
        host: text(fields, "host")?,
        methods: methods(fields)?,
        path_pattern: text(fields, "pathPattern")?,
        service: text(fields, "service")?,
        upstream_id: identifier(fields, "upstreamId", UpstreamId::parse)?,
        flags: decode_flags(fields)?,
        enforcement: variant(fields, "enforcement", EnforcementMode::parse)?,
        body_limit: number(fields, "bodyLimit")?,
        request_timeout_ms: number(fields, "requestTimeoutMs")?,
        idle_timeout_ms: number(fields, "idleTimeoutMs")?,
        retry: variant(fields, "retry", RetryPolicy::parse)?,
        rate_policies,
        cors,
    };
    Ok(PolicyState::Route(RouteState {
        id: identifier(fields, "id", RouteId::parse)?,
        fields: RouteFields::new(&draft).map_err(|_violations| field_error("route"))?,
        system: flag(fields, "system")?,
        version: version(fields)?,
    }))
}

fn decode_rate_policy(fields: &Fields) -> Result<PolicyState, InvalidStateRecord> {
    let draft = RatePolicyDraft {
        name: text(fields, "name")?,
        key_kind: variant(fields, "keyKind", RateKeyKind::parse)?,
        limit: number(fields, "limit")?,
        period_seconds: number(fields, "periodSeconds")?,
        burst: number(fields, "burst")?,
        fallback: variant(fields, "fallback", RateFallback::parse)?,
    };
    Ok(PolicyState::RatePolicy(RatePolicyState {
        id: identifier(fields, "id", RatePolicyId::parse)?,
        fields: RatePolicyFields::new(draft).map_err(|_violations| field_error("fields"))?,
        version: version(fields)?,
    }))
}

fn decode_session_revocation(fields: &Fields) -> Result<PolicyState, InvalidStateRecord> {
    Ok(PolicyState::SessionRevocation(SessionRevocationState {
        session: SessionId::new(&text(fields, "session")?)
            .map_err(|_error| field_error("session"))?,
        user: Uuid::parse(&text(fields, "user")?).map_err(|_error| field_error("user"))?,
        revoked_at_micros: number(fields, "revokedAtMicros")?,
        prune_after_micros: number(fields, "pruneAfterMicros")?,
    }))
}

fn decode_user_revocation(fields: &Fields) -> Result<PolicyState, InvalidStateRecord> {
    Ok(PolicyState::UserRevocation(UserRevocationState {
        user: Uuid::parse(&text(fields, "user")?).map_err(|_error| field_error("user"))?,
        tokens_valid_after_micros: number(fields, "tokensValidAfterMicros")?,
        prune_after_micros: number(fields, "pruneAfterMicros")?,
    }))
}

fn decode_global_revocation(fields: &Fields) -> Result<PolicyState, InvalidStateRecord> {
    Ok(PolicyState::GlobalRevocation(GlobalRevocationState {
        tokens_valid_after_micros: number(fields, "tokensValidAfterMicros")?,
    }))
}

fn decode_head(fields: &Fields) -> Result<PolicyState, InvalidStateRecord> {
    Ok(PolicyState::Head(PolicyHead {
        version: PolicyVersion::new(number(fields, "version")?)
            .map_err(|_error| field_error("version"))?,
        digest: PolicyDigestValue::from_hex(&text(fields, "digest")?)
            .map_err(|_error| field_error("digest"))?,
    }))
}

impl StateRecordCodec for JsonStateRecordCodec {
    fn encode(&self, state: &PolicyState) -> Result<String, InvalidStateRecord> {
        let value = match state {
            PolicyState::Role(role) => encode_role(role.clone()),
            PolicyState::Subject(subject) => encode_subject(subject.clone()),
            PolicyState::Manifest(manifest) => encode_manifest(manifest),
            PolicyState::Chunk(chunk) => encode_chunk(chunk),
            PolicyState::Upstream(upstream) => encode_upstream(upstream),
            PolicyState::Route(route) => encode_route(route),
            PolicyState::RatePolicy(policy) => encode_rate_policy(policy),
            PolicyState::SessionRevocation(state) => encode_session_revocation(state),
            PolicyState::UserRevocation(state) => encode_user_revocation(state),
            PolicyState::GlobalRevocation(state) => encode_global_revocation(state),
            PolicyState::Head(head) => encode_head(head),
        };
        Ok(value.to_string())
    }

    fn decode(&self, key: &StateKey, payload: &str) -> Result<PolicyState, InvalidStateRecord> {
        let value: Value =
            serde_json::from_str(payload).map_err(|_error| field_error("payload"))?;
        let fields = member(&value, "payload")?;
        let found = number(fields, "schemaVersion")?;
        if found != SCHEMA_VERSION {
            return Err(InvalidStateRecord::UnsupportedSchema { found });
        }
        let state = match key {
            StateKey::Role(_) => decode_role(fields),
            StateKey::Subject(_) => decode_subject(fields),
            StateKey::CatalogueManifest(_) => decode_manifest(fields),
            StateKey::CatalogueChunk { .. } => decode_chunk(fields),
            StateKey::Head => decode_head(fields),
            StateKey::Upstream(_) => decode_upstream(fields),
            StateKey::Route(_) => decode_route(fields),
            StateKey::RatePolicy(_) => decode_rate_policy(fields),
            StateKey::SessionRevocation(_) => decode_session_revocation(fields),
            StateKey::UserRevocation(_) => decode_user_revocation(fields),
            StateKey::GlobalRevocation => decode_global_revocation(fields),
        }?;
        if state.belongs_to(key) {
            Ok(state)
        } else {
            Err(field_error("key"))
        }
    }

    fn entry_size(&self, entry: &CatalogueEntryState) -> usize {
        encode_entry(entry).to_string().len().saturating_add(1)
    }
}

#[cfg(test)]
mod tests;
