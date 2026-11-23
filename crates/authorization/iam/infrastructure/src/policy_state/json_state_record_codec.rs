//! Canonical JSON encoding of the policy state records.
//!
//! Every object lists its fields in alphabetical order and every list is in canonical order, so the
//! same state always encodes to the same bytes. Each record carries its `schemaVersion`.

use iam_domain::{
    AssignmentScope, AssignmentState, CatalogueChunk, CatalogueEntryState, CatalogueManifest,
    ChunkId, EntityVersion, GrantState, InvalidStateRecord, PolicyDigestValue, PolicyHead,
    PolicyState, PolicyVersion, ProjectId, RoleId, RoleKind, RoleState, ServiceName, StateKey,
    StateRecordCodec, SubjectKind, SubjectRef, SubjectState,
};
use serde_json::{Map, Value};

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
            StateKey::Route(_)
            | StateKey::Upstream(_)
            | StateKey::RatePolicy(_)
            | StateKey::SessionRevocation(_)
            | StateKey::UserRevocation(_)
            | StateKey::GlobalRevocation => Err(field_error("key")),
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
