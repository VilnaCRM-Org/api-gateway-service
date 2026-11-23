use iam_domain::{
    AssignmentScope, AssignmentState, CatalogueChunk, CatalogueEntryState, CatalogueManifest,
    ChunkId, EntityVersion, GrantState, InvalidStateRecord, PolicyDigestValue, PolicyHead,
    PolicyState, PolicyVersion, ProjectId, RoleId, RoleKind, RoleState, ServiceName, StateKey,
    StateRecordCodec as _, SubjectRef, SubjectState,
};
use rstest::rstest;
use serde_json::Value as Json;
use shared_domain::Uuid;

use super::JsonStateRecordCodec;

const ROLE: &str = "0192f6a0-0000-7000-8000-000000000001";
const USER: &str = "0192f6a0-0000-7000-8000-000000000002";
const PROJECT: &str = "0192f6a0-0000-7000-8000-000000000003";

fn role_id() -> RoleId {
    RoleId::parse(ROLE).unwrap()
}

fn service() -> ServiceName {
    ServiceName::new("user-service").unwrap()
}

fn role() -> PolicyState {
    PolicyState::Role(RoleState {
        id: role_id(),
        name: "Editor".to_owned(),
        description: Some("Edits \"things\"".to_owned()),
        kind: RoleKind::Custom,
        version: EntityVersion::new(3).unwrap(),
        grants: vec![
            GrantState {
                key: "gql:user-service:Query.users".to_owned(),
                active: true,
            },
            GrantState {
                key: "rest:user-service:GET /users".to_owned(),
                active: false,
            },
        ],
    })
}

fn subject() -> PolicyState {
    PolicyState::Subject(SubjectState {
        subject: SubjectRef::user(Uuid::parse(USER).unwrap()),
        assignments: vec![
            AssignmentState {
                role: role_id(),
                scope: AssignmentScope::from_parts("global", None).unwrap(),
                expires_at_micros: None,
            },
            AssignmentState {
                role: role_id(),
                scope: AssignmentScope::from_parts(
                    "project",
                    Some(ProjectId::parse(PROJECT).unwrap()),
                )
                .unwrap(),
                expires_at_micros: Some(1_700_000_000_123_456),
            },
        ],
    })
}

fn manifest() -> PolicyState {
    PolicyState::Manifest(CatalogueManifest {
        service: service(),
        catalog_epoch: 4,
        chunks: vec![ChunkId::new("00ff").unwrap(), ChunkId::new("a1").unwrap()],
    })
}

fn chunk() -> PolicyState {
    PolicyState::Chunk(CatalogueChunk {
        service: service(),
        entries: vec![
            CatalogueEntryState {
                key: "gql:user-service:Mutation.createUser".to_owned(),
                sensitive: true,
                audit_always: false,
            },
            CatalogueEntryState {
                key: "gql:user-service:Query.users".to_owned(),
                sensitive: false,
                audit_always: true,
            },
        ],
    })
}

fn head() -> PolicyState {
    PolicyState::Head(PolicyHead {
        version: PolicyVersion::new(12).unwrap(),
        digest: PolicyDigestValue::from_bytes([0xab; 16]),
    })
}

fn key_of(state: &PolicyState) -> StateKey {
    match state {
        PolicyState::Role(role) => StateKey::Role(role.id),
        PolicyState::Subject(subject) => StateKey::Subject(subject.subject.clone()),
        PolicyState::Manifest(manifest) => StateKey::CatalogueManifest(manifest.service.clone()),
        PolicyState::Chunk(chunk) => {
            StateKey::chunk(chunk.service.clone(), ChunkId::new("00ff").unwrap())
        }
        PolicyState::Head(_) => StateKey::Head,
    }
}

#[rstest]
#[case::role(role())]
#[case::subject(subject())]
#[case::manifest(manifest())]
#[case::chunk(chunk())]
#[case::head(head())]
fn each_kind_round_trips_to_the_same_state_and_the_same_bytes(#[case] state: PolicyState) {
    let key = key_of(&state);

    let encoded = JsonStateRecordCodec.encode(&state).unwrap();
    let decoded = JsonStateRecordCodec.decode(&key, &encoded).unwrap();

    assert_eq!(JsonStateRecordCodec.encode(&decoded).unwrap(), encoded);
    assert!(decoded.belongs_to(&key));
}

#[test]
fn a_role_encodes_to_canonical_json_with_its_schema_version() {
    let encoded = JsonStateRecordCodec.encode(&role()).unwrap();

    assert_eq!(
        encoded,
        concat!(
            r#"{"description":"Edits \"things\"","#,
            r#""grants":[{"active":true,"key":"gql:user-service:Query.users"},"#,
            r#"{"active":false,"key":"rest:user-service:GET /users"}],"#,
            r#""id":"0192f6a0-0000-7000-8000-000000000001","kind":"custom","name":"Editor","#,
            r#""schemaVersion":1,"version":3}"#
        )
    );
}

#[test]
fn a_role_without_a_description_writes_null() {
    let PolicyState::Role(mut state) = role() else {
        panic!("expected a role");
    };
    state.description = None;

    let encoded = JsonStateRecordCodec
        .encode(&PolicyState::Role(state))
        .unwrap();

    assert!(encoded.starts_with(r#"{"description":null,"grants":"#));
}

#[test]
fn the_head_encodes_the_version_and_the_digest_in_hexadecimal() {
    let encoded = JsonStateRecordCodec.encode(&head()).unwrap();

    assert_eq!(
        encoded,
        format!(
            r#"{{"digest":"{}","schemaVersion":1,"version":12}}"#,
            "ab".repeat(16)
        )
    );
}

#[test]
fn the_order_of_grants_and_assignments_does_not_change_the_bytes() {
    let PolicyState::Role(mut reversed) = role() else {
        panic!("expected a role");
    };
    reversed.grants.reverse();
    let PolicyState::Subject(mut shuffled) = subject() else {
        panic!("expected a subject");
    };
    shuffled.assignments.reverse();

    assert_eq!(
        JsonStateRecordCodec
            .encode(&PolicyState::Role(reversed))
            .unwrap(),
        JsonStateRecordCodec.encode(&role()).unwrap()
    );
    assert_eq!(
        JsonStateRecordCodec
            .encode(&PolicyState::Subject(shuffled))
            .unwrap(),
        JsonStateRecordCodec.encode(&subject()).unwrap()
    );
}

#[test]
fn a_payload_of_another_schema_version_is_refused() {
    let key = StateKey::Head;
    let payload = format!(
        r#"{{"digest":"{}","schemaVersion":2,"version":1}}"#,
        "00".repeat(16)
    );

    assert_eq!(
        JsonStateRecordCodec.decode(&key, &payload),
        Err(InvalidStateRecord::UnsupportedSchema { found: 2 })
    );
}

#[rstest]
#[case::not_json("not json")]
#[case::not_an_object("[]")]
#[case::no_schema_version(r#"{"version":1}"#)]
#[case::bad_version(r#"{"digest":"00","schemaVersion":1,"version":1}"#)]
#[case::missing_field(r#"{"schemaVersion":1,"version":1}"#)]
#[case::negative_version(
    r#"{"digest":"00000000000000000000000000000000","schemaVersion":1,"version":-1}"#
)]
fn a_payload_that_is_not_the_head_is_refused(#[case] payload: &str) {
    let result = JsonStateRecordCodec.decode(&StateKey::Head, payload);

    assert!(matches!(result, Err(InvalidStateRecord::Field { .. })));
}

#[test]
fn a_payload_is_refused_for_the_key_of_another_entity() {
    let encoded = JsonStateRecordCodec.encode(&role()).unwrap();
    let other = StateKey::Role(RoleId::parse("0192f6a0-0000-7000-8000-0000000000ff").unwrap());

    assert_eq!(
        JsonStateRecordCodec.decode(&other, &encoded),
        Err(InvalidStateRecord::Field { field: "key" })
    );
}

#[test]
fn a_payload_is_refused_for_a_key_that_carries_no_state_yet() {
    let encoded = JsonStateRecordCodec.encode(&head()).unwrap();

    assert_eq!(
        JsonStateRecordCodec.decode(&StateKey::GlobalRevocation, &encoded),
        Err(InvalidStateRecord::Field { field: "key" })
    );
}

#[test]
fn a_role_with_an_invalid_value_is_refused() {
    let key = StateKey::Role(role_id());
    let encoded = JsonStateRecordCodec.encode(&role()).unwrap();

    let bad_kind = encoded.replace("custom", "other");
    let bad_version = encoded.replace(r#""version":3"#, r#""version":0"#);
    let bad_id = encoded.replace(ROLE, "nope");

    assert_eq!(
        JsonStateRecordCodec.decode(&key, &bad_kind),
        Err(InvalidStateRecord::Field { field: "kind" })
    );
    assert_eq!(
        JsonStateRecordCodec.decode(&key, &bad_version),
        Err(InvalidStateRecord::Field { field: "version" })
    );
    assert_eq!(
        JsonStateRecordCodec.decode(&key, &bad_id),
        Err(InvalidStateRecord::Field { field: "id" })
    );
}

#[test]
fn a_subject_with_an_invalid_scope_or_project_is_refused() {
    let key = key_of(&subject());
    let encoded = JsonStateRecordCodec.encode(&subject()).unwrap();

    let bad_scope = encoded.replace(r#""scope":"project""#, r#""scope":"team""#);
    let bad_project = encoded.replace(PROJECT, "nope");

    assert_eq!(
        JsonStateRecordCodec.decode(&key, &bad_scope),
        Err(InvalidStateRecord::Field { field: "scope" })
    );
    assert_eq!(
        JsonStateRecordCodec.decode(&key, &bad_project),
        Err(InvalidStateRecord::Field { field: "project" })
    );
}

#[test]
fn a_manifest_with_an_invalid_chunk_id_is_refused() {
    let key = key_of(&manifest());
    let encoded = JsonStateRecordCodec.encode(&manifest()).unwrap();

    let result = JsonStateRecordCodec.decode(&key, &encoded.replace("00ff", "XYZ"));

    assert_eq!(result, Err(InvalidStateRecord::ChunkId));
}

#[test]
fn the_size_of_the_entries_bounds_the_size_of_the_chunk() {
    let empty = PolicyState::Chunk(CatalogueChunk {
        service: service(),
        entries: Vec::new(),
    });
    let PolicyState::Chunk(full) = chunk() else {
        panic!("expected a chunk");
    };
    let entries_size: usize = full
        .entries
        .iter()
        .map(|entry| JsonStateRecordCodec.entry_size(entry))
        .sum();

    let empty_length = JsonStateRecordCodec.encode(&empty).unwrap().len();
    let full_length = JsonStateRecordCodec
        .encode(&PolicyState::Chunk(full))
        .unwrap()
        .len();

    assert_eq!(full_length + 1, empty_length + entries_size);
}

/// The encoding of `state` with one value changed by `edit`.
fn edited(state: &PolicyState, edit: fn(&mut Json)) -> String {
    let mut value: Json =
        serde_json::from_str(&JsonStateRecordCodec.encode(state).unwrap()).unwrap();
    edit(&mut value);
    value.to_string()
}

#[rstest]
#[case::grant_key_not_text(role(), |v: &mut Json| v["grants"][0]["key"] = 1.into(), "key")]
#[case::grant_flag_not_boolean(role(), |v: &mut Json| v["grants"][0]["active"] = "yes".into(), "active")]
#[case::version_not_a_number(role(), |v: &mut Json| v["version"] = "3".into(), "version")]
#[case::description_not_text(role(), |v: &mut Json| v["description"] = 5.into(), "description")]
#[case::grants_not_a_list(role(), |v: &mut Json| v["grants"] = serde_json::json!({}), "grants")]
#[case::assigned_role_not_an_id(subject(), |v: &mut Json| v["assignments"][0]["role"] = "nope".into(), "role")]
#[case::subject_kind_unknown(subject(), |v: &mut Json| v["subject"]["kind"] = "robot".into(), "kind")]
#[case::user_id_not_a_uuid(subject(), |v: &mut Json| v["subject"]["id"] = "nope".into(), "id")]
#[case::service_name_invalid(manifest(), |v: &mut Json| v["service"] = "".into(), "service")]
#[case::chunks_not_a_list(manifest(), |v: &mut Json| v["chunks"] = "00ff".into(), "chunks")]
#[case::chunk_id_not_text(manifest(), |v: &mut Json| v["chunks"][0] = 1.into(), "chunks")]
fn a_payload_with_a_value_of_the_wrong_shape_names_its_field(
    #[case] state: PolicyState,
    #[case] edit: fn(&mut Json),
    #[case] field: &'static str,
) {
    let result = JsonStateRecordCodec.decode(&key_of(&state), &edited(&state, edit));

    assert_eq!(result, Err(InvalidStateRecord::Field { field }));
}
