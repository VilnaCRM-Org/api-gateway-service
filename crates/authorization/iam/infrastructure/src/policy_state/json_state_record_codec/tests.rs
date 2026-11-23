use iam_domain::{
    AssignmentScope, AssignmentState, CatalogueChunk, CatalogueEntryState, CatalogueManifest,
    ChunkId, CorsDraft, EnforcementMode, EntityVersion, GrantState, HttpMethod, InvalidStateRecord,
    PolicyDigestValue, PolicyHead, PolicyState, PolicyVersion, ProjectId, RateFallback,
    RateKeyKind, RatePolicyDraft, RatePolicyFields, RatePolicyId, RatePolicyState, RetryPolicy,
    RoleId, RoleKind, RoleState, RouteDraft, RouteFields, RouteFlag, RouteFlags, RouteId,
    RouteState, ServiceName, StateKey, StateRecordCodec as _, SubjectRef, SubjectState,
    UpstreamFields, UpstreamId, UpstreamProtocol, UpstreamSettingsDraft, UpstreamState,
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

const UPSTREAM: &str = "5b2e9c1a-7d3f-4a6b-8c0d-1e2f3a4b5c6d";
const POLICY_ONE: &str = "6c3f0d2b-8e4a-4b7c-9d1e-2f3a4b5c6d7e";
const POLICY_TWO: &str = "7d4f1e3c-9f5b-4c8d-8e2f-3a4b5c6d7e8f";
const ROUTE: &str = "0192f6a0-0000-7000-8000-0000000000a1";

fn upstream() -> PolicyState {
    let (name, settings) = UpstreamFields::new(
        "core",
        &UpstreamSettingsDraft {
            namespace: "platform".to_owned(),
            service_name: "core-service".to_owned(),
            catalog_service: "core".to_owned(),
            port: 8080,
            protocol: UpstreamProtocol::H2c,
            forward_credentials: true,
            connect_timeout_ms: 1_000,
            response_timeout_ms: 30_000,
            concurrency_limit: 256,
            retry_budget_percent: 20,
            outlier_threshold: 5,
        },
    )
    .unwrap()
    .into_parts();
    PolicyState::Upstream(UpstreamState {
        id: UpstreamId::parse(UPSTREAM).unwrap(),
        name,
        settings,
        system: false,
        version: EntityVersion::new(2).unwrap(),
    })
}

fn route_draft() -> RouteDraft {
    RouteDraft {
        host: "api.example.com".to_owned(),
        methods: vec![HttpMethod::Post, HttpMethod::Get],
        path_pattern: "/users/{id}".to_owned(),
        service: "core".to_owned(),
        upstream_id: UpstreamId::parse(UPSTREAM).unwrap(),
        flags: RouteFlags::default()
            .with(RouteFlag::Graphql, true)
            .with(RouteFlag::Anonymous, true),
        enforcement: EnforcementMode::Audit,
        body_limit: 1_048_576,
        request_timeout_ms: 30_000,
        idle_timeout_ms: 60_000,
        retry: RetryPolicy::Idempotent,
        rate_policies: vec![
            RatePolicyId::parse(POLICY_TWO).unwrap(),
            RatePolicyId::parse(POLICY_ONE).unwrap(),
        ],
        cors: Some(CorsDraft {
            origins: vec!["https://app.example.com".to_owned()],
            methods: vec![HttpMethod::Get],
            headers: vec!["Authorization".to_owned()],
            allow_credentials: true,
            max_age_seconds: 600,
        }),
    }
}

fn route_with(draft: &RouteDraft) -> PolicyState {
    PolicyState::Route(RouteState {
        id: RouteId::parse(ROUTE).unwrap(),
        fields: RouteFields::new(draft).unwrap(),
        system: true,
        version: EntityVersion::new(5).unwrap(),
    })
}

fn route() -> PolicyState {
    route_with(&route_draft())
}

fn rate_policy() -> PolicyState {
    PolicyState::RatePolicy(RatePolicyState {
        id: RatePolicyId::parse(POLICY_ONE).unwrap(),
        fields: RatePolicyFields::new(RatePolicyDraft {
            name: "per-ip".to_owned(),
            key_kind: RateKeyKind::SubjectRoute,
            limit: 100,
            period_seconds: 60,
            burst: 10,
            fallback: RateFallback::Full,
        })
        .unwrap(),
        version: EntityVersion::new(1).unwrap(),
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
        PolicyState::Upstream(upstream) => StateKey::Upstream(upstream.name.clone()),
        PolicyState::Route(route) => StateKey::Route(route.id),
        PolicyState::RatePolicy(policy) => StateKey::RatePolicy(policy.id),
        PolicyState::Head(_) => StateKey::Head,
    }
}

#[rstest]
#[case::role(role())]
#[case::subject(subject())]
#[case::manifest(manifest())]
#[case::chunk(chunk())]
#[case::upstream(upstream())]
#[case::route(route())]
#[case::rate_policy(rate_policy())]
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
fn an_upstream_encodes_to_canonical_json_with_its_schema_version() {
    assert_eq!(
        JsonStateRecordCodec.encode(&upstream()).unwrap(),
        concat!(
            r#"{"catalogService":"core","concurrencyLimit":256,"connectTimeoutMs":1000,"#,
            r#""forwardCredentials":true,"id":"5b2e9c1a-7d3f-4a6b-8c0d-1e2f3a4b5c6d","#,
            r#""name":"core","namespace":"platform","outlierThreshold":5,"port":8080,"#,
            r#""protocol":"h2c","responseTimeoutMs":30000,"retryBudgetPercent":20,"#,
            r#""schemaVersion":1,"serviceName":"core-service","system":false,"version":2}"#
        )
    );
}

#[test]
fn a_route_encodes_to_canonical_json_with_its_methods_in_order_and_its_rate_policies_as_given() {
    assert_eq!(
        JsonStateRecordCodec.encode(&route()).unwrap(),
        concat!(
            r#"{"bodyLimit":1048576,"cors":{"allowCredentials":true,"headers":["Authorization"],"#,
            r#""maxAgeSeconds":600,"methods":["GET"],"origins":["https://app.example.com"]},"#,
            r#""enforcement":"audit","flags":{"anonymous":true,"graphql":true,"streaming":false},"#,
            r#""host":"api.example.com","id":"0192f6a0-0000-7000-8000-0000000000a1","#,
            r#""idleTimeoutMs":60000,"methods":["GET","POST"],"pathPattern":"/users/{id}","#,
            r#""ratePolicies":["7d4f1e3c-9f5b-4c8d-8e2f-3a4b5c6d7e8f","#,
            r#""6c3f0d2b-8e4a-4b7c-9d1e-2f3a4b5c6d7e"],"requestTimeoutMs":30000,"#,
            r#""retry":"idempotent","schemaVersion":1,"service":"core","system":true,"#,
            r#""upstreamId":"5b2e9c1a-7d3f-4a6b-8c0d-1e2f3a4b5c6d","version":5}"#
        )
    );
}

#[test]
fn a_route_without_cors_writes_null() {
    let encoded = JsonStateRecordCodec
        .encode(&route_with(&RouteDraft {
            cors: None,
            ..route_draft()
        }))
        .unwrap();

    assert!(encoded.starts_with(r#"{"bodyLimit":1048576,"cors":null,"#));
}

#[test]
fn a_rate_policy_encodes_to_canonical_json_with_its_schema_version() {
    assert_eq!(
        JsonStateRecordCodec.encode(&rate_policy()).unwrap(),
        concat!(
            r#"{"burst":10,"fallback":"full","id":"6c3f0d2b-8e4a-4b7c-9d1e-2f3a4b5c6d7e","#,
            r#""keyKind":"subject_route","limit":100,"name":"per-ip","periodSeconds":60,"#,
            r#""schemaVersion":1,"version":1}"#
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
#[case::upstream_protocol_unknown(upstream(), |v: &mut Json| v["protocol"] = "h3".into(), "protocol")]
#[case::upstream_port_not_a_number(upstream(), |v: &mut Json| v["port"] = "80".into(), "port")]
#[case::upstream_id_not_a_uuid(upstream(), |v: &mut Json| v["id"] = "nope".into(), "id")]
#[case::upstream_settings_invalid(upstream(), |v: &mut Json| v["port"] = 0.into(), "settings")]
#[case::upstream_name_invalid(upstream(), |v: &mut Json| v["name"] = "Not A Name".into(), "settings")]
#[case::upstream_version_not_positive(upstream(), |v: &mut Json| v["version"] = 0.into(), "version")]
#[case::route_enforcement_unknown(route(), |v: &mut Json| v["enforcement"] = "warn".into(), "enforcement")]
#[case::route_retry_unknown(route(), |v: &mut Json| v["retry"] = "always".into(), "retry")]
#[case::route_method_unknown(route(), |v: &mut Json| v["methods"][0] = "FETCH".into(), "methods")]
#[case::route_methods_not_text(route(), |v: &mut Json| v["methods"][0] = 1.into(), "methods")]
#[case::route_methods_not_a_list(route(), |v: &mut Json| v["methods"] = "GET".into(), "methods")]
#[case::route_rate_policy_not_an_id(route(), |v: &mut Json| v["ratePolicies"][0] = "nope".into(), "ratePolicies")]
#[case::route_flag_not_boolean(route(), |v: &mut Json| v["flags"]["graphql"] = 1.into(), "graphql")]
#[case::route_flags_not_an_object(route(), |v: &mut Json| v["flags"] = 1.into(), "flags")]
#[case::route_cors_not_an_object(route(), |v: &mut Json| v["cors"] = 1.into(), "cors")]
#[case::route_cors_origins_not_a_list(route(), |v: &mut Json| v["cors"]["origins"] = 1.into(), "origins")]
#[case::route_configuration_invalid(route(), |v: &mut Json| v["bodyLimit"] = 0.into(), "route")]
#[case::route_cors_invalid(route(), |v: &mut Json| v["cors"]["maxAgeSeconds"] = 86_401.into(), "route")]
#[case::route_id_not_a_uuid(route(), |v: &mut Json| v["id"] = "nope".into(), "id")]
#[case::rate_policy_key_kind_unknown(rate_policy(), |v: &mut Json| v["keyKind"] = "user".into(), "keyKind")]
#[case::rate_policy_fallback_unknown(rate_policy(), |v: &mut Json| v["fallback"] = "half".into(), "fallback")]
#[case::rate_policy_limit_invalid(rate_policy(), |v: &mut Json| v["limit"] = 0.into(), "fields")]
#[case::rate_policy_id_not_a_uuid(rate_policy(), |v: &mut Json| v["id"] = "nope".into(), "id")]
fn a_payload_with_a_value_of_the_wrong_shape_names_its_field(
    #[case] state: PolicyState,
    #[case] edit: fn(&mut Json),
    #[case] field: &'static str,
) {
    let result = JsonStateRecordCodec.decode(&key_of(&state), &edited(&state, edit));

    assert_eq!(result, Err(InvalidStateRecord::Field { field }));
}
