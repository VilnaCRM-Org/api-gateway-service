use shared_domain::Uuid;

use super::*;

fn role_id(last: u8) -> RoleId {
    RoleId::from_uuid(
        Uuid::parse(&format!("0192f6a0-0000-7000-8000-0000000000{last:02x}")).unwrap(),
    )
}

fn role(id: RoleId) -> RoleState {
    RoleState {
        id,
        name: "editor".to_owned(),
        description: None,
        kind: RoleKind::Custom,
        version: EntityVersion::new(1).unwrap(),
        grants: Vec::new(),
    }
}

#[test]
fn the_grants_of_a_role_take_their_canonical_order() {
    let mut state = role(role_id(1));
    state.grants = vec![
        GrantState {
            key: "rest:b:GET /x".to_owned(),
            active: true,
        },
        GrantState {
            key: "gql:a:Query.x".to_owned(),
            active: false,
        },
    ];

    let keys: Vec<_> = state
        .canonical()
        .grants
        .into_iter()
        .map(|grant| grant.key)
        .collect();

    assert_eq!(keys, ["gql:a:Query.x", "rest:b:GET /x"]);
}

#[test]
fn the_assignments_of_a_subject_take_their_canonical_order() {
    let global = AssignmentScope::from_parts("global", None).unwrap();
    let assignment = |role: u8, expires_at_micros| AssignmentState {
        role: role_id(role),
        scope: global,
        expires_at_micros,
    };
    let state = SubjectState {
        subject: SubjectRef::user(Uuid::parse("0192f6a0-0000-7000-8000-0000000000aa").unwrap()),
        assignments: vec![
            assignment(2, None),
            assignment(1, Some(5)),
            assignment(1, None),
        ],
    };

    let order: Vec<_> = state
        .canonical()
        .assignments
        .iter()
        .map(|assignment| (assignment.role, assignment.expires_at_micros))
        .collect();

    assert_eq!(
        order,
        [
            (role_id(1), None),
            (role_id(1), Some(5)),
            (role_id(2), None)
        ]
    );
}

#[test]
fn a_record_carries_the_state_its_key_names_or_none() {
    let id = role_id(1);
    let key = StateKey::Role(id);

    let live = StateRecord::new(key.clone(), Some(PolicyState::Role(role(id)))).unwrap();
    let tombstone = StateRecord::new(key.clone(), None).unwrap();

    assert!(!live.is_tombstone());
    assert!(live.state().is_some());
    assert_eq!(live.key(), &key);
    assert!(tombstone.is_tombstone());
}

#[test]
fn a_record_refuses_the_state_of_another_entity_or_kind() {
    let other_role = StateRecord::new(
        StateKey::Role(role_id(1)),
        Some(PolicyState::Role(role(role_id(2)))),
    );
    let head_state = PolicyState::Head(PolicyHead {
        version: PolicyVersion::new(1).unwrap(),
        digest: PolicyDigestValue::ZERO,
    });
    let wrong_kind = StateRecord::new(StateKey::Role(role_id(1)), Some(head_state.clone()));
    let head = StateRecord::new(StateKey::Head, Some(head_state));
    let route_with_state = StateRecord::new(
        StateKey::GlobalRevocation,
        Some(PolicyState::Role(role(role_id(1)))),
    );

    assert_eq!(
        other_role,
        Err(InvalidStateRecord::Field { field: "state" })
    );
    assert_eq!(
        wrong_kind,
        Err(InvalidStateRecord::Field { field: "state" })
    );
    assert!(head.is_ok());
    assert!(route_with_state.is_err());
}

#[test]
fn a_manifest_and_a_chunk_belong_to_their_service_only() {
    let service = ServiceName::new("user-service").unwrap();
    let other = ServiceName::new("billing").unwrap();
    let manifest = PolicyState::Manifest(CatalogueManifest {
        service: service.clone(),
        catalog_epoch: 1,
        chunks: Vec::new(),
    });
    let chunk = PolicyState::Chunk(CatalogueChunk {
        service: service.clone(),
        entries: Vec::new(),
    });
    let chunk_key = StateKey::chunk(service.clone(), ChunkId::new("ab").unwrap());

    assert!(manifest.belongs_to(&StateKey::CatalogueManifest(service)));
    assert!(!manifest.belongs_to(&StateKey::CatalogueManifest(other)));
    assert!(chunk.belongs_to(&chunk_key));
    assert!(!chunk.belongs_to(&StateKey::Head));
}

#[test]
fn a_role_a_subject_and_the_head_belong_to_their_own_key_only() {
    let subject = SubjectRef::user(Uuid::parse("0192f6a0-0000-7000-8000-0000000000aa").unwrap());
    let role_state = PolicyState::Role(role(role_id(1)));
    let subject_state = PolicyState::Subject(SubjectState {
        subject: subject.clone(),
        assignments: Vec::new(),
    });
    let head = PolicyState::Head(PolicyHead {
        version: PolicyVersion::new(1).unwrap(),
        digest: PolicyDigestValue::from_bytes([0; 16]),
    });

    assert!(role_state.belongs_to(&StateKey::Role(role_id(1))));
    assert!(!role_state.belongs_to(&StateKey::Role(role_id(2))));
    assert!(subject_state.belongs_to(&StateKey::Subject(subject)));
    assert!(head.belongs_to(&StateKey::Head));
    assert!(!head.belongs_to(&StateKey::Role(role_id(1))));
}

fn upstream_parts(name: &str) -> UpstreamParts {
    use crate::upstream::settings::{UpstreamFields, UpstreamProtocol, UpstreamSettingsDraft};

    let (name, settings) = UpstreamFields::new(
        name,
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
    UpstreamParts {
        id: UpstreamId::parse("5b2e9c1a-7d3f-4a6b-8c0d-1e2f3a4b5c6d").unwrap(),
        name,
        settings,
        system: true,
        version: EntityVersion::new(4).unwrap(),
        created_at: std::time::SystemTime::UNIX_EPOCH,
        updated_at: std::time::SystemTime::UNIX_EPOCH,
        deleted_at: None,
    }
}

fn rate_policy_parts(id: &str) -> RatePolicyParts {
    use crate::rate_policy::fields::{RateFallback, RateKeyKind, RatePolicyDraft};

    RatePolicyParts {
        id: RatePolicyId::parse(id).unwrap(),
        fields: RatePolicyFields::new(RatePolicyDraft {
            name: "per-ip".to_owned(),
            key_kind: RateKeyKind::Ip,
            limit: 100,
            period_seconds: 60,
            burst: 10,
            fallback: RateFallback::Full,
        })
        .unwrap(),
        version: EntityVersion::new(2).unwrap(),
        created_at: std::time::SystemTime::UNIX_EPOCH,
        updated_at: std::time::SystemTime::UNIX_EPOCH,
        deleted_at: None,
    }
}

#[test]
fn the_state_of_an_upstream_is_that_of_its_stored_parts() {
    let parts = upstream_parts("core");

    let state = UpstreamState::of(&parts);

    assert_eq!(state.id, parts.id);
    assert_eq!(state.name, parts.name);
    assert_eq!(state.settings, parts.settings);
    assert!(state.system);
    assert_eq!(state.version, parts.version);
}

#[test]
fn the_state_of_a_route_is_that_of_its_stored_parts() {
    use crate::route::fixtures::{fields, parts};
    use crate::value_object::http_method::HttpMethod;

    let parts = parts(7, fields("api.example.com", "/users", &[HttpMethod::Get]));

    let state = RouteState::of(&parts);

    assert_eq!(state.id, parts.id);
    assert_eq!(state.fields, parts.fields);
    assert!(!state.system);
    assert_eq!(state.version, parts.version);
}

#[test]
fn the_state_of_a_rate_policy_is_that_of_its_stored_parts() {
    let parts = rate_policy_parts("6c3f0d2b-8e4a-4b7c-9d1e-2f3a4b5c6d7e");

    let state = RatePolicyState::of(&parts);

    assert_eq!(state.id, parts.id);
    assert_eq!(state.fields, parts.fields);
    assert_eq!(state.version, parts.version);
}

#[test]
fn an_upstream_a_route_and_a_rate_policy_belong_to_their_own_key_only() {
    use crate::route::fixtures::{fields, parts, route_id};
    use crate::value_object::http_method::HttpMethod;

    let upstream = PolicyState::Upstream(UpstreamState::of(&upstream_parts("core")));
    let route = PolicyState::Route(RouteState::of(&parts(
        1,
        fields("api.example.com", "/users", &[HttpMethod::Get]),
    )));
    let policy_id = "6c3f0d2b-8e4a-4b7c-9d1e-2f3a4b5c6d7e";
    let policy = PolicyState::RatePolicy(RatePolicyState::of(&rate_policy_parts(policy_id)));

    assert!(upstream.belongs_to(&StateKey::Upstream(UpstreamName::new("core").unwrap())));
    assert!(!upstream.belongs_to(&StateKey::Upstream(UpstreamName::new("billing").unwrap())));
    assert!(!upstream.belongs_to(&StateKey::Route(route_id(1))));
    assert!(route.belongs_to(&StateKey::Route(route_id(1))));
    assert!(!route.belongs_to(&StateKey::Route(route_id(2))));
    assert!(policy.belongs_to(&StateKey::RatePolicy(
        RatePolicyId::parse(policy_id).unwrap()
    )));
    assert!(!policy.belongs_to(&StateKey::RatePolicy(
        RatePolicyId::parse("7d4f1e3c-9f5b-4c8d-8e2f-3a4b5c6d7e8f").unwrap()
    )));
    assert!(!policy.belongs_to(&StateKey::Head));
}

#[test]
fn the_test_codec_names_an_upstream_a_route_and_a_rate_policy() {
    use crate::port::state_record_codec::StateRecordCodec as _;
    use crate::route::fixtures::{fields, parts};
    use crate::state::fakes::TextCodec;
    use crate::value_object::http_method::HttpMethod;

    let upstream = PolicyState::Upstream(UpstreamState::of(&upstream_parts("core")));
    let route = PolicyState::Route(RouteState::of(&parts(
        1,
        fields("api.example.com", "/users", &[HttpMethod::Get]),
    )));
    let policy = PolicyState::RatePolicy(RatePolicyState::of(&rate_policy_parts(
        "6c3f0d2b-8e4a-4b7c-9d1e-2f3a4b5c6d7e",
    )));

    assert_eq!(TextCodec.encode(&upstream).unwrap(), "upstream core v4");
    let route_text = TextCodec.encode(&route).unwrap();
    assert!(route_text.starts_with("route /users v"), "{route_text}");
    assert_eq!(TextCodec.encode(&policy).unwrap(), "ratepolicy per-ip v2");
}
