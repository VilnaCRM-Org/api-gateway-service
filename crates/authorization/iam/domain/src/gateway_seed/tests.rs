use std::time::SystemTime;

use super::IamGatewaySeed;
use crate::policy::route_conflict_guard::RouteConflictGuard;
use crate::route::RouteParts;
use crate::route::fields::RouteFields;
use crate::upstream::settings::{UpstreamFields, UpstreamProtocol};
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::http_method::HttpMethod;
use crate::value_object::identifier::{RouteId, UpstreamId};
use crate::value_object::route_host::RouteHost;

const UPSTREAM: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890cf";

fn seed() -> IamGatewaySeed {
    IamGatewaySeed::new(RouteHost::new("iam.example.test").unwrap())
}

fn upstream_id() -> UpstreamId {
    UpstreamId::parse(UPSTREAM).unwrap()
}

#[test]
fn the_seed_keeps_its_host() {
    assert_eq!(seed().host().as_str(), "iam.example.test");
}

#[test]
fn the_upstream_is_iam_control_on_port_80_with_credentials_forwarded() {
    let fields = UpstreamFields::new(
        IamGatewaySeed::UPSTREAM_NAME,
        &IamGatewaySeed::upstream_draft(),
    )
    .unwrap();

    assert_eq!(fields.name().as_str(), "iam-control");
    let settings = fields.settings();
    assert_eq!(settings.namespace(), "iam");
    assert_eq!(settings.service_name(), "iam-control");
    assert!(settings.catalog_service().is_iam());
    assert_eq!(settings.port(), 80);
    assert_eq!(settings.protocol(), UpstreamProtocol::Http1);
    assert!(settings.forward_credentials());
}

#[test]
fn every_seeded_route_is_valid_enforced_and_belongs_to_the_iam_service() {
    let drafts = seed().route_drafts(upstream_id());

    assert_eq!(drafts.len(), 4);
    for draft in &drafts {
        let fields = RouteFields::new(draft).unwrap();
        assert_eq!(fields.host().as_str(), "iam.example.test");
        assert!(fields.service().is_iam());
        assert_eq!(fields.upstream_id(), upstream_id());
        assert_eq!(fields.enforcement().as_str(), "enforce");
        assert!(!fields.flags().anonymous());
    }
}

#[test]
fn the_graphql_route_is_flagged_and_the_upload_routes_take_six_mebibytes() {
    let drafts = seed().route_drafts(upstream_id());

    let by_path = |path: &str| {
        drafts
            .iter()
            .find(|draft| draft.path_pattern == path)
            .unwrap()
    };
    let graphql = by_path("/api/graphql");
    assert!(graphql.flags.graphql());
    assert_eq!(graphql.methods, vec![HttpMethod::Post]);
    assert_eq!(graphql.body_limit, 6 * 1024 * 1024);
    assert_eq!(by_path("/api/openapi-specs").body_limit, 6 * 1024 * 1024);
    assert_eq!(by_path("/api/graphql-specs").body_limit, 6 * 1024 * 1024);
    let rest = by_path("/api/{rest:*}");
    assert!(!rest.flags.graphql());
    assert_eq!(rest.body_limit, 1_048_576);
    assert!(rest.methods.contains(&HttpMethod::Get));
    assert!(rest.methods.contains(&HttpMethod::Delete));
}

#[test]
fn the_seeded_routes_do_not_conflict_with_each_other() {
    let at = SystemTime::UNIX_EPOCH;
    let routes: Vec<RouteParts> = seed()
        .route_drafts(upstream_id())
        .iter()
        .enumerate()
        .map(|(index, draft)| RouteParts {
            id: RouteId::parse(&format!("0190f2a8-7b3c-7d4e-8f10-{index:012x}")).unwrap(),
            fields: RouteFields::new(draft).unwrap(),
            system: true,
            version: EntityVersion::INITIAL,
            created_at: at,
            updated_at: at,
            deleted_at: None,
        })
        .collect();

    assert_eq!(RouteConflictGuard::check_set(&routes), Ok(()));
}

#[test]
fn only_the_seeded_upstream_name_is_reserved() {
    assert!(IamGatewaySeed::reserves_upstream_name("iam-control"));
    assert!(!IamGatewaySeed::reserves_upstream_name("iam-control-2"));
    assert!(!IamGatewaySeed::reserves_upstream_name("orders"));
}
