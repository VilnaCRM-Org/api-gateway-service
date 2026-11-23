use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, ContentHash, FlagDowngrade, GqlName, GraphQlCoordinate, GraphQlSpecContent,
    GraphQlSpecParts, GraphQlTypeGraph, PermissionFlags, RemovedGrant, RoleId, ServiceName,
    SpecDiff, SpecId, SpecStatus, WildcardGain, WildcardPattern,
};
use serde_json::json;
use shared_domain::Uuid;
use validator::Validate as _;

use super::{
    CoordinateFlagsResponse, FlagDowngradeResponse, GraphQlSpecResponse, LoadGraphQlSpecRequest,
    RemovedGrantResponse, SpecDiffResponse, WildcardGainResponse,
};
use crate::query::get_graphql_spec_diff::GraphQlSpecView;

const SPEC: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ad";
const ROLE: &str = "0190f2a8-7b3c-7d4e-8f11-1234567890ad";
const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";

fn coordinate(text: &str) -> GraphQlCoordinate {
    GraphQlCoordinate::parse(text).unwrap()
}

fn billing() -> ServiceName {
    ServiceName::new("billing").unwrap()
}

fn request(service: &str, sdl: &str) -> LoadGraphQlSpecRequest {
    LoadGraphQlSpecRequest {
        service: service.to_owned(),
        sdl: sdl.to_owned(),
    }
}

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn view(status: SpecStatus, activated: Option<SystemTime>) -> GraphQlSpecView {
    let graph = GraphQlTypeGraph::new(
        [(
            coordinate("Query.invoices"),
            iam_domain::GraphQlField {
                return_type: GqlName::parse("String").unwrap(),
                flags: PermissionFlags::NONE,
            },
        )],
        [],
    )
    .unwrap();
    let spec = GraphQlSpecParts {
        id: SpecId::parse(SPEC).unwrap(),
        content: GraphQlSpecContent {
            service: billing(),
            content_hash: ContentHash::new(&[0xab; 32]).unwrap(),
            type_graph: graph,
        },
        status,
        uploaded_by: ActorRef::User(Uuid::parse(USER).unwrap()),
        created_at: at(86_400),
        activated_at: activated,
        retired_at: None,
    };
    let candidate = spec_coordinates(&spec);
    GraphQlSpecView {
        coordinate_count: 1,
        diff: SpecDiff::compute(
            &billing(),
            &candidate,
            &iam_domain::CoordinateSet::new(),
            &[],
        ),
        spec,
    }
}

fn spec_coordinates(spec: &GraphQlSpecParts) -> iam_domain::CoordinateSet {
    spec.content.type_graph.coordinates()
}

#[test]
fn a_request_with_a_service_and_an_sdl_is_valid() {
    assert!(
        request("billing", "type Query { a: Int }")
            .validate()
            .is_ok()
    );
}

#[test]
fn an_empty_service_or_sdl_and_a_service_over_63_characters_are_invalid() {
    assert!(request("", "type Query { a: Int }").validate().is_err());
    assert!(request("billing", "").validate().is_err());
    assert!(request(&"a".repeat(64), "x").validate().is_err());
    assert!(request(&"a".repeat(63), "x").validate().is_ok());
}

#[test]
fn a_request_refuses_unknown_fields() {
    let parsed = serde_json::from_value::<LoadGraphQlSpecRequest>(
        json!({"service": "billing", "sdl": "x", "extra": 1}),
    );

    assert!(parsed.is_err());
}

#[test]
fn the_debug_output_of_a_request_does_not_show_the_sdl() {
    let text = format!("{:?}", request("billing", "type Secret { a: Int }"));

    assert!(text.contains("billing"));
    assert!(!text.contains("Secret"));
}

#[test]
fn flags_are_two_booleans() {
    let flags = PermissionFlags::NONE.with_sensitive();

    assert_eq!(
        CoordinateFlagsResponse::from(flags),
        CoordinateFlagsResponse {
            sensitive: true,
            audit_always: false,
        }
    );
}

#[test]
fn a_draft_is_rendered_without_activation_times() {
    let response = GraphQlSpecResponse::from(&view(SpecStatus::Draft, None));

    assert_eq!(response.id, SPEC);
    assert_eq!(response.service, "billing");
    assert_eq!(response.content_hash, "ab".repeat(32));
    assert_eq!(response.status, "draft");
    assert_eq!(response.uploaded_by, format!("user:{USER}"));
    assert_eq!(response.created_at, "1970-01-02T00:00:00.000000Z");
    assert_eq!(response.activated_at, None);
    assert_eq!(response.retired_at, None);
    assert_eq!(response.coordinate_count, 1);
    assert_eq!(response.diff.added, ["Query.invoices"]);
    let value = serde_json::to_value(&response).unwrap();
    assert!(value.get("activatedAt").is_none());
    assert_eq!(value["contentHash"], "ab".repeat(32));
}

#[test]
fn an_active_version_is_rendered_with_its_activation_time() {
    let response = GraphQlSpecResponse::from(&view(SpecStatus::Active, Some(at(172_800))));

    assert_eq!(response.status, "active");
    assert_eq!(
        response.activated_at.as_deref(),
        Some("1970-01-03T00:00:00.000000Z")
    );
}

#[test]
fn a_diff_is_rendered_with_its_grants_gains_and_downgrades() {
    let role = RoleId::parse(ROLE).unwrap();
    let diff = SpecDiff::compute(
        &billing(),
        &iam_domain::CoordinateSet::new(),
        &iam_domain::CoordinateSet::new(),
        &[],
    );
    assert_eq!(
        SpecDiffResponse::from(&diff),
        SpecDiffResponse {
            added: vec![],
            removed: vec![],
            removed_grants: vec![],
            wildcard_gains: vec![],
            flag_downgrades: vec![],
        }
    );

    let removed = RemovedGrant {
        coordinate: coordinate("Mutation.pay"),
        roles: vec![role],
    };
    assert_eq!(
        RemovedGrantResponse::from(&removed),
        RemovedGrantResponse {
            coordinate: "Mutation.pay".to_owned(),
            roles: vec![ROLE.to_owned()],
        }
    );
    let gain = WildcardGain {
        role,
        pattern: WildcardPattern::parse("gql:billing:Query.*").unwrap(),
        coordinates: vec![coordinate("Query.orders")],
    };
    assert_eq!(
        WildcardGainResponse::from(&gain),
        WildcardGainResponse {
            role: ROLE.to_owned(),
            pattern: "gql:billing:Query.*".to_owned(),
            coordinates: vec!["Query.orders".to_owned()],
        }
    );
    let downgrade = FlagDowngrade {
        coordinate: coordinate("Mutation.pay"),
        before: PermissionFlags::NONE.with_sensitive(),
        after: PermissionFlags::NONE,
    };
    assert_eq!(
        FlagDowngradeResponse::from(&downgrade),
        FlagDowngradeResponse {
            coordinate: "Mutation.pay".to_owned(),
            before: CoordinateFlagsResponse {
                sensitive: true,
                audit_always: false,
            },
            after: CoordinateFlagsResponse {
                sensitive: false,
                audit_always: false,
            },
        }
    );
}
