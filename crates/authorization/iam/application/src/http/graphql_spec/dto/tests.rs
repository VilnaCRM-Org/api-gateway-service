use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, ContentHash, FlagDowngrade, GqlName, GraphQlCoordinate, GraphQlSpecContent,
    GraphQlSpecParts, GraphQlTypeGraph, PermissionFlags, RemovedGrant, RoleId, ServiceName,
    SpecDiff, SpecId, SpecStatus, WildcardGain, WildcardPattern,
};
use serde_json::json;
use shared_domain::Uuid;
use validator::Validate as _;

use rstest::rstest;

use super::{
    CoordinateFlagsResponse, FlagDowngradeResponse, GetGraphQlSpecParams, GraphQlSpecPageResponse,
    GraphQlSpecResponse, GraphQlSpecSummaryResponse, ListGraphQlSpecsParams,
    LoadGraphQlSpecRequest, RemovedGrantResponse, SpecDiffResponse, WildcardGainResponse,
};
use crate::error::IamError;
use crate::query::get_graphql_spec_diff::GraphQlSpecView;
use crate::query::get_graphql_specs::{GetGraphQlSpecsQuery, GraphQlSpecPage, GraphQlSpecSummary};

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

fn summary(
    status: SpecStatus,
    activated: Option<SystemTime>,
    sdl: Option<&str>,
) -> GraphQlSpecSummary {
    let view = view(status, activated);
    GraphQlSpecSummary {
        spec: view.spec,
        coordinate_count: view.coordinate_count,
        sdl: sdl.map(str::to_owned),
    }
}

#[test]
fn a_summary_response_carries_the_state_the_count_and_the_requested_sdl() {
    let response = GraphQlSpecSummaryResponse::from(summary(
        SpecStatus::Active,
        Some(at(90_000)),
        Some("type Query { invoices: String }"),
    ));

    assert_eq!(response.id, SPEC);
    assert_eq!(response.service, "billing");
    assert_eq!(response.content_hash, "ab".repeat(32));
    assert_eq!(response.status, "active");
    assert_eq!(response.uploaded_by, format!("user:{USER}"));
    assert_eq!(response.created_at, "1970-01-02T00:00:00.000000Z");
    assert_eq!(
        response.activated_at.as_deref(),
        Some("1970-01-02T01:00:00.000000Z")
    );
    assert_eq!(response.retired_at, None);
    assert_eq!(response.coordinate_count, 1);
    assert_eq!(
        response.sdl.as_deref(),
        Some("type Query { invoices: String }")
    );
}

#[test]
fn a_summary_response_leaves_out_what_a_draft_does_not_have() {
    let body = serde_json::to_value(GraphQlSpecSummaryResponse::from(summary(
        SpecStatus::Draft,
        None,
        None,
    )))
    .unwrap();

    assert_eq!(body["status"], json!("draft"));
    assert_eq!(body["coordinateCount"], json!(1));
    assert!(body.get("activatedAt").is_none());
    assert!(body.get("retiredAt").is_none());
    assert!(body.get("sdl").is_none());
}

#[test]
fn a_page_response_lists_its_items_and_names_the_cursor_of_the_next_page() {
    let next = SpecId::parse(SPEC).unwrap();
    let page = GraphQlSpecPageResponse::from(GraphQlSpecPage {
        specs: vec![summary(SpecStatus::Draft, None, None)],
        next_after: Some(next),
    });
    let last = GraphQlSpecPageResponse::from(GraphQlSpecPage {
        specs: Vec::new(),
        next_after: None,
    });

    assert_eq!(page.items.len(), 1);
    assert_eq!(page.next_cursor.as_deref(), Some(SPEC));
    assert_eq!(last.items, Vec::new());
    assert_eq!(last.next_cursor, None);
    let body = serde_json::to_value(&last).unwrap();
    assert!(body.get("nextCursor").is_none());
}

fn params() -> ListGraphQlSpecsParams {
    ListGraphQlSpecsParams::default()
}

fn violations(error: IamError) -> Vec<(String, String)> {
    let IamError::Invalid(violations) = error else {
        panic!("a validation error expected: {error:?}");
    };
    violations
        .into_iter()
        .map(|violation| (violation.property_path, violation.code))
        .collect()
}

#[test]
fn the_list_parameters_default_to_the_first_page_of_thirty_without_the_sdl() {
    let query = params().into_query().unwrap();

    assert_eq!(
        query,
        GetGraphQlSpecsQuery {
            limit: 30,
            after: None,
            service: None,
            status: None,
            include_sdl: false,
        }
    );
}

#[test]
fn the_list_parameters_become_the_query_filters() {
    let query = ListGraphQlSpecsParams {
        limit: 5,
        after: Some(SPEC.to_owned()),
        service: Some("billing".to_owned()),
        status: Some("retired".to_owned()),
        include_sdl: true,
    }
    .into_query()
    .unwrap();

    assert_eq!(
        query,
        GetGraphQlSpecsQuery {
            limit: 5,
            after: Some(SpecId::parse(SPEC).unwrap()),
            service: Some(billing()),
            status: Some(SpecStatus::Retired),
            include_sdl: true,
        }
    );
}

#[rstest]
#[case::zero(0, false)]
#[case::one(1, true)]
#[case::hundred(100, true)]
#[case::over(101, false)]
#[case::negative(-1, false)]
fn the_limit_is_between_one_and_one_hundred(#[case] limit: i32, #[case] valid: bool) {
    let parameters = ListGraphQlSpecsParams { limit, ..params() };

    assert_eq!(parameters.validate().is_ok(), valid);
}

#[test]
fn the_service_filter_has_at_most_63_characters() {
    let long = ListGraphQlSpecsParams {
        service: Some("a".repeat(64)),
        ..params()
    };
    let longest = ListGraphQlSpecsParams {
        service: Some("a".repeat(63)),
        ..params()
    };

    assert!(long.validate().is_err());
    assert!(longest.validate().is_ok());
}

#[test]
fn every_invalid_filter_is_a_violation_of_its_own_parameter() {
    let error = ListGraphQlSpecsParams {
        after: Some("not-a-uuid".to_owned()),
        service: Some("Not A Service".to_owned()),
        status: Some("pending".to_owned()),
        ..params()
    }
    .into_query()
    .unwrap_err();

    assert_eq!(
        violations(error),
        [
            ("after".to_owned(), "uuid".to_owned()),
            ("service".to_owned(), "pattern".to_owned()),
            ("status".to_owned(), "choice".to_owned()),
        ]
    );
}

#[test]
fn a_single_invalid_status_is_one_violation() {
    let error = ListGraphQlSpecsParams {
        status: Some("pending".to_owned()),
        ..params()
    }
    .into_query()
    .unwrap_err();

    assert_eq!(
        violations(error),
        [("status".to_owned(), "choice".to_owned())]
    );
}

#[test]
fn the_read_parameters_default_to_no_sdl_and_refuse_unknown_members() {
    assert!(!GetGraphQlSpecParams::default().include_sdl);
    assert!(GetGraphQlSpecParams::default().validate().is_ok());
    let parsed = serde_json::from_value::<GetGraphQlSpecParams>(json!({"includeSdl": true}));
    let unknown = serde_json::from_value::<GetGraphQlSpecParams>(json!({"sdl": true}));

    assert!(parsed.unwrap().include_sdl);
    assert!(unknown.is_err());
}
