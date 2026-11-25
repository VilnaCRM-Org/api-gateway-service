use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

use axum::Router;
use axum::body::Body;
use axum::extract::FromRef;
use axum::http::{Request, StatusCode};
use shared_domain::{CommandBus, QueryBus};
use test_support::bus::{FakeCommandBus, FakeQueryBus};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::policy_epoch::seeded_policy_epoch;
use test_support::request_digester::FakeRequestDigester;
use tower::ServiceExt as _;

use iam_domain::DecisionReason;

use super::{IamState, decision_router, router, stale_decision_router};
use crate::access_validation_fixtures::{allowed, denied};
use crate::gateway_decision::stale::{ValidateAccessStaleBatchQuery, ValidateAccessStaleQuery};
use crate::query::get_policy_epoch::GetPolicyEpochQuery;
use crate::query::validate_access::ValidateAccessQuery;
use crate::query::validate_access_batch::ValidateAccessBatchQuery;

/// The state of a whole application that holds the IAM state as one of its fields.
#[derive(Debug, Clone, FromRef)]
struct ApplicationState {
    iam: IamState,
}

/// The time of the fixed clock.
const fn fixed_time() -> SystemTime {
    SystemTime::UNIX_EPOCH
}

fn state() -> IamState {
    let command_bus: Arc<dyn CommandBus> = Arc::new(FakeCommandBus::unregistered());
    let query_bus: Arc<dyn QueryBus> =
        Arc::new(FakeQueryBus::answering(|_query: GetPolicyEpochQuery| {
            Ok(seeded_policy_epoch())
        }));
    IamState {
        command_bus,
        query_bus,
        uuid_generator: Arc::new(SequenceUuidGenerator::starting_at(1)),
        clock: Arc::new(FixedClock::at(fixed_time())),
        request_digester: Arc::new(FakeRequestDigester),
    }
}

/// What the bus of a stale gateway was asked: the real decisions, which it must never be asked for,
/// and the stale answers it gives.
#[derive(Debug, Default, Clone)]
struct StaleAsked {
    decided: Arc<Mutex<Vec<&'static str>>>,
    stale: Arc<Mutex<Vec<&'static str>>>,
}

fn names(log: &Arc<Mutex<Vec<&'static str>>>) -> Vec<&'static str> {
    log.lock().unwrap_or_else(PoisonError::into_inner).clone()
}

fn unavailable() -> iam_domain::DecisionOutcome {
    denied(DecisionReason::Unavailable, &[])
}

/// The state over a bus that answers the stale queries with the deny `unavailable` and the real
/// decisions with an allow, and records which of them it was asked.
fn stale_state() -> (IamState, StaleAsked) {
    let asked = StaleAsked::default();
    let (decided, stale) = (Arc::clone(&asked.decided), Arc::clone(&asked.stale));
    let (decided_batch, stale_batch) = (Arc::clone(&decided), Arc::clone(&stale));
    let bus = FakeQueryBus::answering(move |_query: ValidateAccessQuery| {
        decided
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push("single");
        Ok(allowed())
    })
    .and_answering(move |_query: ValidateAccessBatchQuery| {
        decided_batch
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push("batch");
        Ok(vec![allowed()])
    })
    .and_answering(move |_query: ValidateAccessStaleQuery| {
        stale
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push("single");
        Ok(unavailable())
    })
    .and_answering(move |query: ValidateAccessStaleBatchQuery| {
        stale_batch
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push("batch");
        Ok(query.0.checks.iter().map(|_item| unavailable()).collect())
    });
    let mut base = state();
    base.query_bus = Arc::new(bus);
    (base, asked)
}

#[tokio::test]
async fn the_state_carries_the_buses_the_identifier_source_and_the_clock() {
    let state = state();
    let copy = state.clone();

    let epoch = copy.query_bus.ask(GetPolicyEpochQuery).await.unwrap();

    assert_eq!(epoch, seeded_policy_epoch());
    assert_eq!(copy.clock.now(), fixed_time());
    assert_ne!(
        copy.uuid_generator.generate(),
        state.uuid_generator.generate()
    );
    assert!(format!("{state:?}").contains("IamState"));
}

#[test]
fn the_state_is_extracted_from_the_state_of_the_application() {
    let application = ApplicationState { iam: state() };

    let extracted = IamState::from_ref(&application);

    assert_eq!(extracted.clock.now(), fixed_time());
}

#[test]
fn the_router_documents_the_token_resolution_operation_under_the_iam_tag() {
    let (_routes, document) = router::<ApplicationState>().split_for_parts();

    let operation = document
        .paths
        .paths
        .get("/token-resolutions")
        .and_then(|item| item.post.as_ref())
        .unwrap();
    assert_eq!(
        operation.operation_id.as_deref(),
        Some("api_token_resolutions_post")
    );
    assert_eq!(
        operation.tags.as_deref(),
        Some(["iam".to_owned()].as_slice())
    );
    assert!(operation.security.is_some());
}

#[test]
fn the_router_documents_the_role_operations_under_the_iam_tag_behind_the_bearer_scheme() {
    let (_routes, document) = router::<ApplicationState>().split_for_parts();

    let collection = &document.paths.paths["/roles"];
    let item = &document.paths.paths["/roles/{id}"];
    let operations = [
        (collection.post.as_ref().unwrap(), "api_roles_post"),
        (collection.get.as_ref().unwrap(), "api_roles_get"),
        (item.get.as_ref().unwrap(), "api_roles_id_get"),
        (item.patch.as_ref().unwrap(), "api_roles_id_patch"),
        (item.delete.as_ref().unwrap(), "api_roles_id_delete"),
    ];
    for (operation, operation_id) in operations {
        assert_eq!(operation.operation_id.as_deref(), Some(operation_id));
        assert_eq!(
            operation.tags.as_deref(),
            Some(["iam".to_owned()].as_slice())
        );
        assert!(operation.security.is_some(), "{operation_id}");
    }
    let permissions = &document.paths.paths["/roles/{id}/permissions"];
    assert_eq!(
        permissions.get.as_ref().unwrap().operation_id.as_deref(),
        Some("api_roles_id_permissions_get")
    );
    assert_eq!(
        permissions.put.as_ref().unwrap().operation_id.as_deref(),
        Some("api_roles_id_permissions_put")
    );
    assert!(permissions.post.is_none() && permissions.delete.is_none());
    assert!(collection.put.is_none() && collection.delete.is_none() && collection.patch.is_none());
    assert!(item.post.is_none() && item.put.is_none());
    for retirement in [
        "/graphql-specs/{id}/retirement",
        "/openapi-specs/{id}/retirement",
    ] {
        assert!(
            document.paths.paths[retirement].post.is_some(),
            "{retirement}"
        );
    }
    assert!(
        document.paths.paths["/access-validations/batch"]
            .post
            .is_some()
    );
    let routes = &document.paths.paths["/routes"];
    let route = &document.paths.paths["/routes/{id}"];
    assert!(routes.post.is_some() && routes.get.is_some());
    assert!(route.get.is_some() && route.patch.is_some() && route.delete.is_some());
    let configuration = &document.paths.paths["/route-configurations/{host}"];
    assert!(configuration.get.is_some() && configuration.put.is_some());
    assert!(document.paths.paths["/policy-resyncs"].post.is_some());
    let revocations = &document.paths.paths["/session-revocations"];
    assert!(revocations.post.is_some() && revocations.get.is_some());
    assert!(
        document.paths.paths["/session-revocations/{id}"]
            .get
            .is_some()
    );
    assert!(
        document.paths.paths["/users/{userId}/token-cutoff"]
            .get
            .is_some()
    );
    assert!(
        document.paths.paths["/global-token-cutoffs/current"]
            .get
            .is_some()
    );
    assert!(document.paths.paths["/global-token-cutoffs"].post.is_some());
    assert!(document.paths.paths["/security-audit-events"].get.is_some());
    assert!(
        document.paths.paths["/security-audit-events/{id}"]
            .get
            .is_some()
    );
    assert!(
        document.paths.paths["/security-audit-events/chain-verification"]
            .get
            .is_some()
    );
    assert!(document.paths.paths["/access-decisions"].get.is_some());
    assert!(document.paths.paths["/access-decisions/{id}"].get.is_some());
    assert_eq!(document.paths.paths.len(), 37);
}

#[test]
fn the_router_documents_the_assignment_operations_under_the_iam_tag_behind_the_bearer_scheme() {
    let (_routes, document) = router::<ApplicationState>().split_for_parts();

    let collection = &document.paths.paths["/user-roles"];
    let item = &document.paths.paths["/user-roles/{id}"];
    let operations = [
        (collection.post.as_ref().unwrap(), "api_user_roles_post"),
        (collection.get.as_ref().unwrap(), "api_user_roles_get"),
        (item.get.as_ref().unwrap(), "api_user_roles_id_get"),
    ];
    for (operation, operation_id) in operations {
        assert_eq!(operation.operation_id.as_deref(), Some(operation_id));
        assert_eq!(
            operation.tags.as_deref(),
            Some(["iam".to_owned()].as_slice())
        );
        assert!(operation.security.is_some(), "{operation_id}");
    }
    assert!(collection.put.is_none() && collection.delete.is_none() && collection.patch.is_none());
    assert!(item.post.is_none() && item.put.is_none());
}

#[tokio::test]
async fn the_router_serves_no_other_route() {
    let (routes, _document) = router::<IamState>().split_for_parts();
    let app: Router = routes.with_state(state());
    let request = Request::builder()
        .uri("/policy_epoch")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[test]
fn the_decision_router_documents_the_three_decision_operations_and_nothing_else() {
    let (_routes, document) = decision_router::<ApplicationState>().split_for_parts();

    let mut paths: Vec<&str> = document.paths.paths.keys().map(String::as_str).collect();
    paths.sort_unstable();

    assert_eq!(
        paths,
        [
            "/access-validations",
            "/access-validations/batch",
            "/token-resolutions"
        ]
    );
}

#[tokio::test]
async fn the_decision_router_serves_no_management_route() {
    let (routes, _document) = decision_router::<ApplicationState>().split_for_parts();
    let app = routes.with_state(ApplicationState { iam: state() });

    let response = app
        .oneshot(Request::get("/roles").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_stale_router_decides_a_check_without_authenticating_the_caller() {
    let (state, asked) = stale_state();
    let app = stale_decision_router().with_state(state);
    let body = serde_json::json!({
        "credential": "token",
        "service": "orders",
        "permissions": ["rest:orders:GET /api/orders"],
        "requestId": "request-1",
    });

    let response = app
        .oneshot(
            Request::post("/api/access-validations")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let decision: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decision["decision"], "deny");
    assert_eq!(decision["reason"], "unavailable");
    assert_eq!(decision["requestId"], "request-1");
    assert_eq!(names(&asked.decided), Vec::<&str>::new());
    assert_eq!(names(&asked.stale), ["single"]);
}

#[tokio::test]
async fn the_stale_router_never_asks_the_bus_for_a_decision_of_a_batch() {
    let (state, asked) = stale_state();
    let app = stale_decision_router().with_state(state);
    let item = |id: &str| {
        serde_json::json!({
            "credential": "token",
            "service": "orders",
            "permissions": ["rest:orders:GET /api/orders"],
            "requestId": id,
        })
    };
    let body = serde_json::json!({ "checks": [item("a"), item("b")] });

    let response = app
        .oneshot(
            Request::post("/api/access-validations/batch")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let decision: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let results = decision["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    for (result, id) in results.iter().zip(["a", "b"]) {
        assert_eq!(result["decision"], "deny");
        assert_eq!(result["reason"], "unavailable");
        assert_eq!(result["requestId"], id);
    }
    assert_eq!(names(&asked.decided), Vec::<&str>::new());
    assert_eq!(names(&asked.stale), ["batch"]);
}

#[tokio::test]
async fn the_stale_router_refuses_an_invalid_single_body_with_422() {
    let (state, asked) = stale_state();
    let app = stale_decision_router().with_state(state);
    let body = serde_json::json!({ "credential": "token", "service": "orders", "requestId": "r" });

    let response = app
        .oneshot(
            Request::post("/api/access-validations")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(names(&asked.stale), Vec::<&str>::new());
    assert_eq!(names(&asked.decided), Vec::<&str>::new());
}

#[tokio::test]
async fn the_stale_router_serves_the_two_validations_and_nothing_else() {
    let app = stale_decision_router().with_state(state());

    for path in ["/api/token-resolutions", "/api/roles"] {
        let response = app
            .clone()
            .oneshot(Request::post(path).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
    }
    let response = app
        .oneshot(
            Request::post("/api/access-validations/batch")
                .header("content-type", "application/json")
                .body(Body::from("{\"checks\":[]}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}
