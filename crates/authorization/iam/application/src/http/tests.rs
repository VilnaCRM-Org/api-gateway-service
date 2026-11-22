use std::sync::Arc;
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
use tower::ServiceExt as _;

use super::{IamState, router};
use crate::query::get_policy_epoch::GetPolicyEpochQuery;

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
    }
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
    assert_eq!(document.paths.paths.len(), 1);
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
