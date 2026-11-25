//! Tests of the REST reads of the security audit log.

use std::sync::PoisonError;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use iam_domain::{AuditOutcome, ChainBreak, ChainBreakCause, ChainVerification};
use serde_json::Value;
use tower::ServiceExt as _;

use crate::error::IamError;
use crate::fixtures::principal;
use crate::http::{IamState, router};
use crate::security_audit_fixtures::{
    Asked, COMMITTED, REJECTED, UNKNOWN, Verified, actor, asked_count, scenario, stored, uuid,
    verification_scenario,
};

fn app(failure: Option<fn() -> IamError>) -> (Router, Asked) {
    let (state, asked) = scenario(stored(), failure);
    let (routes, _document) = router::<IamState>().split_for_parts();
    (routes.with_state(state), asked)
}

fn get(uri: &str, authenticated: bool) -> Request<Body> {
    let mut request = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    if authenticated {
        request.extensions_mut().insert(principal());
    }
    request
}

async fn answer(app: Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn a_committed_record_is_read_with_its_summaries_and_policy_version() {
    let (app, asked) = app(None);

    let (status, body) = answer(
        app,
        get(&format!("/security-audit-events/{COMMITTED}"), true),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], COMMITTED);
    assert_eq!(body["actor"], actor().to_string());
    assert_eq!(body["action"], "role.update");
    assert_eq!(body["before"], "name=readers");
    assert_eq!(body["after"], "name=writers");
    assert_eq!(body["outcome"], "committed");
    assert_eq!(body["policyVersion"], 7);
    let recorded = asked.lock().unwrap_or_else(PoisonError::into_inner);
    assert_eq!(recorded.gets.len(), 1);
    assert_eq!(recorded.gets[0].actor, actor());
}

#[tokio::test]
async fn a_rejected_record_is_read_with_its_reason() {
    let (app, _asked) = app(None);

    let (status, body) = answer(
        app,
        get(&format!("/security-audit-events/{REJECTED}"), true),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["outcome"], "rejected");
    assert_eq!(body["reason"], "forbidden");
}

#[tokio::test]
async fn an_unknown_record_is_a_404_problem() {
    let (app, _asked) = app(None);

    let (status, body) = answer(app, get(&format!("/security-audit-events/{UNKNOWN}"), true)).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["status"], 404);
}

#[tokio::test]
async fn an_identifier_that_is_not_a_uuid_is_a_422_problem_without_a_query() {
    let (app, asked) = app(None);

    let (status, body) = answer(app, get("/security-audit-events/nope", true)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["violations"][0]["propertyPath"], "id");
    assert_eq!(asked_count(&asked), 0);
}

#[tokio::test]
async fn the_records_are_listed_newest_first() {
    let (app, asked) = app(None);

    let (status, body) = answer(app, get("/security-audit-events", true)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"][0]["id"], REJECTED);
    assert_eq!(body["items"][1]["id"], COMMITTED);
    assert!(body.get("nextCursor").is_none());
    let recorded = asked.lock().unwrap_or_else(PoisonError::into_inner);
    assert_eq!(recorded.lists[0].limit, 30);
    assert_eq!(recorded.lists[0].actor, actor());
}

#[tokio::test]
async fn a_page_of_one_names_the_cursor_of_the_older_page() {
    let (app, _asked) = app(None);

    let (status, body) = answer(app, get("/security-audit-events?limit=1", true)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"].as_array().unwrap().len(), 1);
    assert_eq!(body["nextCursor"], "2");
}

#[tokio::test]
async fn the_cursor_continues_before_the_record_it_names() {
    let (app, _asked) = app(None);

    let (status, body) = answer(app, get("/security-audit-events?limit=1&after=2", true)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"][0]["id"], COMMITTED);
}

#[tokio::test]
async fn the_filters_reach_the_query() {
    let (app, asked) = app(None);

    let (status, _body) = answer(
        app,
        get(
            "/security-audit-events?outcome=rejected&action=role.create&targetType=role",
            true,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let filter = asked.lock().unwrap_or_else(PoisonError::into_inner).lists[0]
        .filter
        .clone();
    assert_eq!(filter.outcome(), Some(AuditOutcome::Rejected));
    assert_eq!(filter.target_type(), Some("role"));
}

#[tokio::test]
async fn an_invalid_parameter_is_a_422_problem_without_a_query() {
    let (limit_app, asked) = app(None);
    let (outcome_app, _other) = app(None);

    let (limit_status, _limit) =
        answer(limit_app, get("/security-audit-events?limit=0", true)).await;
    let (outcome_status, body) = answer(
        outcome_app,
        get("/security-audit-events?outcome=maybe", true),
    )
    .await;

    assert_eq!(limit_status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(outcome_status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["violations"][0]["propertyPath"], "outcome");
    assert_eq!(asked_count(&asked), 0);
}

#[tokio::test]
async fn a_request_without_a_principal_is_a_401_problem_without_a_query() {
    let (app, asked) = app(None);

    let (status, _body) = answer(app, get("/security-audit-events", false)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(asked_count(&asked), 0);
}

#[tokio::test]
async fn a_storage_failure_is_a_500_problem() {
    let (list_app, _asked) = app(Some(|| IamError::Storage("down".into())));
    let (get_app, _other) = app(Some(|| IamError::Storage("down".into())));

    let (list_status, _list) = answer(list_app, get("/security-audit-events", true)).await;
    let (get_status, _one) = answer(
        get_app,
        get(&format!("/security-audit-events/{COMMITTED}"), true),
    )
    .await;

    assert_eq!(list_status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(get_status, StatusCode::INTERNAL_SERVER_ERROR);
}

const HASH: &str = "00000000000000000000000000000000000000000000000000000000000000ab";

fn verifying_app(answer: Result<ChainVerification, fn() -> IamError>) -> (Router, Verified) {
    let (state, verified) = verification_scenario(answer);
    let (routes, _document) = router::<IamState>().split_for_parts();
    (routes.with_state(state), verified)
}

#[tokio::test]
async fn a_valid_chain_is_verified_with_the_number_of_records_checked() {
    let (app, verified) = verifying_app(Ok(ChainVerification::valid(12)));

    let (status, body) = answer(app, get("/security-audit-events/chain-verification", true)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "valid");
    assert_eq!(body["recordsChecked"], 12);
    assert!(body.get("invalidRecordId").is_none());
    assert!(body.get("invalidSeq").is_none());
    assert!(body.get("cause").is_none());
    let asked = verified.lock().unwrap_or_else(PoisonError::into_inner);
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].actor, actor());
    assert_eq!(asked[0].anchors, Vec::new());
    drop(asked);
}

#[tokio::test]
async fn a_broken_chain_names_the_record_its_place_and_the_cause() {
    let broken = ChainBreak::new(
        4,
        Some(iam_domain::SecurityAuditEventId::from_uuid(uuid(4))),
        ChainBreakCause::Digest,
    );
    let (app, _verified) = verifying_app(Ok(ChainVerification::invalid(4, broken)));

    let (status, body) = answer(app, get("/security-audit-events/chain-verification", true)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "invalid");
    assert_eq!(body["recordsChecked"], 4);
    assert_eq!(
        body["invalidRecordId"],
        "00000000-0000-0000-0000-000000000004"
    );
    assert_eq!(body["invalidSeq"], 4);
    assert_eq!(body["cause"], "digest");
}

#[tokio::test]
async fn the_anchors_reach_the_query() {
    let (app, verified) = verifying_app(Ok(ChainVerification::valid(3)));
    let uri = format!("/security-audit-events/chain-verification?anchors=2:{HASH},3:{HASH}");

    let (status, _body) = answer(app, get(&uri, true)).await;

    assert_eq!(status, StatusCode::OK);
    let asked = verified.lock().unwrap_or_else(PoisonError::into_inner);
    let seqs: Vec<i64> = asked[0]
        .anchors
        .iter()
        .map(iam_domain::AuditChainHead::seq)
        .collect();
    assert_eq!(seqs, [2, 3]);
    assert_eq!(asked[0].anchors[0].hash().to_string(), HASH);
}

#[tokio::test]
async fn the_literal_path_is_not_read_as_a_record_id() {
    let (app, verified) = verifying_app(Ok(ChainVerification::valid(0)));

    let (status, _body) = answer(app, get("/security-audit-events/chain-verification", true)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        verified
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len(),
        1
    );
}

#[tokio::test]
async fn an_invalid_anchor_is_a_422_problem_without_a_query() {
    let (app, verified) = verifying_app(Ok(ChainVerification::valid(0)));

    let (status, body) = answer(
        app,
        get(
            "/security-audit-events/chain-verification?anchors=nope",
            true,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["violations"][0]["propertyPath"], "anchors");
    assert!(
        verified
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty()
    );
}

#[tokio::test]
async fn an_unknown_parameter_is_refused_without_a_query() {
    let (app, verified) = verifying_app(Ok(ChainVerification::valid(0)));

    let (status, _body) = answer(
        app,
        get(
            "/security-audit-events/chain-verification?from=2026-01-01T00:00:00Z",
            true,
        ),
    )
    .await;

    assert!(status.is_client_error());
    assert!(
        verified
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty()
    );
}

#[tokio::test]
async fn a_verification_without_a_principal_is_a_401_problem_without_a_query() {
    let (app, verified) = verifying_app(Ok(ChainVerification::valid(0)));

    let (status, _body) =
        answer(app, get("/security-audit-events/chain-verification", false)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        verified
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty()
    );
}

#[tokio::test]
async fn a_verification_that_cannot_be_audited_is_a_500_problem() {
    let (app, _verified) = verifying_app(Err(|| IamError::Storage("down".into())));

    let (status, _body) = answer(app, get("/security-audit-events/chain-verification", true)).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}
