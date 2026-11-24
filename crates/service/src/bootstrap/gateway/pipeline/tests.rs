use axum::http::header::HOST;
use axum::http::request::Parts;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt as _;

use super::*;

fn parts(host: Option<&str>, uri: &str) -> Parts {
    let mut builder = Request::builder().uri(uri);
    if let Some(host) = host {
        builder = builder.header(HOST, host);
    }
    builder.body(()).unwrap().into_parts().0
}

#[test]
fn the_host_is_lower_case_and_loses_its_port() {
    assert_eq!(
        host_of(&parts(Some("API.Example.Test:8443"), "/x")).as_deref(),
        Some("api.example.test")
    );
    assert_eq!(
        host_of(&parts(Some("api.example.test"), "/x")).as_deref(),
        Some("api.example.test")
    );
}

#[test]
fn a_colon_that_does_not_start_a_port_stays_in_the_host() {
    assert_eq!(
        host_of(&parts(Some("api:example"), "/x")).as_deref(),
        Some("api:example")
    );
}

#[test]
fn the_host_falls_back_to_the_authority_of_the_target_and_may_be_missing() {
    assert_eq!(
        host_of(&parts(None, "http://Gateway.Example.Test:8080/x")).as_deref(),
        Some("gateway.example.test")
    );
    assert_eq!(host_of(&parts(None, "/x")), None);
}

#[test]
fn the_upstream_target_is_the_canonical_path_with_the_query_as_it_came() {
    let path = PathNormalizer::normalize("/api/a%20b/%7Euser").unwrap();

    assert_eq!(
        forwarded_uri(&path, None).unwrap().to_string(),
        "/api/a%20b/~user"
    );
    assert_eq!(
        forwarded_uri(&path, Some("x=1&y=%2F")).unwrap().to_string(),
        "/api/a%20b/~user?x=1&y=%2F"
    );
}

#[test]
fn a_query_that_is_no_uri_has_no_target() {
    let path = PathNormalizer::normalize("/api").unwrap();

    assert!(forwarded_uri(&path, Some("a b")).is_none());
}

async fn problem(response: Response) -> (StatusCode, String) {
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let document: serde_json::Value = serde_json::from_slice(&body).unwrap();
    (status, document["type"].as_str().unwrap().to_owned())
}

#[tokio::test]
async fn a_forwarder_that_returns_no_response_is_answered_with_502_503_or_504() {
    let answers = [
        (
            ForwardError::NotSent,
            StatusCode::BAD_GATEWAY,
            "about:blank",
        ),
        (
            ForwardError::NoEndpoint,
            StatusCode::BAD_GATEWAY,
            "about:blank",
        ),
        (
            ForwardError::Upstream,
            StatusCode::BAD_GATEWAY,
            "about:blank",
        ),
        (
            ForwardError::ConnectTimeout,
            StatusCode::GATEWAY_TIMEOUT,
            "about:blank",
        ),
        (
            ForwardError::ResponseTimeout,
            StatusCode::GATEWAY_TIMEOUT,
            "about:blank",
        ),
        (
            ForwardError::Overloaded,
            StatusCode::SERVICE_UNAVAILABLE,
            TYPE_UPSTREAM_OVERLOADED,
        ),
    ];

    for (error, status, kind) in answers {
        assert_eq!(problem(failure(error)).await, (status, kind.to_owned()));
    }
}

#[tokio::test]
async fn a_refusal_names_its_reason_and_the_other_answers_are_problems() {
    let denied = [
        (DecisionReason::PermissionMissing, TYPE_PERMISSION_MISSING),
        (DecisionReason::UnknownOperation, TYPE_UNKNOWN_OPERATION),
        (DecisionReason::UnknownService, TYPE_UNKNOWN_SERVICE),
        (DecisionReason::MalformedOperation, TYPE_PERMISSION_MISSING),
    ];

    for (reason, kind) in denied {
        assert_eq!(
            problem(forbidden(reason)).await,
            (StatusCode::FORBIDDEN, kind.to_owned())
        );
    }
    assert_eq!(
        problem(malformed_path()).await,
        (StatusCode::BAD_REQUEST, TYPE_MALFORMED_PATH.to_owned())
    );
    assert_eq!(
        problem(no_route()).await,
        (StatusCode::NOT_FOUND, "about:blank".to_owned())
    );
    assert_eq!(
        problem(unauthorized()).await,
        (StatusCode::UNAUTHORIZED, "about:blank".to_owned())
    );
}

#[test]
fn a_request_id_is_read_from_its_header() {
    let mut headers = HeaderMap::new();
    assert_eq!(request_id_of(&headers), None);

    headers.insert(&REQUEST_ID_HEADER, "req-1".parse().unwrap());

    assert_eq!(request_id_of(&headers), Some("req-1"));
}

#[test]
fn every_refusal_becomes_the_answer_of_its_status() {
    let answers = [
        (Refusal::Stale, StatusCode::SERVICE_UNAVAILABLE),
        (Refusal::MalformedPath, StatusCode::BAD_REQUEST),
        (Refusal::NoRoute, StatusCode::NOT_FOUND),
        (Refusal::Unauthorized, StatusCode::UNAUTHORIZED),
        (
            Refusal::Forbidden(DecisionReason::PermissionMissing),
            StatusCode::FORBIDDEN,
        ),
        (
            Refusal::Failed(ForwardError::Upstream),
            StatusCode::BAD_GATEWAY,
        ),
    ];

    for (refusal, status) in answers {
        assert_eq!(Response::from(refusal).status(), status);
    }
}

#[test]
fn a_token_that_cannot_be_checked_is_stale_and_any_other_rejection_is_a_401() {
    use iam_domain::{AccessToken, AccessTokenParts, SessionId, SubjectId, TokenId};
    use shared_domain::Uuid;

    let token = AccessToken::new(AccessTokenParts {
        subject: SubjectId::User(Uuid::parse("3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a").unwrap()),
        session: Some(SessionId::new("session-1").unwrap()),
        token_id: TokenId::new("token-1").unwrap(),
        roles: Vec::new(),
        issued_at: std::time::SystemTime::UNIX_EPOCH,
        expires_at: std::time::SystemTime::UNIX_EPOCH,
    });
    assert!(principal_of(Ok(TokenIdentity::from(&token))).is_ok());
    assert!(matches!(
        principal_of(Err(TokenRejection::Unavailable)),
        Err(Refusal::Stale)
    ));
    assert!(matches!(
        principal_of(Err(TokenRejection::Expired)),
        Err(Refusal::Unauthorized)
    ));
}

#[test]
fn an_authorization_that_cannot_be_decided_is_stale() {
    let version = iam_domain::PolicyVersion::new(1).unwrap();

    assert!(permitted(Authorization::Allowed(version)).is_ok());
    assert!(matches!(
        permitted(Authorization::Denied(DecisionReason::PermissionMissing)),
        Err(Refusal::Forbidden(DecisionReason::PermissionMissing))
    ));
    assert!(matches!(
        permitted(Authorization::Unavailable),
        Err(Refusal::Stale)
    ));
}

#[tokio::test]
async fn the_response_of_the_upstream_is_the_answer_and_a_failure_is_its_problem() {
    let relayed = answer(Ok(StatusCode::CREATED.into_response()));
    let failed = answer(Err(ForwardError::ResponseTimeout));

    assert_eq!(relayed.status(), StatusCode::CREATED);
    assert_eq!(failed.status(), StatusCode::GATEWAY_TIMEOUT);
}
