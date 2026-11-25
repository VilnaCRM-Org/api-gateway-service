use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::http::header::RETRY_AFTER;
use axum::http::request::Parts;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt as _;
use iam_application::Principal;
use iam_domain::{AccessToken, AccessTokenParts, SessionId, SubjectId, TokenId, TokenIdentity};
use shared_domain::Uuid;

use super::{TYPE_CONNECTION_LIMIT, claim, refused};
use crate::bootstrap::gateway::edge::{Edge, EdgeLimits, SubjectClaims};
use crate::bootstrap::gateway::pipeline::Refusal;

const USER: &str = "3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a";
const OTHER: &str = "7a1c5e3b-2d4f-4a6b-8c9d-0e1f2a3b4c5d";

fn principal(user: &str) -> Principal {
    Principal::from(TokenIdentity::from(&AccessToken::new(AccessTokenParts {
        subject: SubjectId::User(Uuid::parse(user).unwrap()),
        session: Some(SessionId::new("session-1").unwrap()),
        token_id: TokenId::new("jti-1").unwrap(),
        roles: vec!["ROLE_USER".to_owned()],
        issued_at: SystemTime::UNIX_EPOCH,
        expires_at: SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_mins(15))
            .unwrap(),
    })))
}

fn parts(claims: Option<Arc<SubjectClaims>>) -> Parts {
    let mut request = Request::get("/api/users/1").body(()).unwrap();
    if let Some(claims) = claims {
        request.extensions_mut().insert(claims);
    }
    request.into_parts().0
}

fn edge(per_subject: usize) -> Edge {
    Edge::new(
        EdgeLimits {
            connections_per_subject: per_subject,
            ..EdgeLimits::default()
        },
        false,
        None,
    )
}

#[test]
fn a_request_without_connection_claims_is_never_limited() {
    assert_eq!(claim(&parts(None), &principal(USER)), Ok(()));
}

#[test]
fn a_subject_over_its_connection_limit_is_refused_on_the_connection_that_exceeds_it() {
    let edge = edge(1);
    let first = edge.claims();
    let second = edge.claims();

    assert_eq!(
        claim(&parts(Some(Arc::clone(&first))), &principal(USER)),
        Ok(())
    );
    assert_eq!(
        claim(&parts(Some(Arc::clone(&second))), &principal(USER)),
        Err(Refusal::ConnectionLimit)
    );
    assert_eq!(claim(&parts(Some(second)), &principal(OTHER)), Ok(()));
    assert_eq!(claim(&parts(Some(first)), &principal(USER)), Ok(()));
}

#[tokio::test]
async fn the_refusal_is_429_with_a_problem_and_retry_after() {
    let response = refused();

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers().get(RETRY_AFTER).unwrap(), "1");
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(text.contains(TYPE_CONNECTION_LIMIT));
}
