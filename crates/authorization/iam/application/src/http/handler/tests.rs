use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, StatusCode};
use iam_domain::{
    AccessToken, AccessTokenParts, SessionId, SubjectId, TokenId, TokenIdentity, TokenRejection,
};
use rstest::rstest;
use serde_json::{Value, json};
use shared_domain::{CommandBus, QueryBus, Uuid};
use test_support::bus::{FakeCommandBus, FakeQueryBus};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use tower::ServiceExt as _;

use crate::error::IamError;
use crate::http::{IamState, router};
use crate::principal::Principal;
use crate::query::resolve_subject_token::{ResolveSubjectTokenQuery, TokenResolution};

/// The extractor types a handler of this module may take.
const ALLOWED_EXTRACTORS: [&str; 7] = [
    "State<IamState>",
    "ApiPath<",
    "ValidatedQuery<",
    "ValidatedJson<",
    "ApiJson<",
    "IdempotencyKeyHeader",
    "IfMatchHeader",
];

/// Splits `text` at every `separator` that is not nested in brackets.
fn split_top_level(text: &str, separator: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut depth = 0_usize;
    let mut skip = 0_usize;
    for (index, character) in text.char_indices() {
        if skip > 0 {
            skip = skip.saturating_sub(1);
            continue;
        }
        let at_separator = depth == 0
            && text
                .get(index..)
                .is_some_and(|rest| rest.starts_with(separator));
        if at_separator {
            parts.push(std::mem::take(&mut current));
            skip = separator.chars().count().saturating_sub(1);
            continue;
        }
        match character {
            '(' | '[' | '<' | '{' => depth = depth.saturating_add(1),
            ')' | ']' | '>' | '}' => depth = depth.saturating_sub(1),
            _ => {}
        }
        current.push(character);
    }
    parts.push(current);
    parts
}

/// Returns the name and the parameter list of every `pub async fn` of `source`.
fn handler_parameters(source: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for chunk in source.split("pub async fn ").skip(1) {
        let (name, after) = chunk
            .split_once('(')
            .expect("a handler has a parameter list");
        let mut depth = 1_usize;
        let mut parameters = String::new();
        for character in after.chars() {
            match character {
                '(' => depth = depth.saturating_add(1),
                ')' => depth = depth.saturating_sub(1),
                _ => {}
            }
            if depth == 0 {
                break;
            }
            parameters.push(character);
        }
        found.push((name.trim().to_owned(), parameters));
    }
    found
}

/// Returns every handler parameter whose type is not an allowed extractor.
fn disallowed_parameters(source: &str) -> Vec<String> {
    let mut disallowed = Vec::new();
    for (name, parameters) in handler_parameters(source) {
        for parameter in split_top_level(&parameters, ",") {
            let parameter = parameter.trim();
            if parameter.is_empty() {
                continue;
            }
            let parts = split_top_level(parameter, ": ");
            let kind = parts.iter().skip(1).cloned().collect::<Vec<_>>().join(": ");
            if !ALLOWED_EXTRACTORS
                .iter()
                .any(|allowed| kind.trim().starts_with(allowed))
            {
                disallowed.push(format!("{name}: {parameter}"));
            }
        }
    }
    disallowed
}

/// Every handler of the IAM context must pass this check: it takes the IAM state and the
/// problem-aware extractors only. The list of names grows with every handler that is added.
#[test]
fn handlers_use_only_the_problem_aware_extractors() {
    let source = include_str!("../handler.rs");

    assert_eq!(disallowed_parameters(source), Vec::<String>::new());
    let names: Vec<String> = handler_parameters(source)
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    assert_eq!(names, ["resolve".to_owned()]);
}

#[rstest]
#[case::qualified_json("Json(b): axum::Json<T>")]
#[case::fully_qualified_json("axum::extract::Json(b): axum::extract::Json<T>")]
#[case::bare_json("Json(b): Json<T>")]
#[case::query("Query(p): Query<T>")]
#[case::path("Path(id): Path<uuid::Uuid>")]
#[case::form("Form(b): Form<T>")]
#[case::raw_query("RawQuery(q): RawQuery")]
#[case::raw_body("body: String")]
#[case::foreign_state("State(state): State<OtherState>")]
fn the_extractor_check_reports_a_planted_violation(#[case] parameter: &str) {
    let source = format!(
        "pub async fn ok(State(state): State<IamState>, {parameter}) -> Result<(), Problem> {{}}"
    );

    assert_eq!(disallowed_parameters(&source), [format!("ok: {parameter}")]);
}

#[test]
fn the_extractor_check_accepts_the_allowed_extractors() {
    let source = "pub async fn ok(State(state): State<IamState>, \
        ApiPath(id): ApiPath<uuid::Uuid>, ValidatedQuery(q): ValidatedQuery<Q>, \
        ValidatedJson(b): ValidatedJson<B>, ApiJson(j): ApiJson<J>, \
        IdempotencyKeyHeader(key): IdempotencyKeyHeader, IfMatchHeader(version): IfMatchHeader) \
        -> Result<(), Problem> {}";

    assert_eq!(disallowed_parameters(source), Vec::<String>::new());
    assert_eq!(handler_parameters(source).len(), 1);
}

fn principal() -> Principal {
    Principal::from(TokenIdentity::from(&AccessToken::new(AccessTokenParts {
        subject: SubjectId::User(Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap()),
        session: Some(SessionId::new("session-1").unwrap()),
        token_id: TokenId::new("jti-1").unwrap(),
        roles: vec!["ROLE_USER".to_owned()],
        issued_at: SystemTime::UNIX_EPOCH,
        expires_at: SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_mins(15))
            .unwrap(),
    })))
}

fn app(bus: FakeQueryBus) -> (Router, Arc<FakeQueryBus>) {
    let bus = Arc::new(bus);
    let query_bus: Arc<dyn QueryBus> = Arc::<FakeQueryBus>::clone(&bus);
    let command_bus: Arc<dyn CommandBus> = Arc::new(FakeCommandBus::unregistered());
    let state = IamState {
        command_bus,
        query_bus,
        uuid_generator: Arc::new(SequenceUuidGenerator::starting_at(1)),
        clock: Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
    };
    let (routes, _document) = router::<IamState>().split_for_parts();
    (routes.with_state(state), bus)
}

fn resolving(resolution: TokenResolution) -> FakeQueryBus {
    FakeQueryBus::answering(move |_query: ResolveSubjectTokenQuery| Ok(resolution.clone()))
}

fn post(body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/token-resolutions")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap()
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
async fn a_valid_credential_is_resolved_into_its_subject_and_never_echoed() {
    let (app, bus) = app(resolving(TokenResolution::Resolved(principal())));

    let (status, body) = answer(app, post(r#"{"credential":"raw-secret-token"}"#)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({
            "resolved": true,
            "subjectId": "0190f2a8-7b3c-7d4e-8f10-1234567890ab",
            "subjectKind": "user",
            "sessionId": "session-1",
            "roles": ["ROLE_USER"],
            "expiresAt": 900,
        })
    );
    assert!(!body.to_string().contains("raw-secret-token"));
    assert_eq!(bus.asked(), ["ResolveSubjectTokenQuery"]);
}

#[rstest]
#[case::invalid(TokenRejection::Invalid, "token_invalid")]
#[case::expired(TokenRejection::Expired, "token_expired")]
#[case::revoked(TokenRejection::Revoked, "token_revoked")]
#[tokio::test]
async fn a_refused_credential_is_a_200_answer_with_the_reason_code(
    #[case] rejection: TokenRejection,
    #[case] code: &str,
) {
    let (app, _bus) = app(resolving(TokenResolution::Unresolved(rejection)));

    let (status, body) = answer(app, post(r#"{"credential":"bad"}"#)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "resolved": false, "reason": code }));
}

#[tokio::test]
async fn an_unreadable_revocation_state_is_the_internal_problem() {
    let failing = FakeQueryBus::answering(|_query: ResolveSubjectTokenQuery| {
        Err::<TokenResolution, _>(IamError::Storage("disk on fire".into()))
    });
    let (app, _bus) = app(failing);

    let (status, body) = answer(app, post(r#"{"credential":"token"}"#)).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!body.to_string().contains("disk on fire"));
}

#[rstest]
#[case::too_long(format!(r#"{{"credential":"{}"}}"#, "a".repeat(8193)))]
#[case::wrong_type(r#"{"credential":7}"#.to_owned())]
#[case::missing("{}".to_owned())]
#[case::unknown_member(r#"{"credential":"a","extra":1}"#.to_owned())]
#[tokio::test]
async fn an_invalid_body_is_refused_before_the_query_is_asked(#[case] body: String) {
    let (app, bus) = app(resolving(TokenResolution::Resolved(principal())));

    let (status, _problem) = answer(app, post(&body)).await;

    assert!(status.is_client_error(), "{status}");
    assert_eq!(bus.asked(), Vec::<&str>::new());
}

#[tokio::test]
async fn an_empty_credential_is_asked_as_it_is() {
    let missing = TokenResolution::Unresolved(TokenRejection::Missing);
    let (app, bus) = app(resolving(missing));

    let (status, body) = answer(app, post(r#"{"credential":""}"#)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({ "resolved": false, "reason": "token_missing" })
    );
    assert_eq!(bus.asked().len(), 1);
}
