use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, ETAG};
use axum::http::{HeaderMap, Method, Request, StatusCode};
use iam_domain::PropagationOutcome;
use rstest::rstest;
use serde_json::{Value, json};
use test_support::bus::{FakeCommandBus, FakeQueryBus};
use tower::ServiceExt as _;

use crate::error::IamError;
use crate::fixtures::principal;
use crate::http::{IamState, router};
use crate::route_configuration_fixtures::{
    Answers, Asked, configuration, declared, preview, receipt_of, recorded, scenario,
};
use crate::route_fixtures::{HOST, UPSTREAM, actor};

/// The router over the doubles, with the doubles to read back.
fn app(answers: Answers) -> (Router, Arc<FakeCommandBus>, Arc<FakeQueryBus>, Asked) {
    let (state, commands, queries, asked) = scenario(answers);
    let (routes, _document) = router::<IamState>().split_for_parts();
    (routes.with_state(state), commands, queries, asked)
}

/// A request of a caller whose token the middleware resolved.
fn request(
    method: Method,
    uri: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    if body.is_some() {
        builder = builder.header(CONTENT_TYPE, "application/json");
    }
    let mut request = builder
        .body(Body::from(body.unwrap_or_default().to_owned()))
        .unwrap();
    request.extensions_mut().insert(principal());
    request
}

fn one() -> String {
    format!("/route-configurations/{HOST}")
}

fn put(query: &str, headers: &[(&str, &str)], body: &str) -> Request<Body> {
    request(
        Method::PUT,
        &format!("{}{query}", one()),
        headers,
        Some(body),
    )
}

fn get() -> Request<Body> {
    request(Method::GET, &one(), &[], None)
}

async fn answer(app: Router, request: Request<Body>) -> (StatusCode, HeaderMap, Value) {
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        headers,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .map(|value| value.to_str().unwrap().to_owned())
}

fn declaration(path: &str) -> Value {
    json!({
        "methods": ["GET"],
        "pathPattern": path,
        "service": "core",
        "upstreamId": UPSTREAM,
    })
}

fn body_of(paths: &[&str]) -> String {
    json!({ "routes": paths.iter().map(|path| declaration(path)).collect::<Vec<_>>() }).to_string()
}

fn version_tag() -> String {
    format!("\"{}\"", configuration().version.value())
}

#[tokio::test]
async fn the_configuration_of_a_host_is_200_with_its_version_as_the_etag() {
    let (app, commands, queries, asked) = app(Answers::default());

    let (status, headers, body) = answer(app, get()).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, ETAG.as_str()), Some(version_tag()));
    assert_eq!(body["host"], json!(HOST));
    assert_eq!(body["version"], json!(configuration().version.value()));
    assert_eq!(body["routes"][0]["pathPattern"], json!("/a"));
    assert_eq!(body["routes"][0]["upstreamId"], json!(UPSTREAM));
    assert_eq!(body["routes"][1]["pathPattern"], json!("/b"));
    assert_eq!(body["routes"][0].get("id"), None);
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
    assert_eq!(queries.asked(), ["GetRouteConfigurationQuery"]);
    assert_eq!(recorded(&asked.configurations)[0].host, HOST);
}

#[tokio::test]
async fn a_read_without_a_token_is_the_401_problem() {
    let (app, ..) = app(Answers::default());
    let mut unauthenticated = get();
    unauthenticated
        .extensions_mut()
        .remove::<crate::principal::Principal>();

    let (status, ..) = answer(app, unauthenticated).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_host_that_is_not_a_host_name_is_the_422_problem() {
    let answers = Answers {
        configuration: Err(|| IamError::invalid_property("host", "Invalid.", "host")),
        ..Answers::default()
    };
    let (app, ..) = app(answers);

    let (status, _headers, body) = answer(app, get()).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["violations"][0]["propertyPath"], json!("host"));
}

#[tokio::test]
async fn an_application_is_200_with_the_diff_the_new_version_and_the_policy_version() {
    let (app, commands, queries, asked) = app(Answers::default());

    let (status, headers, body) = answer(
        app,
        put(
            "",
            &[("If-Match", &version_tag())],
            &body_of(&["/a", "/b", "/c"]),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, ETAG.as_str()), Some("\"5\"".to_owned()));
    assert_eq!(header(&headers, "iam-policy-version"), Some("8".to_owned()));
    assert_eq!(body["host"], json!(HOST));
    assert_eq!(body["dryRun"], json!(false));
    assert_eq!(body["version"], json!(5));
    assert_eq!(body["revocation"], json!(false));
    assert_eq!(body["unchanged"], json!(2));
    assert_eq!(
        body["added"],
        json!([{ "methods": ["GET"], "pathPattern": "/c" }])
    );
    assert_eq!(body["changed"], json!([]));
    assert_eq!(body["removed"], json!([]));
    assert_eq!(commands.dispatched(), ["ApplyRouteConfigurationCommand"]);
    assert_eq!(
        queries.asked(),
        ["PreviewRouteConfigurationQuery", "GetChangeReceiptQuery"]
    );
    let sent = recorded(&asked.applies);
    assert_eq!(sent[0].host, HOST);
    assert_eq!(sent[0].routes.len(), 3);
    assert_eq!(sent[0].actor, actor());
    assert_eq!(sent[0].expected, configuration().version);
    assert_eq!(
        recorded(&asked.previews)[0].expected,
        configuration().version
    );
}

#[tokio::test]
async fn a_dry_run_reports_the_diff_with_the_stored_version_and_dispatches_nothing() {
    let answers = Answers {
        preview: Ok(preview(vec![declared("/b"), declared("/c")])),
        ..Answers::default()
    };
    let (app, commands, queries, _asked) = app(answers);

    let (status, headers, body) = answer(
        app,
        put(
            "?dryRun=true",
            &[("If-Match", &version_tag())],
            &body_of(&["/b", "/c"]),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, ETAG.as_str()), Some(version_tag()));
    assert_eq!(header(&headers, "iam-policy-version"), None);
    assert_eq!(body["dryRun"], json!(true));
    assert_eq!(body["version"], json!(configuration().version.value()));
    assert_eq!(body["revocation"], json!(true));
    assert_eq!(
        body["added"],
        json!([{ "methods": ["GET"], "pathPattern": "/c" }])
    );
    assert_eq!(
        body["removed"],
        json!([{ "methods": ["GET"], "pathPattern": "/a" }])
    );
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
    assert_eq!(queries.asked(), ["PreviewRouteConfigurationQuery"]);
}

#[tokio::test]
async fn a_set_that_changes_nothing_dispatches_nothing() {
    let answers = Answers {
        preview: Ok(preview(vec![declared("/a"), declared("/b")])),
        ..Answers::default()
    };
    let (app, commands, _queries, _asked) = app(answers);

    let (status, headers, body) = answer(
        app,
        put("", &[("If-Match", &version_tag())], &body_of(&["/a", "/b"])),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, ETAG.as_str()), Some(version_tag()));
    assert_eq!(body["dryRun"], json!(false));
    assert_eq!(body["unchanged"], json!(2));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_receipt_that_was_not_acknowledged_in_time_is_202_with_its_status() {
    let answers = Answers {
        receipt: receipt_of(5, Some(8)).with_propagation(PropagationOutcome::CommittedPending),
        ..Answers::default()
    };
    let (app, ..) = app(answers);

    let (status, headers, _body) = answer(
        app,
        put(
            "",
            &[("If-Match", &version_tag())],
            &body_of(&["/a", "/b", "/c"]),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(
        header(&headers, "iam-propagation-status"),
        Some("committed_pending_propagation".to_owned())
    );
}

#[tokio::test]
async fn an_application_without_if_match_is_the_428_problem_and_asks_nothing() {
    let (app, commands, queries, _asked) = app(Answers::default());

    let (status, _headers, body) = answer(app, put("", &[], &body_of(&["/a"]))).await;

    assert_eq!(status, StatusCode::PRECONDITION_REQUIRED);
    assert_eq!(body["status"], json!(428));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
    assert_eq!(queries.asked(), Vec::<&str>::new());
}

#[rstest]
#[case::stale(|| IamError::PreconditionFailed, StatusCode::PRECONDITION_FAILED)]
#[case::system_entry(|| IamError::SystemEntry, StatusCode::CONFLICT)]
#[case::forbidden(|| IamError::Forbidden, StatusCode::FORBIDDEN)]
#[case::conflict(
    || IamError::RouteTableConflict { code: "route_table_conflict" },
    StatusCode::CONFLICT
)]
#[case::too_many(
    || IamError::invalid_property("routes", "Too many.", "max_items"),
    StatusCode::UNPROCESSABLE_ENTITY
)]
#[tokio::test]
async fn a_refusal_of_the_dry_run_is_its_problem_and_dispatches_nothing(
    #[case] refusal: fn() -> IamError,
    #[case] expected: StatusCode,
) {
    let answers = Answers {
        preview: Err(refusal),
        ..Answers::default()
    };
    let (app, commands, ..) = app(answers);

    let (status, ..) = answer(
        app,
        put("", &[("If-Match", &version_tag())], &body_of(&["/a"])),
    )
    .await;

    assert_eq!(status, expected);
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_refusal_of_the_command_is_its_problem() {
    let answers = Answers {
        apply: Err(|| IamError::PreconditionFailed),
        ..Answers::default()
    };
    let (app, commands, ..) = app(answers);

    let (status, ..) = answer(
        app,
        put(
            "",
            &[("If-Match", &version_tag())],
            &body_of(&["/a", "/b", "/c"]),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(commands.dispatched(), ["ApplyRouteConfigurationCommand"]);
}

#[tokio::test]
async fn a_route_with_an_identifier_that_is_not_a_uuid_names_its_position() {
    let (app, commands, ..) = app(Answers::default());
    let body = json!({ "routes": [{
        "methods": ["GET"],
        "pathPattern": "/a",
        "service": "core",
        "upstreamId": "nope",
    }] })
    .to_string();

    let (status, _headers, body) =
        answer(app, put("", &[("If-Match", &version_tag())], &body)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        body["violations"][0]["propertyPath"],
        json!("routes[0].upstreamId")
    );
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[rstest]
#[case::an_unknown_member(r#"{"routes":[],"host":"x"}"#)]
#[case::an_unknown_route_member(
    r#"{"routes":[{"methods":["GET"],"pathPattern":"/a","service":"core","upstreamId":"u","host":"x"}]}"#
)]
#[case::routes_missing("{}")]
#[tokio::test]
async fn a_body_that_does_not_fit_the_shape_is_a_client_error(#[case] body: &str) {
    let (app, commands, ..) = app(Answers::default());

    let (status, ..) = answer(app, put("", &[("If-Match", &version_tag())], body)).await;

    assert!(status.is_client_error(), "{status}");
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn an_unknown_query_parameter_is_a_client_error() {
    let (app, ..) = app(Answers::default());

    let (status, ..) = answer(
        app,
        put(
            "?dry=true",
            &[("If-Match", &version_tag())],
            &body_of(&["/a"]),
        ),
    )
    .await;

    assert!(status.is_client_error(), "{status}");
}

#[tokio::test]
async fn a_stale_if_match_text_is_the_412_problem() {
    let (app, ..) = app(Answers::default());

    let (status, ..) = answer(app, put("", &[("If-Match", "W/\"5\"")], &body_of(&["/a"]))).await;

    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
}
