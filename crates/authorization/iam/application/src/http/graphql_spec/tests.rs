use axum::Router;
use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, LOCATION};
use axum::http::{HeaderMap, Method, Request, StatusCode};
use iam_domain::{ActorRef, ContentHash, RequestDigester as _, ServiceName, SpecId};
use rstest::rstest;
use serde_json::{Value, json};
use shared_application::http::Violation;
use shared_domain::Uuid;
use test_support::request_digester::FakeRequestDigester;
use tower::ServiceExt as _;

use crate::error::IamError;
use crate::fixtures::{USER, principal};
use crate::graphql_spec_fixtures::{
    Answers, Asked, ReadAnswers, ReadAsked, SPEC, read_scenario, recorded, scenario, summary,
};
use crate::http::{IamState, specification_router};
use crate::query::get_graphql_spec::GetGraphQlSpecQuery;
use crate::query::get_graphql_specs::{GetGraphQlSpecsQuery, GraphQlSpecPage};

const SDL: &str = "type Query { invoices: [String!]! }";

fn app(answers: Answers) -> (Router, Asked) {
    let (state, asked) = scenario(answers);
    let (routes, _document) = specification_router::<IamState>().split_for_parts();
    (routes.with_state(state), asked)
}

fn post(body: &str) -> Request<Body> {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri("/graphql-specs")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap();
    request.extensions_mut().insert(principal());
    request
}

fn upload(service: &str, sdl: &str) -> Request<Body> {
    post(&json!({"service": service, "sdl": sdl}).to_string())
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

#[tokio::test]
async fn a_new_sdl_is_201_with_its_location_and_its_version_with_the_diff() {
    let (app, asked) = app(Answers::default());

    let (status, headers, body) = answer(app, upload("billing", SDL)).await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        headers.get(LOCATION).unwrap().to_str().unwrap(),
        format!("/api/graphql-specs/{SPEC}")
    );
    assert_eq!(body["id"], json!(SPEC));
    assert_eq!(body["service"], json!("billing"));
    assert_eq!(body["status"], json!("draft"));
    assert_eq!(body["contentHash"], json!("ab".repeat(32)));
    assert_eq!(body["coordinateCount"], json!(1));
    assert_eq!(body["diff"]["added"], json!(["Query.invoices"]));
    assert_eq!(body["diff"]["removed"], json!([]));
    assert_eq!(recorded(&asked.commands).len(), 1);
    assert_eq!(recorded(&asked.reads).len(), 1);
}

#[tokio::test]
async fn the_command_carries_the_caller_the_document_and_fresh_identifiers() {
    let (app, asked) = app(Answers::default());

    answer(app, upload("billing", SDL)).await;

    let sent = recorded(&asked.commands);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].actor, ActorRef::User(Uuid::parse(USER).unwrap()));
    assert_eq!(sent[0].service, "billing");
    assert_eq!(sent[0].sdl, SDL);
    assert_ne!(sent[0].change_id.as_uuid(), sent[0].spec_id.as_uuid());
    assert_eq!(recorded(&asked.reads), [sent[0].spec_id]);
}

#[tokio::test]
async fn the_lookup_asks_for_the_hash_of_the_document() {
    let (app, asked) = app(Answers::default());

    answer(app, upload("billing", SDL)).await;

    let finds = recorded(&asked.finds);
    assert_eq!(finds.len(), 1);
    assert_eq!(finds[0].service, ServiceName::new("billing").unwrap());
    let digest = FakeRequestDigester.digest(SDL);
    assert_eq!(
        finds[0].content_hash,
        ContentHash::new(digest.as_bytes()).unwrap()
    );
}

#[tokio::test]
async fn an_sdl_that_the_service_holds_is_200_with_that_version_and_no_command() {
    let answers = Answers {
        existing: Ok(Some(SpecId::parse(SPEC).unwrap())),
        ..Answers::default()
    };
    let (app, asked) = app(answers);

    let (status, headers, body) = answer(app, upload("billing", SDL)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(LOCATION).unwrap().to_str().unwrap(),
        format!("/api/graphql-specs/{SPEC}")
    );
    assert_eq!(body["id"], json!(SPEC));
    assert!(recorded(&asked.commands).is_empty());
    assert_eq!(recorded(&asked.reads), [SpecId::parse(SPEC).unwrap()]);
}

#[tokio::test]
async fn the_reserved_service_is_the_403_problem_and_nothing_is_looked_up() {
    let (app, asked) = app(Answers::default());

    let (status, _headers, body) = answer(app, upload("iam", SDL)).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["status"], json!(403));
    assert!(recorded(&asked.finds).is_empty());
    assert!(recorded(&asked.commands).is_empty());
}

#[tokio::test]
async fn an_invalid_service_name_is_a_422_problem_naming_the_service() {
    let (app, asked) = app(Answers::default());

    let (status, _headers, body) = answer(app, upload("Not A Service", SDL)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["violations"][0]["propertyPath"], json!("service"));
    assert!(recorded(&asked.commands).is_empty());
}

#[rstest]
#[case::empty_service(r#"{"service":"","sdl":"x"}"#, "service")]
#[case::empty_sdl(r#"{"service":"billing","sdl":""}"#, "sdl")]
#[tokio::test]
async fn an_empty_field_is_a_422_problem_naming_it_and_dispatches_nothing(
    #[case] body: &str,
    #[case] property: &str,
) {
    let (app, asked) = app(Answers::default());

    let (status, _headers, problem) = answer(app, post(body)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(problem["violations"][0]["propertyPath"], json!(property));
    assert!(recorded(&asked.commands).is_empty());
}

#[rstest]
#[case::missing_sdl(r#"{"service":"billing"}"#)]
#[case::unknown_member(r#"{"service":"billing","sdl":"x","kind":"y"}"#)]
#[case::not_json("service=billing")]
#[tokio::test]
async fn a_malformed_body_is_a_client_error_and_dispatches_nothing(#[case] body: &str) {
    let (app, asked) = app(Answers::default());

    let (status, _headers, _problem) = answer(app, post(body)).await;

    assert!(status.is_client_error(), "{status}");
    assert!(recorded(&asked.commands).is_empty());
}

#[tokio::test]
async fn a_request_without_a_token_is_the_401_problem() {
    let (app, asked) = app(Answers::default());
    let mut request = upload("billing", SDL);
    request
        .extensions_mut()
        .remove::<crate::principal::Principal>();

    let (status, _headers, body) = answer(app, request).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["status"], json!(401));
    assert!(recorded(&asked.commands).is_empty());
}

#[tokio::test]
async fn an_sdl_that_does_not_parse_is_the_422_problem_of_the_command() {
    let answers = Answers {
        command: Err(|| {
            IamError::Invalid(vec![Violation {
                property_path: "sdl".to_owned(),
                message: "unexpected token (line 1, column 14)".to_owned(),
                code: "syntax".to_owned(),
            }])
        }),
        ..Answers::default()
    };
    let (app, _asked) = app(answers);

    let (status, _headers, body) = answer(app, upload("billing", "type Query {")).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["violations"][0]["propertyPath"], json!("sdl"));
    assert_eq!(
        body["violations"][0]["message"],
        json!("unexpected token (line 1, column 14)")
    );
}

#[tokio::test]
async fn a_concurrent_upload_of_the_same_sdl_is_the_409_problem() {
    let answers = Answers {
        command: Err(|| IamError::Conflict),
        ..Answers::default()
    };
    let (app, _asked) = app(answers);

    let (status, _headers, _body) = answer(app, upload("billing", SDL)).await;

    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn a_version_that_cannot_be_read_back_is_a_404_problem() {
    let answers = Answers {
        view: Ok(None),
        ..Answers::default()
    };
    let (app, _asked) = app(answers);

    let (status, _headers, _body) = answer(app, upload("billing", SDL)).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[rstest]
#[case::lookup(Answers { existing: Err(|| IamError::Storage("down".into())), ..Answers::default() })]
#[case::command(Answers { command: Err(|| IamError::Storage("down".into())), ..Answers::default() })]
#[case::read(Answers { view: Err(|| IamError::Storage("down".into())), ..Answers::default() })]
#[tokio::test]
async fn a_storage_failure_is_an_internal_problem(#[case] answers: Answers) {
    let (app, _asked) = app(answers);

    let (status, _headers, _body) = answer(app, upload("billing", SDL)).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

fn read_app(answers: ReadAnswers) -> (Router, ReadAsked) {
    let (state, asked) = read_scenario(answers);
    let (routes, _document) = specification_router::<IamState>().split_for_parts();
    (routes.with_state(state), asked)
}

fn get(uri: &str) -> Request<Body> {
    let mut request = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    request.extensions_mut().insert(principal());
    request
}

fn spec_id() -> SpecId {
    SpecId::parse(SPEC).unwrap()
}

#[tokio::test]
async fn the_list_is_a_page_of_summaries_with_the_cursor_of_the_next_page() {
    let (app, asked) = read_app(ReadAnswers::default());

    let (status, _headers, body) = answer(app, get("/graphql-specs")).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["nextCursor"], json!(SPEC));
    let item = &body["items"][0];
    assert_eq!(item["id"], json!(SPEC));
    assert_eq!(item["service"], json!("billing"));
    assert_eq!(item["status"], json!("draft"));
    assert_eq!(item["contentHash"], json!("ab".repeat(32)));
    assert_eq!(item["coordinateCount"], json!(1));
    assert!(item.get("sdl").is_none());
    assert!(item.get("diff").is_none());
    assert_eq!(
        recorded(&asked.pages),
        [GetGraphQlSpecsQuery {
            limit: 30,
            after: None,
            service: None,
            status: None,
            include_sdl: false,
        }]
    );
}

#[tokio::test]
async fn the_list_passes_its_filters_and_the_sdl_flag_to_the_query() {
    let (app, asked) = read_app(ReadAnswers::default());
    let uri = format!(
        "/graphql-specs?limit=5&after={SPEC}&service=billing&status=active&includeSdl=true"
    );

    let (status, _headers, _body) = answer(app, get(&uri)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        recorded(&asked.pages),
        [GetGraphQlSpecsQuery {
            limit: 5,
            after: Some(spec_id()),
            service: Some(ServiceName::new("billing").unwrap()),
            status: Some(iam_domain::SpecStatus::Active),
            include_sdl: true,
        }]
    );
}

#[tokio::test]
async fn the_last_page_has_no_cursor() {
    let answers = ReadAnswers {
        page: Ok(GraphQlSpecPage {
            specs: Vec::new(),
            next_after: None,
        }),
        ..ReadAnswers::default()
    };
    let (app, _asked) = read_app(answers);

    let (status, _headers, body) = answer(app, get("/graphql-specs")).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"], json!([]));
    assert!(body.get("nextCursor").is_none());
}

#[rstest]
#[case::limit_zero("/graphql-specs?limit=0", "limit")]
#[case::limit_over("/graphql-specs?limit=101", "limit")]
#[case::cursor("/graphql-specs?after=nope", "after")]
#[case::service("/graphql-specs?service=Not%20A%20Service", "service")]
#[case::status("/graphql-specs?status=pending", "status")]
#[tokio::test]
async fn an_invalid_parameter_is_a_422_problem_naming_it_and_asks_nothing(
    #[case] uri: &str,
    #[case] property: &str,
) {
    let (app, asked) = read_app(ReadAnswers::default());

    let (status, _headers, body) = answer(app, get(uri)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["violations"][0]["propertyPath"], json!(property));
    assert_eq!(recorded(&asked.pages), Vec::<GetGraphQlSpecsQuery>::new());
}

#[tokio::test]
async fn an_unknown_list_parameter_is_a_client_error() {
    let (app, asked) = read_app(ReadAnswers::default());

    let (status, _headers, _body) = answer(app, get("/graphql-specs?colour=red")).await;

    assert!(status.is_client_error(), "{status}");
    assert_eq!(recorded(&asked.pages), Vec::<GetGraphQlSpecsQuery>::new());
}

#[tokio::test]
async fn one_version_is_its_summary_without_the_sdl_by_default() {
    let (app, asked) = read_app(ReadAnswers::default());

    let (status, _headers, body) = answer(app, get(&format!("/graphql-specs/{SPEC}"))).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], json!(SPEC));
    assert_eq!(body["coordinateCount"], json!(1));
    assert!(body.get("sdl").is_none());
    assert_eq!(
        recorded(&asked.ones),
        [GetGraphQlSpecQuery {
            id: spec_id(),
            include_sdl: false,
        }]
    );
}

#[tokio::test]
async fn one_version_carries_its_sdl_when_asked_for() {
    let mut with_sdl = summary();
    with_sdl.sdl = Some(SDL.to_owned());
    let answers = ReadAnswers {
        one: Ok(Some(with_sdl)),
        ..ReadAnswers::default()
    };
    let (app, asked) = read_app(answers);

    let (status, _headers, body) =
        answer(app, get(&format!("/graphql-specs/{SPEC}?includeSdl=true"))).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["sdl"], json!(SDL));
    assert_eq!(
        recorded(&asked.ones),
        [GetGraphQlSpecQuery {
            id: spec_id(),
            include_sdl: true,
        }]
    );
}

#[tokio::test]
async fn an_unknown_version_is_the_404_problem() {
    let answers = ReadAnswers {
        one: Ok(None),
        ..ReadAnswers::default()
    };
    let (app, _asked) = read_app(answers);

    let (status, _headers, body) = answer(app, get(&format!("/graphql-specs/{SPEC}"))).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["status"], json!(404));
}

#[tokio::test]
async fn an_identifier_that_is_not_a_uuid_is_a_422_problem_naming_the_id() {
    let (app, asked) = read_app(ReadAnswers::default());

    let (status, _headers, body) = answer(app, get("/graphql-specs/nope")).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["violations"][0]["propertyPath"], json!("id"));
    assert_eq!(recorded(&asked.ones), Vec::<GetGraphQlSpecQuery>::new());
}

#[tokio::test]
async fn the_diff_is_the_diff_of_the_version_alone() {
    let (app, asked) = read_app(ReadAnswers::default());

    let (status, _headers, body) = answer(app, get(&format!("/graphql-specs/{SPEC}/diff"))).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["added"], json!(["Query.invoices"]));
    assert_eq!(body["removed"], json!([]));
    assert_eq!(body["removedGrants"], json!([]));
    assert_eq!(body["wildcardGains"], json!([]));
    assert_eq!(body["flagDowngrades"], json!([]));
    assert!(body.get("id").is_none());
    assert_eq!(recorded(&asked.diffs), [spec_id()]);
}

#[tokio::test]
async fn the_diff_of_an_unknown_version_is_the_404_problem() {
    let answers = ReadAnswers {
        diff: Ok(None),
        ..ReadAnswers::default()
    };
    let (app, _asked) = read_app(answers);

    let (status, _headers, _body) = answer(app, get(&format!("/graphql-specs/{SPEC}/diff"))).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_diff_of_an_identifier_that_is_not_a_uuid_is_a_422_problem() {
    let (app, asked) = read_app(ReadAnswers::default());

    let (status, _headers, body) = answer(app, get("/graphql-specs/nope/diff")).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["violations"][0]["propertyPath"], json!("id"));
    assert_eq!(recorded(&asked.diffs), Vec::<SpecId>::new());
}

#[rstest]
#[case::list("/graphql-specs")]
#[case::one("/graphql-specs/0190f2a8-7b3c-7d4e-8f10-1234567890ad")]
#[case::diff("/graphql-specs/0190f2a8-7b3c-7d4e-8f10-1234567890ad/diff")]
#[tokio::test]
async fn a_read_without_a_token_is_the_401_problem(#[case] uri: &str) {
    let (app, asked) = read_app(ReadAnswers::default());
    let mut request = get(uri);
    request
        .extensions_mut()
        .remove::<crate::principal::Principal>();

    let (status, _headers, body) = answer(app, request).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["status"], json!(401));
    assert_eq!(recorded(&asked.pages), Vec::<GetGraphQlSpecsQuery>::new());
    assert_eq!(recorded(&asked.ones), Vec::<GetGraphQlSpecQuery>::new());
    assert_eq!(recorded(&asked.diffs), Vec::<SpecId>::new());
}

#[rstest]
#[case::list("/graphql-specs")]
#[case::one("/graphql-specs/0190f2a8-7b3c-7d4e-8f10-1234567890ad")]
#[case::diff("/graphql-specs/0190f2a8-7b3c-7d4e-8f10-1234567890ad/diff")]
#[tokio::test]
async fn a_read_storage_failure_is_an_internal_problem(#[case] uri: &str) {
    let answers = ReadAnswers {
        page: Err(|| IamError::Storage("down".into())),
        one: Err(|| IamError::Storage("down".into())),
        diff: Err(|| IamError::Storage("down".into())),
    };
    let (app, _asked) = read_app(answers);

    let (status, _headers, _body) = answer(app, get(uri)).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}
