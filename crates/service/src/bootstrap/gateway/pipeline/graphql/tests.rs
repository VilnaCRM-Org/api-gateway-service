use async_graphql::futures_util::stream;
use axum::body::Body;
use axum::http::header::{ALLOW, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use rstest::rstest;

use super::*;

fn headers(content_type: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Some(value) = content_type {
        headers.insert(CONTENT_TYPE, HeaderValue::from_str(value).unwrap());
    }
    headers
}

fn rejected(body: &str) -> Refusal {
    decode(body.as_bytes()).unwrap_err()
}

#[test]
fn a_single_operation_is_read_with_its_name() {
    let operations =
        decode(br#"{"query":"query A { a }","operationName":"A","variables":{"x":1}}"#).unwrap();

    assert_eq!(
        operations,
        vec![GraphQlOperation {
            document: "query A { a }".to_owned(),
            operation_name: Some("A".to_owned()),
        }]
    );
}

#[test]
fn null_members_are_the_same_as_absent_ones() {
    let operations =
        decode(br#"{"query":"{ a }","operationName":null,"variables":null,"extensions":null}"#)
            .unwrap();

    assert_eq!(operations[0].operation_name, None);
}

#[test]
fn a_batch_is_read_in_order() {
    let operations = decode(br#"  [{"query":"{ a }"},{"query":"{ b }"}]"#).unwrap();

    assert_eq!(
        operations
            .iter()
            .map(|operation| operation.document.as_str())
            .collect::<Vec<_>>(),
        ["{ a }", "{ b }"]
    );
}

#[test]
fn a_batch_of_ten_is_accepted_and_one_of_eleven_is_refused() {
    let batch = |count: usize| format!("[{}]", vec![r#"{"query":"{ a }"}"#; count].join(","));

    assert_eq!(decode(batch(10).as_bytes()).unwrap().len(), 10);
    assert!(matches!(rejected(&batch(11)), Refusal::BadRequest(_)));
    assert!(matches!(rejected("[]"), Refusal::BadRequest(_)));
}

#[rstest]
#[case::duplicate_query(r#"{"query":"{ a }","query":"{ b }"}"#)]
#[case::duplicate_in_a_batch(r#"[{"query":"{ a }","operationName":"x","operationName":"y"}]"#)]
#[case::persisted_query_only(
    r#"{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"ab"}}}"#
)]
#[case::persisted_query_beside_a_document(
    r#"{"query":"{ a }","extensions":{"persistedQuery":{"version":1}}}"#
)]
#[case::document_id(r#"{"documentId":"abc"}"#)]
#[case::query_id(r#"{"query":"{ a }","queryId":"abc"}"#)]
#[case::id(r#"{"query":"{ a }","id":"abc"}"#)]
#[case::empty_query(r#"{"query":""}"#)]
#[case::missing_query(r#"{"operationName":"A"}"#)]
#[case::numeric_query(r#"{"query":1}"#)]
#[case::unknown_member(r#"{"query":"{ a }","debug":true}"#)]
#[case::a_member_of_another_case(r#"{"Query":"{ a }"}"#)]
#[case::name_that_is_not_text(r#"{"query":"{ a }","operationName":1}"#)]
#[case::variables_that_are_a_list(r#"{"query":"{ a }","variables":[1]}"#)]
#[case::extensions_that_are_text(r#"{"query":"{ a }","extensions":"x"}"#)]
#[case::an_element_that_is_not_an_object("[1]")]
#[case::not_json("query { a }")]
#[case::empty("")]
fn a_body_that_is_not_an_accepted_graphql_request_is_a_bad_request(#[case] body: &str) {
    assert!(matches!(rejected(body), Refusal::BadRequest(_)), "{body}");
}

#[rstest]
#[case("application/json")]
#[case("Application/JSON")]
#[case("application/json; charset=utf-8")]
#[case("  application/json ;charset=utf-8")]
fn a_json_body_is_accepted(#[case] declared: &str) {
    assert_eq!(content_type(&headers(Some(declared))), Ok(()));
}

#[rstest]
#[case(Some("multipart/form-data; boundary=x"))]
#[case(Some("text/plain"))]
#[case(Some("application/graphql"))]
#[case(Some("application/jsonp"))]
#[case(Some(""))]
#[case(None)]
fn any_other_body_type_is_unsupported(#[case] declared: Option<&str>) {
    assert_eq!(
        content_type(&headers(declared)),
        Err(Refusal::UnsupportedMediaType)
    );
}

#[tokio::test]
async fn a_body_is_read_up_to_the_limit_and_refused_above_it() {
    let at_limit = buffer(Body::from(vec![b'a'; 64]), 64).await;
    let above = buffer(Body::from(vec![b'a'; 65]), 64).await;

    assert_eq!(at_limit.unwrap().len(), 64);
    assert_eq!(above, Err(Refusal::PayloadTooLarge));
}

#[tokio::test]
async fn a_large_body_is_read_when_the_limit_of_the_route_is_large() {
    let body = Body::from(vec![b'a'; 5 * 1024 * 1024]);

    let bytes = buffer(body, 6 * 1024 * 1024).await.unwrap();

    assert_eq!(bytes.len(), 5 * 1024 * 1024);
}

#[tokio::test]
async fn a_body_that_fails_while_it_is_read_is_a_bad_request() {
    let failing = Body::from_stream(stream::iter([Err::<Bytes, std::io::Error>(
        std::io::Error::other("reset"),
    )]));

    assert!(matches!(
        buffer(failing, 64).await,
        Err(Refusal::BadRequest(_))
    ));
}

async fn answer(response: Response) -> (StatusCode, String) {
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let document: Value = serde_json::from_slice(&body).unwrap();
    (status, document["type"].as_str().unwrap().to_owned())
}

#[tokio::test]
async fn the_answers_of_a_graphql_route_are_problems() {
    assert_eq!(
        answer(bad_request("no")).await,
        (
            StatusCode::BAD_REQUEST,
            TYPE_MALFORMED_GRAPHQL_REQUEST.to_owned()
        )
    );
    assert_eq!(
        answer(unsupported_media_type()).await.0,
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    assert_eq!(
        answer(payload_too_large()).await.0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

#[test]
fn a_method_that_is_not_post_is_told_to_use_post() {
    let response = method_not_allowed();

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(response.headers().get(ALLOW).unwrap(), "POST");
}
