use axum::Router;
use axum::body::Body;
use axum::http::request::Parts;
use axum::http::{HeaderValue, Request, StatusCode, header};
use axum::middleware::from_fn;
use axum::routing::get;
use tower::ServiceExt as _;

use super::{FramingError, check, reject_ambiguous};

fn parts(headers: &[(&str, &str)], target: &str) -> Parts {
    let mut builder = Request::builder().uri(target);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(()).unwrap().into_parts().0
}

#[test]
fn a_plain_request_passes() {
    assert_eq!(
        check(&parts(&[("content-length", "5")], "/api/users")),
        Ok(())
    );
}

#[test]
fn content_length_with_transfer_encoding_is_refused() {
    let request = parts(
        &[("content-length", "5"), ("transfer-encoding", "chunked")],
        "/",
    );

    assert_eq!(check(&request), Err(FramingError::LengthAndEncoding));
}

#[test]
fn transfer_encoding_alone_passes() {
    assert_eq!(
        check(&parts(&[("transfer-encoding", "chunked")], "/")),
        Ok(())
    );
}

#[test]
fn two_different_content_lengths_are_refused() {
    let request = parts(&[("content-length", "5"), ("content-length", "6")], "/");

    assert_eq!(check(&request), Err(FramingError::ContentLength));
}

#[test]
fn a_list_of_different_content_lengths_is_refused() {
    assert_eq!(
        check(&parts(&[("content-length", "5, 6")], "/")),
        Err(FramingError::ContentLength)
    );
}

#[test]
fn repeated_equal_content_lengths_pass() {
    let request = parts(&[("content-length", "5"), ("content-length", "5, 5")], "/");

    assert_eq!(check(&request), Ok(()));
}

#[test]
fn a_content_length_that_is_not_a_number_is_refused() {
    for value in ["", "-1", "+5", "5x", "0x5", ","] {
        assert_eq!(
            check(&parts(&[("content-length", value)], "/")),
            Err(FramingError::ContentLength),
            "{value:?}"
        );
    }
}

#[test]
fn a_content_length_that_is_not_text_is_refused() {
    let mut request = parts(&[], "/");
    request.headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_bytes(&[0xff]).unwrap(),
    );

    assert_eq!(check(&request), Err(FramingError::ContentLength));
}

#[test]
fn an_asterisk_target_is_refused() {
    assert_eq!(check(&parts(&[], "*")), Err(FramingError::Path));
}

#[test]
fn a_path_that_is_not_absolute_or_not_printable_is_refused() {
    assert_eq!(super::check_path("/a\\b"), Err(FramingError::Path));
    assert_eq!(super::check_path("/a\u{7f}b"), Err(FramingError::Path));
    assert_eq!(super::check_path("/a b"), Err(FramingError::Path));
    assert_eq!(super::check_path("api"), Err(FramingError::Path));
    assert_eq!(super::check_path(""), Err(FramingError::Path));
    assert_eq!(super::check_path("/api/users/42"), Ok(()));
}

async fn ok() -> &'static str {
    "ok"
}

async fn answer(headers: &[(&str, &str)]) -> StatusCode {
    let router = Router::new()
        .route("/", get(ok))
        .layer(from_fn(reject_ambiguous));
    let mut builder = Request::builder().uri("/");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    router
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn the_middleware_answers_400_for_an_ambiguous_request_and_passes_the_rest() {
    assert_eq!(answer(&[]).await, StatusCode::OK);
    assert_eq!(
        answer(&[("content-length", "0"), ("transfer-encoding", "chunked")]).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        answer(&[("content-length", "1"), ("content-length", "2")]).await,
        StatusCode::BAD_REQUEST
    );
}

#[test]
fn every_error_is_a_400_problem() {
    for error in [
        FramingError::LengthAndEncoding,
        FramingError::ContentLength,
        FramingError::Path,
    ] {
        let response: axum::response::Response = error.into();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
