use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, StatusCode};
use tower::ServiceExt as _;

use super::router;

#[tokio::test]
async fn every_path_is_an_unknown_route_until_the_internal_endpoints_exist() {
    for path in [
        "/",
        "/ping",
        "/internal/freshness",
        "/internal/policy/applied",
    ] {
        let response = router()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/problem+json"
        );
    }
}
