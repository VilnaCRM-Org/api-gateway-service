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

mod freshness_endpoint {
    use std::sync::Arc;
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt as _;
    use iam_application::FreshnessState;
    use iam_domain::freshness::proof::FreshnessProof;
    use iam_domain::{BootClock as _, BootInstant, FreshnessRule, PolicyVersion};
    use serde_json::{Value, json};
    use test_support::boot_clock::FakeBootClock;
    use test_support::policy_view::{EmptySnapshot, FakePolicyView};
    use tower::ServiceExt as _;

    use super::super::router_with_freshness;

    fn state() -> (Arc<FreshnessState>, Arc<FakeBootClock>) {
        let clock = Arc::new(FakeBootClock::starting_at(BootInstant::from_elapsed(
            Duration::from_secs(100),
        )));
        let state = Arc::new(FreshnessState::new(
            FreshnessRule::new(Duration::from_secs(15), Duration::from_secs(2)),
            Arc::<FakeBootClock>::clone(&clock),
        ));
        (state, clock)
    }

    async fn read(router: axum::Router) -> (StatusCode, Value) {
        let response = router
            .oneshot(
                Request::get("/internal/freshness")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn a_fresh_pod_reports_its_version_proof_age_digest_and_hard_bound() {
        let (state, clock) = state();
        let snapshot = EmptySnapshot::at(PolicyVersion::new(7).unwrap());
        let view = Arc::new(FakePolicyView::with_snapshot(Arc::new(snapshot)));
        state.attach(
            FreshnessProof {
                taken_at: clock.now(),
                watermark: 4,
            },
            PolicyVersion::new(7).unwrap(),
        );
        clock.advance(Duration::from_millis(1_250));

        let (status, body) = read(router_with_freshness(state, view)).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            json!({
                "version": 7,
                "digest": "00000000000000000000000000000000",
                "proofAgeMs": 1_250,
                "hardBoundMs": 15_000,
                "fresh": true,
            })
        );
    }

    #[tokio::test]
    async fn a_pod_without_a_snapshot_or_a_proof_reports_nulls_and_is_not_fresh() {
        let (state, _clock) = state();
        let view = Arc::new(FakePolicyView::failing());

        let (status, body) = read(router_with_freshness(state, view)).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            json!({
                "version": null,
                "digest": null,
                "proofAgeMs": null,
                "hardBoundMs": 15_000,
                "fresh": false,
            })
        );
    }

    #[tokio::test]
    async fn the_other_paths_still_answer_the_404_problem() {
        let (state, _clock) = state();
        let router = router_with_freshness(state, Arc::new(FakePolicyView::failing()));

        let response = router
            .oneshot(
                Request::get("/internal/policy/applied")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
