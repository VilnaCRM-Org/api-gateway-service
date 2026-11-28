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

mod applied_endpoint {
    use std::sync::Arc;
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::header::CONTENT_TYPE;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt as _;
    use iam_application::{
        AppliedPoll, AppliedPollSettings, BootstrapHighWater, PolicyVersionBoard, ReevaluationBoard,
    };
    use iam_domain::PolicyVersion;
    use serde_json::{Value, json};
    use tower::ServiceExt as _;

    use super::super::{router, with_applied};

    struct Pod {
        versions: Arc<PolicyVersionBoard>,
        reevaluation: Arc<ReevaluationBoard>,
        high_water: Arc<BootstrapHighWater>,
        router: axum::Router,
    }

    fn pod(max_concurrent: usize) -> Pod {
        let versions = Arc::new(PolicyVersionBoard::new());
        let reevaluation = Arc::new(ReevaluationBoard::new());
        let high_water = Arc::new(BootstrapHighWater::new());
        let poll = Arc::new(AppliedPoll::new(
            Arc::clone(&versions),
            Arc::clone(&reevaluation),
            Arc::clone(&high_water),
            AppliedPollSettings {
                pod: "gateway-3".to_owned(),
                hard_bound: Duration::from_secs(15),
                max_concurrent,
            },
        ));
        Pod {
            versions,
            reevaluation,
            high_water,
            router: with_applied(router(), poll),
        }
    }

    fn apply(pod: &Pod, version: i64) {
        let version = PolicyVersion::new(version).unwrap();
        pod.versions.note_published(Some(version));
        pod.reevaluation.advance(version);
    }

    async fn get(router: axum::Router, query: &str) -> (StatusCode, Option<String>, Vec<u8>) {
        let response = router
            .oneshot(
                Request::get(format!("/internal/policy/applied?{query}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .map(|value| value.to_str().unwrap().to_owned());
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, content_type, body.to_vec())
    }

    #[tokio::test]
    async fn an_applied_version_answers_with_the_version_the_pod_and_its_hard_bound() {
        let pod = pod(4);
        apply(&pod, 6);

        let (status, _type, body) = get(pod.router, "atLeast=5&offset=40&wait=0").await;

        assert_eq!(status, StatusCode::OK);
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body,
            json!({"version": 6, "pod": "gateway-3", "hardBoundMs": 15_000})
        );
    }

    #[tokio::test]
    async fn a_bootstrapping_pod_answers_with_no_version_when_hw0_is_beyond_the_offset() {
        let pod = pod(4);
        pod.high_water.capture(41);

        let (status, _type, body) = get(pod.router, "atLeast=5&offset=40&wait=0").await;

        assert_eq!(status, StatusCode::OK);
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body,
            json!({"version": null, "pod": "gateway-3", "hardBoundMs": 15_000})
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_wait_that_ends_first_answers_204_without_a_body() {
        let pod = pod(4);
        apply(&pod, 4);

        let (status, _type, body) = get(pod.router, "atLeast=5&offset=40&wait=2000").await;

        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(body.len(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_poll_beyond_the_limit_gets_a_503_problem_at_once() {
        let pod = pod(1);
        let waiting = tokio::spawn(get(pod.router.clone(), "atLeast=5&offset=40&wait=5000"));
        tokio::time::sleep(Duration::from_millis(1)).await;

        let (status, content_type, _body) =
            get(pod.router.clone(), "atLeast=5&offset=40&wait=5000").await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(content_type.as_deref(), Some("application/problem+json"));
        apply(&pod, 5);
        assert_eq!(waiting.await.unwrap().0, StatusCode::OK);
    }

    #[tokio::test]
    async fn a_missing_or_negative_parameter_is_a_problem_document() {
        for query in ["offset=1&wait=0", "atLeast=-1&offset=1&wait=0", "atLeast=x"] {
            let (status, content_type, _body) = get(pod(1).router, query).await;

            assert!(status.is_client_error(), "{query}");
            assert_eq!(
                content_type.as_deref(),
                Some("application/problem+json"),
                "{query}"
            );
        }
    }

    #[tokio::test]
    async fn the_other_paths_keep_answering_the_404_problem() {
        let response = pod(1)
            .router
            .oneshot(Request::get("/internal/other").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
