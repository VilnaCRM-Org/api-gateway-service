use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;

use super::router;

#[tokio::test]
async fn ping_answers_pong() {
    let response = router()
        .oneshot(Request::get("/ping").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"pong");
}

#[tokio::test]
async fn an_unknown_path_is_a_404_problem() {
    let response = router()
        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn ping_with_another_method_is_a_405_problem() {
    let response = router()
        .oneshot(Request::post("/ping").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

mod probes {
    use std::sync::Arc;
    use std::time::Duration;

    use axum::Router;
    use axum::body::Body;
    use axum::http::header::CONTENT_TYPE;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt as _;
    use iam_application::{FreshnessState, LIVENESS_LIMIT, PodProbes, PodStatus};
    use iam_domain::freshness::proof::FreshnessProof;
    use iam_domain::{BootClock as _, FreshnessRule, PolicyVersion};
    use test_support::boot_clock::FakeBootClock;
    use test_support::policy_view::{EmptySnapshot, FakePolicyView};
    use tower::ServiceExt as _;

    use super::super::router_with_probes;

    struct Pod {
        status: Arc<PodStatus>,
        state: Arc<FreshnessState>,
        clock: Arc<FakeBootClock>,
        router: Router,
    }

    fn pod(view: FakePolicyView) -> Pod {
        let clock = Arc::new(FakeBootClock::new());
        let state = Arc::new(FreshnessState::new(
            FreshnessRule::new(Duration::from_secs(15), Duration::from_secs(2)),
            Arc::<FakeBootClock>::clone(&clock),
        ));
        let status = Arc::new(PodStatus::new());
        let probes = PodProbes::new(Arc::clone(&status), Arc::clone(&state), Arc::new(view));
        Pod {
            status,
            state,
            clock,
            router: router_with_probes(Arc::new(probes)),
        }
    }

    fn published() -> FakePolicyView {
        FakePolicyView::with_snapshot(Arc::new(EmptySnapshot::at(PolicyVersion::new(1).unwrap())))
    }

    fn complete_the_start(pod: &Pod) {
        pod.status.mark_keys_parsed();
        pod.status.mark_config_gates_passed();
        pod.status.mark_bootstrapped();
        prove(pod);
    }

    fn prove(pod: &Pod) {
        pod.state.attach(
            FreshnessProof {
                taken_at: pod.clock.now(),
                watermark: 1,
            },
            PolicyVersion::new(1).unwrap(),
        );
    }

    async fn get(pod: &Pod, path: &str) -> (StatusCode, String, Option<String>) {
        let response = pod
            .router
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .map(|value| value.to_str().unwrap().to_owned());
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            String::from_utf8(body.to_vec()).unwrap(),
            content_type,
        )
    }

    #[tokio::test]
    async fn before_the_bootstrap_startup_and_ready_answer_503_and_ping_answers_200() {
        let pod = pod(FakePolicyView::failing());

        let (startup, startup_body, startup_type) = get(&pod, "/internal/startup").await;
        let (ready, _body, _type) = get(&pod, "/internal/ready").await;
        let (ping, ping_body, _type) = get(&pod, "/ping").await;

        assert_eq!(startup, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(startup_type.as_deref(), Some("application/problem+json"));
        assert!(
            startup_body.contains("the JWT key set is not parsed"),
            "{startup_body}"
        );
        assert_eq!(ready, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(ping, StatusCode::OK);
        assert_eq!(ping_body, "pong");
    }

    #[tokio::test]
    async fn a_completed_bootstrap_with_an_attached_proof_passes_startup_and_ready() {
        let pod = pod(published());
        complete_the_start(&pod);

        let (startup, _body, _type) = get(&pod, "/internal/startup").await;
        let (ready, _body, _type) = get(&pod, "/internal/ready").await;

        assert_eq!(startup, StatusCode::OK);
        assert_eq!(ready, StatusCode::OK);
    }

    #[tokio::test]
    async fn a_fenced_pod_is_not_ready_until_the_rebootstrap_completes_and_stays_started() {
        let pod = pod(published());
        complete_the_start(&pod);
        assert_eq!(get(&pod, "/internal/startup").await.0, StatusCode::OK);

        pod.status.begin_rebootstrap();
        let (fenced_startup, _body, _type) = get(&pod, "/internal/startup").await;
        let (fenced_ready, body, _type) = get(&pod, "/internal/ready").await;
        pod.status.end_rebootstrap();
        let (lifted_ready, _body, _type) = get(&pod, "/internal/ready").await;

        assert_eq!(fenced_startup, StatusCode::OK);
        assert_eq!(fenced_ready, StatusCode::SERVICE_UNAVAILABLE);
        assert!(body.contains("rebootstrapping"), "{body}");
        assert_eq!(lifted_ready, StatusCode::OK);
    }

    #[tokio::test]
    async fn a_proof_past_the_ready_bound_makes_ready_503_while_ping_stays_200() {
        let pod = pod(published());
        complete_the_start(&pod);

        pod.clock.advance(Duration::from_millis(2001));
        pod.state.tick();
        let (ready, _body, _type) = get(&pod, "/internal/ready").await;
        let (ping, _body, _type) = get(&pod, "/ping").await;

        assert_eq!(ready, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(ping, StatusCode::OK);
    }

    #[tokio::test]
    async fn a_watchdog_stalled_for_ten_seconds_makes_ping_503() {
        let pod = pod(published());
        complete_the_start(&pod);
        pod.state.tick();

        pod.clock.advance(LIVENESS_LIMIT);
        let (stalled, body, content_type) = get(&pod, "/ping").await;
        pod.state.tick();
        let (resumed, _body, _type) = get(&pod, "/ping").await;

        assert_eq!(stalled, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(content_type.as_deref(), Some("application/problem+json"));
        assert!(body.contains("watchdog"), "{body}");
        assert_eq!(resumed, StatusCode::OK);
    }

    #[tokio::test]
    async fn an_unknown_path_and_another_method_are_problem_documents() {
        let pod = pod(published());

        let (unknown, _body, _type) = get(&pod, "/internal/drain").await;
        let wrong_method = pod
            .router
            .clone()
            .oneshot(
                Request::post("/internal/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(unknown, StatusCode::NOT_FOUND);
        assert_eq!(wrong_method.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}
