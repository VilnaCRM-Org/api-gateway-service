use std::time::SystemTime;

use iam_application::FreshnessState;
use iam_domain::freshness::proof::FreshnessProof;
use iam_domain::{
    AccessToken, AccessTokenParts, BootClock as _, BootInstant, FreshnessRule, PolicyView, RouteId,
    SessionId, SubjectId, TokenId, TokenIdentity, UpstreamName,
};
use shared_domain::{Clock, Uuid};
use shared_infrastructure::clock::SystemClock;
use test_support::access_token::DEVELOPMENT_PUBLIC_KEYS_FILE;
use test_support::boot_clock::FakeBootClock;
use test_support::gateway_snapshot::{CountingPolicyView, GatewaySnapshot};
use tokio_tungstenite::tungstenite::error::CapacityError;

use super::super::{UnreachableUpstreams, from_config};
use super::*;
use crate::bootstrap::gateway::streams::StreamSettings;
use crate::cli::GatewayArgs;
use crate::config::GatewayConfig;

#[test]
fn a_revoked_connection_is_closed_with_4403_and_any_other_reason_keeps_its_code() {
    assert_eq!(close_code(CloseReason::Revoked), 4403);
    assert_eq!(close_code(CloseReason::TokenExpired), 1008);
    assert_eq!(close_code(CloseReason::Fenced), 1013);
    assert_eq!(close_code(CloseReason::Idle), 1001);
}

#[test]
fn a_closed_or_broken_connection_leaves_nobody_to_tell() {
    assert_eq!(read_failure(&WsError::ConnectionClosed), Ending::Gone);
    assert_eq!(read_failure(&WsError::AlreadyClosed), Ending::Gone);
    assert_eq!(
        read_failure(&WsError::Io(std::io::Error::other("reset"))),
        Ending::Gone
    );
}

#[test]
fn a_frame_that_is_too_large_or_cannot_be_decoded_closes_with_4400() {
    let too_large = WsError::Capacity(CapacityError::MessageTooLong {
        size: 70 * 1024,
        max_size: 64 * 1024,
    });

    assert_eq!(
        read_failure(&too_large),
        Ending::Close(CLOSE_INVALID_MESSAGE, "invalid message")
    );
    assert_eq!(
        read_failure(&WsError::AttackAttempt),
        Ending::Close(CLOSE_INVALID_MESSAGE, "invalid message")
    );
}

#[test]
fn an_unknown_subprotocol_is_a_400_before_the_upgrade() {
    assert!(matches!(
        refused(Unacceptable::Subprotocol),
        Refusal::BadRequest(detail) if detail.contains("graphql-transport-ws")
    ));
    assert!(matches!(
        refused(Unacceptable::Handshake("no key")),
        Refusal::BadRequest("no key")
    ));
}

#[test]
fn the_default_settings_wait_five_seconds_for_connection_init() {
    assert_eq!(
        graphql_ws::SocketSettings::default().init_timeout,
        Duration::from_secs(5)
    );
}

#[test]
fn an_unavailable_pod_or_upstream_is_told_to_try_again_later() {
    assert_eq!(UNAVAILABLE, Ending::Close(1013, "try again later"));
}

const HOST: &str = "api.example.test";
const USER: &str = "3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a";

fn config() -> GatewayConfig {
    let mut args = GatewayArgs::default();
    args.service.app_env = Some("test".to_owned());
    args.service.tokens.public_keys_file = Some(DEVELOPMENT_PUBLIC_KEYS_FILE.to_owned());
    args.service.kafka.bootstrap_servers = Some("localhost:9092".to_owned());
    args.service.kafka.security_protocol = Some("PLAINTEXT".to_owned());
    GatewayConfig::from_args(&args).unwrap()
}

fn freshness() -> Arc<FreshnessState> {
    let clock = Arc::new(FakeBootClock::starting_at(BootInstant::from_elapsed(
        Duration::from_secs(100),
    )));
    let state = FreshnessState::new(
        FreshnessRule::new(Duration::from_secs(15), Duration::from_secs(2)),
        Arc::<FakeBootClock>::clone(&clock),
    );
    state.attach(
        FreshnessProof {
            taken_at: clock.now(),
            watermark: 1,
        },
        iam_domain::PolicyVersion::new(1).unwrap(),
    );
    Arc::new(state)
}

fn pipeline_over(view: Arc<dyn PolicyView>) -> Pipeline {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    from_config(
        &config(),
        view,
        freshness(),
        &clock,
        Arc::new(UnreachableUpstreams),
    )
    .unwrap()
}

fn with_streams(pipeline: Pipeline) -> Pipeline {
    pipeline.with_streams(Streams::new(
        StreamSettings {
            idle_timeout: Duration::from_mins(5),
            per_subject: 4,
        },
        Arc::new(SystemClock),
    ))
}

fn serving_view() -> Arc<dyn PolicyView> {
    Arc::new(CountingPolicyView::serving(GatewaySnapshot::at(
        iam_domain::PolicyVersion::new(1).unwrap(),
    )))
}

fn session(pipeline: Pipeline, path: &str) -> Session {
    let (parts, ()) = Request::get(path)
        .header("host", HOST)
        .body(())
        .unwrap()
        .into_parts();
    Session {
        subscriptions: SubscriptionAuthorizer::new(Arc::clone(&pipeline.authorizer)),
        pipeline,
        parts,
        host: HOST.to_owned(),
        protocol: Protocol::Transport,
    }
}

fn principal() -> Principal {
    let at = |seconds: u64| {
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds))
            .unwrap()
    };
    Principal::from(TokenIdentity::from(&AccessToken::new(AccessTokenParts {
        subject: SubjectId::User(Uuid::parse(USER).unwrap()),
        session: Some(SessionId::new("session-1").unwrap()),
        token_id: TokenId::new("jti-1").unwrap(),
        roles: vec!["ROLE_USER".to_owned()],
        issued_at: at(1_799_999_940),
        expires_at: at(1_800_000_900),
    })))
}

fn admission() -> Admission {
    Admission {
        principal: principal(),
        token: "token".to_owned(),
        target: UpstreamTarget::new(
            UpstreamName::new("orders").unwrap(),
            RouteId::from_uuid(Uuid::parse("00000000-0000-0000-0000-000000000001").unwrap()),
        ),
        forward_credentials: false,
        version: 1,
        record: StreamRecord {
            subject: None,
            session: None,
            required_keys: Vec::new(),
            scope: "global".to_owned(),
            token_expires_at: None,
            assignment_expires_at: None,
            version: 1,
            route: None,
            service: None,
        },
        grant: Grant {
            principal: None,
            host: HOST.to_owned(),
            method: HttpMethod::Get,
            path: "/graphql".to_owned(),
            operation: None,
        },
    }
}

fn operation() -> GraphQlOperation {
    GraphQlOperation {
        document: "subscription { orderUpdated }".to_owned(),
        operation_name: None,
    }
}

#[tokio::test]
async fn a_pipeline_without_streams_cannot_decide_an_operation() {
    let session = session(pipeline_over(serving_view()), "/graphql");

    let decided = session.decide(&admission(), operation()).await;

    assert_eq!(decided.err(), Some(CANNOT_DECIDE));
}

#[tokio::test]
async fn a_gateway_without_a_snapshot_cannot_decide_an_operation() {
    let view: Arc<dyn PolicyView> = Arc::new(CountingPolicyView::empty());
    let session = session(with_streams(pipeline_over(view)), "/graphql");

    let decided = session.decide(&admission(), operation()).await;

    assert_eq!(decided.err(), Some(CANNOT_DECIDE));
}

#[tokio::test]
async fn an_operation_on_a_path_that_breaks_the_path_rule_is_not_permitted() {
    let session = session(with_streams(pipeline_over(serving_view())), "/api/%zz");

    let decided = session.decide(&admission(), operation()).await;

    assert_eq!(decided.err(), Some(NOT_PERMITTED));
}

#[tokio::test]
async fn an_operation_on_a_route_the_snapshot_no_longer_holds_is_not_permitted() {
    let session = session(with_streams(pipeline_over(serving_view())), "/graphql");

    let decided = session.decide(&admission(), operation()).await;

    assert_eq!(decided.err(), Some(NOT_PERMITTED));
}

#[tokio::test]
async fn a_session_whose_upgrade_never_completes_ends_quietly() {
    let session = session(with_streams(pipeline_over(serving_view())), "/graphql");

    session
        .run(hyper::upgrade::on(Request::new(Body::empty())))
        .await;
}

#[tokio::test]
async fn a_request_that_cannot_be_upgraded_is_answered_400() {
    let pipeline = with_streams(pipeline_over(serving_view()));
    let request = Request::get("/graphql")
        .header("host", HOST)
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .header("sec-websocket-protocol", "graphql-transport-ws")
        .body(())
        .unwrap();
    let handshake = graphql_ws::accept(request.headers()).unwrap();
    let (parts, ()) = request.into_parts();

    let response = open(&pipeline, parts, &handshake);

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
