use std::time::Duration;

use axum::http::HeaderValue;
use http_body_util::BodyExt as _;
use iam_domain::HttpMethod;
use rstest::rstest;

use super::*;
use crate::bootstrap::gateway::streams::registry::{Grant, StreamRecord, StreamRegistry};

fn open(registry: &Arc<StreamRegistry>) -> Arc<StreamHandle> {
    let record = StreamRecord {
        subject: Some("user-1".to_owned()),
        session: None,
        required_keys: Vec::new(),
        scope: "global".to_owned(),
        token_expires_at: None,
        assignment_expires_at: None,
        version: 1,
        route: None,
        service: None,
    };
    let grant = Grant {
        principal: None,
        host: "api.example.test".to_owned(),
        method: HttpMethod::Get,
        path: "/events".to_owned(),
        operation: None,
    };
    Arc::new(registry.open(record, grant).unwrap())
}

/// A body that never yields a frame.
struct Silent;

impl HttpBody for Silent {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        Poll::Pending
    }
}

#[rstest]
#[case("text/event-stream", true)]
#[case("text/event-stream; charset=utf-8", true)]
#[case("Text/Event-Stream", true)]
#[case("application/json", false)]
#[case("text/plain", false)]
#[case("", false)]
fn only_an_event_stream_content_type_is_recognised(#[case] value: &str, #[case] expected: bool) {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_str(value).unwrap());

    assert_eq!(is_event_stream(&headers), expected);
}

#[test]
fn a_response_without_a_content_type_is_not_an_event_stream() {
    assert!(!is_event_stream(&HeaderMap::new()));
}

#[tokio::test]
async fn the_events_of_the_upstream_are_relayed_unchanged() {
    let registry = StreamRegistry::new(4);
    let handle = open(&registry);
    let response = Response::new(Body::from("data: hello\n\ndata: again\n\n"));

    let guarded = guard(response, handle);

    let body = guarded.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"data: hello\n\ndata: again\n\n");
}

#[tokio::test]
async fn the_stream_ends_when_the_registry_closes_it() {
    let registry = StreamRegistry::new(4);
    let handle = open(&registry);
    let id = handle.id();
    let guarded = guard(Response::new(Body::new(Silent)), handle);
    let collecting = tokio::spawn(async move { guarded.into_body().collect().await });

    tokio::task::yield_now().await;
    registry.close(id, CloseReason::Fenced);

    let collected = collecting.await.unwrap().unwrap();
    assert!(collected.to_bytes().is_empty());
}

#[tokio::test(start_paused = true)]
async fn every_frame_counts_as_traffic() {
    let registry = StreamRegistry::new(4);
    let handle = open(&registry);
    let activity = Arc::clone(handle.activity());
    let guarded = guard(Response::new(Body::from("data: x\n\n")), handle);

    tokio::time::advance(Duration::from_secs(40)).await;
    drop(guarded.into_body().collect().await.unwrap());

    assert_eq!(activity.idle_for(), Duration::ZERO);
}

#[tokio::test]
async fn the_stream_stays_registered_while_its_body_lives_and_leaves_with_it() {
    let registry = StreamRegistry::new(4);
    let handle = open(&registry);
    let guarded = guard(Response::new(Body::from("data: x\n\n")), handle);

    assert_eq!(registry.len(), 1);
    drop(guarded);

    assert!(registry.is_empty());
}
