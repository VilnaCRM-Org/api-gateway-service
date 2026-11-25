use super::*;

/// Reads a body to its end and returns the bytes.
async fn drain(mut body: ReplayBody) -> Result<Vec<u8>, BodyError> {
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame?.into_data() {
            bytes.extend_from_slice(&data);
        }
    }
    Ok(bytes)
}

/// A body that hands out its chunks one by one and declares no length.
#[derive(Debug)]
struct Chunked(Vec<&'static str>);

impl HttpBody for Chunked {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        Poll::Ready((!self.0.is_empty()).then(|| Ok(Frame::data(Bytes::from(self.0.remove(0))))))
    }
}

/// A body that declares eight bytes and fails when it is read.
#[derive(Debug)]
struct Failing;

impl HttpBody for Failing {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        Poll::Ready(Some(Err("the caller went away".into())))
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(8)
    }
}

#[tokio::test]
async fn a_body_that_fails_while_it_is_buffered_is_an_upstream_failure() {
    let outcome = Payload::prepare(Body::new(Failing), 100, true).await;

    assert_eq!(outcome.unwrap_err(), ForwardError::Upstream);
}

#[tokio::test]
async fn a_request_without_a_body_has_an_empty_payload() {
    let payload = Payload::prepare(Body::empty(), 100, true).await.unwrap();

    assert_eq!(payload.kind(), RequestBody::Empty);
    assert!(payload.replayable());
    assert!(payload.body().is_end_stream());
    assert_eq!(payload.body().size_hint().exact(), Some(0));
    assert_eq!(drain(payload.body()).await.unwrap(), b"");
}

#[tokio::test]
async fn a_small_body_of_a_retryable_request_is_buffered_and_sent_whole_every_time() {
    let payload = Payload::prepare(Body::from("hello"), 100, true)
        .await
        .unwrap();

    assert_eq!(payload.kind(), RequestBody::Buffered(5));
    assert!(payload.replayable());
    assert_eq!(payload.body().size_hint().exact(), Some(5));
    assert_eq!(drain(payload.body()).await.unwrap(), b"hello");
    assert_eq!(drain(payload.body()).await.unwrap(), b"hello");
}

#[tokio::test]
async fn a_buffered_body_above_the_limit_of_the_route_is_refused() {
    let outcome = Payload::prepare(Body::from("hello"), 4, true).await;

    assert_eq!(outcome.unwrap_err(), ForwardError::BodyTooLarge);
}

#[tokio::test]
async fn a_body_that_is_not_to_be_retried_is_streamed_even_when_small() {
    let payload = Payload::prepare(Body::from("hello"), 100, false)
        .await
        .unwrap();

    assert_eq!(payload.kind(), RequestBody::Streamed);
}

#[tokio::test]
async fn a_body_at_the_buffer_size_is_streamed_and_one_below_it_is_buffered() {
    let size = usize::try_from(MAX_BUFFERED_BODY_BYTES).unwrap();
    let below = Payload::prepare(Body::from(vec![0_u8; size - 1]), u64::MAX, true)
        .await
        .unwrap();
    let at = Payload::prepare(Body::from(vec![0_u8; size]), u64::MAX, true)
        .await
        .unwrap();

    assert_eq!(
        below.kind(),
        RequestBody::Buffered(MAX_BUFFERED_BODY_BYTES - 1)
    );
    assert_eq!(at.kind(), RequestBody::Streamed);
}

#[tokio::test]
async fn a_body_of_unknown_length_is_streamed() {
    let payload = Payload::prepare(Body::new(Chunked(vec!["a", "b"])), 100, true)
        .await
        .unwrap();

    assert_eq!(payload.kind(), RequestBody::Streamed);
}

#[tokio::test]
async fn a_streamed_body_can_be_sent_again_until_an_attempt_reads_it() {
    let payload = Payload::prepare(Body::new(Chunked(vec!["a", "b"])), 100, true)
        .await
        .unwrap();
    assert!(payload.replayable());
    let _unread = payload.body();
    assert!(payload.replayable());

    let first = drain(payload.body()).await.unwrap();

    assert_eq!(first, b"ab");
    assert!(!payload.replayable());
}

#[tokio::test]
async fn a_streamed_body_fails_above_the_limit_of_the_route() {
    let payload = Payload::prepare(Body::new(Chunked(vec!["abc", "def"])), 4, true)
        .await
        .unwrap();

    let error = drain(payload.body()).await.unwrap_err();

    assert!(error.is::<LengthLimitError>());
}

#[tokio::test]
async fn a_streamed_body_reports_the_length_that_the_caller_declared() {
    let payload = Payload::prepare(Body::from("hello"), 100, false)
        .await
        .unwrap();

    let body = payload.body();

    assert_eq!(body.size_hint().exact(), Some(5));
    assert!(!body.is_end_stream());
}
