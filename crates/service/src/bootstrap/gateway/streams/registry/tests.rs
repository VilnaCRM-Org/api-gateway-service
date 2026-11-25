use std::time::Duration;

use super::*;

fn record(subject: Option<&str>, session: Option<&str>) -> StreamRecord {
    StreamRecord {
        subject: subject.map(str::to_owned),
        session: session.map(str::to_owned),
        required_keys: vec!["rest:users:GET /api/stream".to_owned()],
        scope: "global".to_owned(),
        token_expires_at: None,
        assignment_expires_at: None,
        version: 7,
    }
}

fn grant() -> Grant {
    Grant {
        principal: None,
        host: "api.example.test".to_owned(),
        method: HttpMethod::Get,
        path: "/api/stream".to_owned(),
    }
}

#[test]
fn a_stream_is_held_under_its_subject_and_its_session() {
    let registry = StreamRegistry::new(4);

    let first = registry
        .open(record(Some("user-1"), Some("session-1")), grant())
        .unwrap();
    let second = registry
        .open(record(Some("user-1"), Some("session-2")), grant())
        .unwrap();

    assert_eq!(registry.len(), 2);
    assert_eq!(registry.held_by_subject("user-1"), 2);
    assert_eq!(registry.held_by_session("session-1"), 1);
    assert_eq!(registry.held_by_session("session-2"), 1);
    assert_eq!(registry.record(first.id()).unwrap().version, 7);
    drop(second);
    assert_eq!(registry.held_by_subject("user-1"), 1);
    assert_eq!(registry.held_by_session("session-2"), 0);
}

#[test]
fn dropping_the_handle_removes_the_stream() {
    let registry = StreamRegistry::new(4);
    let handle = registry
        .open(record(Some("user-1"), None), grant())
        .unwrap();

    drop(handle);

    assert!(registry.is_empty());
    assert_eq!(registry.held_by_subject("user-1"), 0);
}

#[test]
fn a_subject_at_its_cap_is_refused_and_another_subject_is_not() {
    let registry = StreamRegistry::new(1);
    let held = registry
        .open(record(Some("user-1"), None), grant())
        .unwrap();

    let refused = registry.open(record(Some("user-1"), None), grant());
    let other = registry.open(record(Some("user-2"), None), grant());

    assert_eq!(refused.unwrap_err(), SubjectAtCap);
    assert!(other.is_ok());
    assert_eq!(registry.len(), 2);
    drop(held);
}

#[test]
fn a_stream_without_a_subject_is_never_limited() {
    let registry = StreamRegistry::new(1);

    let first = registry.open(record(None, None), grant()).unwrap();
    let second = registry.open(record(None, None), grant()).unwrap();

    assert_eq!(registry.len(), 2);
    drop((first, second));
}

#[tokio::test]
async fn closing_a_stream_removes_it_and_tells_its_task_why() {
    let registry = StreamRegistry::new(4);
    let handle = registry
        .open(record(Some("user-1"), Some("session-1")), grant())
        .unwrap();
    let closed = handle.closed();

    registry.close(handle.id(), CloseReason::Revoked);

    assert_eq!(closed.await, CloseReason::Revoked);
    assert!(registry.is_empty());
    assert_eq!(registry.held_by_session("session-1"), 0);
}

#[tokio::test]
async fn a_reason_that_was_set_before_the_wait_still_arrives() {
    let registry = StreamRegistry::new(4);
    let handle = registry.open(record(None, None), grant()).unwrap();

    registry.close_all(CloseReason::Fenced);

    assert_eq!(handle.closed().await, CloseReason::Fenced);
}

#[test]
fn closing_a_stream_twice_changes_nothing() {
    let registry = StreamRegistry::new(4);
    let handle = registry.open(record(None, None), grant()).unwrap();

    registry.close(handle.id(), CloseReason::Idle);
    registry.close(handle.id(), CloseReason::Revoked);

    assert!(registry.is_empty());
}

#[test]
fn closing_every_stream_empties_the_registry() {
    let registry = StreamRegistry::new(4);
    let first = registry.open(record(Some("a"), None), grant()).unwrap();
    let second = registry.open(record(Some("b"), None), grant()).unwrap();

    registry.close_all(CloseReason::Fenced);

    assert!(registry.is_empty());
    drop((first, second));
}

#[test]
fn renewing_a_stream_replaces_its_assignment_expiry() {
    let registry = StreamRegistry::new(4);
    let handle = registry
        .open(record(Some("user-1"), None), grant())
        .unwrap();
    let later = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(90))
        .unwrap();

    registry.renew(handle.id(), Some(later));

    assert_eq!(
        registry.record(handle.id()).unwrap().assignment_expires_at,
        Some(later)
    );
    assert_eq!(registry.watched()[0].assignment_expires_at, Some(later));
}

#[test]
fn each_close_reason_has_its_websocket_code_and_name() {
    let codes: Vec<(u16, &str)> = [
        CloseReason::TokenExpired,
        CloseReason::Revoked,
        CloseReason::Fenced,
        CloseReason::Idle,
    ]
    .into_iter()
    .map(|reason| (reason.code(), reason.label()))
    .collect();

    assert_eq!(
        codes,
        vec![
            (1008, "token_expired"),
            (1008, "revoked"),
            (1013, "fenced"),
            (1001, "idle"),
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn the_idle_time_counts_from_the_last_traffic() {
    let registry = StreamRegistry::new(4);
    let handle = registry.open(record(None, None), grant()).unwrap();

    tokio::time::advance(Duration::from_secs(30)).await;
    assert_eq!(handle.activity().idle_for(), Duration::from_secs(30));
    handle.activity().touch();
    tokio::time::advance(Duration::from_secs(5)).await;

    assert_eq!(handle.activity().idle_for(), Duration::from_secs(5));
}

#[derive(Clone, Default)]
struct Written(Arc<Mutex<Vec<u8>>>);

impl Written {
    fn text(&self) -> String {
        let bytes = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

impl std::io::Write for Written {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for Written {
    type Writer = Self;

    fn make_writer(&'writer self) -> Self {
        self.clone()
    }
}

fn debug_logs() -> (tracing::subscriber::DefaultGuard, Written) {
    let written = Written::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(written.clone())
        .finish();
    (tracing::subscriber::set_default(subscriber), written)
}

#[test]
fn closing_a_stream_logs_its_subject_session_version_and_reason() {
    let (_guard, written) = debug_logs();
    let registry = StreamRegistry::new(4);
    let handle = registry
        .open(record(Some("user-1"), Some("session-1")), grant())
        .unwrap();

    registry.close(handle.id(), CloseReason::Fenced);

    let text = written.text();
    assert!(text.contains("stream closed by the gateway"), "{text}");
    assert!(text.contains("subject=\"user-1\""), "{text}");
    assert!(text.contains("session=\"session-1\""), "{text}");
    assert!(text.contains("version=7"), "{text}");
    assert!(registry.is_empty());
}

#[test]
fn a_key_that_was_never_indexed_leaves_the_index_as_it_is() {
    let mut index = HashMap::from([("user-1".to_owned(), BTreeSet::from([1_u64]))]);

    unindex(&mut index, "user-2", 1);

    assert_eq!(index.len(), 1);
}

#[tokio::test(start_paused = true)]
async fn a_stream_that_ended_before_it_was_closed_never_reports_a_reason() {
    let registry = StreamRegistry::new(4);
    let handle = registry.open(record(None, None), grant()).unwrap();
    let closed = handle.closed();

    drop(handle);

    let waited = tokio::time::timeout(Duration::from_secs(60), closed).await;
    assert!(waited.is_err());
}

#[test]
fn renewing_a_stream_that_is_gone_changes_nothing() {
    let registry = StreamRegistry::new(4);

    registry.renew(99, None);

    assert!(registry.is_empty());
}
