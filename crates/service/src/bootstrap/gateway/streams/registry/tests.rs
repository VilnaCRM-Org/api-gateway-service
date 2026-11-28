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
        route: None,
        service: None,
    }
}

fn grant() -> Grant {
    Grant {
        principal: None,
        host: "api.example.test".to_owned(),
        method: HttpMethod::Get,
        path: "/api/stream".to_owned(),
        operation: None,
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

fn route_id(route: u32) -> RouteId {
    RouteId::parse(&format!("0192f6a0-0000-7000-8000-{route:012x}")).unwrap()
}

fn on(route: u32, service: &str) -> StreamRecord {
    StreamRecord {
        route: Some(route_id(route)),
        service: Some(ServiceName::new(service).unwrap()),
        ..record(Some("user-1"), None)
    }
}

fn route_scope(route: u32) -> StreamScope {
    StreamScope {
        routes: [route_id(route)].into(),
        ..StreamScope::default()
    }
}

#[test]
fn the_streams_of_a_subject_or_a_session_are_selected_through_the_indexes() {
    let registry = StreamRegistry::new(8);
    let first = registry
        .open(record(Some("user-1"), Some("session-1")), grant())
        .unwrap();
    let second = registry
        .open(record(Some("user-2"), Some("session-2")), grant())
        .unwrap();
    let _third = registry
        .open(record(Some("user-3"), None), grant())
        .unwrap();

    let by_subject = StreamScope {
        subjects: ["user-1".to_owned(), "user-9".to_owned()].into(),
        ..StreamScope::default()
    };
    let by_session = StreamScope {
        sessions: ["session-2".to_owned()].into(),
        ..StreamScope::default()
    };

    assert_eq!(registry.select(&by_subject), vec![first.id()]);
    assert_eq!(registry.select(&by_session), vec![second.id()]);
    assert_eq!(registry.select(&StreamScope::default()), Vec::<u64>::new());
}

#[test]
fn a_stream_selected_twice_is_listed_once() {
    let registry = StreamRegistry::new(8);
    let held = registry
        .open(record(Some("user-1"), Some("session-1")), grant())
        .unwrap();
    let scope = StreamScope {
        subjects: ["user-1".to_owned()].into(),
        sessions: ["session-1".to_owned()].into(),
        ..StreamScope::default()
    };

    assert_eq!(registry.select(&scope), vec![held.id()]);
}

#[test]
fn the_streams_on_a_route_or_of_a_service_are_selected_by_a_scan() {
    let registry = StreamRegistry::new(8);
    let first = registry.open(on(1, "users"), grant()).unwrap();
    let second = registry.open(on(2, "orders"), grant()).unwrap();
    let _plain = registry.open(record(None, None), grant()).unwrap();
    let by_service = StreamScope {
        services: [ServiceName::new("orders").unwrap()].into(),
        ..StreamScope::default()
    };

    assert_eq!(registry.select(&route_scope(1)), vec![first.id()]);
    assert_eq!(registry.select(&by_service), vec![second.id()]);
}

#[test]
fn everything_selects_every_open_stream() {
    let registry = StreamRegistry::new(8);
    let first = registry.open(record(None, None), grant()).unwrap();
    let second = registry
        .open(record(Some("user-1"), None), grant())
        .unwrap();
    let scope = StreamScope {
        everything: true,
        ..StreamScope::default()
    };

    assert_eq!(registry.select(&scope), vec![first.id(), second.id()]);
}

#[test]
fn a_mark_lies_above_every_stream_registered_before_it() {
    let registry = StreamRegistry::new(8);
    let first = registry.open(record(None, None), grant()).unwrap();
    let mark = registry.mark();
    let second = registry.open(record(None, None), grant()).unwrap();

    assert!(first.id() < mark);
    assert!(second.id() >= mark);
}

#[test]
fn a_stream_lags_until_it_is_decided_against_the_version() {
    let registry = StreamRegistry::new(8);
    let held = registry.open(record(None, None), grant()).unwrap();

    assert!(
        registry.lagging(7).is_empty(),
        "the opening version is the record's"
    );
    assert_eq!(registry.lagging(8), vec![held.id()]);
    registry.evaluated(held.id(), 8);
    assert_eq!(registry.lagging(8), Vec::<u64>::new());
    registry.evaluated(held.id(), 3);
    assert!(
        registry.lagging(8).is_empty(),
        "the version never goes down"
    );
}

#[test]
fn settling_skips_the_streams_registered_after_the_mark_and_those_waiting_for_their_check() {
    let registry = StreamRegistry::new(8);
    let checked = registry.open(record(None, None), grant()).unwrap();
    registry.admitted(checked.id());
    let waiting = registry.open(record(None, None), grant()).unwrap();
    let mark = registry.mark();
    let later = registry.open(record(None, None), grant()).unwrap();
    registry.admitted(later.id());

    registry.settle(mark, 9);

    assert_eq!(registry.lagging(9), vec![waiting.id(), later.id()]);
}

#[test]
fn the_record_moves_only_when_no_stream_lags_and_never_down() {
    let registry = StreamRegistry::new(8);
    let board = ReevaluationBoard::new();
    let held = registry.open(record(None, None), grant()).unwrap();
    let version = |value| PolicyVersion::new(value).unwrap();

    assert!(!registry.finish(version(9), &board));
    assert_eq!(board.finished(), -1);
    registry.evaluated(held.id(), 9);
    assert!(registry.finish(version(9), &board));
    assert_eq!(board.finished(), 9);
    assert!(registry.finish(version(4), &board));
    assert_eq!(board.finished(), 9);
}

#[test]
fn the_grant_of_an_open_stream_is_found_and_that_of_a_closed_one_is_not() {
    let registry = StreamRegistry::new(8);
    let held = registry.open(record(None, None), grant()).unwrap();
    let id = held.id();

    assert_eq!(registry.grant(id).unwrap().path, "/api/stream");
    drop(held);
    assert!(registry.grant(id).is_none());
}

#[test]
fn deciding_a_stream_that_is_gone_changes_nothing() {
    let registry = StreamRegistry::new(8);

    registry.evaluated(5, 3);
    registry.admitted(5);

    assert!(registry.is_empty());
}

#[test]
fn an_operation_is_held_under_its_subject_and_counted_apart_from_the_streams() {
    let registry = StreamRegistry::new(1);
    let socket = registry
        .open(record(Some("user-1"), Some("session-1")), grant())
        .unwrap();

    let first = registry.open_operation(record(Some("user-1"), Some("session-1")), grant());
    let second = registry.open_operation(record(Some("user-1"), Some("session-1")), grant());

    assert_eq!(registry.len(), 3);
    assert_eq!(registry.operations(), 2);
    assert_eq!(registry.held_by_subject("user-1"), 3);
    assert_eq!(registry.held_by_session("session-1"), 3);
    drop(first);
    assert_eq!(registry.operations(), 1);
    drop(second);
    drop(socket);
    assert!(registry.is_empty());
}

#[test]
fn operations_do_not_use_up_the_stream_cap_of_their_subject() {
    let registry = StreamRegistry::new(1);
    let _first = registry.open_operation(record(Some("user-1"), None), grant());
    let _second = registry.open_operation(record(Some("user-1"), None), grant());

    let socket = registry.open(record(Some("user-1"), None), grant());
    let refused = registry.open(record(Some("user-1"), None), grant());

    assert!(socket.is_ok());
    assert_eq!(refused.unwrap_err(), SubjectAtCap);
}

#[test]
fn an_operation_is_beyond_the_stream_cap_even_when_the_subject_is_at_it() {
    let registry = StreamRegistry::new(1);
    let _socket = registry
        .open(record(Some("user-1"), None), grant())
        .unwrap();

    let operation = registry.open_operation(record(Some("user-1"), None), grant());

    assert_eq!(registry.operations(), 1);
    drop(operation);
}

#[test]
fn a_scope_that_names_the_subject_selects_its_operations_too() {
    let registry = StreamRegistry::new(4);
    let socket = registry
        .open(record(Some("user-1"), None), grant())
        .unwrap();
    let operation = registry.open_operation(record(Some("user-1"), None), grant());
    let _other = registry.open_operation(record(Some("user-2"), None), grant());
    let scope = StreamScope {
        subjects: ["user-1".to_owned()].into(),
        ..StreamScope::default()
    };

    let selected = registry.select(&scope);

    assert_eq!(selected, vec![socket.id(), operation.id()]);
}

#[test]
fn the_scan_sees_which_entries_are_operations() {
    let registry = StreamRegistry::new(4);
    let _socket = registry
        .open(record(Some("user-1"), None), grant())
        .unwrap();
    let _operation = registry.open_operation(record(Some("user-1"), None), grant());

    let watched = registry.watched();

    assert_eq!(
        watched
            .iter()
            .map(|entry| entry.operation)
            .collect::<Vec<_>>(),
        vec![false, true]
    );
}
