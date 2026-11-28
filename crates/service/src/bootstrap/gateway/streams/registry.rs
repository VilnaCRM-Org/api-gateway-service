//! The stream registry (Story 11.1, FR-61): every open WebSocket and SSE stream of the pod, with
//! what authorized it, indexed by subject and by session.
//!
//! A stream is registered before it is forwarded, so a subject at its cap is refused before any
//! upgrade. The registry never closes a socket itself: [`StreamRegistry::close`] removes the entry
//! and tells the task that serves the stream, through the watch channel of its [`StreamHandle`],
//! why it must end.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};

use iam_application::{Principal, ReevaluationBoard, StreamScope};
use iam_domain::{HttpMethod, PolicyVersion, RouteId, ServiceName};
use tokio::sync::watch;
use tokio::time::Instant;

use crate::bootstrap::gateway::edge::SubjectClaims;

/// Why the gateway ends a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    /// The token of the stream expired.
    TokenExpired,
    /// The stream was decided again and the policy no longer allows it.
    Revoked,
    /// The pod fenced, went unready for staleness, or its proof is older than the hard bound.
    Fenced,
    /// No traffic for `STREAM_IDLE_TIMEOUT`.
    Idle,
}

impl CloseReason {
    /// The WebSocket close code of the reason: 1008 (policy violation) for a token or a policy
    /// that ended, 1013 (try again later) for a pod that may not serve, 1001 (going away) for an
    /// idle stream.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::TokenExpired | Self::Revoked => 1008,
            Self::Fenced => 1013,
            Self::Idle => 1001,
        }
    }

    /// The name of the reason in the logs.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::TokenExpired => "token_expired",
            Self::Revoked => "revoked",
            Self::Fenced => "fenced",
            Self::Idle => "idle",
        }
    }
}

/// What the registry holds about a stream: what authorized it and until when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamRecord {
    /// The subject that opened the stream; `None` on a route flagged `anonymous`.
    pub subject: Option<String>,
    /// The session of the token, when it names one.
    pub session: Option<String>,
    /// The permission keys the opening request required.
    pub required_keys: Vec<String>,
    /// The scope the keys were held in; the opening request names no project, so `global`.
    pub scope: String,
    /// When the token expires; `None` without a token.
    pub token_expires_at: Option<SystemTime>,
    /// The earliest expiry of the assignments that authorized the stream; `None` when none of
    /// them expires.
    pub assignment_expires_at: Option<SystemTime>,
    /// The version of the snapshot that authorized the stream.
    pub version: i64,
    /// The route the stream was opened on, which a change of the route decides again.
    pub route: Option<RouteId>,
    /// The service of that route, which a change of its catalogue decides again.
    pub service: Option<ServiceName>,
}

/// What the pipeline needs to decide a stream again on a later snapshot.
#[derive(Debug, Clone)]
pub struct Grant {
    /// The caller the token proved; `None` on a route flagged `anonymous`.
    pub principal: Option<Principal>,
    /// The host of the opening request, in lower case and without a port.
    pub host: String,
    /// The method of the opening request.
    pub method: HttpMethod,
    /// The path of the opening request.
    pub path: String,
}

/// When a stream last carried traffic, on the clock of tokio so that a test can pause it.
#[derive(Debug)]
pub struct Activity {
    origin: Instant,
    last_ms: AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Self {
            origin: Instant::now(),
            last_ms: AtomicU64::new(0),
        }
    }

    /// Notes that traffic flowed now.
    pub fn touch(&self) {
        let elapsed = Instant::now().saturating_duration_since(self.origin);
        let millis = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        self.last_ms.store(millis, Ordering::Relaxed);
    }

    /// How long the stream has carried no traffic.
    #[must_use]
    pub fn idle_for(&self) -> Duration {
        let last = Duration::from_millis(self.last_ms.load(Ordering::Relaxed));
        Instant::now()
            .saturating_duration_since(self.origin)
            .saturating_sub(last)
    }
}

/// The subject is at the most streams it may hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the subject holds the most streams it may")]
pub struct SubjectAtCap;

#[derive(Debug)]
struct Entry {
    record: StreamRecord,
    grant: Grant,
    close: watch::Sender<Option<CloseReason>>,
    activity: Arc<Activity>,
    /// The version the stream was last decided against: the one that authorized it, until a
    /// published version decides it again.
    evaluated: i64,
    /// Whether the stream still waits for the check that follows its registration.
    pending: bool,
}

#[derive(Debug, Default)]
struct State {
    entries: BTreeMap<u64, Entry>,
    by_subject: HashMap<String, BTreeSet<u64>>,
    by_session: HashMap<String, BTreeSet<u64>>,
}

impl State {
    fn insert(&mut self, id: u64, entry: Entry) {
        if let Some(subject) = entry.record.subject.as_ref() {
            self.by_subject
                .entry(subject.clone())
                .or_default()
                .insert(id);
        }
        if let Some(session) = entry.record.session.as_ref() {
            self.by_session
                .entry(session.clone())
                .or_default()
                .insert(id);
        }
        self.entries.insert(id, entry);
    }

    fn remove(&mut self, id: u64) -> Option<Entry> {
        let entry = self.entries.remove(&id)?;
        if let Some(subject) = entry.record.subject.as_ref() {
            unindex(&mut self.by_subject, subject, id);
        }
        if let Some(session) = entry.record.session.as_ref() {
            unindex(&mut self.by_session, session, id);
        }
        Some(entry)
    }
}

fn unindex(index: &mut HashMap<String, BTreeSet<u64>>, key: &str, id: u64) {
    if let Some(ids) = index.get_mut(key) {
        ids.remove(&id);
        if ids.is_empty() {
            index.remove(key);
        }
    }
}

/// One stream as the scan of the registry sees it.
#[derive(Debug, Clone)]
pub struct Watched {
    /// The id of the stream in the registry.
    pub id: u64,
    /// When the token expires.
    pub token_expires_at: Option<SystemTime>,
    /// The earliest expiry of the assignments behind the stream.
    pub assignment_expires_at: Option<SystemTime>,
    /// When the stream last carried traffic.
    pub activity: Arc<Activity>,
    /// What decides the stream again.
    pub grant: Grant,
}

/// Every open stream of the pod.
#[derive(Debug)]
pub struct StreamRegistry {
    per_subject: usize,
    next: AtomicU64,
    state: Mutex<State>,
}

fn locked(state: &Mutex<State>) -> MutexGuard<'_, State> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

impl StreamRegistry {
    /// An empty registry in which one subject holds at most `per_subject` streams.
    #[must_use]
    pub fn new(per_subject: usize) -> Arc<Self> {
        Arc::new(Self {
            per_subject,
            next: AtomicU64::new(0),
            state: Mutex::new(State::default()),
        })
    }

    /// Registers a stream. A subject that already holds `per_subject` streams is refused; a stream
    /// without a subject is never limited.
    ///
    /// # Errors
    ///
    /// [`SubjectAtCap`] when the subject holds the most streams it may.
    pub fn open(
        self: &Arc<Self>,
        record: StreamRecord,
        grant: Grant,
    ) -> Result<StreamHandle, SubjectAtCap> {
        let mut state = locked(&self.state);
        let held = record
            .subject
            .as_ref()
            .and_then(|subject| state.by_subject.get(subject))
            .map_or(0, BTreeSet::len);
        if record.subject.is_some() && held >= self.per_subject {
            return Err(SubjectAtCap);
        }
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let evaluated = record.version;
        let (close, closed) = watch::channel(None);
        let activity = Arc::new(Activity::new());
        let entry = Entry {
            record,
            grant,
            close,
            activity: Arc::clone(&activity),
            evaluated,
            pending: true,
        };
        state.insert(id, entry);
        drop(state);
        Ok(StreamHandle {
            registry: Arc::clone(self),
            id,
            closed,
            activity,
            claims: None,
        })
    }

    /// How many streams are open.
    #[must_use]
    pub fn len(&self) -> usize {
        locked(&self.state).entries.len()
    }

    /// Whether no stream is open.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// How many streams `subject` holds.
    #[must_use]
    pub fn held_by_subject(&self, subject: &str) -> usize {
        locked(&self.state)
            .by_subject
            .get(subject)
            .map_or(0, BTreeSet::len)
    }

    /// How many streams `session` holds.
    #[must_use]
    pub fn held_by_session(&self, session: &str) -> usize {
        locked(&self.state)
            .by_session
            .get(session)
            .map_or(0, BTreeSet::len)
    }

    /// The record of the stream `id`, when it is open.
    #[must_use]
    pub fn record(&self, id: u64) -> Option<StreamRecord> {
        locked(&self.state)
            .entries
            .get(&id)
            .map(|entry| entry.record.clone())
    }

    /// Every open stream, for the scan.
    #[must_use]
    pub fn watched(&self) -> Vec<Watched> {
        locked(&self.state)
            .entries
            .iter()
            .map(|(id, entry)| Watched {
                id: *id,
                token_expires_at: entry.record.token_expires_at,
                assignment_expires_at: entry.record.assignment_expires_at,
                activity: Arc::clone(&entry.activity),
                grant: entry.grant.clone(),
            })
            .collect()
    }

    /// A point in the registration order: every stream registered so far has an id below it.
    #[must_use]
    pub fn mark(&self) -> u64 {
        // The counter moves under the lock of the state in `open`, so reading it there orders
        // this mark against every registration.
        let _state = locked(&self.state);
        self.next.load(Ordering::Relaxed)
    }

    /// The grant of the stream `id`, when it is open.
    #[must_use]
    pub fn grant(&self, id: u64) -> Option<Grant> {
        locked(&self.state)
            .entries
            .get(&id)
            .map(|entry| entry.grant.clone())
    }

    /// The ids of the open streams within `scope`. The subjects and the sessions come from their
    /// indexes; a route or a service is a scan, because a change of one is rare.
    #[must_use]
    pub fn select(&self, scope: &StreamScope) -> Vec<u64> {
        let state = locked(&self.state);
        if scope.everything {
            return state.entries.keys().copied().collect();
        }
        let mut ids: BTreeSet<u64> = BTreeSet::new();
        for subject in &scope.subjects {
            ids.extend(state.by_subject.get(subject).into_iter().flatten());
        }
        for session in &scope.sessions {
            ids.extend(state.by_session.get(session).into_iter().flatten());
        }
        if !scope.routes.is_empty() || !scope.services.is_empty() {
            ids.extend(state.entries.iter().filter_map(|(id, entry)| {
                let on_route = entry
                    .record
                    .route
                    .is_some_and(|route| scope.routes.contains(&route));
                let of_service = entry
                    .record
                    .service
                    .as_ref()
                    .is_some_and(|service| scope.services.contains(service));
                (on_route || of_service).then_some(*id)
            }));
        }
        drop(state);
        ids.into_iter().collect()
    }

    /// Records that the stream `id` was decided against `version` and no longer waits for the
    /// check that follows its registration. The version never goes down.
    pub fn evaluated(&self, id: u64, version: i64) {
        if let Some(entry) = locked(&self.state).entries.get_mut(&id) {
            entry.evaluated = entry.evaluated.max(version);
            entry.pending = false;
        }
    }

    /// Records that the stream `id` needs no decision beyond the one that authorized it: the
    /// check that follows its registration found the published version no higher.
    pub fn admitted(&self, id: u64) {
        if let Some(entry) = locked(&self.state).entries.get_mut(&id) {
            entry.pending = false;
        }
    }

    /// Records that every stream registered before `mark` that has passed its first check is
    /// decided against `version`.
    pub fn settle(&self, mark: u64, version: i64) {
        for (_id, entry) in locked(&self.state).entries.range_mut(..mark) {
            if !entry.pending {
                entry.evaluated = entry.evaluated.max(version);
            }
        }
    }

    /// The ids of the streams that were not decided against `version` yet.
    #[must_use]
    pub fn lagging(&self, version: i64) -> Vec<u64> {
        locked(&self.state)
            .entries
            .iter()
            .filter(|(_id, entry)| entry.evaluated < version)
            .map(|(id, _entry)| *id)
            .collect()
    }

    /// Moves the record of `board` to `version` when every stream is decided against it. The
    /// check and the move happen under the lock of the registry, so no registration falls
    /// between them. Whether the record moved.
    pub fn finish(&self, version: PolicyVersion, board: &ReevaluationBoard) -> bool {
        let state = locked(&self.state);
        let lagging = state
            .entries
            .values()
            .any(|entry| entry.evaluated < version.value());
        if !lagging {
            board.advance(version);
        }
        drop(state);
        !lagging
    }

    /// Replaces the earliest assignment expiry of the stream `id` after it was decided again.
    pub fn renew(&self, id: u64, assignment_expires_at: Option<SystemTime>) {
        if let Some(entry) = locked(&self.state).entries.get_mut(&id) {
            entry.record.assignment_expires_at = assignment_expires_at;
        }
    }

    /// Removes the stream `id` and tells its task to end for `reason`.
    pub fn close(&self, id: u64, reason: CloseReason) {
        let removed = locked(&self.state).remove(id);
        if let Some(entry) = removed {
            log_closed(&entry.record, reason);
            entry.close.send_replace(Some(reason));
        }
    }

    /// Closes every open stream for `reason`.
    pub fn close_all(&self, reason: CloseReason) {
        let ids: Vec<u64> = locked(&self.state).entries.keys().copied().collect();
        for id in ids {
            self.close(id, reason);
        }
    }

    fn release(&self, id: u64) {
        drop(locked(&self.state).remove(id));
    }
}

/// The registration of one stream. Dropping it removes the stream from the registry, and so does
/// the end of the connection: the handle lives as long as the task or the body that serves it.
#[derive(Debug)]
pub struct StreamHandle {
    registry: Arc<StreamRegistry>,
    id: u64,
    closed: watch::Receiver<Option<CloseReason>>,
    activity: Arc<Activity>,
    claims: Option<Arc<SubjectClaims>>,
}

impl StreamHandle {
    /// The id of the stream in the registry.
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// When the stream last carried traffic.
    #[must_use]
    pub const fn activity(&self) -> &Arc<Activity> {
        &self.activity
    }

    /// Keeps the connection slots of the subject held for as long as the stream lives, so that
    /// the per-subject connection cap of Story 10.9 bounds the streams too.
    pub fn hold(&mut self, claims: Arc<SubjectClaims>) {
        self.claims = Some(claims);
    }

    /// Completes with the reason when the registry closes the stream; never when the stream
    /// ends first.
    pub fn closed(&self) -> impl Future<Output = CloseReason> + Send + use<> {
        let mut closed = self.closed.clone();
        async move {
            let reason = closed.wait_for(Option::is_some).await.map(|held| *held);
            match reason {
                Ok(reason) => reason.unwrap_or(CloseReason::Fenced),
                Err(_gone) => std::future::pending().await,
            }
        }
    }
}

impl Drop for StreamHandle {
    fn drop(&mut self) {
        self.registry.release(self.id);
    }
}

fn log_closed(record: &StreamRecord, reason: CloseReason) {
    let subject = record.subject.as_deref().unwrap_or_default();
    let session = record.session.as_deref().unwrap_or_default();
    let reason = reason.label();
    tracing::info!(
        subject,
        session,
        version = record.version,
        reason,
        "stream closed by the gateway"
    );
}

#[cfg(test)]
mod tests;
