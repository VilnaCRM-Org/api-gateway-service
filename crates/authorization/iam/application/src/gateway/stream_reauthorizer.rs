//! The re-authorization of open streams when a policy version is published (FR-61, Story 11.2).
//!
//! The apply thread hands every publication, with what the versions it covers touched, to the
//! [`ReevaluationBoard`] and goes on: the board only merges the change into the one that is
//! waiting, so applying and publishing later versions is never stalled. The
//! [`StreamReauthorizer`] runs on a task of its own, takes the waiting change and decides again
//! only the open streams it can affect:
//!
//! - a touched subject, a touched session, and the holders of a touched role (found through the
//!   reverse index of the published snapshot);
//! - the streams on a touched route and on the routes of a service whose catalogue changed;
//! - every stream, when the change holds a global cut-off or replaced the state as a whole.
//!
//! The board records the highest version whose re-evaluation has finished. The record moves up
//! only when no stream that was authorized on an older version is left undecided, so a stream
//! that registers while a version is being applied is decided against it before the version is
//! reported applied.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, PoisonError};

use iam_domain::{PolicyChange, PolicyTouch, PolicyVersion, PolicyView, RouteId, ServiceName};
use tokio::sync::{Notify, watch};

/// The record before any re-evaluation has finished.
const NOTHING_FINISHED: i64 = -1;

/// The publications that wait for their re-evaluation, and the record of the finished ones.
#[derive(Debug)]
pub struct ReevaluationBoard {
    waiting: Mutex<Option<PolicyChange>>,
    wake: Notify,
    finished: watch::Sender<i64>,
}

impl Default for ReevaluationBoard {
    fn default() -> Self {
        Self::new()
    }
}

impl ReevaluationBoard {
    /// A board with nothing waiting and nothing finished.
    #[must_use]
    pub fn new() -> Self {
        Self {
            waiting: Mutex::new(None),
            wake: Notify::new(),
            finished: watch::Sender::new(NOTHING_FINISHED),
        }
    }

    /// Hands a publication over. It never waits: a change that is still waiting absorbs this one,
    /// so the re-evaluation of a slow hook catches up in one pass.
    pub fn submit(&self, change: PolicyChange) {
        {
            let mut waiting = self.waiting.lock().unwrap_or_else(PoisonError::into_inner);
            match waiting.as_mut() {
                Some(held) => held.absorb(change),
                None => *waiting = Some(change),
            }
        }
        self.wake.notify_one();
    }

    /// Completes with the change that waits, or with the next one submitted.
    pub async fn next(&self) -> PolicyChange {
        loop {
            let taken = self
                .waiting
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            if let Some(change) = taken {
                return change;
            }
            self.wake.notified().await;
        }
    }

    /// The highest version whose re-evaluation has finished; `-1` before the first.
    #[must_use]
    pub fn finished(&self) -> i64 {
        *self.finished.borrow()
    }

    /// Records that the re-evaluation of `version` finished. The record never goes down.
    pub fn advance(&self, version: PolicyVersion) {
        let value = version.value();
        self.finished.send_if_modified(|held| {
            let moves = value > *held;
            if moves {
                *held = value;
            }
            moves
        });
    }

    /// Completes once the record has reached `version`.
    pub async fn reached(&self, version: PolicyVersion) {
        let mut record = self.finished.subscribe();
        drop(record.wait_for(|held| *held >= version.value()).await);
    }
}

/// Which open streams a change can affect.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StreamScope {
    /// Every stream.
    pub everything: bool,
    /// The streams of these subjects, written as the registry holds them: the bare user id or
    /// service name.
    pub subjects: BTreeSet<String>,
    /// The streams of these sessions.
    pub sessions: BTreeSet<String>,
    /// The streams on these routes.
    pub routes: BTreeSet<RouteId>,
    /// The streams on the routes of these services.
    pub services: BTreeSet<ServiceName>,
}

/// The open streams of the pod, as the re-authorization sees them.
#[async_trait::async_trait]
pub trait OpenStreams: std::fmt::Debug + Send + Sync {
    /// A point in the registration order: every stream registered before it has an id below it.
    fn mark(&self) -> u64;

    /// The ids of the open streams within `scope`.
    fn select(&self, scope: &StreamScope) -> Vec<u64>;

    /// Decides the stream again on the published snapshot, which holds `version` or a later one:
    /// a stream the policy no longer allows is closed, any other is recorded as decided against
    /// `version`.
    async fn reevaluate(&self, stream: u64, version: PolicyVersion);

    /// Records that every stream registered before `mark` and not waiting for its first check is
    /// decided against `version`: none of them is in the scope, so the change leaves them as they
    /// were.
    fn settle(&self, mark: u64, version: PolicyVersion);

    /// The ids of the streams that were authorized on a version below `version` and are not
    /// decided against it yet.
    fn lagging(&self, version: PolicyVersion) -> Vec<u64>;

    /// Moves the record of `board` to `version` when no stream lags behind it, as one step that
    /// no registration can interleave with. Whether the record moved.
    fn finish(&self, version: PolicyVersion, board: &ReevaluationBoard) -> bool;
}

/// Decides again the open streams that a published version affects.
#[derive(Debug)]
pub struct StreamReauthorizer {
    streams: Arc<dyn OpenStreams>,
    view: Arc<dyn PolicyView>,
    board: Arc<ReevaluationBoard>,
}

impl StreamReauthorizer {
    /// A re-authorization of `streams` that takes its changes from `board` and finds the holders
    /// of a role in the snapshot `view` publishes.
    #[must_use]
    pub fn new(
        streams: Arc<dyn OpenStreams>,
        view: Arc<dyn PolicyView>,
        board: Arc<ReevaluationBoard>,
    ) -> Self {
        Self {
            streams,
            view,
            board,
        }
    }

    /// The task name of the loop.
    #[must_use]
    pub const fn name() -> &'static str {
        "stream-reauthorizer"
    }

    /// Re-authorizes the changes of the board one after the other until the stop flag is set.
    pub async fn run(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        loop {
            tokio::select! {
                () = stopped(&mut shutdown) => return,
                change = self.board.next() => self.reauthorize(change).await,
            }
        }
    }

    /// Decides again the streams `change` affects, then records its version as finished.
    pub async fn reauthorize(&self, change: PolicyChange) {
        let version = change.version;
        let mark = self.streams.mark();
        let scope = self.scope_of(&change.touch);
        for stream in self.streams.select(&scope) {
            self.streams.reevaluate(stream, version).await;
        }
        self.streams.settle(mark, version);
        loop {
            for stream in self.streams.lagging(version) {
                self.streams.reevaluate(stream, version).await;
            }
            if self.streams.finish(version, &self.board) {
                break;
            }
        }
        log_finished(version, &scope);
    }

    /// The streams a touch can affect. Without a published snapshot the holders of a role are
    /// unknown, so every stream is decided again.
    fn scope_of(&self, touch: &PolicyTouch) -> StreamScope {
        let mut scope = StreamScope {
            everything: touch.touches_everything(),
            subjects: touch
                .subjects()
                .iter()
                .map(|subject| subject.id().to_string())
                .collect(),
            sessions: touch
                .sessions()
                .iter()
                .map(|session| session.as_str().to_owned())
                .collect(),
            routes: touch.routes().clone(),
            services: touch.services().clone(),
        };
        if touch.roles().is_empty() {
            return scope;
        }
        match self.view.current() {
            Some(snapshot) => {
                for role in touch.roles() {
                    scope.subjects.extend(
                        snapshot
                            .subjects_of_role(*role)
                            .iter()
                            .map(|subject| subject.id().to_string()),
                    );
                }
            }
            None => scope.everything = true,
        }
        scope
    }
}

/// Completes when the stop flag is set or its sender is gone.
async fn stopped(shutdown: &mut watch::Receiver<bool>) {
    drop(shutdown.wait_for(|stopping| *stopping).await);
}

fn log_finished(version: PolicyVersion, scope: &StreamScope) {
    let version = version.value();
    let everything = scope.everything;
    tracing::debug!(version, everything, "open streams decided again");
}

#[cfg(test)]
mod tests;
