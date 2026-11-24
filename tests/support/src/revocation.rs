//! Revocation repository and revocation view doubles of the IAM context.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};

use async_trait::async_trait;
use iam_domain::{
    GlobalTokenCutoff, InboundEvent, RepositoryError, RevocationRepository, RevocationStatus,
    RevocationView, SessionId, SessionRevocation, SessionRevocationId, SessionRevocationSearch,
    SubjectId, TokenIdentity, UserTokenCutoff,
};
use shared_domain::Uuid;

/// The revocation state the repository double holds.
#[derive(Debug, Default)]
struct State {
    sessions: BTreeMap<SessionId, SessionRevocation>,
    users: BTreeMap<Uuid, UserTokenCutoff>,
    global: Option<GlobalTokenCutoff>,
    events: BTreeSet<Uuid>,
}

fn failure() -> RepositoryError {
    RepositoryError::Unavailable("in-memory repository failure".into())
}

/// A revocation repository that keeps the revocation state in memory.
///
/// It follows the rules of the PostgreSQL adapter: a revoked session keeps its first record,
/// cut-offs never move back and an event id is recorded once. It is also a [`RevocationView`]
/// over the same state.
#[derive(Debug, Default)]
pub struct FakeRevocationRepository {
    state: Mutex<State>,
    failing: AtomicBool,
}

impl FakeRevocationRepository {
    /// A repository with no revocation.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes every later call answer `Unavailable`, or answer normally again.
    pub fn fail(&self, failing: bool) {
        self.failing.store(failing, Ordering::Release);
    }

    fn with_state<T>(&self, change: impl FnOnce(&mut State) -> T) -> Result<T, RepositoryError> {
        if self.failing.load(Ordering::Acquire) {
            return Err(failure());
        }
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        Ok(change(&mut state))
    }
}

/// Whether `id` is the id of a record of another session.
fn id_taken(state: &State, revocation: &SessionRevocation) -> bool {
    state
        .sessions
        .values()
        .any(|stored| stored.id == revocation.id && stored.session != revocation.session)
}

#[async_trait]
impl RevocationRepository for FakeRevocationRepository {
    async fn revoke_session(&self, revocation: &SessionRevocation) -> Result<(), RepositoryError> {
        self.with_state(|state| {
            if id_taken(state, revocation) {
                return Err(RepositoryError::AlreadyExists);
            }
            state
                .sessions
                .entry(revocation.session.clone())
                .or_insert_with(|| revocation.clone());
            Ok(())
        })?
    }

    async fn set_user_cutoff(&self, cutoff: &UserTokenCutoff) -> Result<(), RepositoryError> {
        self.with_state(|state| {
            let moves_forward = state
                .users
                .get(&cutoff.user)
                .is_none_or(|stored| cutoff.tokens_valid_after > stored.tokens_valid_after);
            if moves_forward {
                state.users.insert(cutoff.user, cutoff.clone());
            }
        })
    }

    async fn set_global_cutoff(&self, cutoff: &GlobalTokenCutoff) -> Result<(), RepositoryError> {
        self.with_state(|state| {
            let moves_forward = state
                .global
                .as_ref()
                .is_none_or(|stored| cutoff.tokens_valid_after > stored.tokens_valid_after);
            if moves_forward {
                state.global = Some(cutoff.clone());
            }
        })
    }

    async fn session_revocation(
        &self,
        session: &SessionId,
    ) -> Result<Option<SessionRevocation>, RepositoryError> {
        self.with_state(|state| state.sessions.get(session).cloned())
    }

    async fn session_revocation_by_id(
        &self,
        id: SessionRevocationId,
    ) -> Result<Option<SessionRevocation>, RepositoryError> {
        self.with_state(|state| {
            state
                .sessions
                .values()
                .find(|stored| stored.id == id)
                .cloned()
        })
    }

    async fn search_session_revocations(
        &self,
        search: &SessionRevocationSearch,
    ) -> Result<Vec<SessionRevocation>, RepositoryError> {
        self.with_state(|state| {
            let mut found: Vec<&SessionRevocation> = state
                .sessions
                .values()
                .filter(|stored| search.matches(stored))
                .collect();
            found.sort_by_key(|stored| SessionRevocationSearch::order_key(stored));
            let cursor = search.after.and_then(|after| {
                state
                    .sessions
                    .values()
                    .find(|stored| stored.id == after)
                    .map(SessionRevocationSearch::order_key)
            });
            found
                .into_iter()
                .filter(|stored| {
                    cursor
                        .as_ref()
                        .is_none_or(|key| SessionRevocationSearch::order_key(stored) > *key)
                })
                .take(usize::try_from(search.limit).unwrap_or(usize::MAX))
                .cloned()
                .collect()
        })
    }

    async fn user_cutoff(&self, user: Uuid) -> Result<Option<UserTokenCutoff>, RepositoryError> {
        self.with_state(|state| state.users.get(&user).cloned())
    }

    async fn global_cutoff(&self) -> Result<Option<GlobalTokenCutoff>, RepositoryError> {
        self.with_state(|state| state.global.clone())
    }

    async fn record_inbound_event(&self, event: &InboundEvent) -> Result<bool, RepositoryError> {
        self.with_state(|state| state.events.insert(event.event_id))
    }
}

#[async_trait]
impl RevocationView for FakeRevocationRepository {
    async fn status(&self, identity: &TokenIdentity) -> Result<RevocationStatus, RepositoryError> {
        self.with_state(|state| RevocationStatus {
            session_revoked: identity
                .session()
                .is_some_and(|session| state.sessions.contains_key(session)),
            user_cutoff: match identity.subject() {
                SubjectId::User(user) => state
                    .users
                    .get(user)
                    .map(|cutoff| cutoff.tokens_valid_after),
                SubjectId::Service(_) => None,
            },
            global_cutoff: state
                .global
                .as_ref()
                .map(|cutoff| cutoff.tokens_valid_after),
        })
    }
}

/// A revocation view whose answer the test sets, and that counts its calls.
#[derive(Debug, Default)]
pub struct FakeRevocationView {
    status: Mutex<Option<RevocationStatus>>,
    unavailable: AtomicBool,
    calls: AtomicUsize,
}

impl FakeRevocationView {
    /// A view under which no token is revoked.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes every later call answer `status`.
    pub fn answer(&self, status: RevocationStatus) {
        *self.status.lock().unwrap_or_else(PoisonError::into_inner) = Some(status);
        self.unavailable.store(false, Ordering::Release);
    }

    /// Makes every later call answer `Unavailable`.
    pub fn fail(&self) {
        self.unavailable.store(true, Ordering::Release);
    }

    /// How many statuses were read.
    #[must_use]
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::Acquire)
    }
}

#[async_trait]
impl RevocationView for FakeRevocationView {
    async fn status(&self, _identity: &TokenIdentity) -> Result<RevocationStatus, RepositoryError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        if self.unavailable.load(Ordering::Acquire) {
            return Err(failure());
        }
        Ok(self
            .status
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .unwrap_or_default())
    }
}

#[cfg(test)]
mod tests;
