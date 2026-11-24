//! The revocation view of the gateway: it reads the revocation sets of the published snapshot.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    PolicySnapshot, PolicyView, RepositoryError, RevocationStatus, RevocationView, SubjectId,
    TokenIdentity,
};

/// Why the snapshot cannot answer.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotRevocationError {
    /// No snapshot is published yet, so no revocation is known.
    #[error("no policy snapshot is published yet")]
    NoSnapshot,
    /// A stored cut-off holds a negative number of microseconds.
    #[error("a revocation record holds an instant before 1970")]
    InstantBeforeEpoch,
}

/// A policy view that always hands out the one snapshot it was given.
#[derive(Debug)]
struct PinnedSnapshot(Arc<dyn PolicySnapshot>);

impl PolicyView for PinnedSnapshot {
    fn current(&self) -> Option<Arc<dyn PolicySnapshot>> {
        Some(Arc::clone(&self.0))
    }
}

/// Answers `RevocationView::status` from the revocation sets of the current snapshot.
///
/// It reports whether the session of the token has a record, the cut-off of its user (none for a
/// service principal) and the global cut-off. A read costs a map lookup and no I/O.
#[derive(Debug)]
pub struct SnapshotRevocationView {
    policy: Arc<dyn PolicyView>,
}

impl SnapshotRevocationView {
    /// A view over the policy view that publishes the snapshot.
    #[must_use]
    pub fn new(policy: Arc<dyn PolicyView>) -> Self {
        Self { policy }
    }

    /// A view over `snapshot` itself, the one a request loaded: it never loads another, so the
    /// revocation check and the decision of the request read the same version.
    #[must_use]
    pub fn over(snapshot: Arc<dyn PolicySnapshot>) -> Self {
        Self::new(Arc::new(PinnedSnapshot(snapshot)))
    }

    fn read(&self, identity: &TokenIdentity) -> Result<RevocationStatus, RepositoryError> {
        let snapshot = self
            .policy
            .current()
            .ok_or_else(|| unavailable(SnapshotRevocationError::NoSnapshot))?;
        let session_revoked = identity
            .session()
            .is_some_and(|session| snapshot.session_revoked(session));
        let user_cutoff = match identity.subject() {
            SubjectId::User(user) => snapshot
                .user_cutoff(*user)
                .map(|state| instant(state.tokens_valid_after_micros))
                .transpose()?,
            SubjectId::Service(_) => None,
        };
        let global_cutoff = snapshot
            .global_cutoff()
            .map(|state| instant(state.tokens_valid_after_micros))
            .transpose()?;
        Ok(RevocationStatus {
            session_revoked,
            user_cutoff,
            global_cutoff,
        })
    }
}

/// The instant `micros` microseconds after 1970.
fn instant(micros: i64) -> Result<SystemTime, RepositoryError> {
    u64::try_from(micros)
        .ok()
        .and_then(|micros| SystemTime::UNIX_EPOCH.checked_add(Duration::from_micros(micros)))
        .ok_or_else(|| unavailable(SnapshotRevocationError::InstantBeforeEpoch))
}

fn unavailable(error: SnapshotRevocationError) -> RepositoryError {
    RepositoryError::Unavailable(Box::new(error))
}

#[async_trait::async_trait]
impl RevocationView for SnapshotRevocationView {
    async fn status(&self, identity: &TokenIdentity) -> Result<RevocationStatus, RepositoryError> {
        self.read(identity)
    }
}

#[cfg(test)]
mod tests;
