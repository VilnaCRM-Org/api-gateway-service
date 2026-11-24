//! Repository port of the revocation state and of the consumed User service events.

use shared_domain::Uuid;

use crate::port::RepositoryError;
use crate::revocation::global_token_cutoff::GlobalTokenCutoff;
use crate::revocation::inbound_event::InboundEvent;
use crate::revocation::session_revocation::SessionRevocation;
use crate::revocation::session_revocation_search::SessionRevocationSearch;
use crate::revocation::user_token_cutoff::UserTokenCutoff;
use crate::value_object::identifier::SessionRevocationId;
use crate::value_object::session_id::SessionId;

/// Writes and reads session revocations, user and global cut-offs, and records consumed events
/// once per event id.
#[async_trait::async_trait]
pub trait RevocationRepository: std::fmt::Debug + Send + Sync {
    /// Records a session revocation; a session that is already revoked keeps its first record.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::AlreadyExists`] when another session's record has the same id, and
    /// [`RepositoryError::Unavailable`] when the storage fails.
    async fn revoke_session(&self, revocation: &SessionRevocation) -> Result<(), RepositoryError>;

    /// Sets the user's cut-off; a cut-off never moves back.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails.
    async fn set_user_cutoff(&self, cutoff: &UserTokenCutoff) -> Result<(), RepositoryError>;

    /// Sets the global cut-off; it never moves back.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails.
    async fn set_global_cutoff(&self, cutoff: &GlobalTokenCutoff) -> Result<(), RepositoryError>;

    /// The revocation of `session`, if any.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn session_revocation(
        &self,
        session: &SessionId,
    ) -> Result<Option<SessionRevocation>, RepositoryError>;

    /// The revocation with the identifier `id`, if any.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn session_revocation_by_id(
        &self,
        id: SessionRevocationId,
    ) -> Result<Option<SessionRevocation>, RepositoryError>;

    /// One page of the revocations that meet the conditions of `search`, newest first.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn search_session_revocations(
        &self,
        search: &SessionRevocationSearch,
    ) -> Result<Vec<SessionRevocation>, RepositoryError>;

    /// The cut-off of `user`, if any.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn user_cutoff(&self, user: Uuid) -> Result<Option<UserTokenCutoff>, RepositoryError>;

    /// The global cut-off, if any.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn global_cutoff(&self) -> Result<Option<GlobalTokenCutoff>, RepositoryError>;

    /// Records a consumed event; returns `false` when its id was recorded before, so the caller
    /// skips a redelivery.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails.
    async fn record_inbound_event(&self, event: &InboundEvent) -> Result<bool, RepositoryError>;
}
