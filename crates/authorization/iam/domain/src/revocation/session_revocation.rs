//! The record of one revoked User service session.

use std::time::SystemTime;

use shared_domain::Uuid;

use crate::revocation::revocation_source::RevocationSource;
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::identifier::SessionRevocationId;
use crate::value_object::session_id::SessionId;

/// An append-only record: every token of `session` is refused until the record is pruned after
/// `prune_after`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRevocation {
    /// The id the management API exposes.
    pub id: SessionRevocationId,
    /// The revoked session.
    pub session: SessionId,
    /// The user the session belongs to.
    pub user: Uuid,
    /// Who caused the revocation.
    pub source: RevocationSource,
    /// The actor that recorded it.
    pub revoked_by: ActorRef,
    /// When it was recorded.
    pub revoked_at: SystemTime,
    /// The earliest instant at which the record may be pruned.
    pub prune_after: SystemTime,
}
