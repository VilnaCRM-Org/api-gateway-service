//! The cut-off of every token, for an emergency key compromise.

use std::time::SystemTime;

use crate::value_object::actor_ref::ActorRef;

/// The single record: every token issued at or before `tokens_valid_after` is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalTokenCutoff {
    /// Tokens whose `iat` is at or before this instant are refused.
    pub tokens_valid_after: SystemTime,
    /// The actor that set it.
    pub set_by: ActorRef,
    /// When it was set.
    pub set_at: SystemTime,
}
