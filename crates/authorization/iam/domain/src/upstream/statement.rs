//! The write of one upstream that a change hands to the unit of work.

use crate::upstream::{Upstream, UpstreamParts};
use crate::value_object::entity_version::EntityVersion;

/// The write of one upstream: an insert, or an update guarded by the version the change read. A
/// deletion is an update of an upstream that carries its deletion time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamStatement {
    upstream: UpstreamParts,
    expected: Option<EntityVersion>,
}

impl UpstreamStatement {
    /// The insert of a new upstream; a stored upstream with the same identifier, or one that is not
    /// deleted with the same name, refuses it as a duplicate.
    #[must_use]
    pub fn insert(upstream: &Upstream) -> Self {
        Self {
            upstream: upstream.parts().clone(),
            expected: None,
        }
    }

    /// The update of a stored upstream that is not deleted and still holds the version `expected`;
    /// any other stored state refuses it as a conflict.
    #[must_use]
    pub fn update(upstream: &Upstream, expected: EntityVersion) -> Self {
        Self {
            upstream: upstream.parts().clone(),
            expected: Some(expected),
        }
    }

    /// The state of the upstream to store.
    #[must_use]
    pub const fn upstream(&self) -> &UpstreamParts {
        &self.upstream
    }

    /// The version the stored upstream must hold; `None` for an insert.
    #[must_use]
    pub const fn expected(&self) -> Option<EntityVersion> {
        self.expected
    }
}

#[cfg(test)]
mod tests;
