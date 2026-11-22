//! When an assignment stops granting its role.

use std::time::SystemTime;

use crate::error::InvalidUserRole;

/// The instant at which an assignment expires; from that instant on it grants nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AssignmentExpiry(SystemTime);

impl AssignmentExpiry {
    /// An expiry for a new or changed assignment: `at` must lie after `now`, the current time of
    /// the `Clock` port.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidUserRole::ExpiryNotInFuture`] when `at` is not later than `now`.
    pub fn new(at: SystemTime, now: SystemTime) -> Result<Self, InvalidUserRole> {
        if at > now {
            Ok(Self(at))
        } else {
            Err(InvalidUserRole::ExpiryNotInFuture)
        }
    }

    /// Rebuilds a stored expiry, which may already have passed.
    #[must_use]
    pub const fn restore(at: SystemTime) -> Self {
        Self(at)
    }

    /// The instant of the expiry.
    #[must_use]
    pub const fn at(self) -> SystemTime {
        self.0
    }

    /// Whether the expiry has passed at `now`: an assignment expires at its expiry instant.
    #[must_use]
    pub fn has_passed(self, now: SystemTime) -> bool {
        self.0 <= now
    }
}

#[cfg(test)]
mod tests;
