//! `LastAdministratorGuard`: the platform keeps at least one active global administrator (FR-5).

use std::time::SystemTime;

use crate::policy::platform_administrator::PlatformAdministrator;
use crate::role::RoleParts;
use crate::user_role::UserRoleParts;
use crate::value_object::assignment_expiry::AssignmentExpiry;
use crate::value_object::assignment_scope::AssignmentScope;
use crate::value_object::identifier::UserRoleId;

/// The refusal of a change that would leave the platform without an active global administrator;
/// the application answers 409 and the GraphQL code `LAST_ADMINISTRATOR`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("The last active administrator assignment cannot be revoked or given an earlier expiry.")]
pub struct LastAdministratorRefused;

impl LastAdministratorRefused {
    /// The machine-readable refusal code.
    pub const CODE: &'static str = "last_administrator";
}

/// The rule for one assignment that a change would end or shorten.
///
/// It protects the assignment when it is an active global assignment of `iam-platform-admin`, and
/// then lets the change through only while another such assignment is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LastAdministratorGuard {
    protects: bool,
}

impl LastAdministratorGuard {
    /// The rule for `assignment` of `role` at `now`.
    #[must_use]
    pub fn of(role: &RoleParts, assignment: &UserRoleParts, now: SystemTime) -> Self {
        Self {
            protects: PlatformAdministrator::is_role(role)
                && assignment.role_id == role.id
                && Self::is_active_global(assignment, now),
        }
    }

    /// Whether the assignment is one that the guard protects: the application then counts the
    /// other administrators before it decides.
    #[must_use]
    pub const fn protects(self) -> bool {
        self.protects
    }

    /// Whether `candidate`, an assignment of the administrator role, is another active global
    /// administrator than `excluded` at `now`.
    #[must_use]
    pub fn is_other_administrator(
        candidate: &UserRoleParts,
        excluded: UserRoleId,
        now: SystemTime,
    ) -> bool {
        candidate.id != excluded && Self::is_active_global(candidate, now)
    }

    /// Lets a revocation through when it is not protected or `others` is above zero.
    ///
    /// # Errors
    ///
    /// [`LastAdministratorRefused`] for the last active global administrator.
    pub const fn check_revocation(self, others: usize) -> Result<(), LastAdministratorRefused> {
        if self.protects && others == 0 {
            Err(LastAdministratorRefused)
        } else {
            Ok(())
        }
    }

    /// Lets a change of the expiry from `current` to `new` through when it is not protected, does
    /// not end the assignment earlier (it clears the expiry or moves it later) or `others` is above
    /// zero.
    ///
    /// # Errors
    ///
    /// [`LastAdministratorRefused`] for an earlier expiry of the last active global administrator.
    pub fn check_expiry(
        self,
        current: Option<AssignmentExpiry>,
        new: Option<SystemTime>,
        others: usize,
    ) -> Result<(), LastAdministratorRefused> {
        if Self::ends_earlier(current, new) {
            self.check_revocation(others)
        } else {
            Ok(())
        }
    }

    /// Whether the new expiry ends the assignment earlier than the current one: any expiry of an
    /// assignment that never expires, or an earlier instant.
    fn ends_earlier(current: Option<AssignmentExpiry>, new: Option<SystemTime>) -> bool {
        match (current, new) {
            (_, None) => false,
            (None, Some(_)) => true,
            (Some(current), Some(new)) => new < current.at(),
        }
    }

    fn is_active_global(assignment: &UserRoleParts, now: SystemTime) -> bool {
        assignment.scope == AssignmentScope::Global && assignment.is_active_at(now)
    }
}

#[cfg(test)]
mod tests;
