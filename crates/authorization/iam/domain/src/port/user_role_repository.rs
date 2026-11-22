//! Assignment read port (board name `UserRoleRepository`).

use std::time::SystemTime;

use crate::port::RepositoryError;
use crate::user_role::UserRole;
use crate::value_object::identifier::{ProjectId, RoleId, UserRoleId};
use crate::value_object::subject::SubjectKind;

/// One page of assignments to read: at most `limit` assignments after the cursor that are not
/// revoked and match every filter that is set. The caller validates `limit` (1 to 100).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRolePageQuery {
    /// The largest number of assignments of the page.
    pub limit: u32,
    /// The last assignment of the previous page; `None` for the first page.
    pub after: Option<UserRoleId>,
    /// Only assignments of subjects of this kind.
    pub subject_kind: Option<SubjectKind>,
    /// Only assignments of subjects with this id: the text form of a user UUID or a service name.
    pub subject_id: Option<String>,
    /// Only assignments of this role.
    pub role_id: Option<RoleId>,
    /// Only assignments scoped to this project.
    pub project_id: Option<ProjectId>,
    /// Whether assignments that have expired at `now` are listed as well.
    pub include_expired: bool,
    /// The current time of the `Clock` port, against which expiry is judged.
    pub now: SystemTime,
}

/// Reads `UserRole` aggregates. Assignments are written through the
/// [`IamUnitOfWork`](crate::IamUnitOfWork), as statements of an administrative change.
#[async_trait::async_trait]
pub trait UserRoleRepository: std::fmt::Debug + Send + Sync {
    /// The assignment with the identifier, unless it is unknown or revoked; an expired assignment
    /// is found.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn find_by_id(&self, id: UserRoleId) -> Result<Option<UserRole>, RepositoryError>;

    /// One page of assignments that are not revoked, in a stable order in which every matching
    /// assignment appears exactly once across pages.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn find_page(&self, query: &UserRolePageQuery) -> Result<Vec<UserRole>, RepositoryError>;
}
