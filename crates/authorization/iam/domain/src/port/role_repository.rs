//! Role read port (board name `RoleRepository`).

use crate::port::RepositoryError;
use crate::role::Role;
use crate::value_object::identifier::RoleId;
use crate::value_object::role_kind::RoleKind;

/// One page of roles to read: at most `limit` roles after the cursor, filtered by a name prefix
/// (compared without regard to case) and a kind. The caller validates `limit` (1 to 100).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolePageQuery {
    /// The largest number of roles of the page.
    pub limit: u32,
    /// The last role of the previous page; `None` for the first page.
    pub after: Option<RoleId>,
    /// Only roles whose name starts with this text, compared without regard to case.
    pub name_prefix: Option<String>,
    /// Only roles of this kind.
    pub kind: Option<RoleKind>,
}

/// Reads `Role` aggregates. Roles are written through the
/// [`IamUnitOfWork`](crate::IamUnitOfWork), as statements of an administrative change.
#[async_trait::async_trait]
pub trait RoleRepository: std::fmt::Debug + Send + Sync {
    /// The role with the identifier, unless it is unknown or deleted.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn find_by_id(&self, id: RoleId) -> Result<Option<Role>, RepositoryError>;

    /// One page of roles that are not deleted, in a stable order in which every matching role
    /// appears exactly once across pages.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails or holds unusable data.
    async fn find_page(&self, query: &RolePageQuery) -> Result<Vec<Role>, RepositoryError>;
}
