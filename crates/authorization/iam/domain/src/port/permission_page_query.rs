//! The page query shared by the permission catalogue ports.

use crate::value_object::identifier::PermissionId;
use crate::value_object::service_name::ServiceName;

/// One page of catalogue entries to read: at most `limit` entries after the cursor, filtered by
/// service and state. The caller validates `limit` (1 to 100).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionPageQuery {
    /// The largest number of entries of the page.
    pub limit: u32,
    /// The last entry of the previous page; `None` for the first page.
    pub after: Option<PermissionId>,
    /// Only entries of this service.
    pub service: Option<ServiceName>,
    /// Only active (`true`) or only inactive (`false`) entries.
    pub active: Option<bool>,
}
