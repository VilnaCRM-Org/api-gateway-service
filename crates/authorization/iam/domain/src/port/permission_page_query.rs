//! The page query shared by the permission catalogue ports.

use crate::value_object::gql_name::GqlName;
use crate::value_object::http_method::HttpMethod;
use crate::value_object::identifier::PermissionId;
use crate::value_object::service_name::ServiceName;

/// One page of catalogue entries to read: at most `limit` entries after the cursor.
///
/// The entries are filtered by service, type or method, state, the sensitive flag and the start of
/// the key. The caller validates `limit` (1 to 100).
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
    /// Only entries that are sensitive (`true`) or not (`false`).
    pub sensitive: Option<bool>,
    /// Only entries whose key starts with this text.
    pub key_prefix: Option<String>,
    /// Only GraphQL entries of this type; the REST repository ignores it.
    pub type_name: Option<GqlName>,
    /// Only REST entries of this method; the GraphQL repository ignores it.
    pub method: Option<HttpMethod>,
}
