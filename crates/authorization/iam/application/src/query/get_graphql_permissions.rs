//! Lists GraphQL catalogue entries with cursor pagination and filters (FR-1, FR-33).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use iam_domain::{
    CoordinateSet, GqlCoordinate, GqlName, GrantRecord, GraphQlCoordinate, GraphQlPermission,
    GraphQlPermissionParts, GraphQlPermissionRepository, GraphQlSpecRepository, PermissionId,
    PermissionKey, PermissionKeyKind, PermissionPageQuery, RoleId, RoleRepository, ServiceName,
    SpecId,
};
use shared_domain::{Query, QueryHandler};

use crate::error::IamError;

/// The largest page of entries.
pub const MAX_PAGE_SIZE: u32 = 100;

/// Asks for one page of GraphQL catalogue entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetGraphQlPermissionsQuery {
    /// The largest number of entries of the page; a value outside 1 to [`MAX_PAGE_SIZE`] is
    /// brought into that range.
    pub limit: u32,
    /// The last entry of the previous page; none for the first page.
    pub after: Option<PermissionId>,
    /// Only entries of this service.
    pub service: Option<ServiceName>,
    /// Only entries of this GraphQL type.
    pub type_name: Option<GqlName>,
    /// Only active (`true`) or only inactive (`false`) entries.
    pub active: Option<bool>,
    /// Only entries that are sensitive (`true`) or not (`false`).
    pub sensitive: Option<bool>,
    /// Only entries whose key starts with this text.
    pub key_prefix: Option<String>,
}

/// A catalogue entry with the active versions that contain its key and the roles that grant it by
/// its exact key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphQlPermissionView {
    /// The state of the entry.
    pub permission: GraphQlPermissionParts,
    /// The active versions of the service that contain the key, in identifier order.
    pub versions: Vec<SpecId>,
    /// The roles that are not deleted and grant the key, in identifier order.
    pub roles: Vec<RoleId>,
}

/// One page of catalogue entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphQlPermissionPage {
    /// The entries of the page, in the stable order of the repository.
    pub permissions: Vec<GraphQlPermissionView>,
    /// The cursor of the next page: the last entry of this one; none when none follows.
    pub next_after: Option<PermissionId>,
}

impl Query for GetGraphQlPermissionsQuery {
    type Output = GraphQlPermissionPage;
    type Error = IamError;
    const NAME: &'static str = "GetGraphQlPermissionsQuery";
}

/// The repositories that the two permission queries read.
#[derive(Debug, Clone)]
pub struct PermissionReads {
    /// The catalogue entries.
    pub permissions: Arc<dyn GraphQlPermissionRepository>,
    /// The versions, whose active ones contain the keys.
    pub specs: Arc<dyn GraphQlSpecRepository>,
    /// The roles, whose grants name the keys.
    pub roles: Arc<dyn RoleRepository>,
}

/// What one service contributes to the entries that name it.
#[derive(Debug, Default)]
struct ServiceReads {
    versions: Vec<(SpecId, CoordinateSet)>,
    grants: Vec<GrantRecord>,
}

/// The active versions and the exact-key grants of the service.
async fn read_service(
    reads: &PermissionReads,
    service: &ServiceName,
) -> Result<ServiceReads, IamError> {
    let mut versions: Vec<(SpecId, CoordinateSet)> = reads
        .specs
        .find_active(service)
        .await?
        .iter()
        .map(|spec| (spec.parts().id, spec.coordinates()))
        .collect();
    versions.sort_by_key(|(id, _coordinates)| *id);
    let grants = reads
        .roles
        .find_catalogue_grants(service, PermissionKeyKind::Gql)
        .await?;
    Ok(ServiceReads { versions, grants })
}

/// Whether a version with `coordinates` contains the key of `entry`: every active version has the
/// introspection key, and a field key is contained when the version declares the field.
fn contains(entry: &GraphQlPermission, coordinates: &CoordinateSet) -> bool {
    let key = &entry.parts().key;
    match key {
        PermissionKey::Gql {
            coordinate: GqlCoordinate::Introspection,
            ..
        } => true,
        other @ (PermissionKey::Gql { .. }
        | PermissionKey::Rest { .. }
        | PermissionKey::Reserved(_)) => {
            GraphQlCoordinate::from_permission_key(other, entry.service())
                .is_some_and(|coordinate| coordinates.contains(&coordinate))
        }
    }
}

/// The entry with the versions that contain its key and the roles that grant it.
fn view_of(entry: &GraphQlPermission, service: &ServiceReads) -> GraphQlPermissionView {
    let permission = entry.parts().clone();
    let versions = service
        .versions
        .iter()
        .filter(|(_id, coordinates)| contains(entry, coordinates))
        .map(|(id, _coordinates)| *id)
        .collect();
    let roles: BTreeSet<RoleId> = service
        .grants
        .iter()
        .filter(|grant| grant.key == permission.key)
        .map(|grant| grant.role)
        .collect();
    GraphQlPermissionView {
        permission,
        versions,
        roles: roles.into_iter().collect(),
    }
}

/// The views of `entries`, in their order; each service is read once.
///
/// # Errors
///
/// [`IamError::Storage`] when a repository fails.
pub(super) async fn describe(
    reads: &PermissionReads,
    entries: &[GraphQlPermission],
) -> Result<Vec<GraphQlPermissionView>, IamError> {
    let mut services: BTreeMap<ServiceName, ServiceReads> = BTreeMap::new();
    for entry in entries {
        if !services.contains_key(entry.service()) {
            let read = read_service(reads, entry.service()).await?;
            services.insert(entry.service().clone(), read);
        }
    }
    let none = ServiceReads::default();
    Ok(entries
        .iter()
        .map(|entry| view_of(entry, services.get(entry.service()).unwrap_or(&none)))
        .collect())
}

/// Handles [`GetGraphQlPermissionsQuery`].
///
/// It reads one entry more than the page holds, to know whether another page follows without a
/// second query.
#[derive(Debug)]
pub struct GetGraphQlPermissionsQueryHandler {
    reads: PermissionReads,
}

impl GetGraphQlPermissionsQueryHandler {
    /// A handler over the repositories of the catalogue, the versions and the roles.
    #[must_use]
    pub const fn new(reads: PermissionReads) -> Self {
        Self { reads }
    }

    async fn list(
        &self,
        query: GetGraphQlPermissionsQuery,
    ) -> Result<GraphQlPermissionPage, IamError> {
        let limit = query.limit.clamp(1, MAX_PAGE_SIZE);
        let read = PermissionPageQuery {
            limit: limit.saturating_add(1),
            after: query.after,
            service: query.service,
            active: query.active,
            sensitive: query.sensitive,
            key_prefix: query.key_prefix,
            type_name: query.type_name,
            method: None,
        };
        let mut found = self.reads.permissions.find_page(&read).await?;
        let size = usize::try_from(limit).unwrap_or(usize::MAX);
        let next_after = found
            .get(size.saturating_sub(1))
            .filter(|_last| found.len() > size)
            .map(|last| last.parts().id);
        found.truncate(size);
        Ok(GraphQlPermissionPage {
            permissions: describe(&self.reads, &found).await?,
            next_after,
        })
    }
}

#[async_trait::async_trait]
impl QueryHandler<GetGraphQlPermissionsQuery> for GetGraphQlPermissionsQueryHandler {
    async fn handle(
        &self,
        query: GetGraphQlPermissionsQuery,
    ) -> Result<GraphQlPermissionPage, IamError> {
        self.list(query).await
    }
}

#[cfg(test)]
mod tests;
