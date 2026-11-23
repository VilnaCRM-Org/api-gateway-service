//! Lists REST catalogue entries with cursor pagination and filters (FR-1, FR-37).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use iam_domain::{
    GrantRecord, HttpMethod, OpenApiSpecRepository, PathTemplate, PermissionId, PermissionKeyKind,
    PermissionPageQuery, RestOperationKey, RestOperationSet, RestPermission, RestPermissionParts,
    RestPermissionRepository, RoleId, RoleRepository, ServiceName, SpecId,
};
use shared_domain::{Query, QueryHandler};

pub use super::get_graphql_permissions::MAX_PAGE_SIZE;
use crate::error::IamError;

/// Asks for one page of REST catalogue entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetRestPermissionsQuery {
    /// The largest number of entries of the page; a value outside 1 to [`MAX_PAGE_SIZE`] is
    /// brought into that range.
    pub limit: u32,
    /// The last entry of the previous page; none for the first page.
    pub after: Option<PermissionId>,
    /// Only entries of this service.
    pub service: Option<ServiceName>,
    /// Only entries of this HTTP method.
    pub method: Option<HttpMethod>,
    /// Only active (`true`) or only inactive (`false`) entries.
    pub active: Option<bool>,
    /// Only entries that are sensitive (`true`) or not (`false`).
    pub sensitive: Option<bool>,
    /// Only entries whose normalised path template starts with this text.
    pub template_prefix: Option<String>,
}

/// A catalogue entry with the active versions that contain its key and the roles that grant it by
/// its exact key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestPermissionView {
    /// The state of the entry.
    pub permission: RestPermissionParts,
    /// The active versions of the service that contain the key, in identifier order.
    pub versions: Vec<SpecId>,
    /// The roles that are not deleted and grant the key, in identifier order.
    pub roles: Vec<RoleId>,
}

/// One page of catalogue entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestPermissionPage {
    /// The entries of the page, in the stable order of the repository.
    pub permissions: Vec<RestPermissionView>,
    /// The cursor of the next page: the last entry of this one; none when none follows.
    pub next_after: Option<PermissionId>,
}

impl Query for GetRestPermissionsQuery {
    type Output = RestPermissionPage;
    type Error = IamError;
    const NAME: &'static str = "GetRestPermissionsQuery";
}

/// The repositories that the two REST permission queries read.
#[derive(Debug, Clone)]
pub struct RestPermissionReads {
    /// The catalogue entries.
    pub permissions: Arc<dyn RestPermissionRepository>,
    /// The versions, whose active ones contain the keys.
    pub specs: Arc<dyn OpenApiSpecRepository>,
    /// The roles, whose grants name the keys.
    pub roles: Arc<dyn RoleRepository>,
}

/// What one service contributes to the entries that name it.
#[derive(Debug, Default)]
struct ServiceReads {
    versions: Vec<(SpecId, RestOperationSet)>,
    grants: Vec<GrantRecord>,
}

/// The active versions and the exact-key grants of the service.
async fn read_service(
    reads: &RestPermissionReads,
    service: &ServiceName,
) -> Result<ServiceReads, IamError> {
    let mut versions: Vec<(SpecId, RestOperationSet)> = reads
        .specs
        .find_active(service)
        .await?
        .iter()
        .map(|spec| (spec.parts().id, spec.operations().clone()))
        .collect();
    versions.sort_by_key(|(id, _operations)| *id);
    let grants = reads
        .roles
        .find_catalogue_grants(service, PermissionKeyKind::Rest)
        .await?;
    Ok(ServiceReads { versions, grants })
}

/// The operation that the key of `entry` names; none when the stored template is not normalised.
fn operation_of(entry: &RestPermission) -> Option<RestOperationKey> {
    let (method, template) = entry.parts().key.rest_operation()?;
    PathTemplate::from_stored(template.as_str())
        .map(|template| RestOperationKey { method, template })
}

/// The entry with the versions that contain its key and the roles that grant it.
fn view_of(entry: &RestPermission, service: &ServiceReads) -> RestPermissionView {
    let permission = entry.parts().clone();
    let operation = operation_of(entry);
    let versions = service
        .versions
        .iter()
        .filter(|(_id, operations)| {
            operation
                .as_ref()
                .is_some_and(|operation| operations.contains(operation))
        })
        .map(|(id, _operations)| *id)
        .collect();
    let roles: BTreeSet<RoleId> = service
        .grants
        .iter()
        .filter(|grant| grant.key == permission.key)
        .map(|grant| grant.role)
        .collect();
    RestPermissionView {
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
    reads: &RestPermissionReads,
    entries: &[RestPermission],
) -> Result<Vec<RestPermissionView>, IamError> {
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

/// Whether the normalised template of `entry` starts with `prefix`.
fn has_template_prefix(entry: &RestPermission, prefix: &str) -> bool {
    entry
        .parts()
        .key
        .rest_operation()
        .is_some_and(|(_method, template)| template.as_str().starts_with(prefix))
}

/// Handles [`GetRestPermissionsQuery`].
///
/// It reads one entry more than the page holds, to know whether another page follows without a
/// second query. A template prefix is applied here, over repository pages that follow each other
/// by the cursor, so the page keeps the stable order and holds every match exactly once.
#[derive(Debug)]
pub struct GetRestPermissionsQueryHandler {
    reads: RestPermissionReads,
}

impl GetRestPermissionsQueryHandler {
    /// A handler over the repositories of the catalogue, the versions and the roles.
    #[must_use]
    pub const fn new(reads: RestPermissionReads) -> Self {
        Self { reads }
    }

    /// Up to `wanted` entries that satisfy the filters, after the cursor.
    async fn find(
        &self,
        query: &GetRestPermissionsQuery,
        wanted: usize,
    ) -> Result<Vec<RestPermission>, IamError> {
        let batch = MAX_PAGE_SIZE.saturating_add(1);
        let mut after = query.after;
        let mut found: Vec<RestPermission> = Vec::new();
        loop {
            let read = PermissionPageQuery {
                limit: if query.template_prefix.is_some() {
                    batch
                } else {
                    u32::try_from(wanted).unwrap_or(batch)
                },
                after,
                service: query.service.clone(),
                active: query.active,
                sensitive: query.sensitive,
                key_prefix: None,
                type_name: None,
                method: query.method,
            };
            let page = self.reads.permissions.find_page(&read).await?;
            let Some(prefix) = query.template_prefix.as_deref() else {
                return Ok(page);
            };
            let exhausted = page.len() < usize::try_from(batch).unwrap_or(usize::MAX);
            after = page.last().map(|last| last.parts().id);
            found.extend(
                page.into_iter()
                    .filter(|entry| has_template_prefix(entry, prefix)),
            );
            if found.len() >= wanted || exhausted {
                found.truncate(wanted);
                return Ok(found);
            }
        }
    }

    async fn list(&self, query: GetRestPermissionsQuery) -> Result<RestPermissionPage, IamError> {
        let limit = query.limit.clamp(1, MAX_PAGE_SIZE);
        let size = usize::try_from(limit).unwrap_or(usize::MAX);
        let mut found = self.find(&query, size.saturating_add(1)).await?;
        let next_after = found
            .get(size.saturating_sub(1))
            .filter(|_last| found.len() > size)
            .map(|last| last.parts().id);
        found.truncate(size);
        Ok(RestPermissionPage {
            permissions: describe(&self.reads, &found).await?,
            next_after,
        })
    }
}

#[async_trait::async_trait]
impl QueryHandler<GetRestPermissionsQuery> for GetRestPermissionsQueryHandler {
    async fn handle(&self, query: GetRestPermissionsQuery) -> Result<RestPermissionPage, IamError> {
        self.list(query).await
    }
}

#[cfg(test)]
mod tests;
