//! GraphQL objects and the resolvers of the REST catalogue read operations.
//!
//! The resolvers share the use-case calls and the response shapes of the REST handlers, so both
//! transports apply one set of rules.

use async_graphql::{Context, ID, InputObject, SimpleObject};
use shared_application::http::Problem;
use validator::Validate as _;

use super::openapi_spec::OperationFlagsObject;
use super::{require_caller, state};
use crate::http::dto::DEFAULT_PAGE_SIZE;
use crate::http::graphql_permission::parse_permission_id;
use crate::http::rest_permission::dto::{
    ListRestPermissionsParams, RestPermissionPageResponse, RestPermissionResponse,
};
use crate::http::rest_permission::{find_rest_permission, list_rest_permissions};

/// Filters of the REST permission list.
#[derive(Debug, Default, InputObject)]
#[graphql(name = "RestPermissionFilter")]
pub struct RestPermissionFilterInput {
    /// Only permissions of this service.
    pub service: Option<String>,
    /// Only permissions of this HTTP method, in upper case.
    pub method: Option<String>,
    /// Only active (`true`) or only inactive (`false`) permissions.
    pub active: Option<bool>,
    /// Only permissions that are sensitive (`true`) or not (`false`).
    pub sensitive: Option<bool>,
    /// Only permissions whose normalised path template starts with this text.
    pub template_prefix: Option<String>,
}

/// A REST catalogue entry.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "RestPermission")]
pub struct RestPermissionObject {
    /// The identifier of the entry.
    pub id: ID,
    /// The permission key, `rest:{service}:{METHOD} {template}`.
    pub key: String,
    /// The service of the key.
    pub service: String,
    /// The HTTP method of the key.
    pub method: String,
    /// The normalised path template of the key; parameters are written `{}`.
    pub template: String,
    /// The flags of the entry: the most restrictive ones across the active versions.
    pub flags: OperationFlagsObject,
    /// Whether some active version holds the key.
    pub active: bool,
    /// The identifiers of the active versions that contain the key.
    pub versions: Vec<String>,
    /// The identifiers of the roles that grant the key by its exact key; wildcard grants are not listed.
    pub roles: Vec<String>,
}

impl From<RestPermissionResponse> for RestPermissionObject {
    fn from(permission: RestPermissionResponse) -> Self {
        Self {
            id: ID::from(permission.id),
            key: permission.key,
            service: permission.service,
            method: permission.method,
            template: permission.template,
            flags: permission.flags.into(),
            active: permission.active,
            versions: permission.versions,
            roles: permission.roles,
        }
    }
}

/// One page of REST catalogue entries.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "RestPermissionPage")]
pub struct RestPermissionPageObject {
    /// The entries of the page.
    pub items: Vec<RestPermissionObject>,
    /// The `after` value of the next page; null on the last page.
    pub next_cursor: Option<String>,
}

impl From<RestPermissionPageResponse> for RestPermissionPageObject {
    fn from(page: RestPermissionPageResponse) -> Self {
        Self {
            items: page
                .items
                .into_iter()
                .map(RestPermissionObject::from)
                .collect(),
            next_cursor: page.next_cursor,
        }
    }
}

/// Reads one entry; none when it is unknown.
pub(super) async fn rest_permission_field(
    ctx: &Context<'_>,
    id: &ID,
) -> Result<Option<RestPermissionObject>, Problem> {
    require_caller(ctx)?;
    let view = find_rest_permission(state(ctx)?, parse_permission_id(id.as_str())?).await?;
    Ok(view.map(|view| RestPermissionObject::from(RestPermissionResponse::from(view))))
}

/// Reads one page of entries.
pub(super) async fn rest_permissions_field(
    ctx: &Context<'_>,
    first: Option<i32>,
    after: Option<String>,
    filter: RestPermissionFilterInput,
) -> Result<RestPermissionPageObject, Problem> {
    require_caller(ctx)?;
    let params = ListRestPermissionsParams {
        limit: first.unwrap_or(DEFAULT_PAGE_SIZE),
        after,
        service: filter.service,
        method: filter.method,
        active: filter.active,
        sensitive: filter.sensitive,
        template_prefix: filter.template_prefix,
    };
    params.validate()?;
    let page = list_rest_permissions(state(ctx)?, params).await?;
    Ok(RestPermissionPageObject::from(
        RestPermissionPageResponse::from(page),
    ))
}

#[cfg(test)]
mod tests;
