//! GraphQL objects and the resolvers of the GraphQL catalogue read operations.
//!
//! The resolvers share the use-case calls and the response shapes of the REST handlers, so both
//! transports apply one set of rules.

use async_graphql::{Context, ID, InputObject, SimpleObject};
use shared_application::http::Problem;
use validator::Validate as _;

use super::graphql_spec::CoordinateFlagsObject;
use super::{require_caller, state};
use crate::http::dto::DEFAULT_PAGE_SIZE;
use crate::http::graphql_permission::dto::{
    GraphQlPermissionPageResponse, GraphQlPermissionResponse, ListGraphQlPermissionsParams,
};
use crate::http::graphql_permission::{
    find_graphql_permission, list_graphql_permissions, parse_permission_id,
};

/// Filters of the permission list.
#[derive(Debug, Default, InputObject)]
#[graphql(name = "GraphqlPermissionFilter")]
pub struct GraphQlPermissionFilterInput {
    /// Only permissions of this service.
    pub service: Option<String>,
    /// Only permissions of this GraphQL type.
    #[graphql(name = "type")]
    pub type_name: Option<String>,
    /// Only active (`true`) or only inactive (`false`) permissions.
    pub active: Option<bool>,
    /// Only permissions that are sensitive (`true`) or not (`false`).
    pub sensitive: Option<bool>,
    /// Only permissions whose key starts with this text.
    pub key_prefix: Option<String>,
}

/// A GraphQL catalogue entry.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "GraphqlPermission")]
pub struct GraphQlPermissionObject {
    /// The identifier of the entry.
    pub id: ID,
    /// The permission key, `gql:{service}:{Type}.{field}` or `gql:{service}:__introspection`.
    pub key: String,
    /// The service of the key.
    pub service: String,
    /// The GraphQL type of the key; `__introspection` for the introspection key.
    #[graphql(name = "type")]
    pub type_of: String,
    /// The field of the key; `__introspection` for the introspection key.
    pub field: String,
    /// The flags of the entry: the most restrictive ones across the active versions.
    pub flags: CoordinateFlagsObject,
    /// Whether some active version holds the key.
    pub active: bool,
    /// The identifiers of the active versions that contain the key.
    pub versions: Vec<String>,
    /// The identifiers of the roles that grant the key by its exact key; wildcard grants are not listed.
    pub roles: Vec<String>,
}

impl From<GraphQlPermissionResponse> for GraphQlPermissionObject {
    fn from(permission: GraphQlPermissionResponse) -> Self {
        Self {
            id: ID::from(permission.id),
            key: permission.key,
            service: permission.service,
            type_of: permission.type_name,
            field: permission.field,
            flags: permission.flags.into(),
            active: permission.active,
            versions: permission.versions,
            roles: permission.roles,
        }
    }
}

/// One page of GraphQL catalogue entries.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "GraphqlPermissionPage")]
pub struct GraphQlPermissionPageObject {
    /// The entries of the page.
    pub items: Vec<GraphQlPermissionObject>,
    /// The `after` value of the next page; null on the last page.
    pub next_cursor: Option<String>,
}

impl From<GraphQlPermissionPageResponse> for GraphQlPermissionPageObject {
    fn from(page: GraphQlPermissionPageResponse) -> Self {
        Self {
            items: page
                .items
                .into_iter()
                .map(GraphQlPermissionObject::from)
                .collect(),
            next_cursor: page.next_cursor,
        }
    }
}

/// Reads one entry; none when it is unknown.
pub(super) async fn graphql_permission_field(
    ctx: &Context<'_>,
    id: &ID,
) -> Result<Option<GraphQlPermissionObject>, Problem> {
    require_caller(ctx)?;
    let view = find_graphql_permission(state(ctx)?, parse_permission_id(id.as_str())?).await?;
    Ok(view.map(|view| GraphQlPermissionObject::from(GraphQlPermissionResponse::from(view))))
}

/// Reads one page of entries.
pub(super) async fn graphql_permissions_field(
    ctx: &Context<'_>,
    first: Option<i32>,
    after: Option<String>,
    filter: GraphQlPermissionFilterInput,
) -> Result<GraphQlPermissionPageObject, Problem> {
    require_caller(ctx)?;
    let params = ListGraphQlPermissionsParams {
        limit: first.unwrap_or(DEFAULT_PAGE_SIZE),
        after,
        service: filter.service,
        type_name: filter.type_name,
        active: filter.active,
        sensitive: filter.sensitive,
        key_prefix: filter.key_prefix,
    };
    params.validate()?;
    let page = list_graphql_permissions(state(ctx)?, params).await?;
    Ok(GraphQlPermissionPageObject::from(
        GraphQlPermissionPageResponse::from(page),
    ))
}

#[cfg(test)]
mod tests;
