//! GraphQL objects and the resolver of the activation of a GraphQL specification version.
//!
//! The resolver shares the use-case call and the response shape of the REST handler, so both
//! transports apply one set of rules.

use async_graphql::{Context, ID, InputObject, SimpleObject};
use shared_application::http::Problem;
use validator::Validate as _;

use super::{idempotency_key, require_caller, state};
use crate::http::graphql_activation::create_graphql_permissions;
use crate::http::graphql_activation::dto::{
    CreateGraphQlPermissionsRequest, GraphQlPermissionsActivationResponse, KeyRenameDto,
};
use crate::http::graphql_spec::parse_spec_id;

/// A coordinate that a version renames: the grants of the old key move to the new key.
#[derive(Debug, InputObject)]
#[graphql(name = "KeyRenameInput")]
pub struct KeyRenameInput {
    /// The old key, which the version no longer holds, such as `gql:billing:Query.bills`.
    pub from: String,
    /// The new key, which the version holds, such as `gql:billing:Query.invoices`.
    pub to: String,
}

/// Input of the mutation that activates a GraphQL specification version.
#[derive(Debug, InputObject)]
#[graphql(name = "CreateGraphqlPermissionsInput")]
pub struct CreateGraphQlPermissionsInput {
    /// The version to activate.
    pub id: ID,
    /// Accepts that grants of keys that leave the catalogue become inactive; without it, an activation that would orphan grants fails with `ORPHAN_CONFIRMATION_REQUIRED`.
    #[graphql(default)]
    pub confirm_orphans: bool,
    /// Accepts that keys lose the sensitive or the always-audit flag; without it, an activation that would remove a flag fails with `FLAG_DOWNGRADE_CONFIRMATION_REQUIRED`.
    #[graphql(default)]
    pub confirm_flag_downgrade: bool,
    /// The coordinates that the version renames; the grants of each old key move to its new key before anything is orphaned.
    #[graphql(default)]
    pub renames: Vec<KeyRenameInput>,
    /// Makes the activation safe to repeat for 24 hours: 1 to 255 visible ASCII characters.
    pub idempotency_key: Option<String>,
}

/// The result of an activation.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "GraphqlPermissionsActivation")]
pub struct GraphQlPermissionsActivationObject {
    /// The identifier of the activated version.
    pub id: ID,
    /// The service the schema belongs to.
    pub service: String,
    /// `active`.
    pub status: String,
    /// The keys that the activation added to the catalogue, in key order; empty for a version that was active already.
    pub created_keys: Vec<String>,
    /// The policy version that the activation produced; for a version that was active already, the current policy version.
    pub policy_version: i64,
}

impl From<GraphQlPermissionsActivationResponse> for GraphQlPermissionsActivationObject {
    fn from(response: GraphQlPermissionsActivationResponse) -> Self {
        Self {
            id: ID::from(response.id),
            service: response.service,
            status: response.status,
            created_keys: response.created_keys,
            policy_version: response.policy_version,
        }
    }
}

impl From<CreateGraphQlPermissionsInput> for CreateGraphQlPermissionsRequest {
    fn from(input: CreateGraphQlPermissionsInput) -> Self {
        Self {
            confirm_orphans: input.confirm_orphans,
            confirm_flag_downgrade: input.confirm_flag_downgrade,
            renames: input
                .renames
                .into_iter()
                .map(|rename| KeyRenameDto {
                    from: rename.from,
                    to: rename.to,
                })
                .collect(),
        }
    }
}

/// Activates a GraphQL specification version as the caller of the request.
pub(super) async fn create_graphql_permissions_field(
    ctx: &Context<'_>,
    input: CreateGraphQlPermissionsInput,
) -> Result<GraphQlPermissionsActivationObject, Problem> {
    let caller = require_caller(ctx)?;
    let id = parse_spec_id(input.id.as_str())?;
    let key = idempotency_key(input.idempotency_key.as_deref())?;
    let request = CreateGraphQlPermissionsRequest::from(input);
    request.validate()?;
    let activation = create_graphql_permissions(state(ctx)?, caller, key, id, &request).await?;
    Ok(GraphQlPermissionsActivationObject::from(
        GraphQlPermissionsActivationResponse::from(&activation),
    ))
}

#[cfg(test)]
mod tests;
