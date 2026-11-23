//! GraphQL objects and resolvers of the retirement of a GraphQL or an `OpenAPI` specification
//! version.
//!
//! The resolvers share the use-case calls and the response shape of the REST handlers, so both
//! transports apply one set of rules.

use async_graphql::{Context, ID, InputObject, SimpleObject};
use shared_application::http::Problem;
use validator::Validate as _;

use super::{idempotency_key, require_caller, state};
use crate::http::graphql_spec::parse_spec_id;
use crate::http::spec_retirement::dto::{RetireSpecRequest, SpecRetirementResponse};
use crate::http::spec_retirement::{SpecRetirement, retire_graphql_spec, retire_openapi_spec};

/// Input of the mutation that retires a GraphQL specification version.
#[derive(Debug, InputObject)]
#[graphql(name = "RetireGraphqlSpecInput")]
pub struct RetireGraphQlSpecInput {
    /// The version to retire.
    pub id: ID,
    /// Accepts that grants of keys that leave the catalogue become inactive; without it, a retirement that would orphan grants fails with `ORPHAN_CONFIRMATION_REQUIRED`.
    #[graphql(default)]
    pub confirm_orphans: bool,
    /// Makes the retirement safe to repeat for 24 hours: 1 to 255 visible ASCII characters.
    pub idempotency_key: Option<String>,
}

/// Input of the mutation that retires an `OpenAPI` specification version.
#[derive(Debug, InputObject)]
#[graphql(name = "RetireOpenapiSpecInput")]
pub struct RetireOpenApiSpecInput {
    /// The version to retire.
    pub id: ID,
    /// Accepts that grants of keys that leave the catalogue become inactive; without it, a retirement that would orphan grants fails with `ORPHAN_CONFIRMATION_REQUIRED`.
    #[graphql(default)]
    pub confirm_orphans: bool,
    /// Makes the retirement safe to repeat for 24 hours: 1 to 255 visible ASCII characters.
    pub idempotency_key: Option<String>,
}

/// The result of a retirement.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "SpecRetirement")]
pub struct SpecRetirementObject {
    /// The identifier of the retired version.
    pub id: ID,
    /// The service the specification belongs to.
    pub service: String,
    /// `retired`.
    pub status: String,
    /// The policy version that the retirement produced.
    pub policy_version: i64,
}

impl From<SpecRetirementResponse> for SpecRetirementObject {
    fn from(response: SpecRetirementResponse) -> Self {
        Self {
            id: ID::from(response.id),
            service: response.service,
            status: response.status,
            policy_version: response.policy_version,
        }
    }
}

/// The object of a retirement that the use-case call produced.
fn object_of(retirement: &SpecRetirement) -> SpecRetirementObject {
    SpecRetirementObject::from(SpecRetirementResponse::from(retirement))
}

/// Retires a GraphQL specification version as the caller of the request.
pub(super) async fn retire_graphql_spec_field(
    ctx: &Context<'_>,
    input: RetireGraphQlSpecInput,
) -> Result<SpecRetirementObject, Problem> {
    let caller = require_caller(ctx)?;
    let id = parse_spec_id(input.id.as_str())?;
    let key = idempotency_key(input.idempotency_key.as_deref())?;
    let request = RetireSpecRequest {
        confirm_orphans: input.confirm_orphans,
    };
    request.validate()?;
    let retirement = retire_graphql_spec(state(ctx)?, caller, key, id, &request).await?;
    Ok(object_of(&retirement))
}

/// Retires an `OpenAPI` specification version as the caller of the request.
pub(super) async fn retire_openapi_spec_field(
    ctx: &Context<'_>,
    input: RetireOpenApiSpecInput,
) -> Result<SpecRetirementObject, Problem> {
    let caller = require_caller(ctx)?;
    let id = parse_spec_id(input.id.as_str())?;
    let key = idempotency_key(input.idempotency_key.as_deref())?;
    let request = RetireSpecRequest {
        confirm_orphans: input.confirm_orphans,
    };
    request.validate()?;
    let retirement = retire_openapi_spec(state(ctx)?, caller, key, id, &request).await?;
    Ok(object_of(&retirement))
}

#[cfg(test)]
mod tests;
