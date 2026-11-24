//! The rule table of IAM's own REST operations (FR-4): what each operation requires of its caller.
//!
//! Every IAM operation has a catalogue key (`rest:iam:POST /api/roles`); the rule adds the reserved
//! `iam:` keys that the operation needs besides, or instead of, its catalogue key. An operation
//! that has no row is refused, so a story that adds an operation adds its row. The reserved keys
//! of grants and assignments (FR-25) and of specification changes (FR-30) depend on the content of
//! the request and are applied by the use cases of Story 6.14, not by this table.

use iam_domain::HttpMethod;

use crate::caller_rule::CallerRule;

/// `iam:validate:*`: the key that admits any caller of the decision API and of token resolution.
///
/// The caller rule of Story 6.13 also admits a caller that holds `iam:validate:{service}` for the
/// service it validates for, or for its own name when it resolves a token.
pub const VALIDATE_ALL: &str = "iam:validate:*";

/// `iam:policy:resync`: the reserved key of the operation that resyncs the policy state.
pub const POLICY_RESYNC: &str = "iam:policy:resync";

/// What an operation requires of its caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requirement {
    /// The catalogue key of the operation and nothing else.
    Catalogue,
    /// The reserved keys only: the operation has no catalogue key requirement.
    Reserved(&'static [&'static str]),
    /// The catalogue key of the operation and the reserved keys.
    CatalogueAndReserved(&'static [&'static str]),
    /// No catalogue key and no fixed key: the keys depend on the content of the request and are
    /// decided by the caller rule (FR-12).
    Caller(CallerRule),
}

impl Requirement {
    /// Whether the caller must hold the catalogue key of the operation.
    #[must_use]
    pub const fn needs_catalogue(self) -> bool {
        matches!(self, Self::Catalogue | Self::CatalogueAndReserved(_))
    }

    /// The caller rule of the row, when its keys depend on the content of the request.
    #[must_use]
    pub const fn caller_rule(self) -> Option<CallerRule> {
        match self {
            Self::Caller(rule) => Some(rule),
            Self::Catalogue | Self::Reserved(_) | Self::CatalogueAndReserved(_) => None,
        }
    }

    /// The reserved keys the caller must hold; none for a catalogue-only operation.
    #[must_use]
    pub const fn reserved(self) -> &'static [&'static str] {
        match self {
            Self::Catalogue | Self::Caller(_) => &[],
            Self::Reserved(keys) | Self::CatalogueAndReserved(keys) => keys,
        }
    }
}

/// The rule of one operation: its method and path template under `/api`, the name its audit
/// records give it and what it requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationRule {
    /// The HTTP method.
    pub method: HttpMethod,
    /// The path template as the router registers it, such as `/api/roles/{id}`.
    pub template: &'static str,
    /// The audited action of a refusal, such as `role.create`.
    pub action: &'static str,
    /// What the caller must hold.
    pub requirement: Requirement,
}

const fn row(
    method: HttpMethod,
    template: &'static str,
    action: &'static str,
    requirement: Requirement,
) -> OperationRule {
    OperationRule {
        method,
        template,
        action,
        requirement,
    }
}

/// The rule of one GraphQL root field that IAM owns: its coordinate (`Query.roles`), the name its
/// audit records give it and what it requires.
///
/// The requirement of a field is that of the REST operation of the same name, so both interfaces
/// enforce one rule (FR-4); the catalogue key of a field is `gql:iam:{coordinate}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GraphQlRule {
    /// The `{Type}.{field}` coordinate of the root field.
    pub coordinate: &'static str,
    /// The audited action of a refusal, such as `role.create`.
    pub action: &'static str,
    /// What the caller must hold.
    pub requirement: Requirement,
}

const fn field(
    coordinate: &'static str,
    action: &'static str,
    requirement: Requirement,
) -> GraphQlRule {
    GraphQlRule {
        coordinate,
        action,
        requirement,
    }
}

/// The rows of every GraphQL root field that IAM owns.
const GRAPHQL_RULES: &[GraphQlRule] = &[
    field(
        "Query.resolveToken",
        "token.resolve",
        Requirement::Caller(CallerRule::ResolveToken),
    ),
    field(
        "Query.validateAccess",
        "access.validate",
        Requirement::Caller(CallerRule::Validate),
    ),
    field(
        "Query.validateAccessBatch",
        "access.validate_batch",
        Requirement::Caller(CallerRule::Validate),
    ),
    field("Query.role", "role.read", Requirement::Catalogue),
    field("Query.roles", "role.list", Requirement::Catalogue),
    field(
        "Query.ratePolicy",
        "rate_policy.read",
        Requirement::Catalogue,
    ),
    field(
        "Query.ratePolicies",
        "rate_policy.list",
        Requirement::Catalogue,
    ),
    field("Query.userRole", "user_role.read", Requirement::Catalogue),
    field("Query.userRoles", "user_role.list", Requirement::Catalogue),
    field(
        "Query.userRolePermissions",
        "user_role_permission.list",
        Requirement::Catalogue,
    ),
    field(
        "Query.bulkOperation",
        "bulk_operation.read",
        Requirement::Catalogue,
    ),
    field(
        "Query.bulkOperations",
        "bulk_operation.list",
        Requirement::Catalogue,
    ),
    field(
        "Query.graphqlPermission",
        "graphql_permission.read",
        Requirement::Catalogue,
    ),
    field(
        "Query.graphqlPermissions",
        "graphql_permission.list",
        Requirement::Catalogue,
    ),
    field(
        "Query.restPermission",
        "rest_permission.read",
        Requirement::Catalogue,
    ),
    field(
        "Query.restPermissions",
        "rest_permission.list",
        Requirement::Catalogue,
    ),
    field(
        "Query.graphqlSpec",
        "graphql_spec.read",
        Requirement::Catalogue,
    ),
    field(
        "Query.graphqlSpecs",
        "graphql_spec.list",
        Requirement::Catalogue,
    ),
    field(
        "Query.openapiSpec",
        "openapi_spec.read",
        Requirement::Catalogue,
    ),
    field(
        "Query.openapiSpecs",
        "openapi_spec.list",
        Requirement::Catalogue,
    ),
    field("Query.upstream", "upstream.read", Requirement::Catalogue),
    field("Query.upstreams", "upstream.list", Requirement::Catalogue),
    field(
        "Mutation.createUpstream",
        "upstream.create",
        Requirement::Catalogue,
    ),
    field(
        "Mutation.updateUpstream",
        "upstream.update",
        Requirement::Catalogue,
    ),
    field(
        "Mutation.deleteUpstream",
        "upstream.delete",
        Requirement::Catalogue,
    ),
    field("Query.route", "route.read", Requirement::Catalogue),
    field("Query.routes", "route.list", Requirement::Catalogue),
    field(
        "Mutation.createRoute",
        "route.create",
        Requirement::Catalogue,
    ),
    field(
        "Mutation.updateRoute",
        "route.update",
        Requirement::Catalogue,
    ),
    field(
        "Mutation.deleteRoute",
        "route.delete",
        Requirement::Catalogue,
    ),
    field(
        "Query.routeConfiguration",
        "route_configuration.read",
        Requirement::Catalogue,
    ),
    field(
        "Mutation.applyRouteConfiguration",
        "route_configuration.apply",
        Requirement::Catalogue,
    ),
    field("Mutation.createRole", "role.create", Requirement::Catalogue),
    field("Mutation.updateRole", "role.update", Requirement::Catalogue),
    field("Mutation.deleteRole", "role.delete", Requirement::Catalogue),
    field(
        "Mutation.resyncPolicy",
        "policy.resync",
        Requirement::Reserved(&[POLICY_RESYNC]),
    ),
    field(
        "Mutation.createRatePolicy",
        "rate_policy.create",
        Requirement::Catalogue,
    ),
    field(
        "Mutation.updateRatePolicy",
        "rate_policy.update",
        Requirement::Catalogue,
    ),
    field(
        "Mutation.deleteRatePolicy",
        "rate_policy.delete",
        Requirement::Catalogue,
    ),
    field(
        "Mutation.setRolePermissions",
        "role_permission.replace",
        Requirement::Catalogue,
    ),
    field(
        "Mutation.assignUserRole",
        "user_role.assign",
        Requirement::Catalogue,
    ),
    field(
        "Mutation.updateUserRole",
        "user_role.update",
        Requirement::Catalogue,
    ),
    field(
        "Mutation.revokeUserRole",
        "user_role.revoke",
        Requirement::Catalogue,
    ),
    field(
        "Mutation.loadGraphqlSpec",
        "graphql_spec.load",
        Requirement::Catalogue,
    ),
    field(
        "Mutation.createGraphqlPermissions",
        "graphql_spec.activate",
        Requirement::Catalogue,
    ),
    field(
        "Mutation.retireGraphqlSpec",
        "graphql_spec.retire",
        Requirement::Catalogue,
    ),
    field(
        "Mutation.loadOpenapiSpec",
        "openapi_spec.load",
        Requirement::Catalogue,
    ),
    field(
        "Mutation.createRestPermissions",
        "openapi_spec.activate",
        Requirement::Catalogue,
    ),
    field(
        "Mutation.retireOpenapiSpec",
        "openapi_spec.retire",
        Requirement::Catalogue,
    ),
];

/// The rows of every IAM operation delivered so far.
const RULES: &[OperationRule] = &[
    row(
        HttpMethod::Post,
        "/api/token-resolutions",
        "token.resolve",
        Requirement::Caller(CallerRule::ResolveToken),
    ),
    row(
        HttpMethod::Post,
        "/api/access-validations",
        "access.validate",
        Requirement::Caller(CallerRule::Validate),
    ),
    row(
        HttpMethod::Post,
        "/api/access-validations/batch",
        "access.validate_batch",
        Requirement::Caller(CallerRule::Validate),
    ),
    row(
        HttpMethod::Post,
        "/api/roles",
        "role.create",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Get,
        "/api/roles",
        "role.list",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Get,
        "/api/roles/{id}",
        "role.read",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Patch,
        "/api/roles/{id}",
        "role.update",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Delete,
        "/api/roles/{id}",
        "role.delete",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Get,
        "/api/roles/{id}/permissions",
        "role_permission.read",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Put,
        "/api/roles/{id}/permissions",
        "role_permission.replace",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Post,
        "/api/user-roles",
        "user_role.assign",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Get,
        "/api/user-roles",
        "user_role.list",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Get,
        "/api/user-roles/{id}",
        "user_role.read",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Patch,
        "/api/user-roles/{id}",
        "user_role.update",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Delete,
        "/api/user-roles/{id}",
        "user_role.revoke",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Get,
        "/api/users/{userId}/role-permissions",
        "user_role_permission.list",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Post,
        "/api/policy-resyncs",
        "policy.resync",
        Requirement::Reserved(&[POLICY_RESYNC]),
    ),
    row(
        HttpMethod::Post,
        "/api/rate-policies",
        "rate_policy.create",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Get,
        "/api/rate-policies",
        "rate_policy.list",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Get,
        "/api/rate-policies/{id}",
        "rate_policy.read",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Patch,
        "/api/rate-policies/{id}",
        "rate_policy.update",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Delete,
        "/api/rate-policies/{id}",
        "rate_policy.delete",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Get,
        "/api/bulk-operations",
        "bulk_operation.list",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Get,
        "/api/bulk-operations/{id}",
        "bulk_operation.read",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Get,
        "/api/graphql-permissions",
        "graphql_permission.list",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Get,
        "/api/graphql-permissions/{id}",
        "graphql_permission.read",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Get,
        "/api/rest-permissions",
        "rest_permission.list",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Get,
        "/api/rest-permissions/{id}",
        "rest_permission.read",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Post,
        "/api/graphql-specs",
        "graphql_spec.load",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Get,
        "/api/graphql-specs",
        "graphql_spec.list",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Get,
        "/api/graphql-specs/{id}",
        "graphql_spec.read",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Get,
        "/api/graphql-specs/{id}/diff",
        "graphql_spec.diff",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Post,
        "/api/graphql-specs/{id}/permissions",
        "graphql_spec.activate",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Post,
        "/api/graphql-specs/{id}/retirement",
        "graphql_spec.retire",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Post,
        "/api/openapi-specs",
        "openapi_spec.load",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Get,
        "/api/openapi-specs",
        "openapi_spec.list",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Get,
        "/api/openapi-specs/{id}",
        "openapi_spec.read",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Get,
        "/api/openapi-specs/{id}/diff",
        "openapi_spec.diff",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Post,
        "/api/openapi-specs/{id}/permissions",
        "openapi_spec.activate",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Post,
        "/api/openapi-specs/{id}/retirement",
        "openapi_spec.retire",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Post,
        "/api/upstreams",
        "upstream.create",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Get,
        "/api/upstreams",
        "upstream.list",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Get,
        "/api/upstreams/{id}",
        "upstream.read",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Patch,
        "/api/upstreams/{id}",
        "upstream.update",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Delete,
        "/api/upstreams/{id}",
        "upstream.delete",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Post,
        "/api/routes",
        "route.create",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Get,
        "/api/routes",
        "route.list",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Get,
        "/api/routes/{id}",
        "route.read",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Patch,
        "/api/routes/{id}",
        "route.update",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Delete,
        "/api/routes/{id}",
        "route.delete",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Get,
        "/api/route-configurations/{host}",
        "route_configuration.read",
        Requirement::Catalogue,
    ),
    row(
        HttpMethod::Put,
        "/api/route-configurations/{host}",
        "route_configuration.apply",
        Requirement::Catalogue,
    ),
];

/// The rule table.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OperationRules;

impl OperationRules {
    /// Every row of the table.
    #[must_use]
    pub const fn all() -> &'static [OperationRule] {
        RULES
    }

    /// The row of the operation with `method` and the registered path `template`; `None` for an
    /// operation without a row.
    #[must_use]
    pub fn find(method: &str, template: &str) -> Option<&'static OperationRule> {
        RULES
            .iter()
            .find(|rule| rule.method.as_str() == method && rule.template == template)
    }

    /// Every row of the GraphQL root fields that IAM owns; a root field of the served schema that
    /// has a row here is IAM's, any other is the template's.
    #[must_use]
    pub const fn graphql() -> &'static [GraphQlRule] {
        GRAPHQL_RULES
    }

    /// The row of the root field at `coordinate` (`Query.roles`); `None` for a field that IAM
    /// does not own.
    #[must_use]
    pub fn find_graphql(coordinate: &str) -> Option<&'static GraphQlRule> {
        GRAPHQL_RULES
            .iter()
            .find(|rule| rule.coordinate == coordinate)
    }
}

#[cfg(test)]
mod tests;
