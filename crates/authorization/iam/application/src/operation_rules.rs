//! The rule table of IAM's own REST operations (FR-4): what each operation requires of its caller.
//!
//! Every IAM operation has a catalogue key (`rest:iam:POST /api/roles`); the rule adds the reserved
//! `iam:` keys that the operation needs besides, or instead of, its catalogue key. An operation
//! that has no row is refused, so a story that adds an operation adds its row. The reserved keys
//! of grants and assignments (FR-25) and of specification changes (FR-30) depend on the content of
//! the request and are applied by the use cases of Story 6.14, not by this table.

use iam_domain::HttpMethod;

/// `iam:validate:*`: the key of the decision API and of token resolution; the caller rule of
/// Story 6.13 narrows it to the target service of each check.
pub const VALIDATE_ALL: &str = "iam:validate:*";

/// What an operation requires of its caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requirement {
    /// The catalogue key of the operation and nothing else.
    Catalogue,
    /// The reserved keys only: the operation has no catalogue key requirement.
    Reserved(&'static [&'static str]),
    /// The catalogue key of the operation and the reserved keys.
    CatalogueAndReserved(&'static [&'static str]),
}

impl Requirement {
    /// Whether the caller must hold the catalogue key of the operation.
    #[must_use]
    pub const fn needs_catalogue(self) -> bool {
        matches!(self, Self::Catalogue | Self::CatalogueAndReserved(_))
    }

    /// The reserved keys the caller must hold; none for a catalogue-only operation.
    #[must_use]
    pub const fn reserved(self) -> &'static [&'static str] {
        match self {
            Self::Catalogue => &[],
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

const RESOLVE: &[&str] = &[VALIDATE_ALL];

/// The rows of every IAM operation delivered so far.
const RULES: &[OperationRule] = &[
    row(
        HttpMethod::Post,
        "/api/token-resolutions",
        "token.resolve",
        Requirement::Reserved(RESOLVE),
    ),
    row(
        HttpMethod::Post,
        "/api/access-validations",
        "access.validate",
        Requirement::Reserved(RESOLVE),
    ),
    row(
        HttpMethod::Post,
        "/api/access-validations/batch",
        "access.validate_batch",
        Requirement::Reserved(RESOLVE),
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
}

#[cfg(test)]
mod tests;
