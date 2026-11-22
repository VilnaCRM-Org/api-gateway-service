//! One access check of FR-6: a target service, one target, an optional project and an optional
//! policy version to wait for.

use crate::error::InvalidAccessCheck;
use crate::value_object::http_method::HttpMethod;
use crate::value_object::identifier::ProjectId;
use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::service_name::ServiceName;

/// `rest {method, path}`: a REST request; the path is normalised and matched later (FR-7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestTarget {
    method: HttpMethod,
    path: String,
}

impl RestTarget {
    /// A REST target with the raw request path.
    #[must_use]
    pub const fn new(method: HttpMethod, path: String) -> Self {
        Self { method, path }
    }

    /// The HTTP method.
    #[must_use]
    pub const fn method(&self) -> HttpMethod {
        self.method
    }

    /// The raw request path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// `graphql {document, operationName?}`: a GraphQL document; its limits are decisions (FR-8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphQlTarget {
    document: String,
    operation_name: Option<String>,
}

impl GraphQlTarget {
    /// A GraphQL target with the document text and the optional operation name.
    #[must_use]
    pub const fn new(document: String, operation_name: Option<String>) -> Self {
        Self {
            document,
            operation_name,
        }
    }

    /// The document text.
    #[must_use]
    pub fn document(&self) -> &str {
        &self.document
    }

    /// The operation name, when the check names one.
    #[must_use]
    pub fn operation_name(&self) -> Option<&str> {
        self.operation_name.as_deref()
    }
}

/// `permissions [key, ...]`: 1 to 100 keys as sent; an unknown key is a decision (FR-9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionsTarget(Vec<String>);

impl PermissionsTarget {
    /// The largest number of keys of one check.
    pub const MAX_KEYS: usize = 100;

    /// Collects the keys.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAccessCheck::PermissionCount`] for no key or more than
    /// [`Self::MAX_KEYS`] keys.
    pub fn new(keys: Vec<String>) -> Result<Self, InvalidAccessCheck> {
        if keys.is_empty() || keys.len() > Self::MAX_KEYS {
            return Err(InvalidAccessCheck::PermissionCount);
        }
        Ok(Self(keys))
    }

    /// The keys in request order.
    #[must_use]
    pub fn keys(&self) -> &[String] {
        &self.0
    }
}

/// Exactly one of the three targets of a check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessTarget {
    /// A REST request.
    Rest(RestTarget),
    /// A GraphQL document.
    GraphQl(GraphQlTarget),
    /// A list of permission keys.
    Permissions(PermissionsTarget),
}

/// One access check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessCheck {
    service: ServiceName,
    target: AccessTarget,
    project: Option<ProjectId>,
    min_policy_version: Option<PolicyVersion>,
}

impl AccessCheck {
    /// A check of `target` on `service`, in `project` when one is given, decided on a policy at
    /// least as new as `min_policy_version` when one is given.
    #[must_use]
    pub const fn new(
        service: ServiceName,
        target: AccessTarget,
        project: Option<ProjectId>,
        min_policy_version: Option<PolicyVersion>,
    ) -> Self {
        Self {
            service,
            target,
            project,
            min_policy_version,
        }
    }

    /// The target service.
    #[must_use]
    pub const fn service(&self) -> &ServiceName {
        &self.service
    }

    /// The target.
    #[must_use]
    pub const fn target(&self) -> &AccessTarget {
        &self.target
    }

    /// The project of the check.
    #[must_use]
    pub const fn project(&self) -> Option<ProjectId> {
        self.project
    }

    /// The policy version the decision must reflect at least.
    #[must_use]
    pub const fn min_policy_version(&self) -> Option<PolicyVersion> {
        self.min_policy_version
    }
}

#[cfg(test)]
mod tests;
