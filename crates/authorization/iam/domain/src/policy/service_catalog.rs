//! The catalogue of one service as the decision path reads it: its active REST operations and
//! GraphQL type graphs, stamped with the policy version of the snapshot they were read in.

use std::sync::Arc;

use crate::value_object::graphql_type_graph::GraphQlTypeGraph;
use crate::value_object::policy_epoch::PolicyEpoch;
use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::rest_operation_set::RestOperationSet;
use crate::value_object::service_name::ServiceName;

/// What the active specification versions of a service say.
///
/// It is read in one snapshot with the policy epoch: one operation set per active `OpenAPI`
/// version and one type graph per active GraphQL version, in the order of their identifiers. The
/// operation sets and the type graphs are shared, so a clone costs no copy of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceCatalog {
    service: ServiceName,
    epoch: PolicyEpoch,
    rest_operations: Arc<[RestOperationSet]>,
    type_graphs: Arc<[GraphQlTypeGraph]>,
}

impl ServiceCatalog {
    /// The catalogue of `service`, read at `epoch`.
    #[must_use]
    pub fn new(
        service: ServiceName,
        epoch: PolicyEpoch,
        rest_operations: Vec<RestOperationSet>,
        type_graphs: Vec<GraphQlTypeGraph>,
    ) -> Self {
        Self {
            service,
            epoch,
            rest_operations: rest_operations.into(),
            type_graphs: type_graphs.into(),
        }
    }

    /// The service.
    #[must_use]
    pub const fn service(&self) -> &ServiceName {
        &self.service
    }

    /// The policy epoch of the snapshot the catalogue was read in.
    #[must_use]
    pub const fn epoch(&self) -> PolicyEpoch {
        self.epoch
    }

    /// The policy version of the snapshot the catalogue was read in.
    #[must_use]
    pub const fn policy_version(&self) -> PolicyVersion {
        self.epoch.version()
    }

    /// The operations of every active `OpenAPI` version.
    #[must_use]
    pub fn rest_operations(&self) -> &[RestOperationSet] {
        &self.rest_operations
    }

    /// The type graphs of every active GraphQL version.
    #[must_use]
    pub fn type_graphs(&self) -> &[GraphQlTypeGraph] {
        &self.type_graphs
    }
}

#[cfg(test)]
mod tests;
