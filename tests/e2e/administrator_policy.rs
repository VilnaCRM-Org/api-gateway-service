//! The policy that lets the service caller of the scenarios call IAM's own operations.
//!
//! IAM refuses every caller of its REST operations that lacks the keys of the rule table
//! (Story 6.11). The scenarios that predate that rule authenticate as the service
//! [`CALLER_SERVICE`] and exercise the operations themselves, not their authorization, so the
//! policy reads of their application instance give that service one global assignment of a role
//! that grants exactly the keys of the bootstrapped `iam-platform-admin` role. Every other subject,
//! and every catalogue, is read from the scenario database unchanged, and no row is written, so
//! policy versions, listings and audit records stay as the scenarios expect. Story 6.12 moves the
//! scenarios onto the bootstrapped administrator itself.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use iam_domain::{
    AssignmentScope, CompiledRoleSet, GrantStatus, PermissionGrant, PlatformAdministrator,
    PolicyReadRepository, RepositoryError, RoleAssignment, RoleId, ServiceCatalog, ServiceName,
    SubjectPolicy, SubjectRef,
};

use crate::tokens::CALLER_SERVICE;

/// The id of the in-memory role that holds the administrator's keys; no stored role has it.
const ADMINISTRATOR_ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-00000000ad01";

/// Policy reads of the scenario database in which the service caller holds the administrator's
/// keys.
#[derive(Debug)]
pub(crate) struct AdministratorCallerPolicy {
    inner: Arc<dyn PolicyReadRepository>,
    caller: SubjectRef,
    role: RoleId,
    role_set: CompiledRoleSet,
}

impl AdministratorCallerPolicy {
    /// Reads through `inner` and adds the administrator's keys to the policy of the caller.
    ///
    /// # Panics
    ///
    /// When a constant above does not parse, which is a defect of the suite.
    pub(crate) fn wrapping(inner: Arc<dyn PolicyReadRepository>) -> Self {
        let grants = PlatformAdministrator::GRANTS.iter().map(|raw| {
            (
                PermissionGrant::parse(raw).expect("an administrator grant"),
                GrantStatus::Active,
            )
        });
        Self {
            inner,
            caller: SubjectRef::service(
                ServiceName::new(CALLER_SERVICE).expect("a valid service name"),
            ),
            role: RoleId::parse(ADMINISTRATOR_ROLE).expect("a valid role id"),
            role_set: CompiledRoleSet::compile(grants),
        }
    }

    async fn subject_policy(&self, subject: &SubjectRef) -> Result<SubjectPolicy, RepositoryError> {
        let stored = self.inner.read_subject_policy(subject).await?;
        if *subject != self.caller {
            return Ok(stored);
        }
        let mut assignments = stored.assignments().to_vec();
        assignments.push(RoleAssignment::new(
            self.role,
            AssignmentScope::Global,
            None,
        ));
        let mut role_sets: BTreeMap<RoleId, CompiledRoleSet> = stored.role_sets().clone();
        role_sets.insert(self.role, self.role_set.clone());
        Ok(SubjectPolicy::new(stored.epoch(), assignments, role_sets))
    }

    async fn service_catalog(
        &self,
        service: &ServiceName,
    ) -> Result<Option<ServiceCatalog>, RepositoryError> {
        self.inner.read_service_catalog(service).await
    }
}

#[async_trait]
impl PolicyReadRepository for AdministratorCallerPolicy {
    async fn read_subject_policy(
        &self,
        subject: &SubjectRef,
    ) -> Result<SubjectPolicy, RepositoryError> {
        self.subject_policy(subject).await
    }

    async fn read_service_catalog(
        &self,
        service: &ServiceName,
    ) -> Result<Option<ServiceCatalog>, RepositoryError> {
        self.service_catalog(service).await
    }
}
