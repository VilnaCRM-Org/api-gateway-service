//! The policy that makes the caller of the scenarios the administrator of IAM.
//!
//! IAM refuses every caller of its REST operations and GraphQL fields that lacks the keys of the
//! rule table (Stories 6.11 and 6.12). The scenarios exercise the operations themselves, not their
//! authorization, so they authenticate as the administrator [`ADMINISTRATOR_ID`]: the policy reads
//! of their application instance give that user one global assignment of a role that grants
//! exactly the keys of the bootstrapped `iam-platform-admin` role (`PlatformAdministrator::GRANTS`).
//! The assignment lives in memory because a real bootstrap would add a role, an assignment and a
//! policy version to every scenario database and move the listings, counts and events that the
//! scenarios assert; the scenarios of the first administrator bootstrap it for real. Every other
//! subject, and every catalogue, is read from the scenario database unchanged, and no row is
//! written.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use iam_domain::{
    AssignmentScope, CompiledRoleSet, GrantStatus, PermissionGrant, PlatformAdministrator,
    PolicyReadRepository, RepositoryError, RoleAssignment, RoleId, ServiceCatalog, ServiceName,
    SubjectPolicy, SubjectRef,
};
use shared_domain::Uuid;

use crate::tokens::ADMINISTRATOR_ID;

/// The id of the in-memory role that holds the administrator's keys; no stored role has it.
const ADMINISTRATOR_ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-00000000ad01";

/// Policy reads of the scenario database in which the administrator holds the keys of the
/// bootstrapped role.
#[derive(Debug)]
pub(crate) struct AdministratorCallerPolicy {
    inner: Arc<dyn PolicyReadRepository>,
    caller: SubjectRef,
    role: RoleId,
    role_set: CompiledRoleSet,
}

impl AdministratorCallerPolicy {
    /// Reads through `inner` and adds the administrator's keys to the policy of the administrator.
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
            caller: SubjectRef::user(Uuid::parse(ADMINISTRATOR_ID).expect("a valid user id")),
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
