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

use crate::tokens::{
    ADMINISTRATOR_ID, RESTRICTED_ADMINISTRATOR_ID, ROUTE_SCOPED_ADMINISTRATOR_ID, SERVICE_CALLERS,
};

/// The id of the in-memory role that holds the administrator's keys; no stored role has it.
const ADMINISTRATOR_ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-00000000ad01";

/// The id of the in-memory role of the administrator that lacks `iam:grant:wildcard`.
const RESTRICTED_ADMINISTRATOR_ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-00000000ad04";

/// The id of the in-memory role of the administrator that holds `iam:route:core` and no other
/// route key.
const ROUTE_SCOPED_ADMINISTRATOR_ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-00000000ad06";

/// The in-memory roles of the service callers of [`SERVICE_CALLERS`], in the same order.
const SERVICE_ROLES: [&str; 2] = [
    "0190f2a8-7b3c-7d4e-8f10-00000000ad11",
    "0190f2a8-7b3c-7d4e-8f10-00000000ad12",
];

/// One caller of the scenarios and the in-memory role that gives it its keys.
#[derive(Debug)]
struct InjectedCaller {
    caller: SubjectRef,
    role: RoleId,
    role_set: CompiledRoleSet,
}

impl InjectedCaller {
    /// A caller `caller` that holds exactly `grants` in the role `role`.
    fn new(caller: SubjectRef, role: &str, grants: &[&str]) -> Self {
        let grants = grants.iter().map(|raw| {
            (
                PermissionGrant::parse(raw).expect("a scenario grant"),
                GrantStatus::Active,
            )
        });
        Self {
            caller,
            role: RoleId::parse(role).expect("a valid role id"),
            role_set: CompiledRoleSet::compile(grants),
        }
    }
}

/// Policy reads of the scenario database in which the administrator holds the keys of the
/// bootstrapped role, and each scenario service holds the one key of its row of
/// [`SERVICE_CALLERS`].
#[derive(Debug)]
pub(crate) struct AdministratorCallerPolicy {
    inner: Arc<dyn PolicyReadRepository>,
    callers: Vec<InjectedCaller>,
}

impl AdministratorCallerPolicy {
    /// Reads through `inner` and adds the administrator's keys to the policy of the administrator.
    ///
    /// # Panics
    ///
    /// When a constant above does not parse, which is a defect of the suite.
    pub(crate) fn wrapping(inner: Arc<dyn PolicyReadRepository>) -> Self {
        let administrator = InjectedCaller::new(
            SubjectRef::user(Uuid::parse(ADMINISTRATOR_ID).expect("a valid user id")),
            ADMINISTRATOR_ROLE,
            &PlatformAdministrator::GRANTS,
        );
        let restricted_grants: Vec<&str> = PlatformAdministrator::GRANTS
            .iter()
            .copied()
            .filter(|grant| *grant != "iam:grant:wildcard")
            .collect();
        let restricted = InjectedCaller::new(
            SubjectRef::user(Uuid::parse(RESTRICTED_ADMINISTRATOR_ID).expect("a valid user id")),
            RESTRICTED_ADMINISTRATOR_ROLE,
            &restricted_grants,
        );
        let mut route_scoped_grants: Vec<&str> = PlatformAdministrator::GRANTS
            .iter()
            .copied()
            .filter(|grant| *grant != "iam:route:*")
            .collect();
        route_scoped_grants.push("iam:route:core");
        let route_scoped = InjectedCaller::new(
            SubjectRef::user(Uuid::parse(ROUTE_SCOPED_ADMINISTRATOR_ID).expect("a valid user id")),
            ROUTE_SCOPED_ADMINISTRATOR_ROLE,
            &route_scoped_grants,
        );
        let services = SERVICE_CALLERS
            .iter()
            .zip(SERVICE_ROLES)
            .map(|((name, grant), role)| {
                InjectedCaller::new(
                    SubjectRef::service(ServiceName::new(name).expect("a valid service name")),
                    role,
                    &[*grant],
                )
            });
        Self {
            inner,
            callers: [administrator, restricted, route_scoped]
                .into_iter()
                .chain(services)
                .collect(),
        }
    }

    async fn subject_policy(&self, subject: &SubjectRef) -> Result<SubjectPolicy, RepositoryError> {
        let stored = self.inner.read_subject_policy(subject).await?;
        let Some(injected) = self
            .callers
            .iter()
            .find(|injected| injected.caller == *subject)
        else {
            return Ok(stored);
        };
        let mut assignments = stored.assignments().to_vec();
        assignments.push(RoleAssignment::new(
            injected.role,
            AssignmentScope::Global,
            None,
        ));
        let mut role_sets: BTreeMap<RoleId, CompiledRoleSet> = stored.role_sets().clone();
        role_sets.insert(injected.role, injected.role_set.clone());
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
