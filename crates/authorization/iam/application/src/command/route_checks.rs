//! The checks that the commands of the routes share (FR-57): the scope of the catalogue service,
//! the entries that the route names, and the host's candidate route table.

use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    ActorRef, AnonymousRouteGuard, ChangeStatement, GatewayPrecondition, IamUnitOfWork,
    PolicyReadRepository, RatePolicyRepository, RejectedAttemptLog, ReservedPermission, Route,
    RouteConflictGuard, RouteFields, RouteHost, RouteParts, RouteRepository, RouteScopeGuard,
    RouteScopeRefused, RouteTableCompiler, ServiceName, ServiceScope, SubjectRef,
    UpstreamRepository,
};

use super::gateway_audit::{
    SystemEntryRefusal, refuse_anonymous_route, refuse_route_scope, refuse_system_entry,
};
use crate::error::IamError;

/// The ports that the creation and the update of a route read and write.
#[derive(Debug, Clone)]
pub struct RoutePorts {
    /// The upstreams, to read the catalogue service the route must equal.
    pub upstreams: Arc<dyn UpstreamRepository>,
    /// The rate policies, to find those the route names.
    pub rate_policies: Arc<dyn RatePolicyRepository>,
    /// The routes of the host, for its candidate route table.
    pub routes: Arc<dyn RouteRepository>,
    /// Builds the candidate route table with the code the gateway uses.
    pub compiler: Arc<dyn RouteTableCompiler>,
    /// The policy of the actor, to tell a missing key from a refused entry.
    pub policies: Arc<dyn PolicyReadRepository>,
    /// Commits the change.
    pub unit_of_work: Arc<dyn IamUnitOfWork>,
    /// The buffer that receives the refusals.
    pub rejected_attempts: Arc<dyn RejectedAttemptLog>,
}

impl RoutePorts {
    /// Lets a change of a route of `service` through when the service is one that the API may
    /// change; a route of the `iam` service is refused with 403 for an actor without
    /// `iam:route:iam` and with 409 `system_entry` for one that holds it, and the refusal is
    /// offered to the buffer of the audit log.
    ///
    /// # Errors
    ///
    /// [`IamError::Forbidden`], [`IamError::SystemEntry`] or the storage failure of the read of
    /// the policy.
    pub(super) async fn admit_service(
        &self,
        service: &ServiceName,
        refusal: SystemEntryRefusal<'_>,
    ) -> Result<(), IamError> {
        if RouteScopeGuard::check_changeable(service, false).is_ok() {
            return Ok(());
        }
        let log = self.rejected_attempts.as_ref();
        if self
            .holds_route_key(refusal.actor, service, refusal.occurred_at)
            .await?
        {
            Err(refuse_system_entry(log, refusal))
        } else {
            Err(refuse_route_scope(log, refusal))
        }
    }

    /// Lets a change of a route of `hosts` through when none of the stored routes of those hosts
    /// is a system route: IAM seeds its own management routes on one host and reserves every
    /// route on it, so a change that creates, moves or changes a route there is refused with 409
    /// `system_entry`, and the refusal is offered to the buffer of the audit log.
    ///
    /// # Errors
    ///
    /// [`IamError::SystemEntry`] or the storage failure of the read of the routes.
    pub(super) async fn admit_hosts(
        &self,
        hosts: &[&RouteHost],
        refusal: SystemEntryRefusal<'_>,
    ) -> Result<(), IamError> {
        for host in hosts {
            let reserved = self
                .routes
                .find_by_host(host)
                .await?
                .iter()
                .any(|route| route.parts().system);
            if reserved {
                return Err(refuse_system_entry(
                    self.rejected_attempts.as_ref(),
                    refusal,
                ));
            }
        }
        Ok(())
    }

    /// Lets a whole route set through when the actor holds the route key of every service the
    /// set touches and, when the set needs it, `iam:route:anonymous`: the checks that the guarded
    /// unit of work applies to the commit of the same set. A refusal is offered to the buffer of
    /// the audit log. An IAM component acts without a check.
    ///
    /// # Errors
    ///
    /// [`IamError::Forbidden`] for a missing key, the storage failure of the read of the policy.
    pub(crate) async fn admit_set(
        &self,
        services: &[ServiceName],
        anonymous_key: bool,
        refusal: SystemEntryRefusal<'_>,
    ) -> Result<(), IamError> {
        let subject = match refusal.actor {
            ActorRef::User(id) => SubjectRef::user(*id),
            ActorRef::Service(name) => SubjectRef::service(name.clone()),
            ActorRef::System(_) => return Ok(()),
        };
        let policy = self.policies.read_subject_policy(&subject).await?;
        let now = refusal.occurred_at;
        let log = self.rejected_attempts.as_ref();
        if services
            .iter()
            .any(|service| RouteScopeGuard::check_policy(&policy, now, service).is_err())
        {
            return Err(refuse_route_scope(log, refusal));
        }
        if anonymous_key && AnonymousRouteGuard::check_policy(&policy, now).is_err() {
            return Err(refuse_anonymous_route(log, refusal));
        }
        Ok(())
    }

    /// Whether the actor holds a route key that reaches the service: `iam:route:*`, which never
    /// covers the `iam` service for a change but tells an administrator from a caller of one
    /// service, or the key of the service itself; an IAM component acts without a check.
    async fn holds_route_key(
        &self,
        actor: &ActorRef,
        service: &ServiceName,
        now: SystemTime,
    ) -> Result<bool, IamError> {
        let subject = match actor {
            ActorRef::User(id) => SubjectRef::user(*id),
            ActorRef::Service(name) => SubjectRef::service(name.clone()),
            ActorRef::System(_) => return Ok(true),
        };
        let policy = self.policies.read_subject_policy(&subject).await?;
        let everywhere = ReservedPermission::Route(ServiceScope::All);
        Ok(policy.holds_reserved(&everywhere, now)
            || RouteScopeGuard::check_policy(&policy, now, service).is_ok())
    }

    /// Lets a route through when its upstream exists and serves the route's service and every
    /// rate policy it names exists.
    ///
    /// # Errors
    ///
    /// [`IamError::Invalid`] with a violation of `upstreamId`, `service` or `ratePolicyIds`.
    pub(super) async fn admit_references(&self, fields: &RouteFields) -> Result<(), IamError> {
        let upstream = self
            .upstreams
            .find_by_id(fields.upstream_id())
            .await?
            .ok_or_else(|| {
                IamError::invalid_property(
                    "upstreamId",
                    "This value is not a stored upstream.",
                    "exists",
                )
            })?;
        let catalog = upstream.parts().settings.catalog_service();
        if catalog != fields.service() {
            return Err(RouteScopeRefused::ServiceMismatch {
                route: fields.service().clone(),
                upstream: catalog.clone(),
            }
            .into());
        }
        let wanted = fields.rate_policies();
        if self.rate_policies.find_many(wanted).await?.len() != wanted.len() {
            return Err(IamError::invalid_property(
                "ratePolicyIds",
                "This collection names a rate policy that is not stored.",
                "exists",
            ));
        }
        Ok(())
    }

    /// Lets a route through when it conflicts with no stored route of its host and the host's
    /// candidate route table, with the route in it, can be built.
    ///
    /// # Errors
    ///
    /// [`IamError::RouteTableConflict`] for a conflict, the storage failure of the read.
    pub(super) async fn admit_table(&self, candidate: &RouteParts) -> Result<(), IamError> {
        let host = candidate.fields.host();
        let mut table: Vec<RouteParts> = self
            .routes
            .find_by_host(host)
            .await?
            .iter()
            .map(|route| route.parts().clone())
            .filter(|route| route.id != candidate.id)
            .collect();
        RouteConflictGuard::check_candidate(candidate, &table)?;
        table.push(candidate.clone());
        self.compiler.compile(host, &table)?;
        Ok(())
    }
}

/// The state of a route that its audit record keeps: the service, the two flags that need
/// `iam:route:anonymous` and the version, then `suffix`.
pub(super) fn summary_of(route: &RouteParts, suffix: &str) -> String {
    format!(
        "service={} anonymous={} enforcement={} version={}{suffix}",
        route.fields.service(),
        route.fields.flags().anonymous(),
        route.fields.enforcement().as_str(),
        route.version.value()
    )
}

/// The statements of a change that writes `route`: first those that make the unit of work check,
/// under the lock of the policy epoch, what `admit_references` and `admit_table` read before it
/// (the upstream of the route is stored and serves its service, every rate policy is stored, and
/// the route table of the host, read again, holds with the route in it), then `write`. A
/// concurrent deletion or route write that this command did not see refuses the change as a
/// conflict (409) instead of committing on a stale answer.
pub(super) fn with_preconditions(route: &Route, write: ChangeStatement) -> Vec<ChangeStatement> {
    let parts = route.parts();
    vec![
        GatewayPrecondition::RouteTargets {
            upstream_id: parts.fields.upstream_id(),
            service: parts.fields.service().clone(),
            rate_policies: parts.fields.rate_policies().to_vec(),
        }
        .into(),
        GatewayPrecondition::RouteTable(Box::new(parts.clone())).into(),
        write,
    ]
}

/// The hosts of a change that touches a route before and after it, each once.
pub(super) fn hosts_of<'a>(before: &'a RouteHost, after: &'a RouteHost) -> Vec<&'a RouteHost> {
    if before == after {
        vec![after]
    } else {
        vec![before, after]
    }
}

/// The services of a change that touches a route before and after it, each once.
pub(super) fn services_of(before: &ServiceName, after: &ServiceName) -> Vec<ServiceName> {
    if before == after {
        vec![after.clone()]
    } else {
        vec![before.clone(), after.clone()]
    }
}
