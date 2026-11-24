//! The plan of a declarative route configuration (FR-58): the checks that the dry run and the
//! application share, and the aggregates that the application commits.

use std::collections::BTreeSet;
use std::time::SystemTime;

use iam_domain::{
    ActorRef, AnonymousRouteGuard, EntityVersion, RatePolicyId, Route, RouteConflictGuard,
    RouteDraft, RouteFields, RouteHost, RouteId, RouteParts, RouteScopeGuard, RouteSetDiff,
    RouteSetVersion, RouteStamp, ServiceName, UpstreamId,
};
use shared_domain::UuidGenerator;

use super::gateway_audit::{SystemEntryRefusal, refuse_system_entry};
use super::route_checks::RoutePorts;
use crate::error::IamError;

/// The audited action of an applied route configuration.
pub(crate) const AUDIT_ACTION: &str = "route_configuration.apply";

/// The kind of the audited entry: the route configuration of one host.
pub(crate) const AUDIT_KIND: &str = "route_configuration";

/// The host that a request names.
///
/// # Errors
///
/// [`IamError::Invalid`] with a violation of `host` when the text is not a host name.
pub(crate) fn host_of(text: &str) -> Result<RouteHost, IamError> {
    RouteHost::new(text)
        .map_err(|error| IamError::invalid_property("host", &error.to_string(), error.code()))
}

/// What a plan is made for: the declared set of a host, the version the caller read of the stored
/// set, who asks and when.
#[derive(Debug)]
pub(crate) struct RouteSetRequest<'a> {
    /// The host the set belongs to.
    pub host: &'a str,
    /// The declared routes; the host of a draft is replaced by `host`.
    pub routes: Vec<RouteDraft>,
    /// The version of the stored set that the caller read.
    pub expected: EntityVersion,
    /// Who asks.
    pub actor: &'a ActorRef,
    /// When the change is made.
    pub occurred_at: SystemTime,
}

/// One route that the set changes, with the version the stored route must hold.
#[derive(Debug)]
pub(crate) struct PlannedRoute {
    /// The route after the change, with its recorded event.
    pub route: Route,
    /// The version the stored route holds; none for a created route.
    pub expected: Option<EntityVersion>,
}

/// The validated plan of a set.
#[derive(Debug)]
pub(crate) struct RouteSetPlan {
    /// The host of the set.
    pub host: RouteHost,
    /// The version of the stored set the plan was made against.
    pub version: EntityVersion,
    /// The number of routes the host holds before the change.
    pub stored_count: usize,
    /// What the set changes.
    pub diff: RouteSetDiff,
    /// The deleted, the updated and the created routes, in that order.
    pub routes: Vec<PlannedRoute>,
    /// The routes of the host after the change.
    pub table: Vec<RouteParts>,
    /// The catalogue services of the routes the set touches, each once.
    pub services: Vec<ServiceName>,
    /// Whether the set needs `iam:route:anonymous`.
    pub anonymous_key: bool,
}

impl RouteSetPlan {
    /// The version of the set after the change.
    pub(crate) fn resulting_version(&self) -> EntityVersion {
        RouteSetVersion::of(&self.table)
    }

    /// The identifiers of the routes the set creates, updates and deletes.
    pub(crate) fn ids(&self) -> ChangedIds {
        let mut ids = ChangedIds::default();
        for planned in &self.routes {
            let parts = planned.route.parts();
            match (planned.expected, parts.deleted_at) {
                (None, _) => ids.created.push(parts.id),
                (Some(_), None) => ids.updated.push(parts.id),
                (Some(_), Some(_)) => ids.deleted.push(parts.id),
            }
        }
        ids
    }
}

/// The identifiers of the routes a set creates, updates and deletes.
#[derive(Debug, Default)]
pub(crate) struct ChangedIds {
    /// The created routes.
    pub created: Vec<RouteId>,
    /// The updated routes.
    pub updated: Vec<RouteId>,
    /// The deleted routes.
    pub deleted: Vec<RouteId>,
}

/// Plans the application of a declared route set against the stored routes of its host.
#[derive(Debug)]
pub(crate) struct RouteConfigurationPlanner<'a> {
    ports: &'a RoutePorts,
    max_routes: usize,
    ids: &'a dyn UuidGenerator,
}

impl<'a> RouteConfigurationPlanner<'a> {
    /// A planner over the ports, the largest set it accepts and the identifier source.
    pub(crate) const fn new(
        ports: &'a RoutePorts,
        max_routes: usize,
        ids: &'a dyn UuidGenerator,
    ) -> Self {
        Self {
            ports,
            max_routes,
            ids,
        }
    }

    /// Validates the whole set and plans its application; one violation rejects the set.
    ///
    /// # Errors
    ///
    /// 422 for a set larger than the limit or a route with invalid values, 412 for a stale
    /// version, 409 `system_entry` for a route that IAM manages itself, 403 for a service of the
    /// `iam` catalogue the actor cannot change, 422 for an unknown upstream, rate policy or a
    /// service that differs from the upstream's, 409 for a conflict of the set or a route table
    /// that the gateway could not build, and the storage failures.
    pub(crate) async fn plan(
        &self,
        request: RouteSetRequest<'_>,
    ) -> Result<RouteSetPlan, IamError> {
        let host = host_of(request.host)?;
        let declared = self.declared(&host, request.routes)?;
        let stored: Vec<RouteParts> = self
            .ports
            .routes
            .find_by_host(&host)
            .await?
            .iter()
            .map(|route| route.parts().clone())
            .collect();
        let version = RouteSetVersion::of(&stored);
        version.check(Some(request.expected))?;
        let diff = RouteSetDiff::between(&stored, declared);
        let refusal = Refusal {
            host: host.to_string(),
            actor: request.actor,
            occurred_at: request.occurred_at,
        };
        self.admit(&diff, &stored, &refusal).await?;
        let routes = self.planned(&diff, &refusal)?;
        let table = table_of(&stored, &routes);
        RouteConflictGuard::check_set(&table)?;
        self.ports.compiler.compile(&host, &table)?;
        Ok(RouteSetPlan {
            host,
            version,
            stored_count: stored.len(),
            services: services_of(&diff),
            anonymous_key: needs_anonymous_key(&diff),
            diff,
            routes,
            table,
        })
    }

    /// The validated configurations of the declared routes, on `host`.
    fn declared(
        &self,
        host: &RouteHost,
        routes: Vec<RouteDraft>,
    ) -> Result<Vec<RouteFields>, IamError> {
        if routes.len() > self.max_routes {
            return Err(IamError::invalid_property(
                "routes",
                &format!(
                    "A route configuration holds at most {} routes.",
                    self.max_routes
                ),
                "max_items",
            ));
        }
        routes
            .into_iter()
            .enumerate()
            .map(|(index, mut draft)| {
                draft.host = host.to_string();
                RouteFields::new(&draft)
                    .map_err(IamError::from)
                    .map_err(|error| indexed(index, error))
            })
            .collect()
    }

    /// Lets the set through when it writes no route on a host that IAM reserves, changes no route
    /// that IAM manages itself, every route it
    /// writes is of a service the API may change and every entry it names exists.
    async fn admit(
        &self,
        diff: &RouteSetDiff,
        stored: &[RouteParts],
        refusal: &Refusal<'_>,
    ) -> Result<(), IamError> {
        self.admit_host(diff, stored, refusal)?;
        for route in diff.removed() {
            self.admit_stored(route, refusal)?;
        }
        for changed in diff.changed() {
            self.admit_stored(&changed.before, refusal)?;
        }
        let written = diff
            .changed()
            .iter()
            .map(|changed| &changed.after)
            .chain(diff.added());
        let mut checked: Vec<(UpstreamId, ServiceName, Vec<RatePolicyId>)> = Vec::new();
        for fields in written {
            self.ports
                .admit_service(fields.service(), refusal.build())
                .await?;
            let references = (
                fields.upstream_id(),
                fields.service().clone(),
                fields.rate_policies().to_vec(),
            );
            if !checked.contains(&references) {
                self.ports.admit_references(fields).await?;
                checked.push(references);
            }
        }
        Ok(())
    }

    /// Refuses a set that creates or changes a route on a host that holds a system route: IAM
    /// reserves every route of the host it seeds its own routes on, so a caller's route cannot
    /// join them even when the set leaves the system routes unchanged.
    fn admit_host(
        &self,
        diff: &RouteSetDiff,
        stored: &[RouteParts],
        refusal: &Refusal<'_>,
    ) -> Result<(), IamError> {
        let writes = !diff.added().is_empty() || !diff.changed().is_empty();
        if writes && stored.iter().any(|route| route.system) {
            return Err(refuse_system_entry(
                self.ports.rejected_attempts.as_ref(),
                refusal.build(),
            ));
        }
        Ok(())
    }

    /// Refuses a stored route that IAM manages itself.
    fn admit_stored(&self, route: &RouteParts, refusal: &Refusal<'_>) -> Result<(), IamError> {
        if RouteScopeGuard::check_changeable(route.fields.service(), route.system).is_err() {
            return Err(refuse_system_entry(
                self.ports.rejected_attempts.as_ref(),
                refusal.build(),
            ));
        }
        Ok(())
    }

    /// The deleted, the updated and the created routes, each with its recorded event.
    fn planned(
        &self,
        diff: &RouteSetDiff,
        refusal: &Refusal<'_>,
    ) -> Result<Vec<PlannedRoute>, IamError> {
        let mut planned = Vec::new();
        for removed in diff.removed() {
            let mut route = Route::restore(removed.clone());
            route.delete(Some(removed.version), self.stamp(refusal))?;
            planned.push(PlannedRoute {
                route,
                expected: Some(removed.version),
            });
        }
        for changed in diff.changed() {
            let mut route = Route::restore(changed.before.clone());
            let stamp = self.stamp(refusal);
            route.update(Some(changed.before.version), changed.after.clone(), stamp)?;
            planned.push(PlannedRoute {
                route,
                expected: Some(changed.before.version),
            });
        }
        for fields in diff.added() {
            let id = RouteId::from_uuid(self.ids.generate());
            planned.push(PlannedRoute {
                route: Route::create(id, fields.clone(), false, self.stamp(refusal)),
                expected: None,
            });
        }
        Ok(planned)
    }

    /// The stamp of the event of one route.
    fn stamp(&self, refusal: &Refusal<'_>) -> RouteStamp {
        RouteStamp {
            event_id: self.ids.generate(),
            actor: refusal.actor.clone(),
            occurred_at: refusal.occurred_at,
        }
    }
}

/// What a refusal of the set records.
struct Refusal<'a> {
    host: String,
    actor: &'a ActorRef,
    occurred_at: SystemTime,
}

impl<'a> Refusal<'a> {
    /// The refusal of a change of the configuration of the host.
    fn build(&self) -> SystemEntryRefusal<'a> {
        SystemEntryRefusal {
            action: AUDIT_ACTION,
            kind: AUDIT_KIND,
            target_id: self.host.clone(),
            actor: self.actor,
            occurred_at: self.occurred_at,
        }
    }
}

/// The error of the route at `index` of the set, with its properties named `routes[index].…`.
pub(crate) fn indexed(index: usize, error: IamError) -> IamError {
    let IamError::Invalid(violations) = error else {
        return error;
    };
    IamError::Invalid(
        violations
            .into_iter()
            .map(|mut violation| {
                violation.property_path = format!("routes[{index}].{}", violation.property_path);
                violation
            })
            .collect(),
    )
}

/// The routes of the host after the change: the stored routes the set keeps and the planned
/// routes that are not deleted.
fn table_of(stored: &[RouteParts], planned: &[PlannedRoute]) -> Vec<RouteParts> {
    let touched: BTreeSet<RouteId> = planned
        .iter()
        .filter(|planned| planned.expected.is_some())
        .map(|planned| planned.route.parts().id)
        .collect();
    stored
        .iter()
        .filter(|route| !touched.contains(&route.id))
        .cloned()
        .chain(
            planned
                .iter()
                .map(|planned| planned.route.parts())
                .filter(|route| route.deleted_at.is_none())
                .cloned(),
        )
        .collect()
}

/// The catalogue services of the routes the set touches, each once, before and after the change.
fn services_of(diff: &RouteSetDiff) -> Vec<ServiceName> {
    let mut services: Vec<ServiceName> = Vec::new();
    let touched = diff
        .removed()
        .iter()
        .map(|route| route.fields.service())
        .chain(
            diff.changed()
                .iter()
                .flat_map(|changed| [changed.before.fields.service(), changed.after.service()]),
        )
        .chain(diff.added().iter().map(RouteFields::service));
    for service in touched {
        if !services.contains(service) {
            services.push(service.clone());
        }
    }
    services
}

/// Whether the set creates an anonymous or audit-only route or changes `anonymous` or
/// `enforcement` of a route.
fn needs_anonymous_key(diff: &RouteSetDiff) -> bool {
    diff.added()
        .iter()
        .any(AnonymousRouteGuard::needs_key_on_create)
        || diff.changed().iter().any(|changed| {
            AnonymousRouteGuard::needs_key_on_update(&changed.before.fields, &changed.after)
        })
}

#[cfg(test)]
mod tests;
