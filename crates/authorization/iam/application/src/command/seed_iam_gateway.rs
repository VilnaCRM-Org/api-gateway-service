//! Seeds the upstream `iam-control` and the routes of IAM's management API (FR-5), or restores
//! them to their seeded state.

use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    ActorRef, ChangeId, DecisionEffect, EntityVersion, IamChange, IamChangeParts, IamGatewaySeed,
    IamUnitOfWork, Route, RouteConflictGuard, RouteFields, RouteHost, RouteId, RoutePageQuery,
    RouteParts, RouteRepository, RouteStamp, RouteStatement, SystemComponent, Upstream,
    UpstreamFields, UpstreamId, UpstreamParts, UpstreamRepository, UpstreamStamp,
    UpstreamStatement, WriteMode,
};
use shared_domain::{Clock, Command, CommandHandler, UuidGenerator};

use super::gateway_audit::{ChangeRecord, committed};
use super::route_checks::summary_of;
use crate::error::IamError;

/// The audited action of a seeded upstream.
const UPSTREAM_CREATE: &str = "upstream.create";

/// The audited action of a restored upstream.
const UPSTREAM_UPDATE: &str = "upstream.update";

/// The audited action of a seeded route.
const ROUTE_CREATE: &str = "route.create";

/// The audited action of a restored route.
const ROUTE_UPDATE: &str = "route.update";

/// The audited action of a route that a repair retires.
const ROUTE_DELETE: &str = "route.delete";

/// The number of routes that one page of the routes of an upstream holds.
const PAGE_SIZE: u32 = 100;

/// [`PAGE_SIZE`] as a length.
const PAGE_LEN: usize = 100;

/// What the command does with the entries that exist already.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedMode {
    /// Inserts what is absent and never changes an existing entry; an entry that occupies the
    /// place of a seeded one without being a system entry refuses the command with
    /// [`IamError::SeedConflict`] before anything is written.
    Seed,
    /// Inserts what is absent and restores an existing entry that is not the seeded one (not a
    /// system entry, or a different configuration) to the system entry, as a revocation-class
    /// change.
    Repair,
}

/// The command that seeds the upstream `iam-control` and the routes of IAM's management API on
/// `host` as `system:bootstrap`; the command returns no data.
#[derive(Debug, Clone)]
pub struct SeedIamGatewayCommand {
    /// The host of IAM's management routes.
    pub host: RouteHost,
    /// What happens to an entry that exists already.
    pub mode: SeedMode,
}

impl Command for SeedIamGatewayCommand {
    type Error = IamError;
    const NAME: &'static str = "SeedIamGatewayCommand";
}

/// Handles [`SeedIamGatewayCommand`].
///
/// It inserts the upstream `iam-control` when no upstream of that name exists, then each seeded
/// route that is absent from the host, as system entries of the catalogue service `iam`. Each
/// entry is one change of its own: the write, its event, the state record that the unit of work
/// adds in the same transaction, and one audit record with the actor `system:bootstrap`.
///
/// An entry is the seeded one only when it is a system entry, forwards to the seeded upstream
/// and holds the seeded configuration. In [`SeedMode::Seed`] a system entry that exists is left as
/// it is, and an entry that is not a system entry (an upstream named `iam-control` or a route of
/// the seeded host, host, pattern and methods that a caller created first) refuses the command with
/// [`IamError::SeedConflict`] before anything is written. In [`SeedMode::Repair`] such an entry
/// is replaced by the system entry, and a system entry whose configuration differs is updated to
/// the seeded one, each as a revocation-class change; the update writes `system = true` itself.
/// A non-system upstream that a repair turns into the system upstream keeps its identifier, so
/// every non-system route on any host that forwards to it is deleted first (a revocation-class
/// change each) and is never left pointing at IAM's management API; in [`SeedMode::Seed`] such
/// routes are named in the [`IamError::SeedConflict`] with the upstream.
/// The caller serializes concurrent runs with the bootstrap lock.
#[derive(Debug)]
pub struct SeedIamGatewayCommandHandler {
    upstreams: Arc<dyn UpstreamRepository>,
    routes: Arc<dyn RouteRepository>,
    unit_of_work: Arc<dyn IamUnitOfWork>,
    clock: Arc<dyn Clock>,
    uuid_generator: Arc<dyn UuidGenerator>,
}

/// The actor of every change of the seed.
const fn actor() -> ActorRef {
    ActorRef::System(SystemComponent::Bootstrap)
}

/// The effect of a change in `mode`.
const fn effect_of(mode: SeedMode) -> DecisionEffect {
    match mode {
        SeedMode::Seed => DecisionEffect::Affected,
        SeedMode::Repair => DecisionEffect::RevocationClass,
    }
}

/// How the conflict of the seed names a route.
fn describe(route: &RouteParts) -> String {
    format!(
        "route {} ({} {})",
        route.id,
        route.fields.host(),
        route.fields.path_pattern()
    )
}

/// Whether `stored` is the seeded route that `fields` describes: the same host, path pattern and
/// methods.
fn is_same_target(stored: &RouteFields, fields: &RouteFields) -> bool {
    stored.host() == fields.host()
        && stored.path_pattern() == fields.path_pattern()
        && stored.methods() == fields.methods()
}

impl SeedIamGatewayCommandHandler {
    /// A handler over the upstream and route repositories, the unit of work, the clock and the
    /// identifier source.
    #[must_use]
    pub const fn new(
        upstreams: Arc<dyn UpstreamRepository>,
        routes: Arc<dyn RouteRepository>,
        unit_of_work: Arc<dyn IamUnitOfWork>,
        clock: Arc<dyn Clock>,
        uuid_generator: Arc<dyn UuidGenerator>,
    ) -> Self {
        Self {
            upstreams,
            routes,
            unit_of_work,
            clock,
            uuid_generator,
        }
    }

    async fn seed(&self, command: SeedIamGatewayCommand) -> Result<(), IamError> {
        let seed = IamGatewaySeed::new(command.host);
        if command.mode == SeedMode::Seed {
            self.refuse_occupants(&seed).await?;
        }
        let upstream_id = self.ensure_upstream(command.mode).await?;
        self.ensure_routes(&seed, upstream_id, command.mode).await
    }

    /// Refuses the seed when an entry that is not a system entry occupies the place of the seeded
    /// upstream or of a seeded route, naming every such entry; nothing is written.
    async fn refuse_occupants(&self, seed: &IamGatewaySeed) -> Result<(), IamError> {
        let draft = IamGatewaySeed::upstream_draft();
        let fields = UpstreamFields::new(IamGatewaySeed::UPSTREAM_NAME, &draft)?;
        let stored = self.upstreams.find_by_name(fields.name()).await?;
        let mut occupants: Vec<String> = stored
            .iter()
            .map(Upstream::parts)
            .filter(|upstream| !upstream.system)
            .map(|upstream| format!("upstream {} ({})", upstream.name, upstream.id))
            .collect();
        if let Some(squatter) = stored.as_ref().filter(|upstream| !upstream.parts().system) {
            occupants.extend(self.callers_routes_to(squatter.parts().id).await?);
        }
        let upstream_id = stored.map_or_else(
            || UpstreamId::from_uuid(self.uuid_generator.generate()),
            |upstream| upstream.parts().id,
        );
        let table = self.routes.find_by_host(seed.host()).await?;
        for draft in seed.route_drafts(upstream_id) {
            let fields = RouteFields::new(&draft)?;
            occupants.extend(
                table
                    .iter()
                    .map(Route::parts)
                    .filter(|route| !route.system && is_same_target(&route.fields, &fields))
                    .map(describe),
            );
        }
        occupants.sort();
        occupants.dedup();
        if occupants.is_empty() {
            Ok(())
        } else {
            Err(IamError::SeedConflict(occupants.join(", ")))
        }
    }

    /// Every route that is not deleted and forwards to `upstream`, on any host.
    async fn referencing(&self, upstream: UpstreamId) -> Result<Vec<RouteParts>, IamError> {
        let mut found = Vec::new();
        let mut after = None;
        loop {
            let page = self
                .routes
                .find_page(&RoutePageQuery {
                    limit: PAGE_SIZE,
                    after,
                    host: None,
                    upstream: Some(upstream),
                    service: None,
                })
                .await?;
            let Some(last) = page.last() else { break };
            after = Some(last.parts().id);
            let full = page.len() >= PAGE_LEN;
            found.extend(page.iter().map(|route| route.parts().clone()));
            if !full {
                break;
            }
        }
        Ok(found)
    }

    /// How the conflict names each non-system route that forwards to `upstream`.
    async fn callers_routes_to(&self, upstream: UpstreamId) -> Result<Vec<String>, IamError> {
        Ok(self
            .referencing(upstream)
            .await?
            .iter()
            .filter(|route| !route.system)
            .map(describe)
            .collect())
    }

    /// Deletes every non-system route that forwards to `upstream`, as a revocation-class change
    /// each: the upstream is about to become the system upstream, and a route of a caller must
    /// not forward to it.
    async fn retire_referencing(&self, upstream: UpstreamId) -> Result<(), IamError> {
        for before in self.referencing(upstream).await? {
            if !before.system {
                self.retire_route(before).await?;
            }
        }
        Ok(())
    }

    async fn retire_route(&self, before: RouteParts) -> Result<(), IamError> {
        let now = self.clock.now();
        let mut route = Route::restore(before.clone());
        route.delete(Some(before.version), self.route_stamp(now))?;
        let events = route.pull_envelopes()?;
        let record = ChangeRecord {
            action: ROUTE_DELETE,
            kind: "route",
            target_id: before.id.to_string(),
            actor: &actor(),
            occurred_at: now,
            before: Some(summary_of(&before, &format!(" system={}", before.system))),
            after: summary_of(route.parts(), " deleted=true"),
            idempotency: None,
        };
        let audit = committed(self.uuid_generator.as_ref(), record)?;
        let change = IamChange::new(IamChangeParts {
            change_id: self.change_id(),
            effect: effect_of(SeedMode::Repair),
            statements: vec![RouteStatement::update(&route, before.version).into()],
            events,
            audit,
            entity_version: route.parts().version,
            idempotency: None,
        })?;
        self.commit(change).await
    }

    async fn commit(&self, change: IamChange) -> Result<(), IamError> {
        self.unit_of_work
            .commit(change, WriteMode::Published)
            .await?;
        Ok(())
    }

    fn change_id(&self) -> ChangeId {
        ChangeId::from_uuid(self.uuid_generator.generate())
    }

    /// The identifier of the seeded upstream, after it was inserted when absent and restored when
    /// `mode` asks for it and its settings differ.
    async fn ensure_upstream(&self, mode: SeedMode) -> Result<UpstreamId, IamError> {
        let draft = IamGatewaySeed::upstream_draft();
        let fields = UpstreamFields::new(IamGatewaySeed::UPSTREAM_NAME, &draft)?;
        match self.upstreams.find_by_name(fields.name()).await? {
            None => self.insert_upstream(fields, mode).await,
            Some(stored) => {
                let id = stored.parts().id;
                let seeded = stored.parts().system && stored.parts().settings == *fields.settings();
                if mode == SeedMode::Repair && !seeded {
                    if !stored.parts().system {
                        self.retire_referencing(id).await?;
                    }
                    self.update_upstream(stored, fields).await?;
                }
                Ok(id)
            }
        }
    }

    async fn insert_upstream(
        &self,
        fields: UpstreamFields,
        mode: SeedMode,
    ) -> Result<UpstreamId, IamError> {
        let now = self.clock.now();
        let id = UpstreamId::from_uuid(self.uuid_generator.generate());
        let service = fields.settings().catalog_service().clone();
        let stamp = self.upstream_stamp(now);
        let mut upstream = Upstream::create(id, fields, true, stamp);
        let events = upstream.pull_envelopes()?;
        let record = ChangeRecord {
            action: UPSTREAM_CREATE,
            kind: "upstream",
            target_id: id.to_string(),
            actor: &actor(),
            occurred_at: now,
            before: None,
            after: format!("catalogService={service} version=1 system=true"),
            idempotency: None,
        };
        let audit = committed(self.uuid_generator.as_ref(), record)?;
        let change = IamChange::new(IamChangeParts {
            change_id: self.change_id(),
            effect: effect_of(mode),
            statements: vec![UpstreamStatement::insert(&upstream).into()],
            events,
            audit,
            entity_version: EntityVersion::INITIAL,
            idempotency: None,
        })?;
        self.commit(change).await?;
        Ok(id)
    }

    /// Updates the stored upstream to the seeded settings and sets `system` explicitly, so that a
    /// non-system occupant becomes the system entry.
    async fn update_upstream(
        &self,
        upstream: Upstream,
        fields: UpstreamFields,
    ) -> Result<(), IamError> {
        let now = self.clock.now();
        let before = upstream.parts().clone();
        let mut upstream = Upstream::restore(UpstreamParts {
            system: true,
            ..before.clone()
        });
        upstream.update(Some(before.version), fields, self.upstream_stamp(now))?;
        let events = upstream.pull_envelopes()?;
        let record = ChangeRecord {
            action: UPSTREAM_UPDATE,
            kind: "upstream",
            target_id: before.id.to_string(),
            actor: &actor(),
            occurred_at: now,
            before: Some(format!(
                "catalogService={} version={} system={}",
                before.settings.catalog_service(),
                before.version.value(),
                before.system
            )),
            after: format!(
                "catalogService={} version={} system=true",
                upstream.parts().settings.catalog_service(),
                upstream.parts().version.value()
            ),
            idempotency: None,
        };
        let audit = committed(self.uuid_generator.as_ref(), record)?;
        let change = IamChange::new(IamChangeParts {
            change_id: self.change_id(),
            effect: effect_of(SeedMode::Repair),
            statements: vec![UpstreamStatement::update(&upstream, before.version).into()],
            events,
            audit,
            entity_version: upstream.parts().version,
            idempotency: None,
        })?;
        self.commit(change).await
    }

    fn upstream_stamp(&self, occurred_at: SystemTime) -> UpstreamStamp {
        UpstreamStamp {
            event_id: self.uuid_generator.generate(),
            actor: actor(),
            occurred_at,
        }
    }

    fn route_stamp(&self, occurred_at: SystemTime) -> RouteStamp {
        RouteStamp {
            event_id: self.uuid_generator.generate(),
            actor: actor(),
            occurred_at,
        }
    }

    /// Inserts each seeded route that the host lacks and, in [`SeedMode::Repair`], restores each
    /// one whose configuration differs.
    async fn ensure_routes(
        &self,
        seed: &IamGatewaySeed,
        upstream_id: UpstreamId,
        mode: SeedMode,
    ) -> Result<(), IamError> {
        let mut table: Vec<RouteParts> = self
            .routes
            .find_by_host(seed.host())
            .await?
            .iter()
            .map(|route| route.parts().clone())
            .collect();
        for draft in seed.route_drafts(upstream_id) {
            let fields = RouteFields::new(&draft)?;
            let stored = table
                .iter()
                .position(|route| is_same_target(&route.fields, &fields));
            match (stored, mode) {
                (None, _) => {
                    let inserted = self.insert_route(fields, &table, mode).await?;
                    table.push(inserted);
                }
                (Some(index), SeedMode::Repair) => {
                    self.restore_route(&mut table, index, fields).await?;
                }
                (Some(_), SeedMode::Seed) => {}
            }
        }
        Ok(())
    }

    async fn insert_route(
        &self,
        fields: RouteFields,
        table: &[RouteParts],
        mode: SeedMode,
    ) -> Result<RouteParts, IamError> {
        let now = self.clock.now();
        let id = RouteId::from_uuid(self.uuid_generator.generate());
        let mut route = Route::create(id, fields, true, self.route_stamp(now));
        RouteConflictGuard::check_candidate(route.parts(), table)?;
        let events = route.pull_envelopes()?;
        let record = ChangeRecord {
            action: ROUTE_CREATE,
            kind: "route",
            target_id: id.to_string(),
            actor: &actor(),
            occurred_at: now,
            before: None,
            after: summary_of(route.parts(), " system=true"),
            idempotency: None,
        };
        let audit = committed(self.uuid_generator.as_ref(), record)?;
        let change = IamChange::new(IamChangeParts {
            change_id: self.change_id(),
            effect: effect_of(mode),
            statements: vec![RouteStatement::insert(&route).into()],
            events,
            audit,
            entity_version: EntityVersion::INITIAL,
            idempotency: None,
        })?;
        self.commit(change).await?;
        Ok(route.parts().clone())
    }

    /// Updates the stored route at `index` of the table to `fields` and sets `system` explicitly
    /// when it is not the seeded route: not a system route, or a different configuration.
    async fn restore_route(
        &self,
        table: &mut [RouteParts],
        index: usize,
        fields: RouteFields,
    ) -> Result<(), IamError> {
        let Some(before) = table
            .get(index)
            .filter(|stored| !stored.system || stored.fields != fields)
        else {
            return Ok(());
        };
        let before = before.clone();
        let now = self.clock.now();
        let mut route = Route::restore(RouteParts {
            system: true,
            ..before.clone()
        });
        route.update(Some(before.version), fields, self.route_stamp(now))?;
        RouteConflictGuard::check_candidate(route.parts(), table)?;
        let events = route.pull_envelopes()?;
        let record = ChangeRecord {
            action: ROUTE_UPDATE,
            kind: "route",
            target_id: before.id.to_string(),
            actor: &actor(),
            occurred_at: now,
            before: Some(summary_of(&before, &format!(" system={}", before.system))),
            after: summary_of(route.parts(), " system=true"),
            idempotency: None,
        };
        let audit = committed(self.uuid_generator.as_ref(), record)?;
        let change = IamChange::new(IamChangeParts {
            change_id: self.change_id(),
            effect: effect_of(SeedMode::Repair),
            statements: vec![RouteStatement::update(&route, before.version).into()],
            events,
            audit,
            entity_version: route.parts().version,
            idempotency: None,
        })?;
        self.commit(change).await?;
        if let Some(slot) = table.get_mut(index) {
            *slot = route.parts().clone();
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl CommandHandler<SeedIamGatewayCommand> for SeedIamGatewayCommandHandler {
    async fn handle(&self, command: SeedIamGatewayCommand) -> Result<(), IamError> {
        self.seed(command).await
    }
}

#[cfg(test)]
mod tests;
