//! Seeds the upstream `iam-control` and the routes of IAM's management API (FR-5), or restores
//! them to their seeded state.

use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    ActorRef, ChangeId, DecisionEffect, EntityVersion, IamChange, IamChangeParts, IamGatewaySeed,
    IamUnitOfWork, Route, RouteConflictGuard, RouteFields, RouteHost, RouteId, RouteParts,
    RouteRepository, RouteStamp, RouteStatement, SystemComponent, Upstream, UpstreamFields,
    UpstreamId, UpstreamRepository, UpstreamStamp, UpstreamStatement, WriteMode,
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

/// What the command does with the entries that exist already.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedMode {
    /// Inserts what is absent and never changes an existing entry.
    Seed,
    /// Inserts what is absent and restores an existing entry that differs from its seeded state,
    /// as a revocation-class change.
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
/// adds in the same transaction, and one audit record with the actor `system:bootstrap`. In
/// [`SeedMode::Seed`] an entry that exists is left as it is; in [`SeedMode::Repair`] an entry
/// whose configuration differs from the seeded one is updated to it as a revocation-class change.
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
        let upstream_id = self.ensure_upstream(command.mode).await?;
        self.ensure_routes(&seed, upstream_id, command.mode).await
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
                if mode == SeedMode::Repair && stored.parts().settings != *fields.settings() {
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

    async fn update_upstream(
        &self,
        mut upstream: Upstream,
        fields: UpstreamFields,
    ) -> Result<(), IamError> {
        let now = self.clock.now();
        let before = upstream.parts().clone();
        upstream.update(Some(before.version), fields, self.upstream_stamp(now))?;
        let events = upstream.pull_envelopes()?;
        let record = ChangeRecord {
            action: UPSTREAM_UPDATE,
            kind: "upstream",
            target_id: before.id.to_string(),
            actor: &actor(),
            occurred_at: now,
            before: Some(format!(
                "catalogService={} version={}",
                before.settings.catalog_service(),
                before.version.value()
            )),
            after: format!(
                "catalogService={} version={}",
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

    /// Updates the stored route at `index` of the table to `fields` when it differs.
    async fn restore_route(
        &self,
        table: &mut [RouteParts],
        index: usize,
        fields: RouteFields,
    ) -> Result<(), IamError> {
        let Some(before) = table.get(index).filter(|stored| stored.fields != fields) else {
            return Ok(());
        };
        let before = before.clone();
        let now = self.clock.now();
        let mut route = Route::restore(before.clone());
        route.update(Some(before.version), fields, self.route_stamp(now))?;
        RouteConflictGuard::check_candidate(route.parts(), table)?;
        let events = route.pull_envelopes()?;
        let record = ChangeRecord {
            action: ROUTE_UPDATE,
            kind: "route",
            target_id: before.id.to_string(),
            actor: &actor(),
            occurred_at: now,
            before: Some(summary_of(&before, " system=true")),
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
