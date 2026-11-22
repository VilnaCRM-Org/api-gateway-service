//! The `GraphQlSpec` aggregate (board name `GraphQLSpec`): one immutable version of the GraphQL
//! schema of a service (FR-30, FR-31, FR-38).

pub mod event;
pub mod statement;

use std::time::SystemTime;

use shared_domain::{AggregateRoot, RecordedEvents, Uuid};

use crate::error::SpecTransitionRefused;
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::content_hash::ContentHash;
use crate::value_object::coordinate_set::CoordinateSet;
use crate::value_object::graphql_type_graph::GraphQlTypeGraph;
use crate::value_object::identifier::SpecId;
use crate::value_object::service_name::ServiceName;
use crate::value_object::spec_status::SpecStatus;
use event::{GraphQlSpecLoaded, GraphQlSpecRetired};

/// Who changes a version, when (from the `Clock` port) and the id of the event that records it
/// (from the `UuidGenerator` port).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecStamp {
    /// The id of the recorded event.
    pub event_id: Uuid,
    /// Who causes the change.
    pub actor: ActorRef,
    /// When the change happens.
    pub occurred_at: SystemTime,
}

/// What a new version is made of: the service, the hash of the SDL and its parsed type graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphQlSpecContent {
    /// The service the schema belongs to.
    pub service: ServiceName,
    /// The SHA-256 hash of the SDL.
    pub content_hash: ContentHash,
    /// The parsed schema.
    pub type_graph: GraphQlTypeGraph,
}

/// The stored state of a version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphQlSpecParts {
    /// The identifier.
    pub id: SpecId,
    /// The service, the hash and the type graph; never change after loading.
    pub content: GraphQlSpecContent,
    /// Where the version stands.
    pub status: SpecStatus,
    /// Who loaded the version.
    pub uploaded_by: ActorRef,
    /// When the version was loaded.
    pub created_at: SystemTime,
    /// When the version became active.
    pub activated_at: Option<SystemTime>,
    /// When the version was retired.
    pub retired_at: Option<SystemTime>,
}

/// Whether an activation changed the version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecActivation {
    /// The draft became active.
    Activated,
    /// The version was already active; nothing changed (FR-32: a no-op).
    AlreadyActive,
}

/// One version of the GraphQL schema of a service. The content never changes; only the status
/// moves, from `draft` to `active` to `retired`.
#[derive(Debug)]
pub struct GraphQlSpec {
    parts: GraphQlSpecParts,
    events: RecordedEvents,
}

impl GraphQlSpec {
    /// The largest SDL document, in bytes: 5 MiB (FR-30), checked before parsing starts.
    pub const MAX_SDL_BYTES: usize = 5 * 1024 * 1024;

    /// Builds a new draft version and records [`GraphQlSpecLoaded`].
    #[must_use]
    pub fn load(id: SpecId, content: GraphQlSpecContent, stamp: SpecStamp) -> Self {
        let mut spec = Self::restore(GraphQlSpecParts {
            id,
            content,
            status: SpecStatus::Draft,
            uploaded_by: stamp.actor.clone(),
            created_at: stamp.occurred_at,
            activated_at: None,
            retired_at: None,
        });
        let content = &spec.parts.content;
        let loaded = GraphQlSpecLoaded {
            event_id: stamp.event_id,
            spec_id: id,
            service: content.service.clone(),
            content_hash: content.content_hash,
            coordinate_count: u32::try_from(content.type_graph.field_count()).unwrap_or(u32::MAX),
            actor: stamp.actor,
            occurred_at: stamp.occurred_at,
        };
        spec.events.record(loaded);
        spec
    }

    /// Rebuilds a stored version; records nothing.
    #[must_use]
    pub fn restore(parts: GraphQlSpecParts) -> Self {
        Self {
            parts,
            events: RecordedEvents::default(),
        }
    }

    /// The state of the version.
    #[must_use]
    pub const fn parts(&self) -> &GraphQlSpecParts {
        &self.parts
    }

    /// The coordinates of the schema with their flags.
    #[must_use]
    pub fn coordinates(&self) -> CoordinateSet {
        self.parts.content.type_graph.coordinates()
    }

    /// Makes a draft active; records no event, since the catalogue records the activation as
    /// `GraphQlPermissionsCreated`. An active version stays as it is.
    ///
    /// # Errors
    ///
    /// [`SpecTransitionRefused`] for a retired version; nothing changes then.
    pub const fn activate(
        &mut self,
        at: SystemTime,
    ) -> Result<SpecActivation, SpecTransitionRefused> {
        match self.parts.status {
            SpecStatus::Draft => {
                self.parts.status = SpecStatus::Active;
                self.parts.activated_at = Some(at);
                Ok(SpecActivation::Activated)
            }
            SpecStatus::Active => Ok(SpecActivation::AlreadyActive),
            SpecStatus::Retired => Err(self.refused(SpecStatus::Active)),
        }
    }

    /// Retires an active version and records [`GraphQlSpecRetired`].
    ///
    /// # Errors
    ///
    /// [`SpecTransitionRefused`] for a draft or an already retired version; nothing changes then.
    pub fn retire(&mut self, stamp: SpecStamp) -> Result<(), SpecTransitionRefused> {
        if self.parts.status != SpecStatus::Active {
            return Err(self.refused(SpecStatus::Retired));
        }
        self.parts.status = SpecStatus::Retired;
        self.parts.retired_at = Some(stamp.occurred_at);
        self.events.record(GraphQlSpecRetired {
            event_id: stamp.event_id,
            spec_id: self.parts.id,
            service: self.parts.content.service.clone(),
            actor: stamp.actor,
            occurred_at: stamp.occurred_at,
        });
        Ok(())
    }

    /// The refusal of a transition from the current status to `to`.
    const fn refused(&self, to: SpecStatus) -> SpecTransitionRefused {
        SpecTransitionRefused {
            from: self.parts.status,
            to,
        }
    }
}

impl AggregateRoot for GraphQlSpec {
    fn recorded_events(&mut self) -> &mut RecordedEvents {
        &mut self.events
    }
}

#[cfg(test)]
mod tests;
