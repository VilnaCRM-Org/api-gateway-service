//! The `OpenApiSpec` aggregate: one immutable version of the `OpenAPI` document of a service
//! (FR-34, FR-38).

pub mod event;
pub mod statement;

use std::any::Any;
use std::time::SystemTime;

use shared_domain::{AggregateRoot, DomainEvent, RecordedEvents};

use crate::entity::event_envelope::EventEnvelope;
use crate::error::{InvalidEventEnvelope, SpecTransitionRefused};
use crate::graphql_spec::{SpecActivation, SpecStamp};
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::content_hash::ContentHash;
use crate::value_object::identifier::SpecId;
use crate::value_object::rest_operation_set::RestOperationSet;
use crate::value_object::service_name::ServiceName;
use crate::value_object::spec_status::SpecStatus;
use event::{OpenApiSpecLoaded, OpenApiSpecRetired};

/// What a new version is made of: the service, the hash of the document and its operation set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenApiSpecContent {
    /// The service the document belongs to.
    pub service: ServiceName,
    /// The SHA-256 hash of the document.
    pub content_hash: ContentHash,
    /// The operations of the document.
    pub operations: RestOperationSet,
}

/// The stored state of a version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenApiSpecParts {
    /// The identifier.
    pub id: SpecId,
    /// The service, the hash and the operations; never change after loading.
    pub content: OpenApiSpecContent,
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

/// One version of the `OpenAPI` document of a service. The content never changes; only the status
/// moves, from `draft` to `active` to `retired`.
#[derive(Debug)]
pub struct OpenApiSpec {
    parts: OpenApiSpecParts,
    events: RecordedEvents,
}

impl OpenApiSpec {
    /// The largest document, in bytes: 5 MiB (FR-34), checked before parsing starts.
    pub const MAX_DOCUMENT_BYTES: usize = 5 * 1024 * 1024;

    /// Builds a new draft version and records [`OpenApiSpecLoaded`].
    #[must_use]
    pub fn load(id: SpecId, content: OpenApiSpecContent, stamp: SpecStamp) -> Self {
        let mut spec = Self::restore(OpenApiSpecParts {
            id,
            content,
            status: SpecStatus::Draft,
            uploaded_by: stamp.actor.clone(),
            created_at: stamp.occurred_at,
            activated_at: None,
            retired_at: None,
        });
        let content = &spec.parts.content;
        let loaded = OpenApiSpecLoaded {
            event_id: stamp.event_id,
            spec_id: id,
            service: content.service.clone(),
            content_hash: content.content_hash,
            operation_count: u32::try_from(content.operations.len()).unwrap_or(u32::MAX),
            actor: stamp.actor,
            occurred_at: stamp.occurred_at,
        };
        spec.events.record(loaded);
        spec
    }

    /// Rebuilds a stored version; records nothing.
    #[must_use]
    pub fn restore(parts: OpenApiSpecParts) -> Self {
        Self {
            parts,
            events: RecordedEvents::default(),
        }
    }

    /// The state of the version.
    #[must_use]
    pub const fn parts(&self) -> &OpenApiSpecParts {
        &self.parts
    }

    /// The operations of the document with their flags.
    #[must_use]
    pub const fn operations(&self) -> &RestOperationSet {
        &self.parts.content.operations
    }

    /// Makes a draft active; records no event, since the catalogue records the activation as
    /// `RestPermissionsCreated`. An active version stays as it is.
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

    /// Retires an active version and records [`OpenApiSpecRetired`].
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
        self.events.record(OpenApiSpecRetired {
            event_id: stamp.event_id,
            spec_id: self.parts.id,
            service: self.parts.content.service.clone(),
            actor: stamp.actor,
            occurred_at: stamp.occurred_at,
        });
        Ok(())
    }

    /// Drains the recorded events as envelopes of `iam.events.v1`, in recording order, for the
    /// change that commits them.
    ///
    /// # Errors
    ///
    /// The [`InvalidEventEnvelope`] of the first event that cannot be enveloped:
    /// [`InvalidEventEnvelope::EventType`] for an event that is neither [`OpenApiSpecLoaded`] nor
    /// [`OpenApiSpecRetired`], which a version never records itself.
    pub fn pull_envelopes(&mut self) -> Result<Vec<EventEnvelope>, InvalidEventEnvelope> {
        self.pull_domain_events()
            .iter()
            .map(|event| envelope_of(event.as_ref()))
            .collect()
    }

    /// The refusal of a transition from the current status to `to`.
    const fn refused(&self, to: SpecStatus) -> SpecTransitionRefused {
        SpecTransitionRefused {
            from: self.parts.status,
            to,
        }
    }
}

impl AggregateRoot for OpenApiSpec {
    fn recorded_events(&mut self) -> &mut RecordedEvents {
        &mut self.events
    }
}

/// The envelope of one of the two events of a version.
fn envelope_of(event: &dyn DomainEvent) -> Result<EventEnvelope, InvalidEventEnvelope> {
    let event: &dyn Any = event;
    if let Some(loaded) = event.downcast_ref::<OpenApiSpecLoaded>() {
        return EventEnvelope::of(loaded);
    }
    if let Some(retired) = event.downcast_ref::<OpenApiSpecRetired>() {
        return EventEnvelope::of(retired);
    }
    Err(InvalidEventEnvelope::EventType)
}

#[cfg(test)]
mod tests;
