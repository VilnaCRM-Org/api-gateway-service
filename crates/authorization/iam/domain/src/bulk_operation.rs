//! The `BulkOperation` aggregate: a large change that the runner commits in ordered, rate-capped
//! chunks, with the progress that operators follow (FR-1, FR-84).

pub mod chunker;
pub mod event;
pub mod statement;

use std::time::SystemTime;

use shared_domain::{AggregateRoot, RecordedEvents, Uuid};

use crate::entity::aggregate_event::{Enveloper, envelope_as, envelopes_of};
use crate::entity::event_envelope::EventEnvelope;
use crate::error::InvalidEventEnvelope;
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::identifier::BulkOperationId;
use crate::value_object::policy_version::PolicyVersion;
use event::BulkOperationCompleted;

/// The longest error text a bulk operation keeps.
const MAX_ERROR_CHARS: usize = 500;

/// A value that breaks an invariant of a bulk operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidBulkOperation {
    /// A bulk operation changes at least one record.
    #[error("A bulk operation must change at least one record.")]
    NoRecords,
    /// The stored kind is not one of the four kinds.
    #[error("This value must be role_deletion, catalogue, resync or other.")]
    Kind,
    /// The stored status is not one of the four statuses.
    #[error("This value must be pending, running, completed or failed.")]
    Status,
    /// The stored progress is inconsistent: more applied than total records, or versions out of
    /// order.
    #[error("The progress of the bulk operation is inconsistent.")]
    Progress,
}

/// A change of a bulk operation that its state does not allow; nothing changes then.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BulkOperationRefused {
    /// The operation is completed or failed and accepts no more chunks.
    #[error("The bulk operation is finished.")]
    Finished,
    /// The chunk is empty or applies more records than remain.
    #[error("The chunk does not fit the remaining records.")]
    ChunkSize,
    /// The chunk's version does not lie above the version of the previous chunk.
    #[error("The chunk version must exceed the previous chunk version.")]
    VersionOrder,
}

/// What a bulk operation changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BulkKind {
    /// A role deleted together with its assignments.
    RoleDeletion,
    /// A catalogue activation that changes many grants.
    Catalogue,
    /// A republication of the complete policy state.
    Resync,
    /// Any other change above the chunk size.
    Other,
}

impl BulkKind {
    /// The stable text form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RoleDeletion => "role_deletion",
            Self::Catalogue => "catalogue",
            Self::Resync => "resync",
            Self::Other => "other",
        }
    }

    /// Parses the stable text form.
    ///
    /// # Errors
    ///
    /// [`InvalidBulkOperation::Kind`] for any other text.
    pub fn parse(value: &str) -> Result<Self, InvalidBulkOperation> {
        match value {
            "role_deletion" => Ok(Self::RoleDeletion),
            "catalogue" => Ok(Self::Catalogue),
            "resync" => Ok(Self::Resync),
            "other" => Ok(Self::Other),
            _ => Err(InvalidBulkOperation::Kind),
        }
    }
}

/// Where a bulk operation stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BulkStatus {
    /// Recorded, no chunk committed yet.
    Pending,
    /// At least one chunk committed, more remain.
    Running,
    /// Every record is applied.
    Completed,
    /// The runner gave up; the error says why.
    Failed,
}

impl BulkStatus {
    /// The stable text form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    /// Parses the stable text form.
    ///
    /// # Errors
    ///
    /// [`InvalidBulkOperation::Status`] for any other text.
    pub fn parse(value: &str) -> Result<Self, InvalidBulkOperation> {
        match value {
            "pending" => Ok(Self::Pending),
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            _ => Err(InvalidBulkOperation::Status),
        }
    }

    /// Whether the operation accepts no more chunks.
    #[must_use]
    pub const fn is_finished(self) -> bool {
        matches!(self, Self::Completed | Self::Failed)
    }
}

/// Who acts on a bulk operation, when (from the `Clock` port) and the id of the event that records
/// the completion (from the `UuidGenerator` port).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BulkStamp {
    /// The id of the event a completion records.
    pub event_id: Uuid,
    /// When the change happens.
    pub occurred_at: SystemTime,
}

/// The stored state of a bulk operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkOperationParts {
    /// The identifier.
    pub id: BulkOperationId,
    /// What the operation changes.
    pub kind: BulkKind,
    /// Where it stands.
    pub status: BulkStatus,
    /// How many records the whole change touches.
    pub total_records: u64,
    /// How many records the committed chunks applied.
    pub applied_records: u64,
    /// The policy version of the first committed chunk.
    pub first_version: Option<PolicyVersion>,
    /// The policy version of the last committed chunk.
    pub last_version: Option<PolicyVersion>,
    /// Who asked for the change.
    pub requester: ActorRef,
    /// Why the operation failed.
    pub error: Option<String>,
    /// When the operation was recorded.
    pub created_at: SystemTime,
    /// When the operation last changed.
    pub updated_at: SystemTime,
}

/// A bulk operation. Every committed chunk records its progress; the last one completes it and
/// records [`BulkOperationCompleted`].
#[derive(Debug)]
pub struct BulkOperation {
    parts: BulkOperationParts,
    events: RecordedEvents,
}

impl BulkOperation {
    /// Records a pending operation over `total_records` records.
    ///
    /// # Errors
    ///
    /// [`InvalidBulkOperation::NoRecords`] when `total_records` is zero.
    pub fn pending(
        id: BulkOperationId,
        kind: BulkKind,
        total_records: u64,
        requester: ActorRef,
        at: SystemTime,
    ) -> Result<Self, InvalidBulkOperation> {
        if total_records == 0 {
            return Err(InvalidBulkOperation::NoRecords);
        }
        Ok(Self::restore_unchecked(BulkOperationParts {
            id,
            kind,
            status: BulkStatus::Pending,
            total_records,
            applied_records: 0,
            first_version: None,
            last_version: None,
            requester,
            error: None,
            created_at: at,
            updated_at: at,
        }))
    }

    /// Rebuilds a stored operation; records nothing.
    ///
    /// # Errors
    ///
    /// [`InvalidBulkOperation::Progress`] when more records are applied than exist or the
    /// versions are out of order, and [`InvalidBulkOperation::NoRecords`] for a zero total.
    pub fn restore(parts: BulkOperationParts) -> Result<Self, InvalidBulkOperation> {
        if parts.total_records == 0 {
            return Err(InvalidBulkOperation::NoRecords);
        }
        let ordered = match (parts.first_version, parts.last_version) {
            (Some(first), Some(last)) => first <= last,
            (None, None) => true,
            _ => false,
        };
        if parts.applied_records > parts.total_records || !ordered {
            return Err(InvalidBulkOperation::Progress);
        }
        Ok(Self::restore_unchecked(parts))
    }

    fn restore_unchecked(parts: BulkOperationParts) -> Self {
        Self {
            parts,
            events: RecordedEvents::default(),
        }
    }

    /// The state of the operation.
    #[must_use]
    pub const fn parts(&self) -> &BulkOperationParts {
        &self.parts
    }

    /// How many records remain to apply.
    #[must_use]
    pub const fn remaining_records(&self) -> u64 {
        self.parts
            .total_records
            .saturating_sub(self.parts.applied_records)
    }

    /// Records one committed chunk of `records` records at policy version `version`; the chunk
    /// that applies the last record completes the operation and records
    /// [`BulkOperationCompleted`].
    ///
    /// # Errors
    ///
    /// [`BulkOperationRefused::Finished`] for a finished operation,
    /// [`BulkOperationRefused::ChunkSize`] when `records` is zero or above the remaining records
    /// and [`BulkOperationRefused::VersionOrder`] when `version` does not exceed the last one;
    /// nothing changes then.
    pub fn record_chunk(
        &mut self,
        records: u64,
        version: PolicyVersion,
        stamp: BulkStamp,
    ) -> Result<(), BulkOperationRefused> {
        if self.parts.status.is_finished() {
            return Err(BulkOperationRefused::Finished);
        }
        if records == 0 || records > self.remaining_records() {
            return Err(BulkOperationRefused::ChunkSize);
        }
        if self.parts.last_version.is_some_and(|last| version <= last) {
            return Err(BulkOperationRefused::VersionOrder);
        }
        self.parts.applied_records = self.parts.applied_records.saturating_add(records);
        self.parts.first_version.get_or_insert(version);
        self.parts.last_version = Some(version);
        self.parts.updated_at = stamp.occurred_at;
        if self.remaining_records() == 0 {
            self.parts.status = BulkStatus::Completed;
            self.record_completion(stamp);
        } else {
            self.parts.status = BulkStatus::Running;
        }
        Ok(())
    }

    /// Marks the operation failed with a one-line `reason`, cut to 500 characters.
    ///
    /// # Errors
    ///
    /// [`BulkOperationRefused::Finished`] for a finished operation.
    pub fn fail(&mut self, reason: &str, at: SystemTime) -> Result<(), BulkOperationRefused> {
        if self.parts.status.is_finished() {
            return Err(BulkOperationRefused::Finished);
        }
        self.parts.status = BulkStatus::Failed;
        self.parts.error = Some(reason.chars().take(MAX_ERROR_CHARS).collect());
        self.parts.updated_at = at;
        Ok(())
    }

    /// Drains the recorded events as envelopes of `iam.events.v1`.
    ///
    /// # Errors
    ///
    /// The [`InvalidEventEnvelope`] of the first event that cannot be enveloped.
    pub fn pull_envelopes(&mut self) -> Result<Vec<EventEnvelope>, InvalidEventEnvelope> {
        envelopes_of(&self.pull_domain_events(), &ENVELOPERS)
    }

    fn record_completion(&mut self, stamp: BulkStamp) {
        self.events.record(BulkOperationCompleted {
            event_id: stamp.event_id,
            bulk_operation_id: self.parts.id,
            kind: self.parts.kind,
            total_records: self.parts.total_records,
            first_version: self.parts.first_version,
            last_version: self.parts.last_version,
            actor: self.parts.requester.clone(),
            occurred_at: stamp.occurred_at,
        });
    }
}

impl AggregateRoot for BulkOperation {
    fn recorded_events(&mut self) -> &mut RecordedEvents {
        &mut self.events
    }
}

/// The event of a bulk operation, with its way to an envelope.
const ENVELOPERS: [Enveloper; 1] = [envelope_as::<BulkOperationCompleted>];

#[cfg(test)]
mod tests;
