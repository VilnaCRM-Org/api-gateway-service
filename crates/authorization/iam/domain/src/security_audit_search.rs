//! What a search of the security audit log asks for (FR-52).

use std::time::SystemTime;

use crate::entity::security_audit_event::{SecurityAuditEventParts, StoredSecurityAuditEvent};
use crate::error::InvalidIamValue;
use crate::micros;
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::audit_action::AuditAction;
use crate::value_object::audit_outcome::AuditOutcome;
use crate::value_object::audit_target::AuditTarget;

/// The conditions that a record must meet to be returned; a record must meet every one that is
/// given, and a filter without conditions keeps every record.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecurityAuditFilter {
    from_micros: Option<i64>,
    until_micros: Option<i64>,
    actor: Option<ActorRef>,
    action: Option<AuditAction>,
    target_type: Option<String>,
    target_id: Option<String>,
    outcome: Option<AuditOutcome>,
}

impl SecurityAuditFilter {
    /// A filter without conditions.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            from_micros: None,
            until_micros: None,
            actor: None,
            action: None,
            target_type: None,
            target_id: None,
            outcome: None,
        }
    }

    /// Keeps the records that happened at or after `from` and before `until`; either bound may be
    /// absent.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIamValue::AuditTimestamp`] when a bound lies before 1970 or past the
    /// largest number of microseconds in 64 bits.
    pub fn within(
        mut self,
        from: Option<SystemTime>,
        until: Option<SystemTime>,
    ) -> Result<Self, InvalidIamValue> {
        self.from_micros = from.map(bound).transpose()?;
        self.until_micros = until.map(bound).transpose()?;
        Ok(self)
    }

    /// Keeps the records of one actor.
    #[must_use]
    pub fn by_actor(mut self, actor: ActorRef) -> Self {
        self.actor = Some(actor);
        self
    }

    /// Keeps the records of one action.
    #[must_use]
    pub fn of_action(mut self, action: AuditAction) -> Self {
        self.action = Some(action);
        self
    }

    /// Keeps the records of one outcome.
    #[must_use]
    pub const fn with_outcome(mut self, outcome: AuditOutcome) -> Self {
        self.outcome = Some(outcome);
        self
    }

    /// Keeps the records about targets of `target_type`, or about the one target `target_id` of
    /// that type.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIamValue::AuditTargetType`] or [`InvalidIamValue::AuditTargetId`] when the
    /// type or the id is not a valid part of a target.
    pub fn about(
        mut self,
        target_type: &str,
        target_id: Option<&str>,
    ) -> Result<Self, InvalidIamValue> {
        let target = AuditTarget::new(target_type, target_id.unwrap_or(PROBE_ID))?;
        self.target_type = Some(target.target_type().to_owned());
        self.target_id = target_id.map(|_id| target.target_id().to_owned());
        Ok(self)
    }

    /// The earliest time kept, in microseconds since 1970.
    #[must_use]
    pub const fn since_micros(&self) -> Option<i64> {
        self.from_micros
    }

    /// The first time not kept, in microseconds since 1970.
    #[must_use]
    pub const fn until_micros(&self) -> Option<i64> {
        self.until_micros
    }

    /// The actor kept.
    #[must_use]
    pub const fn actor(&self) -> Option<&ActorRef> {
        self.actor.as_ref()
    }

    /// The action kept.
    #[must_use]
    pub const fn action(&self) -> Option<&AuditAction> {
        self.action.as_ref()
    }

    /// The target type kept.
    #[must_use]
    pub fn target_type(&self) -> Option<&str> {
        self.target_type.as_deref()
    }

    /// The target id kept.
    #[must_use]
    pub fn target_id(&self) -> Option<&str> {
        self.target_id.as_deref()
    }

    /// The outcome kept.
    #[must_use]
    pub const fn outcome(&self) -> Option<AuditOutcome> {
        self.outcome
    }

    /// Whether the record meets every condition of the filter.
    #[must_use]
    pub fn matches(&self, record: &StoredSecurityAuditEvent) -> bool {
        let event = record.event();
        self.holds_at(event.occurred_at_micros())
            && self.holds_for(event.parts())
            && self.holds_about(&event.parts().target)
    }

    /// Whether `at` lies within the time range.
    fn holds_at(&self, at: i64) -> bool {
        self.from_micros.is_none_or(|from| at >= from)
            && self.until_micros.is_none_or(|until| at < until)
    }

    /// Whether the actor, the action and the outcome of the record are the ones kept.
    fn holds_for(&self, parts: &SecurityAuditEventParts) -> bool {
        self.actor
            .as_ref()
            .is_none_or(|actor| *actor == parts.actor)
            && self
                .action
                .as_ref()
                .is_none_or(|action| *action == parts.action)
            && self.outcome.is_none_or(|outcome| outcome == parts.outcome)
    }

    /// Whether the target is of the type and has the id that are kept.
    fn holds_about(&self, target: &AuditTarget) -> bool {
        self.target_type
            .as_deref()
            .is_none_or(|kind| kind == target.target_type())
            && self
                .target_id
                .as_deref()
                .is_none_or(|id| id == target.target_id())
    }
}

/// A target id that stands in for an absent one while the type is validated.
const PROBE_ID: &str = "-";

/// A bound in microseconds since 1970.
fn bound(time: SystemTime) -> Result<i64, InvalidIamValue> {
    micros::since_epoch(time).ok_or(InvalidIamValue::AuditTimestamp)
}

/// One page of a search: the newest records first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityAuditSearch {
    /// The conditions the records must meet.
    pub filter: SecurityAuditFilter,
    /// The sequence number of the last record of the previous page; only older records are
    /// returned. None for the first page.
    pub before_seq: Option<i64>,
    /// The largest number of records to return.
    pub limit: u32,
}

#[cfg(test)]
mod tests;
