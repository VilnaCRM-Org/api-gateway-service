//! Unit of work double and change fixtures of the IAM context.

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use iam_domain::{
    ActorRef, ChangeId, ChangeReceipt, DecisionEffect, EntityVersion, EventData, EventEnvelope,
    EventEnvelopeParts, EventType, EventValue, IamChange, IamChangeParts, IamUnitOfWork,
    IdempotencyRequest, PolicyVersion, RepositoryError, RequestDigest, SecurityAuditEventParts,
};
use rand::RngExt as _;
use shared_domain::{Uuid, UuidGenerator as _};

use crate::id::SequenceUuidGenerator;
use crate::security_audit::security_audit_event;
use crate::seed::TestRng;

/// A version 7 UUID with a random counter.
pub fn uuid_v7(rng: &mut TestRng) -> Uuid {
    SequenceUuidGenerator::starting_at(rng.rng().random()).generate()
}

/// An `iam.role.updated` envelope of the aggregate `aggregate_id` with a random time after 2020,
/// whose data holds a value of every kind and no credential.
///
/// # Panics
///
/// Never in practice: the generated values satisfy the invariants.
#[expect(
    clippy::expect_used,
    reason = "the generated values satisfy the invariants; a failure is a defect of the fixture"
)]
pub fn event_envelope(rng: &mut TestRng, aggregate_id: Uuid) -> EventEnvelope {
    let micros = rng
        .rng()
        .random_range(1_577_836_800_000_000_u64..4_102_444_800_000_000);
    let grants = rng.rng().random_range(0..5_000_i64);
    let subject = EventData::new()
        .with("kind", EventValue::Text("user".to_owned()))
        .expect("a subject kind");
    let data = EventData::new()
        .with("name", EventValue::Text(format!("role-{grants}")))
        .and_then(|data| data.with("grantCount", EventValue::Integer(grants)))
        .and_then(|data| data.with("system", EventValue::Bool(false)))
        .and_then(|data| data.with("expiresAt", EventValue::Null))
        .and_then(|data| {
            data.with(
                "addedKeys",
                EventValue::List(vec![EventValue::Text("rest:core:GET /users".to_owned())]),
            )
        })
        .and_then(|data| data.with("subject", EventValue::Object(subject)))
        .expect("event fields without a credential");
    EventEnvelope::new(EventEnvelopeParts {
        id: uuid_v7(rng),
        event_type: EventType::new("iam.role.updated").expect("a catalogue type"),
        occurred_at: SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_micros(micros))
            .expect("a time before the year 2100"),
        aggregate_id,
        actor: ActorRef::User(uuid_v7(rng)),
        entity_version: EntityVersion::new(grants.saturating_add(1)).ok(),
        data,
    })
    .expect("a valid envelope")
}

/// A committed change with `events` envelopes of one aggregate, a random committed audit record
/// whose idempotency key the change carries, and a random request digest.
///
/// # Panics
///
/// Never in practice: the generated values satisfy the invariants.
#[expect(
    clippy::expect_used,
    reason = "the generated values satisfy the invariants; a failure is a defect of the fixture"
)]
pub fn iam_change(rng: &mut TestRng, effect: DecisionEffect, events: usize) -> IamChange {
    let audit = security_audit_event(rng);
    let aggregate_id = uuid_v7(rng);
    let envelopes = (0..events)
        .map(|_index| event_envelope(rng, aggregate_id))
        .collect();
    let digest: [u8; RequestDigest::LENGTH] = rng.rng().random();
    let idempotency = audit
        .parts()
        .idempotency_key
        .clone()
        .map(|key| IdempotencyRequest {
            key,
            request_digest: RequestDigest::new(&digest).expect("32 bytes"),
        });
    IamChange::new(IamChangeParts {
        change_id: ChangeId::from_uuid(uuid_v7(rng)),
        effect,
        statements: Vec::new(),
        events: envelopes,
        audit,
        entity_version: EntityVersion::new(rng.rng().random_range(1..1_000)).expect("a version"),
        idempotency,
    })
    .expect("a committed audit record")
}

/// The same change with other values, rebuilt through [`IamChange::new`].
///
/// # Panics
///
/// Panics when the rebuilt change is invalid, for example with a rejected audit record.
#[expect(
    clippy::expect_used,
    reason = "a fixture that builds an invalid change is a defect of the test"
)]
pub fn rebuilt<F: FnOnce(&mut IamChangeParts)>(change: &IamChange, update: F) -> IamChange {
    let mut parts = change.parts().clone();
    update(&mut parts);
    IamChange::new(parts).expect("a valid change")
}

/// The audit values of the change, to rebuild it with another audit record.
#[must_use]
pub fn audit_parts(change: &IamChange) -> SecurityAuditEventParts {
    change.parts().audit.parts().clone()
}

/// The committed state of the in-memory unit of work.
#[derive(Debug, Default)]
struct Committed {
    version: i64,
    changes: Vec<IamChange>,
}

impl Committed {
    /// Applies the change as one transaction would, or nothing.
    fn apply(&mut self, change: IamChange) -> Result<ChangeReceipt, RepositoryError> {
        let locked = PolicyVersion::new(self.version)
            .map_err(|error| RepositoryError::Unavailable(Box::new(error)))?;
        if !change
            .parts()
            .statements
            .iter()
            .all(|statement| statement.holds(locked))
        {
            return Err(RepositoryError::Conflict);
        }
        if self.changes.iter().any(|stored| conflicts(stored, &change)) {
            return Err(RepositoryError::AlreadyExists);
        }
        let version = if change.affects_decisions() {
            PolicyVersion::new(self.version.saturating_add(1))
                .map_err(|error| RepositoryError::Unavailable(Box::new(error)))?
        } else {
            locked
        };
        self.version = version.value();
        let receipt = change.receipt(version);
        self.changes.push(change);
        Ok(receipt)
    }
}

/// Whether two changes share a change id or the idempotency key of one actor.
fn conflicts(stored: &IamChange, change: &IamChange) -> bool {
    let same_key = match (stored.idempotency_record(), change.idempotency_record()) {
        (Some(left), Some(right)) => left.actor() == right.actor() && left.key() == right.key(),
        _ => false,
    };
    same_key || stored.parts().change_id == change.parts().change_id
}

/// A unit of work that keeps the committed changes and the policy version in memory.
#[derive(Debug)]
pub struct FakeIamUnitOfWork {
    committed: Option<Mutex<Committed>>,
}

impl FakeIamUnitOfWork {
    /// A unit of work at policy version 0 without changes.
    #[must_use]
    pub fn new() -> Self {
        Self {
            committed: Some(Mutex::new(Committed::default())),
        }
    }

    /// A unit of work that answers `Unavailable` to every commit.
    #[must_use]
    pub const fn failing() -> Self {
        Self { committed: None }
    }

    /// The committed changes, oldest first; empty for the failing unit of work.
    #[must_use]
    pub fn committed(&self) -> Vec<IamChange> {
        self.committed.as_ref().map_or_else(Vec::new, |committed| {
            committed
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .changes
                .clone()
        })
    }

    /// The current policy version; 0 for the failing unit of work.
    #[must_use]
    pub fn policy_version(&self) -> i64 {
        self.committed.as_ref().map_or(0, |committed| {
            committed
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .version
        })
    }
}

impl Default for FakeIamUnitOfWork {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl IamUnitOfWork for FakeIamUnitOfWork {
    async fn commit(&self, change: IamChange) -> Result<ChangeReceipt, RepositoryError> {
        let committed = self
            .committed
            .as_ref()
            .ok_or_else(|| RepositoryError::Unavailable("in-memory unit of work failure".into()))?;
        committed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .apply(change)
    }
}

#[cfg(test)]
mod tests;
