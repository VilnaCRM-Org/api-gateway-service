//! Security audit log double and fixtures of the IAM context.

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use iam_domain::{
    ActorRef, AssignmentScope, AuditAction, AuditChainHead, AuditHash, AuditOutcome, AuditSummary,
    AuditTarget, IdempotencyKey, PolicyVersion, RepositoryError, RequestId, SecurityAuditEvent,
    SecurityAuditEventId, SecurityAuditEventParts, SecurityAuditLog, StoredSecurityAuditEvent,
};
use rand::RngExt as _;
use shared_domain::UuidGenerator as _;

use crate::id::SequenceUuidGenerator;
use crate::seed::TestRng;

/// A committed record with random identifiers, a random time after 2020 and before and after
/// summaries made of identifiers only.
///
/// # Panics
///
/// Never in practice: the generated values satisfy the invariants.
#[expect(
    clippy::expect_used,
    reason = "the generated values satisfy the invariants; a failure is a defect of the fixture"
)]
pub fn security_audit_event(rng: &mut TestRng) -> SecurityAuditEvent {
    let mut uuid = || SequenceUuidGenerator::starting_at(rng.rng().random()).generate();
    let id = SecurityAuditEventId::from_uuid(uuid());
    let actor = ActorRef::User(uuid());
    let role = uuid();
    let micros = rng
        .rng()
        .random_range(1_577_836_800_000_000_u64..4_102_444_800_000_000);
    let version = rng.rng().random_range(1..=i64::MAX);
    SecurityAuditEvent::record(SecurityAuditEventParts {
        id,
        occurred_at: SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_micros(micros))
            .expect("a time before the year 2100"),
        actor,
        caller_service: None,
        action: AuditAction::new("role.update").expect("a dotted action"),
        target: AuditTarget::new("role", &role.to_string()).expect("a role target"),
        scope: Some(AssignmentScope::Global),
        before: Some(AuditSummary::new(&format!("role={role};name=readers")).expect("a summary")),
        after: Some(AuditSummary::new(&format!("role={role};name=writers")).expect("a summary")),
        idempotency_key: Some(IdempotencyKey::new(&format!("key-{role}")).expect("a key")),
        outcome: AuditOutcome::Committed,
        reason: None,
        policy_version: Some(PolicyVersion::new(version).expect("a policy version")),
        request_id: Some(RequestId::new(&format!("req-{role}")).expect("a request id")),
    })
    .expect("a time after 1970")
}

/// A placeholder link of the in-memory chain: the sequence number in the last 8 bytes.
fn link(seq: i64) -> AuditHash {
    let mut bytes = [0; AuditHash::LENGTH];
    let (_zeros, tail) = bytes.split_at_mut(AuditHash::LENGTH - 8);
    tail.copy_from_slice(&seq.to_be_bytes());
    AuditHash::new(&bytes).unwrap_or(AuditHash::GENESIS)
}

/// A security audit log that keeps the records in memory; its hashes are placeholders, not
/// SHA-256 digests.
#[derive(Debug)]
pub struct FakeSecurityAuditLog {
    records: Option<Mutex<Vec<StoredSecurityAuditEvent>>>,
}

impl FakeSecurityAuditLog {
    /// An empty log.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            records: Some(Mutex::new(Vec::new())),
        }
    }

    /// A log that answers `Unavailable` to every call.
    #[must_use]
    pub const fn failing() -> Self {
        Self { records: None }
    }

    /// The appended records, oldest first; empty for the failing log.
    #[must_use]
    pub fn recorded(&self) -> Vec<StoredSecurityAuditEvent> {
        self.records.as_ref().map_or_else(Vec::new, |records| {
            records
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        })
    }

    fn records(&self) -> Result<&Mutex<Vec<StoredSecurityAuditEvent>>, RepositoryError> {
        self.records.as_ref().ok_or_else(|| {
            RepositoryError::Unavailable("in-memory security audit log failure".into())
        })
    }
}

impl Default for FakeSecurityAuditLog {
    fn default() -> Self {
        Self::new()
    }
}

/// The head of the chain of `records`.
fn head_of(records: &[StoredSecurityAuditEvent]) -> AuditChainHead {
    records.last().map_or(AuditChainHead::GENESIS, |newest| {
        AuditChainHead::new(newest.seq(), newest.hash()).unwrap_or(AuditChainHead::GENESIS)
    })
}

/// Appends `events` after `records`, or nothing when an id is already used.
fn append(
    records: &mut Vec<StoredSecurityAuditEvent>,
    events: &[SecurityAuditEvent],
) -> Result<(), RepositoryError> {
    let mut appended = records.clone();
    for event in events {
        let id = event.parts().id;
        if appended
            .iter()
            .any(|record| record.event().parts().id == id)
        {
            return Err(RepositoryError::AlreadyExists);
        }
        let head = head_of(&appended);
        let seq = head.seq().saturating_add(1);
        let record = StoredSecurityAuditEvent::new(seq, event.clone(), head.hash(), link(seq))
            .map_err(|error| RepositoryError::Unavailable(Box::new(error)))?;
        appended.push(record);
    }
    *records = appended;
    Ok(())
}

#[async_trait]
impl SecurityAuditLog for FakeSecurityAuditLog {
    async fn append_batch(
        &self,
        events: &[SecurityAuditEvent],
    ) -> Result<AuditChainHead, RepositoryError> {
        let mut records = self
            .records()?
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        append(&mut records, events)?;
        Ok(head_of(&records))
    }

    async fn chain_head(&self) -> Result<AuditChainHead, RepositoryError> {
        let records = self
            .records()?
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        Ok(head_of(&records))
    }

    async fn find_by_id(
        &self,
        id: SecurityAuditEventId,
    ) -> Result<StoredSecurityAuditEvent, RepositoryError> {
        let records = self
            .records()?
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        records
            .iter()
            .find(|record| record.event().parts().id == id)
            .cloned()
            .ok_or(RepositoryError::NotFound)
    }

    async fn find_after(
        &self,
        after_seq: i64,
        limit: u32,
    ) -> Result<Vec<StoredSecurityAuditEvent>, RepositoryError> {
        let records = self
            .records()?
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        Ok(records
            .iter()
            .filter(|record| record.seq() > after_seq)
            .take(limit)
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests;
