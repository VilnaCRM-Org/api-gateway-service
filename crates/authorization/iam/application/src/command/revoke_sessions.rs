//! Revokes sessions of a user, or cuts off all of the user's tokens (FR-1, FR-17, FR-70).

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, ChangeId, ChangeStatement, DecisionEffect, EntityVersion, EventEnvelope, IamChange,
    IamChangeParts, IamUnitOfWork, IdempotencyRequest, InvalidIamValue, PrunePolicy,
    RevocationSource, RevocationStatement, SessionId, SessionRevocation, SessionRevocationId,
    SessionRevoked, TokenLifetimeFloor, UserTokenCutoff, UserTokensCutOff, WriteMode,
};
use shared_domain::{Clock, Command, CommandHandler, Uuid, UuidGenerator};

use super::gateway_audit::{ChangeRecord, committed};
use crate::error::IamError;

/// The audit action of revoked sessions.
const SESSIONS_ACTION: &str = "session.revoke";

/// The audit action of a user cut-off.
const CUTOFF_ACTION: &str = "user_tokens.cut_off";

/// Revokes the sessions `session_ids` of `user_id` as `actor`; an empty list sets the cut-off of
/// the user's tokens instead.
///
/// The caller chooses the identifier of the change, so that it can read the receipt after the
/// command returned; the command returns no data.
#[derive(Debug, Clone)]
pub struct RevokeSessionsCommand {
    /// The identifier of the change, the key of its receipt.
    pub change_id: ChangeId,
    /// The user whose sessions or tokens are revoked.
    pub user_id: Uuid,
    /// The sessions to revoke; empty for the cut-off of every token of the user.
    pub session_ids: Vec<SessionId>,
    /// Who revokes.
    pub actor: ActorRef,
    /// The idempotency key and request digest of the write, when it carries a key.
    pub idempotency: Option<IdempotencyRequest>,
}

impl Command for RevokeSessionsCommand {
    type Error = IamError;
    const NAME: &'static str = "RevokeSessionsCommand";
}

/// Handles [`RevokeSessionsCommand`].
///
/// It writes one revocation row and state record for each listed session, or the cut-off of the
/// user at the commit time plus the 2-second margin, with the events and the audit record, in one
/// versioned transaction. The rows take `source = operator`, the revoker and the instant after
/// which they may be pruned, sized by the longest token lifetime ever configured. The change takes
/// access away, so it is revocation-class.
#[derive(Debug)]
pub struct RevokeSessionsCommandHandler {
    unit_of_work: Arc<dyn IamUnitOfWork>,
    floor: Arc<dyn TokenLifetimeFloor>,
    configured_lifetime: Duration,
    clock: Arc<dyn Clock>,
    uuid_generator: Arc<dyn UuidGenerator>,
}

impl RevokeSessionsCommandHandler {
    /// A handler over the unit of work, the floor of the token lifetime, the configured
    /// `MAX_TOKEN_LIFETIME` that applies while the floor holds no value, the clock and the
    /// identifier source.
    #[must_use]
    pub const fn new(
        unit_of_work: Arc<dyn IamUnitOfWork>,
        floor: Arc<dyn TokenLifetimeFloor>,
        configured_lifetime: Duration,
        clock: Arc<dyn Clock>,
        uuid_generator: Arc<dyn UuidGenerator>,
    ) -> Self {
        Self {
            unit_of_work,
            floor,
            configured_lifetime,
            clock,
            uuid_generator,
        }
    }

    async fn revoke(&self, command: RevokeSessionsCommand) -> Result<(), IamError> {
        let longest = self
            .floor
            .longest()
            .await?
            .map_or(self.configured_lifetime, |floor| {
                floor.max(self.configured_lifetime)
            });
        let change = self.change_of(command, PrunePolicy::new(longest))?;
        self.unit_of_work
            .commit(change, WriteMode::Published)
            .await?;
        Ok(())
    }

    /// The change of the command: the statements, the events and the audit record.
    fn change_of(
        &self,
        command: RevokeSessionsCommand,
        policy: PrunePolicy,
    ) -> Result<IamChange, IamError> {
        let now = self.clock.now();
        let RevokeSessionsCommand {
            change_id,
            user_id,
            session_ids,
            actor,
            idempotency,
        } = command;
        let sessions = distinct(session_ids);
        let revoking = Revoking {
            user: user_id,
            actor: &actor,
            now,
            policy,
        };
        let (statements, events, target) = if sessions.is_empty() {
            self.cutoff_parts(&revoking)?
        } else {
            self.session_parts(&revoking, sessions)?
        };
        let record = ChangeRecord {
            action: target.action,
            kind: target.kind,
            target_id: target.id,
            actor: &actor,
            occurred_at: now,
            before: None,
            after: target.after,
            idempotency: idempotency.as_ref(),
        };
        let audit = committed(self.uuid_generator.as_ref(), record)?;
        Ok(IamChange::new(IamChangeParts {
            change_id,
            effect: DecisionEffect::RevocationClass,
            statements,
            events,
            audit,
            entity_version: EntityVersion::INITIAL,
            idempotency,
        })?)
    }

    /// The statement and event of the user cut-off at the commit time plus the margin.
    fn cutoff_parts(&self, revoking: &Revoking<'_>) -> Result<Parts, IamError> {
        let Revoking {
            user,
            actor,
            now,
            policy,
        } = *revoking;
        let cutoff_at = PrunePolicy::cutoff_at(now).ok_or(InvalidIamValue::AuditTimestamp)?;
        let prune_after = policy
            .prune_after(now, Some(cutoff_at))
            .ok_or(InvalidIamValue::AuditTimestamp)?;
        let statement = RevocationStatement::UserCutoff(UserTokenCutoff {
            user,
            tokens_valid_after: cutoff_at,
            source: RevocationSource::Operator,
            updated_at: now,
            prune_after,
        });
        let event = UserTokensCutOff {
            event_id: self.uuid_generator.generate(),
            user,
            tokens_valid_after: cutoff_at,
            source: RevocationSource::Operator,
            actor: actor.clone(),
            occurred_at: now,
            prune_after,
        };
        let target = Target {
            action: CUTOFF_ACTION,
            kind: CUTOFF_KIND,
            id: user.to_string(),
            after: "user cut-off set".to_owned(),
        };
        Ok((
            vec![ChangeStatement::from(statement)],
            vec![EventEnvelope::of(&event)?],
            target,
        ))
    }

    /// The statements and events of the revoked sessions, in the order of the request.
    fn session_parts(
        &self,
        revoking: &Revoking<'_>,
        sessions: Vec<SessionId>,
    ) -> Result<Parts, IamError> {
        let Revoking {
            user,
            actor,
            now,
            policy,
        } = *revoking;
        let prune_after = policy
            .prune_after(now, None)
            .ok_or(InvalidIamValue::AuditTimestamp)?;
        let count = sessions.len();
        let mut statements = Vec::with_capacity(count);
        let mut events = Vec::with_capacity(count);
        let mut first = None;
        for session in sessions {
            let id = SessionRevocationId::from_uuid(self.uuid_generator.generate());
            first.get_or_insert(id);
            let event = SessionRevoked {
                event_id: self.uuid_generator.generate(),
                revocation_id: id,
                session: session.clone(),
                user,
                source: RevocationSource::Operator,
                actor: actor.clone(),
                occurred_at: now,
                prune_after,
            };
            events.push(EventEnvelope::of(&event)?);
            statements.push(ChangeStatement::from(RevocationStatement::Session(
                SessionRevocation {
                    id,
                    session,
                    user,
                    source: RevocationSource::Operator,
                    revoked_by: actor.clone(),
                    revoked_at: now,
                    prune_after,
                },
            )));
        }
        let target = Target {
            action: SESSIONS_ACTION,
            kind: SESSION_KIND,
            id: first.map_or_else(|| user.to_string(), |id| id.to_string()),
            after: format!("sessions={count} user={user}"),
        };
        Ok((statements, events, target))
    }
}

/// The kind of the audit target of revoked sessions.
const SESSION_KIND: &str = "session_revocation";

/// The kind of the audit target of a user cut-off.
const CUTOFF_KIND: &str = "user";

/// Who is revoked, by whom, when, and how long the records stay.
#[derive(Debug, Clone, Copy)]
struct Revoking<'a> {
    user: Uuid,
    actor: &'a ActorRef,
    now: SystemTime,
    policy: PrunePolicy,
}

/// The statements, the events and the audit target of a change.
type Parts = (Vec<ChangeStatement>, Vec<EventEnvelope>, Target);

/// What the audit record names.
#[derive(Debug)]
struct Target {
    action: &'static str,
    kind: &'static str,
    id: String,
    after: String,
}

/// The sessions without repeats, in the order of their first appearance.
fn distinct(sessions: Vec<SessionId>) -> Vec<SessionId> {
    let mut seen = Vec::with_capacity(sessions.len());
    for session in sessions {
        if !seen.contains(&session) {
            seen.push(session);
        }
    }
    seen
}

#[async_trait::async_trait]
impl CommandHandler<RevokeSessionsCommand> for RevokeSessionsCommandHandler {
    async fn handle(&self, command: RevokeSessionsCommand) -> Result<(), IamError> {
        self.revoke(command).await
    }
}

#[cfg(test)]
mod tests;
