//! Replaces the grant set of a role with catalogue keys and wildcards (FR-1, FR-2, FR-24).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use iam_domain::{
    ActorRef, AuditAction, AuditOutcome, AuditSummary, AuditTarget, ChangeId, ChangeStatement,
    DecisionEffect, EntityVersion, GraphQlPermission, GraphQlPermissionRepository, GuardCheck,
    IamChange, IamChangeParts, IamUnitOfWork, IdempotencyRequest, PermissionGrant,
    PermissionGrantSet, PermissionKey, PermissionKeyKind, RestPermission, RestPermissionRepository,
    Role, RoleId, RoleKind, RoleParts, RoleRepository, RoleStamp, RoleStatement,
    SecurityAuditEvent, SecurityAuditEventId, SecurityAuditEventParts, ServiceName,
};
use shared_application::http::Violation;
use shared_domain::{Clock, Command, CommandHandler, UuidGenerator};

use crate::error::IamError;

/// The audit action of a replaced grant set.
const AUDIT_ACTION: &str = "role.permissions.set";

/// The largest number of wildcard patterns that an audit summary lists; the summary holds at most
/// 4,096 bytes, and it counts every wildcard.
const LISTED_WILDCARDS: usize = 16;

/// The violation message of a key that is in no active catalogue.
const UNKNOWN_KEY: &str = "This permission key is not in an active catalogue.";

/// The violation message of a wildcard whose service has no catalogue.
const UNKNOWN_SERVICE: &str = "This service has no permission catalogue.";

/// The command that replaces the whole grant set of `role_id` with `keys` as `actor`, when the
/// stored role still holds the version `expected`.
///
/// The caller chooses the identifier of the change, so that it can read the receipt and the grants
/// after the command returned; the command returns no data.
#[derive(Debug, Clone)]
pub struct SetRolePermissionsCommand {
    /// The identifier of the change, the key of its receipt.
    pub change_id: ChangeId,
    /// The role to change.
    pub role_id: RoleId,
    /// Who changes the role.
    pub actor: ActorRef,
    /// The version the caller read (`If-Match` or `expectedVersion`).
    pub expected: EntityVersion,
    /// The new grant set: catalogue keys and the four wildcard forms, as text; at most 5,000
    /// distinct ones.
    pub keys: Vec<String>,
    /// The idempotency key and request digest of the write, when it carries a key.
    pub idempotency: Option<IdempotencyRequest>,
}

impl Command for SetRolePermissionsCommand {
    type Error = IamError;
    const NAME: &'static str = "SetRolePermissionsCommand";
}

/// The repositories that a replacement reads before it decides.
#[derive(Debug, Clone)]
pub struct SetRolePermissionsReads {
    /// The roles.
    pub roles: Arc<dyn RoleRepository>,
    /// The GraphQL catalogue.
    pub graphql_permissions: Arc<dyn GraphQlPermissionRepository>,
    /// The REST catalogue.
    pub rest_permissions: Arc<dyn RestPermissionRepository>,
}

/// Handles [`SetRolePermissionsCommand`].
///
/// It reads the role, refuses a system role (the grants of `iam-platform-admin` and every other
/// system role are fixed by the bootstrap, FR-22), checks every key against the active catalogue of its service (a wildcard
/// needs a service that has a catalogue), replaces the grant set through the aggregate (which checks
/// the version) and commits the role statement, `iam.role_permissions.changed` and the audit record
/// through the unit of work in one transaction. The change affects decisions, so it takes the next
/// policy version. A wildcard that the replacement adds is audited with
/// `coversFutureElements=true`, because it also covers the elements that a later version adds.
#[derive(Debug)]
pub struct SetRolePermissionsCommandHandler {
    roles: Arc<dyn RoleRepository>,
    graphql_permissions: Arc<dyn GraphQlPermissionRepository>,
    rest_permissions: Arc<dyn RestPermissionRepository>,
    unit_of_work: Arc<dyn IamUnitOfWork>,
    clock: Arc<dyn Clock>,
    uuid_generator: Arc<dyn UuidGenerator>,
}

impl SetRolePermissionsCommandHandler {
    /// A handler over the repositories it reads, the unit of work, the clock and the identifier
    /// source.
    #[must_use]
    pub fn new(
        reads: SetRolePermissionsReads,
        unit_of_work: Arc<dyn IamUnitOfWork>,
        clock: Arc<dyn Clock>,
        uuid_generator: Arc<dyn UuidGenerator>,
    ) -> Self {
        Self {
            roles: reads.roles,
            graphql_permissions: reads.graphql_permissions,
            rest_permissions: reads.rest_permissions,
            unit_of_work,
            clock,
            uuid_generator,
        }
    }

    async fn set(&self, command: SetRolePermissionsCommand) -> Result<(), IamError> {
        let role = self
            .roles
            .find_by_id(command.role_id)
            .await?
            .ok_or(IamError::NotFound)?;
        if role.parts().kind == RoleKind::System {
            return Err(IamError::Forbidden);
        }
        let grants = self.checked_grants(&command.keys).await?;
        let change = self.change_of(role, grants, command)?;
        self.unit_of_work
            .commit(change, iam_domain::WriteMode::Published)
            .await?;
        Ok(())
    }

    /// The grant set of the texts, once every one of them is a grant that the catalogue holds.
    ///
    /// # Errors
    ///
    /// [`IamError::Invalid`] with one violation of `keys[<index>]` for each text that is not a
    /// grant, is not in an active catalogue or is a wildcard of a service without a catalogue, or
    /// with one violation of `keys` for more than 5,000 texts.
    async fn checked_grants(&self, keys: &[String]) -> Result<PermissionGrantSet, IamError> {
        if keys.len() > PermissionGrantSet::MAX_GRANTS {
            return Err(IamError::invalid_property(
                "keys",
                "This collection must contain 5000 elements or fewer.",
                "count",
            ));
        }
        let mut refused: BTreeMap<usize, Violation> = BTreeMap::new();
        let mut parsed: Vec<(usize, PermissionGrant)> = Vec::new();
        for (index, text) in keys.iter().enumerate() {
            match PermissionGrant::parse(text) {
                Ok(grant) => parsed.push((index, grant)),
                Err(error) => {
                    refused.insert(index, violation(index, &error.to_string(), error.code()));
                }
            }
        }
        refused.extend(self.unknown_grants(&parsed).await?);
        if !refused.is_empty() {
            return Err(IamError::Invalid(refused.into_values().collect()));
        }
        let grants = parsed.into_iter().map(|(_index, grant)| grant);
        Ok(PermissionGrantSet::new(grants)?)
    }

    /// The violation of every grant that the catalogue does not hold, by index.
    async fn unknown_grants(
        &self,
        parsed: &[(usize, PermissionGrant)],
    ) -> Result<BTreeMap<usize, Violation>, IamError> {
        let Requested {
            mut unknown,
            exact,
            wildcards,
        } = Requested::of(parsed);
        unknown.extend(self.unknown_keys(exact).await?);
        unknown.extend(self.unknown_services(wildcards).await?);
        Ok(unknown)
    }

    /// The violation of every exact key that no active version of its service holds.
    async fn unknown_keys(
        &self,
        exact: BTreeMap<ServiceName, Vec<(usize, PermissionKey)>>,
    ) -> Result<BTreeMap<usize, Violation>, IamError> {
        let mut unknown = BTreeMap::new();
        for (service, requested) in exact {
            let active = self.active_keys(&service, &requested).await?;
            for (index, key) in requested {
                if !active.contains(&key) {
                    unknown.insert(index, violation(index, UNKNOWN_KEY, "exists"));
                }
            }
        }
        Ok(unknown)
    }

    /// The violation of every wildcard whose service has no catalogue.
    async fn unknown_services(
        &self,
        wildcards: BTreeMap<ServiceName, Vec<usize>>,
    ) -> Result<BTreeMap<usize, Violation>, IamError> {
        let mut unknown = BTreeMap::new();
        for (service, indexes) in wildcards {
            if !self.has_catalogue(&service).await? {
                for index in indexes {
                    unknown.insert(index, violation(index, UNKNOWN_SERVICE, "exists"));
                }
            }
        }
        Ok(unknown)
    }

    /// The requested keys of the service that an active version holds.
    async fn active_keys(
        &self,
        service: &ServiceName,
        requested: &[(usize, PermissionKey)],
    ) -> Result<BTreeSet<PermissionKey>, IamError> {
        let (rest, graphql): (Vec<PermissionKey>, Vec<PermissionKey>) = requested
            .iter()
            .map(|(_index, key)| key.clone())
            .partition(|key| key.kind() == PermissionKeyKind::Rest);
        let mut active = self.active_rest_keys(service, &rest).await?;
        active.extend(self.active_graphql_keys(service, &graphql).await?);
        Ok(active)
    }

    /// The REST keys among `keys` that an active version holds.
    async fn active_rest_keys(
        &self,
        service: &ServiceName,
        keys: &[PermissionKey],
    ) -> Result<BTreeSet<PermissionKey>, IamError> {
        if keys.is_empty() {
            return Ok(BTreeSet::new());
        }
        let entries = self.rest_permissions.find_by_keys(service, keys).await?;
        Ok(entries
            .iter()
            .map(RestPermission::parts)
            .filter(|parts| parts.active)
            .map(|parts| parts.key.clone())
            .collect())
    }

    /// The GraphQL keys among `keys` that an active version holds.
    async fn active_graphql_keys(
        &self,
        service: &ServiceName,
        keys: &[PermissionKey],
    ) -> Result<BTreeSet<PermissionKey>, IamError> {
        if keys.is_empty() {
            return Ok(BTreeSet::new());
        }
        let entries = self.graphql_permissions.find_by_keys(service, keys).await?;
        Ok(entries
            .iter()
            .map(GraphQlPermission::parts)
            .filter(|parts| parts.active)
            .map(|parts| parts.key.clone())
            .collect())
    }

    /// Whether the service has a catalogue entry of either form, active or not.
    async fn has_catalogue(&self, service: &ServiceName) -> Result<bool, IamError> {
        if !self
            .rest_permissions
            .find_by_service(service)
            .await?
            .is_empty()
        {
            return Ok(true);
        }
        Ok(!self
            .graphql_permissions
            .find_by_service(service)
            .await?
            .is_empty())
    }

    /// The change that replaces the grants: the role statement, the event and the audit record.
    fn change_of(
        &self,
        mut role: Role,
        grants: PermissionGrantSet,
        command: SetRolePermissionsCommand,
    ) -> Result<IamChange, IamError> {
        let SetRolePermissionsCommand {
            change_id,
            actor,
            expected,
            idempotency,
            ..
        } = command;
        let before = role.parts().clone();
        let guard = GuardCheck::Grants(
            grants
                .iter()
                .filter(|grant| !before.grants.contains(grant))
                .cloned()
                .collect(),
        );
        let stamp = RoleStamp {
            event_id: self.uuid_generator.generate(),
            actor: actor.clone(),
            occurred_at: self.clock.now(),
        };
        role.replace_permissions(Some(expected), grants, stamp.clone())?;
        let events = role.pull_envelopes()?;
        let audit = self.audit(&before, role.parts(), &stamp, idempotency.as_ref())?;
        let statement = RoleStatement::update(&role, expected, actor);
        Ok(IamChange::new(IamChangeParts {
            change_id,
            effect: DecisionEffect::Affected,
            statements: vec![ChangeStatement::SaveRole(Box::new(statement))],
            events,
            audit,
            entity_version: role.parts().version,
            idempotency,
        })?
        .with_guard(guard))
    }

    /// The committed audit record of the replacement.
    fn audit(
        &self,
        before: &RoleParts,
        after: &RoleParts,
        stamp: &RoleStamp,
        idempotency: Option<&IdempotencyRequest>,
    ) -> Result<SecurityAuditEvent, IamError> {
        let parts = SecurityAuditEventParts {
            id: SecurityAuditEventId::from_uuid(self.uuid_generator.generate()),
            occurred_at: stamp.occurred_at,
            actor: stamp.actor.clone(),
            caller_service: None,
            action: AuditAction::new(AUDIT_ACTION)?,
            target: AuditTarget::new("role", &after.id.to_string())?,
            scope: None,
            before: Some(AuditSummary::new(&before_summary(before))?),
            after: Some(AuditSummary::new(&after_summary(before, after))?),
            idempotency_key: idempotency.map(|request| request.key.clone()),
            outcome: AuditOutcome::Committed,
            reason: None,
            policy_version: None,
            request_id: None,
        };
        Ok(SecurityAuditEvent::record(parts)?)
    }
}

/// The parsed grants sorted by what decides whether they exist: the reserved keys, which no
/// catalogue holds, are unknown at once; the exact keys and the wildcards go by service.
struct Requested {
    unknown: BTreeMap<usize, Violation>,
    exact: BTreeMap<ServiceName, Vec<(usize, PermissionKey)>>,
    wildcards: BTreeMap<ServiceName, Vec<usize>>,
}

impl Requested {
    fn of(parsed: &[(usize, PermissionGrant)]) -> Self {
        let mut requested = Self {
            unknown: BTreeMap::new(),
            exact: BTreeMap::new(),
            wildcards: BTreeMap::new(),
        };
        for (index, grant) in parsed {
            match grant {
                PermissionGrant::Key(key) if key.kind() == PermissionKeyKind::Reserved => {
                    requested
                        .unknown
                        .insert(*index, violation(*index, UNKNOWN_KEY, "exists"));
                }
                PermissionGrant::Key(key) => requested
                    .exact
                    .entry(key.service().clone())
                    .or_default()
                    .push((*index, key.clone())),
                PermissionGrant::Wildcard(pattern) => requested
                    .wildcards
                    .entry(pattern.service().clone())
                    .or_default()
                    .push(*index),
            }
        }
        requested
    }
}

/// The violation of the text at `index`.
fn violation(index: usize, message: &str, code: &str) -> Violation {
    Violation {
        property_path: format!("keys[{index}]"),
        message: message.to_owned(),
        code: code.to_owned(),
    }
}

/// What the audit record keeps of a role before the replacement: the number of grants and the
/// version, never the keys.
fn before_summary(role: &RoleParts) -> String {
    format!(
        "grants={} version={}",
        role.grants.len(),
        role.version.value()
    )
}

/// What the audit record keeps of a role after the replacement: the numbers of grants, added keys
/// and removed keys, the version and, for added wildcards, `coversFutureElements=true` with the
/// patterns (the first ones, when there are many).
fn after_summary(before: &RoleParts, after: &RoleParts) -> String {
    let added = after
        .grants
        .iter()
        .filter(|grant| !before.grants.contains(grant))
        .count();
    let removed = before
        .grants
        .iter()
        .filter(|grant| !after.grants.contains(grant))
        .count();
    let wildcards: Vec<String> = after
        .grants
        .iter()
        .filter(|grant| grant.is_wildcard() && !before.grants.contains(grant))
        .map(ToString::to_string)
        .collect();
    let mut summary = format!(
        "grants={} added={added} removed={removed} version={}",
        after.grants.len(),
        after.version.value()
    );
    if !wildcards.is_empty() {
        let listed = wildcards
            .iter()
            .take(LISTED_WILDCARDS)
            .cloned()
            .collect::<Vec<_>>()
            .join(",");
        summary = format!(
            "{summary} coversFutureElements=true wildcards={} [{listed}]",
            wildcards.len()
        );
    }
    summary
}

#[async_trait::async_trait]
impl CommandHandler<SetRolePermissionsCommand> for SetRolePermissionsCommandHandler {
    async fn handle(&self, command: SetRolePermissionsCommand) -> Result<(), IamError> {
        self.set(command).await
    }
}

#[cfg(test)]
mod tests;
