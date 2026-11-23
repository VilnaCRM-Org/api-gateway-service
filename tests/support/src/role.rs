//! Role repository double and role fixtures of the IAM context.

use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use iam_domain::{
    ActorRef, ChangeStatement, DecisionEffect, EntityVersion, GrantRecord, GrantStatus, IamChange,
    PermissionGrant, PermissionGrantSet, PermissionKeyKind, RepositoryError, Role, RoleGrant,
    RoleId, RoleKind, RoleName, RolePageQuery, RoleParts, RoleRepository, RoleStatement,
    ServiceName,
};
use rand::RngExt as _;

use crate::seed::TestRng;
use crate::unit_of_work::{iam_change, rebuilt, uuid_v7};

/// A stored role of `kind` named `name` without a description or grants at version 1, created and
/// updated at a random time after 2020.
///
/// # Panics
///
/// Panics when `name` is not a valid role name.
#[expect(
    clippy::expect_used,
    reason = "a fixture with an invalid name is a defect of the test"
)]
pub fn role(rng: &mut TestRng, name: &str, kind: RoleKind) -> Role {
    let micros = rng
        .rng()
        .random_range(1_577_836_800_000_000_u64..4_102_444_800_000_000);
    let at = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_micros(micros))
        .expect("a time before the year 2100");
    Role::restore(RoleParts {
        id: RoleId::from_uuid(uuid_v7(rng)),
        name: RoleName::new(name.to_owned()).expect("a valid role name"),
        description: None,
        kind,
        grants: PermissionGrantSet::default(),
        version: EntityVersion::INITIAL,
        created_at: at,
        updated_at: at,
        deleted_at: None,
    })
}

/// A random committed change that runs `statements`, written by a random user.
pub fn role_change(rng: &mut TestRng, statements: Vec<RoleStatement>) -> IamChange {
    rebuilt(&iam_change(rng, DecisionEffect::Affected, 0), |parts| {
        parts.statements = statements
            .into_iter()
            .map(|statement| ChangeStatement::SaveRole(Box::new(statement)))
            .collect();
    })
}

/// A random user who writes roles.
pub fn role_writer(rng: &mut TestRng) -> ActorRef {
    ActorRef::User(uuid_v7(rng))
}

/// What the double answers with.
#[derive(Debug)]
enum Answer {
    Holding(Vec<RoleParts>),
    Failing,
}

/// A role repository that answers from memory with the rules of the port: deleted roles are
/// never found, and pages follow the order of the identifiers.
#[derive(Debug)]
pub struct FakeRoleRepository {
    answer: Answer,
    records: Option<Vec<GrantRecord>>,
}

impl FakeRoleRepository {
    /// A repository without roles.
    #[must_use]
    pub const fn new() -> Self {
        Self::holding(Vec::new())
    }

    /// A repository that holds the state of each role.
    #[must_use]
    pub const fn holding(roles: Vec<RoleParts>) -> Self {
        Self {
            answer: Answer::Holding(roles),
            records: None,
        }
    }

    /// The same repository with `records` as the catalogue grants it answers, instead of the
    /// exact-key grants of its roles, which are all active.
    #[must_use]
    pub fn with_grant_records(mut self, records: Vec<GrantRecord>) -> Self {
        self.records = Some(records);
        self
    }

    /// A repository that answers `Unavailable`.
    #[must_use]
    pub const fn failing() -> Self {
        Self {
            answer: Answer::Failing,
            records: None,
        }
    }

    /// The roles that are not deleted, in the order of their identifiers.
    fn live(&self) -> Result<Vec<&RoleParts>, RepositoryError> {
        match &self.answer {
            Answer::Holding(roles) => {
                let mut live: Vec<&RoleParts> = roles
                    .iter()
                    .filter(|role| role.deleted_at.is_none())
                    .collect();
                live.sort_by_key(|role| role.id);
                Ok(live)
            }
            Answer::Failing => Err(RepositoryError::Unavailable(
                "in-memory repository failure".into(),
            )),
        }
    }
}

impl Default for FakeRoleRepository {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether `role` matches the filters and comes after the cursor of `query`.
fn selected(role: &RoleParts, query: &RolePageQuery) -> bool {
    let after = query.after.is_none_or(|after| role.id > after);
    let prefix = query.name_prefix.as_ref().is_none_or(|prefix| {
        role.name
            .comparison_form()
            .starts_with(&prefix.to_lowercase())
    });
    let kind = query.kind.is_none_or(|kind| role.kind == kind);
    after && prefix && kind
}

/// The exact-key grants of the live roles, all active, in role then key order.
fn role_grant_records(roles: &[&RoleParts]) -> Vec<GrantRecord> {
    roles
        .iter()
        .flat_map(|role| {
            role.grants.iter().filter_map(|grant| match grant {
                PermissionGrant::Key(key) => Some(GrantRecord {
                    role: role.id,
                    key: key.clone(),
                    status: GrantStatus::Active,
                }),
                PermissionGrant::Wildcard(_) => None,
            })
        })
        .collect()
}

#[async_trait]
impl RoleRepository for FakeRoleRepository {
    async fn find_by_id(&self, id: RoleId) -> Result<Option<Role>, RepositoryError> {
        Ok(self
            .live()?
            .into_iter()
            .find(|role| role.id == id)
            .map(|role| Role::restore(role.clone())))
    }

    async fn find_page(&self, query: &RolePageQuery) -> Result<Vec<Role>, RepositoryError> {
        let limit = usize::try_from(query.limit).unwrap_or(usize::MAX);
        Ok(self
            .live()?
            .into_iter()
            .filter(|role| selected(role, query))
            .take(limit)
            .map(|role| Role::restore(role.clone()))
            .collect())
    }

    async fn find_grants(&self, id: RoleId) -> Result<Vec<RoleGrant>, RepositoryError> {
        Ok(self
            .live()?
            .into_iter()
            .find(|role| role.id == id)
            .map(|role| {
                let mut grants: Vec<RoleGrant> = role
                    .grants
                    .iter()
                    .map(|grant| RoleGrant {
                        grant: grant.clone(),
                        active: true,
                    })
                    .collect();
                // The port answers in key order, as the database adapter does.
                grants.sort_by_cached_key(|grant| grant.grant.to_string());
                grants
            })
            .unwrap_or_default())
    }

    async fn find_catalogue_grants(
        &self,
        service: &ServiceName,
        kind: PermissionKeyKind,
    ) -> Result<Vec<GrantRecord>, RepositoryError> {
        let live = self.live()?;
        let mut records = self
            .records
            .clone()
            .unwrap_or_else(|| role_grant_records(&live));
        records.retain(|record| record.key.kind() == kind && record.key.service() == service);
        records.sort_by(|left, right| (left.role, &left.key).cmp(&(right.role, &right.key)));
        Ok(records)
    }
}

#[cfg(test)]
mod tests;
