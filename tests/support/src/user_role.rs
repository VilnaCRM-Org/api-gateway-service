//! Assignment repository double and assignment fixtures of the IAM context.

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use iam_domain::{
    ActorRef, AssignmentScope, ChangeStatement, DecisionEffect, EntityVersion, IamChange,
    RepositoryError, RoleId, SubjectRef, UserRole, UserRoleId, UserRolePageQuery, UserRoleParts,
    UserRoleRepository, UserRoleStatement,
};
use rand::RngExt as _;

use crate::seed::TestRng;
use crate::unit_of_work::{iam_change, rebuilt, uuid_v7};

/// A stored assignment of `role_id` to `subject` at `scope` without an expiry at version 1,
/// created by a random user and created and updated at a random time after 2020.
///
/// # Panics
///
/// Never in practice: the generated time lies before the year 2100.
#[expect(
    clippy::expect_used,
    reason = "the generated time lies before the year 2100; a failure is a defect of the fixture"
)]
pub fn user_role(
    rng: &mut TestRng,
    role_id: RoleId,
    subject: SubjectRef,
    scope: AssignmentScope,
) -> UserRole {
    let micros = rng
        .rng()
        .random_range(1_577_836_800_000_000_u64..4_102_444_800_000_000);
    let at = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_micros(micros))
        .expect("a time before the year 2100");
    UserRole::restore(UserRoleParts {
        id: UserRoleId::from_uuid(uuid_v7(rng)),
        subject,
        role_id,
        scope,
        expires_at: None,
        version: EntityVersion::INITIAL,
        created_by: ActorRef::User(uuid_v7(rng)),
        created_at: at,
        updated_at: at,
        revoked_at: None,
    })
}

/// A random user subject.
pub fn user_subject(rng: &mut TestRng) -> SubjectRef {
    SubjectRef::user(uuid_v7(rng))
}

/// A random committed change that runs `statements`, written by a random user.
pub fn user_role_change(rng: &mut TestRng, statements: Vec<UserRoleStatement>) -> IamChange {
    rebuilt(&iam_change(rng, DecisionEffect::Affected, 0), |parts| {
        parts.statements = statements
            .into_iter()
            .map(|statement| ChangeStatement::SaveUserRole(Box::new(statement)))
            .collect();
    })
}

/// An assignment repository that keeps the assignments in memory with the rules of the port and
/// of the storage.
///
/// Revoked assignments are never found, pages follow the order of the identifiers, and
/// [`FakeUserRoleRepository::save`] applies the uniqueness and version rules of the unit of work.
#[derive(Debug)]
pub struct FakeUserRoleRepository {
    stored: Option<Mutex<Vec<UserRoleParts>>>,
}

impl FakeUserRoleRepository {
    /// A repository without assignments.
    #[must_use]
    pub const fn new() -> Self {
        Self::holding(Vec::new())
    }

    /// A repository that holds the state of each assignment.
    #[must_use]
    pub const fn holding(user_roles: Vec<UserRoleParts>) -> Self {
        Self {
            stored: Some(Mutex::new(user_roles)),
        }
    }

    /// A repository that answers `Unavailable`.
    #[must_use]
    pub const fn failing() -> Self {
        Self { stored: None }
    }

    /// Runs one assignment statement as the unit of work does.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::AlreadyExists`] when an insert meets a stored id or an assignment that
    /// is not revoked with the same subject, role and scope, [`RepositoryError::Conflict`] when an
    /// update finds no assignment that is not revoked at the expected version, and
    /// [`RepositoryError::Unavailable`] for the failing repository; nothing changes then.
    pub fn save(&self, statement: &UserRoleStatement) -> Result<(), RepositoryError> {
        let mut stored = self.lock()?;
        let written = statement.user_role();
        match statement.expected() {
            None => insert(&mut stored, written),
            Some(expected) => update(&mut stored, written, expected),
        }
    }

    /// Every stored assignment, revoked ones included, in the order they were stored; empty for the
    /// failing repository.
    #[must_use]
    pub fn stored(&self) -> Vec<UserRoleParts> {
        self.lock().map(|stored| stored.clone()).unwrap_or_default()
    }

    /// The assignments that are not revoked, in the order of their identifiers.
    fn live(&self) -> Result<Vec<UserRoleParts>, RepositoryError> {
        let mut live: Vec<UserRoleParts> = self
            .lock()?
            .iter()
            .filter(|user_role| !user_role.is_revoked())
            .cloned()
            .collect();
        live.sort_by_key(|user_role| user_role.id);
        Ok(live)
    }

    /// The stored assignments, or `Unavailable` for the failing repository.
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Vec<UserRoleParts>>, RepositoryError> {
        self.stored
            .as_ref()
            .map(|stored| stored.lock().unwrap_or_else(PoisonError::into_inner))
            .ok_or_else(|| RepositoryError::Unavailable("in-memory repository failure".into()))
    }
}

impl Default for FakeUserRoleRepository {
    fn default() -> Self {
        Self::new()
    }
}

/// Stores a new assignment unless its id is taken or an assignment that is not revoked holds its
/// subject, role and scope.
fn insert(stored: &mut Vec<UserRoleParts>, written: &UserRoleParts) -> Result<(), RepositoryError> {
    let taken = stored
        .iter()
        .any(|user_role| user_role.id == written.id || user_role.duplicates(written));
    if taken {
        return Err(RepositoryError::AlreadyExists);
    }
    stored.push(written.clone());
    Ok(())
}

/// Replaces a stored assignment that is not revoked and holds the version `expected`.
fn update(
    stored: &mut [UserRoleParts],
    written: &UserRoleParts,
    expected: EntityVersion,
) -> Result<(), RepositoryError> {
    let current = stored.iter_mut().find(|user_role| {
        user_role.id == written.id && !user_role.is_revoked() && user_role.version == expected
    });
    let Some(current) = current else {
        return Err(RepositoryError::Conflict);
    };
    *current = written.clone();
    Ok(())
}

/// Whether `user_role` matches the filters and comes after the cursor of `query`.
fn selected(user_role: &UserRoleParts, query: &UserRolePageQuery) -> bool {
    let after = query.after.is_none_or(|after| user_role.id > after);
    let kind = query
        .subject_kind
        .is_none_or(|kind| user_role.subject.kind() == kind);
    let subject = query
        .subject_id
        .as_ref()
        .is_none_or(|id| user_role.subject.id().to_string() == *id);
    let role = query.role_id.is_none_or(|id| user_role.role_id == id);
    let project = query
        .project_id
        .is_none_or(|id| user_role.scope.project_id() == Some(id));
    let expiry = query.include_expired || user_role.is_active_at(query.now);
    after && kind && subject && role && project && expiry
}

#[async_trait]
impl UserRoleRepository for FakeUserRoleRepository {
    async fn find_by_id(&self, id: UserRoleId) -> Result<Option<UserRole>, RepositoryError> {
        Ok(self
            .live()?
            .into_iter()
            .find(|user_role| user_role.id == id)
            .map(UserRole::restore))
    }

    async fn find_page(&self, query: &UserRolePageQuery) -> Result<Vec<UserRole>, RepositoryError> {
        let limit = usize::try_from(query.limit).unwrap_or(usize::MAX);
        Ok(self
            .live()?
            .into_iter()
            .filter(|user_role| selected(user_role, query))
            .take(limit)
            .map(UserRole::restore)
            .collect())
    }
}

#[cfg(test)]
mod tests;
