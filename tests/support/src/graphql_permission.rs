//! GraphQL permission repository double of the IAM context.

use std::sync::{Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use iam_domain::{
    GqlCoordinate, GraphQlPermission, GraphQlPermissionParts, GraphQlPermissionRepository,
    PermissionId, PermissionKey, PermissionPageQuery, RepositoryError, ServiceName,
};

/// A permission repository that keeps the GraphQL catalogue entries in memory with the rules of the
/// port.
///
/// Pages follow the order of the identifiers and the other reads the order of the keys. The unit
/// of work writes the entries in production; here [`FakeGraphQlPermissionRepository::insert`]
/// stores them directly.
#[derive(Debug)]
pub struct FakeGraphQlPermissionRepository {
    stored: Option<Mutex<Vec<GraphQlPermissionParts>>>,
}

impl FakeGraphQlPermissionRepository {
    /// A repository without entries.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            stored: Some(Mutex::new(Vec::new())),
        }
    }

    /// A repository that answers `Unavailable`.
    #[must_use]
    pub const fn failing() -> Self {
        Self { stored: None }
    }

    /// Stores an entry.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::AlreadyExists`] when the id or the key is stored, and
    /// [`RepositoryError::Unavailable`] for the failing repository; nothing changes then.
    pub fn insert(&self, entry: &GraphQlPermission) -> Result<(), RepositoryError> {
        let mut stored = self.lock()?;
        let written = entry.parts();
        if stored
            .iter()
            .any(|parts| parts.id == written.id || parts.key == written.key)
        {
            return Err(RepositoryError::AlreadyExists);
        }
        stored.push(written.clone());
        drop(stored);
        Ok(())
    }

    /// The state of every stored entry, in the order they were stored; empty for the failing
    /// repository.
    #[must_use]
    pub fn stored(&self) -> Vec<GraphQlPermissionParts> {
        self.lock().map(|stored| stored.clone()).unwrap_or_default()
    }

    /// The entries that satisfy `keep`, restored.
    fn select(
        &self,
        keep: impl Fn(&GraphQlPermissionParts) -> bool,
    ) -> Result<Vec<GraphQlPermissionParts>, RepositoryError> {
        Ok(self
            .lock()?
            .iter()
            .filter(|parts| keep(parts))
            .cloned()
            .collect())
    }

    /// The stored entries, or `Unavailable` for the failing repository.
    fn lock(&self) -> Result<MutexGuard<'_, Vec<GraphQlPermissionParts>>, RepositoryError> {
        self.stored
            .as_ref()
            .map(|stored| stored.lock().unwrap_or_else(PoisonError::into_inner))
            .ok_or_else(|| RepositoryError::Unavailable("in-memory repository failure".into()))
    }
}

impl Default for FakeGraphQlPermissionRepository {
    fn default() -> Self {
        Self::new()
    }
}

/// Rebuilds the stored entries, which hold GraphQL keys only.
fn restored(parts: Vec<GraphQlPermissionParts>) -> Result<Vec<GraphQlPermission>, RepositoryError> {
    parts
        .into_iter()
        .map(|parts| {
            GraphQlPermission::restore(parts)
                .map_err(|error| RepositoryError::Unavailable(Box::new(error)))
        })
        .collect()
}

/// Whether `parts` matches the filters and comes after the cursor of `query`.
fn selected(parts: &GraphQlPermissionParts, query: &PermissionPageQuery) -> bool {
    query.after.is_none_or(|after| parts.id > after)
        && query
            .service
            .as_ref()
            .is_none_or(|service| parts.key.service() == service)
        && query.active.is_none_or(|active| parts.active == active)
        && query
            .sensitive
            .is_none_or(|sensitive| parts.flags.is_sensitive() == sensitive)
        && query
            .key_prefix
            .as_ref()
            .is_none_or(|prefix| parts.key.to_string().starts_with(prefix.as_str()))
        && query.type_name.as_ref().is_none_or(|type_name| {
            matches!(
                &parts.key,
                PermissionKey::Gql {
                    coordinate: GqlCoordinate::Field { type_name: found, .. },
                    ..
                } if found == type_name
            )
        })
}

#[async_trait]
impl GraphQlPermissionRepository for FakeGraphQlPermissionRepository {
    async fn find_by_id(
        &self,
        id: PermissionId,
    ) -> Result<Option<GraphQlPermission>, RepositoryError> {
        restored(self.select(|parts| parts.id == id)?).map(|mut found| found.pop())
    }

    async fn find_by_keys(
        &self,
        service: &ServiceName,
        keys: &[PermissionKey],
    ) -> Result<Vec<GraphQlPermission>, RepositoryError> {
        let mut found =
            self.select(|parts| parts.key.service() == service && keys.contains(&parts.key))?;
        found.sort_by(|left, right| left.key.cmp(&right.key));
        restored(found)
    }

    async fn find_by_service(
        &self,
        service: &ServiceName,
    ) -> Result<Vec<GraphQlPermission>, RepositoryError> {
        let mut found = self.select(|parts| parts.key.service() == service)?;
        found.sort_by(|left, right| left.key.cmp(&right.key));
        restored(found)
    }

    async fn find_page(
        &self,
        query: &PermissionPageQuery,
    ) -> Result<Vec<GraphQlPermission>, RepositoryError> {
        let limit = usize::try_from(query.limit).unwrap_or(usize::MAX);
        let mut found = self.select(|parts| selected(parts, query))?;
        found.sort_by_key(|parts| parts.id);
        found.truncate(limit);
        restored(found)
    }
}

#[cfg(test)]
mod tests;
