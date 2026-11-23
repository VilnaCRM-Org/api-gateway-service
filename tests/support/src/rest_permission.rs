//! REST permission repository double of the IAM context.

use std::sync::{Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use iam_domain::{
    PermissionId, PermissionKey, PermissionPageQuery, RepositoryError, RestPermission,
    RestPermissionParts, RestPermissionRepository, ServiceName, SpecId,
};

/// A permission repository that keeps the REST catalogue entries in memory with the rules of the
/// port.
///
/// Pages follow the order of the identifiers and the other reads the order of the keys. The unit
/// of work writes the entries in production; here [`FakeRestPermissionRepository::insert`]
/// stores them directly.
#[derive(Debug)]
pub struct FakeRestPermissionRepository {
    stored: Option<Mutex<Vec<RestPermissionParts>>>,
    created: Mutex<Vec<(SpecId, Vec<PermissionKey>)>>,
}

impl FakeRestPermissionRepository {
    /// A repository without entries.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            stored: Some(Mutex::new(Vec::new())),
            created: Mutex::new(Vec::new()),
        }
    }

    /// A repository that answers `Unavailable`.
    #[must_use]
    pub const fn failing() -> Self {
        Self {
            stored: None,
            created: Mutex::new(Vec::new()),
        }
    }

    /// Stores an entry.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::AlreadyExists`] when the id or the key is stored, and
    /// [`RepositoryError::Unavailable`] for the failing repository; nothing changes then.
    pub fn insert(&self, entry: &RestPermission) -> Result<(), RepositoryError> {
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

    /// Records the keys that the activation of `spec_id` created, as the event of the activation
    /// holds them in production.
    pub fn record_created_keys(&self, spec_id: SpecId, keys: Vec<PermissionKey>) {
        self.created
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((spec_id, keys));
    }

    /// The state of every stored entry, in the order they were stored; empty for the failing
    /// repository.
    #[must_use]
    pub fn stored(&self) -> Vec<RestPermissionParts> {
        self.lock().map(|stored| stored.clone()).unwrap_or_default()
    }

    /// The entries that satisfy `keep`, restored.
    fn select(
        &self,
        keep: impl Fn(&RestPermissionParts) -> bool,
    ) -> Result<Vec<RestPermissionParts>, RepositoryError> {
        Ok(self
            .lock()?
            .iter()
            .filter(|parts| keep(parts))
            .cloned()
            .collect())
    }

    /// The stored entries, or `Unavailable` for the failing repository.
    fn lock(&self) -> Result<MutexGuard<'_, Vec<RestPermissionParts>>, RepositoryError> {
        self.stored
            .as_ref()
            .map(|stored| stored.lock().unwrap_or_else(PoisonError::into_inner))
            .ok_or_else(|| RepositoryError::Unavailable("in-memory repository failure".into()))
    }
}

impl Default for FakeRestPermissionRepository {
    fn default() -> Self {
        Self::new()
    }
}

/// Rebuilds the stored entries, which hold REST keys only.
fn restored(parts: Vec<RestPermissionParts>) -> Result<Vec<RestPermission>, RepositoryError> {
    parts
        .into_iter()
        .map(|parts| {
            RestPermission::restore(parts)
                .map_err(|error| RepositoryError::Unavailable(Box::new(error)))
        })
        .collect()
}

/// Whether `parts` matches the filters and comes after the cursor of `query`.
fn selected(parts: &RestPermissionParts, query: &PermissionPageQuery) -> bool {
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
        && query.method.is_none_or(|method| {
            matches!(&parts.key, PermissionKey::Rest { method: found, .. } if *found == method)
        })
}

#[async_trait]
impl RestPermissionRepository for FakeRestPermissionRepository {
    async fn find_by_id(
        &self,
        id: PermissionId,
    ) -> Result<Option<RestPermission>, RepositoryError> {
        restored(self.select(|parts| parts.id == id)?).map(|mut found| found.pop())
    }

    async fn find_by_keys(
        &self,
        service: &ServiceName,
        keys: &[PermissionKey],
    ) -> Result<Vec<RestPermission>, RepositoryError> {
        let mut found =
            self.select(|parts| parts.key.service() == service && keys.contains(&parts.key))?;
        found.sort_by(|left, right| left.key.cmp(&right.key));
        restored(found)
    }

    async fn find_by_service(
        &self,
        service: &ServiceName,
    ) -> Result<Vec<RestPermission>, RepositoryError> {
        let mut found = self.select(|parts| parts.key.service() == service)?;
        found.sort_by(|left, right| left.key.cmp(&right.key));
        restored(found)
    }

    async fn find_page(
        &self,
        query: &PermissionPageQuery,
    ) -> Result<Vec<RestPermission>, RepositoryError> {
        let limit = usize::try_from(query.limit).unwrap_or(usize::MAX);
        let mut found = self.select(|parts| selected(parts, query))?;
        found.sort_by_key(|parts| parts.id);
        found.truncate(limit);
        restored(found)
    }

    async fn find_created_keys(
        &self,
        spec_id: SpecId,
    ) -> Result<Option<Vec<PermissionKey>>, RepositoryError> {
        drop(self.lock()?);
        Ok(self
            .created
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .find(|(recorded, _keys)| *recorded == spec_id)
            .map(|(_recorded, keys)| keys.clone()))
    }
}

#[cfg(test)]
mod tests;
