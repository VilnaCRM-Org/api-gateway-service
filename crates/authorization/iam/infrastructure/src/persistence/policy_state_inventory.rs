//! PostgreSQL implementation of the policy inventory: every entity that has a state record, in a
//! stable order.
//!
//! The statements are checked at run time, so the offline query metadata does not hold them.

use iam_domain::{
    InventoryEntry, PolicyStateInventory, RepositoryError, ServiceName, StateKey, SubjectKind,
};
use sqlx::Row as _;
use sqlx::postgres::PgRow;

use crate::persistence::role::translate;

/// The entities of the policy as `(kind_rank, key_a, key_b)` rows: the rank orders the kinds, the
/// two text columns hold the key. A macro, so that the statements built from it are `'static`.
macro_rules! entries {
    () => {
        "
    SELECT 1 AS kind_rank, 'role' AS kind, id::text AS key_a, '' AS key_b
        FROM iam_roles WHERE deleted_at IS NULL
    UNION ALL
    SELECT 2, 'subject', subject_kind, subject_id
        FROM iam_user_roles WHERE revoked_at IS NULL GROUP BY subject_kind, subject_id
    UNION ALL
    SELECT 3, 'upstream', name, '' FROM iam_upstreams WHERE deleted_at IS NULL
    UNION ALL
    SELECT 4, 'route', id::text, '' FROM iam_routes WHERE deleted_at IS NULL
    UNION ALL
    SELECT 5, 'ratepolicy', id::text, '' FROM iam_rate_policies WHERE deleted_at IS NULL
    UNION ALL
    SELECT 6, 'catalog', service, '' FROM (
        SELECT service FROM iam_rest_permissions WHERE active
        UNION
        SELECT service FROM iam_graphql_permissions WHERE active
    ) AS services"
    };
}

/// The number of entries.
const COUNT: &str = concat!("SELECT count(*) FROM (", entries!(), ") AS entries");

/// The entries after the first `$1`, at most `$2`, in the order that makes the pages stable: the
/// byte order of the `C` collation is the same on every database.
const PAGE: &str = concat!(
    "SELECT kind, key_a, key_b FROM (",
    entries!(),
    ") AS entries ORDER BY kind_rank, key_a COLLATE \"C\", key_b COLLATE \"C\" OFFSET $1 LIMIT $2"
);

/// Lists the entities of the policy from the tables of the system of record.
#[derive(Debug)]
pub struct PgPolicyStateInventory {
    pool: sqlx::PgPool,
}

impl PgPolicyStateInventory {
    /// Builds the inventory over a pool; no connection is opened here.
    #[must_use]
    pub const fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
    async fn count_entries(&self) -> Result<u64, RepositoryError> {
        let count: i64 = sqlx::query_scalar(COUNT)
            .fetch_one(&self.pool)
            .await
            .map_err(translate)?;
        Ok(u64::try_from(count).unwrap_or_default())
    }

    async fn page_entries(
        &self,
        offset: u64,
        limit: u64,
    ) -> Result<Vec<InventoryEntry>, RepositoryError> {
        let rows = sqlx::query(PAGE)
            .bind(parameter(offset))
            .bind(parameter(limit))
            .fetch_all(&self.pool)
            .await
            .map_err(translate)?;
        rows.iter().map(entry_of).collect()
    }
}

/// The entry of one row: the key of a record, or the service of a catalogue.
fn entry_of(row: &PgRow) -> Result<InventoryEntry, RepositoryError> {
    let kind: String = row.try_get("kind").map_err(translate)?;
    let first: String = row.try_get("key_a").map_err(translate)?;
    let second: String = row.try_get("key_b").map_err(translate)?;
    if kind == "catalog" {
        return ServiceName::new(&first)
            .map(InventoryEntry::Catalogue)
            .map_err(unusable);
    }
    let text = match kind.as_str() {
        "subject" => format!("subject/{}/{second}", subject_kind(&first)?),
        other => format!("{other}/{first}"),
    };
    StateKey::parse(&text)
        .map(InventoryEntry::State)
        .map_err(unusable)
}

/// The stored text of a subject kind, checked.
fn subject_kind(text: &str) -> Result<&'static str, RepositoryError> {
    SubjectKind::parse(text)
        .map(SubjectKind::as_str)
        .map_err(unusable)
}

/// A stored value that is no key of the state topic is unusable data.
fn unusable<E>(error: E) -> RepositoryError
where
    E: std::error::Error + Send + Sync + 'static,
{
    RepositoryError::Unavailable(Box::new(error))
}

/// The unsigned value as the signed number of a SQL parameter.
fn parameter(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[async_trait::async_trait]
impl PolicyStateInventory for PgPolicyStateInventory {
    async fn count(&self) -> Result<u64, RepositoryError> {
        self.count_entries().await
    }

    async fn page(&self, offset: u64, limit: u64) -> Result<Vec<InventoryEntry>, RepositoryError> {
        self.page_entries(offset, limit).await
    }
}

#[cfg(test)]
mod tests;
