//! The activation statement that the unit of work contributes to a change.
//!
//! It writes the status of the version, the catalogue entries, the grants that lose or move their
//! key and the catalogue epoch, all inside the transaction of the change.

use iam_domain::{
    CatalogueStatement, CatalogueStatementParts, InvalidPermissionKey, KeyRename, OrphanedGrant,
    PermissionKey, PermissionKeyKind, RepositoryError, SpecId,
};
use sqlx::types::Uuid as SqlUuid;
use sqlx::types::time::OffsetDateTime;
use sqlx::{PgConnection, PgPool, Row as _};

use crate::persistence::role::translate;
use crate::persistence::{graphql_permission, rest_permission};

/// Runs one catalogue statement inside the caller's transaction.
///
/// The writes run in this order: the status of the version and the entries of its form, the
/// orphaned grants, the renamed grants and the catalogue epoch. A failure leaves the rollback to
/// the caller.
///
/// # Errors
///
/// [`RepositoryError::Conflict`] when the version is no longer in the expected status, an entry or
/// a grant the change was decided against is gone, or a created key is stored already, and
/// [`RepositoryError::Unavailable`] when the storage fails.
pub async fn apply_within(
    connection: &mut PgConnection,
    statement: &CatalogueStatement,
) -> Result<(), RepositoryError> {
    let parts = statement.parts();
    if parts.kind == PermissionKeyKind::Gql {
        graphql_permission::write_within(connection, parts).await?;
    } else {
        rest_permission::write_within(connection, parts).await?;
    }
    orphan_grants(connection, parts).await?;
    rename_grants(connection, parts).await?;
    bump_catalog_epoch(connection, OffsetDateTime::from(parts.at)).await
}

/// A stored event payload that does not hold `data.createdKeys` as a list of permission keys is
/// unusable data.
#[derive(Debug, thiserror::Error)]
enum UnusablePayload {
    /// The payload is not JSON.
    #[error("a stored event payload is not JSON")]
    Json(#[source] serde_json::Error),
    /// The payload has no list of created keys.
    #[error("a stored event payload has no list of created keys")]
    Shape,
    /// A created key is not a permission key.
    #[error("a stored created key is invalid")]
    Key(#[source] InvalidPermissionKey),
}

/// The `createdKeys` of the first event of type `event_type` that the outbox holds for the
/// version `spec_id`: `iam.graphql_permissions.created` or `iam.rest_permissions.created`. The
/// statement is checked at run time, so the offline metadata does not hold it.
///
/// # Errors
///
/// [`RepositoryError::Unavailable`] when the storage fails or the payload is unusable.
pub(crate) async fn select_created_keys(
    pool: &PgPool,
    event_type: &str,
    spec_id: SpecId,
) -> Result<Option<Vec<PermissionKey>>, RepositoryError> {
    let row = sqlx::query(
        "SELECT payload FROM iam_outbox
        WHERE kind = 'event' AND event_type = $1 AND aggregate_id = $2
        ORDER BY position LIMIT 1",
    )
    .bind(event_type)
    .bind(spec_id.to_string())
    .fetch_optional(pool)
    .await
    .map_err(translate)?;
    row.as_ref()
        .map(|row| row.try_get::<String, _>("payload").map_err(translate))
        .transpose()?
        .map(|payload| created_keys(&payload))
        .transpose()
}

/// The keys that `payload`, the envelope of a catalogue creation event, lists.
pub(crate) fn created_keys(payload: &str) -> Result<Vec<PermissionKey>, RepositoryError> {
    let unusable = |error: UnusablePayload| RepositoryError::Unavailable(Box::new(error));
    let envelope: serde_json::Value =
        serde_json::from_str(payload).map_err(|error| unusable(UnusablePayload::Json(error)))?;
    envelope
        .get("data")
        .and_then(|data| data.get("createdKeys"))
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| unusable(UnusablePayload::Shape))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or(UnusablePayload::Shape)
                .and_then(|text| PermissionKey::parse(text).map_err(UnusablePayload::Key))
                .map_err(unusable)
        })
        .collect()
}

/// The number of affected rows must be the number the change expects; a stored row that is
/// missing, or already changed, means that the change was decided against a stale state.
pub(crate) fn expect_rows(affected: u64, expected: usize) -> Result<(), RepositoryError> {
    if u64::try_from(expected).is_ok_and(|expected| affected == expected) {
        Ok(())
    } else {
        Err(RepositoryError::Conflict)
    }
}

/// The stored states a page may hold, as the `active:sensitive` texts of the entry columns; a
/// filter left open allows both of its values.
pub(crate) fn state_filter(active: Option<bool>, sensitive: Option<bool>) -> Vec<String> {
    let sensitives = allowed(sensitive);
    allowed(active)
        .into_iter()
        .flat_map(|active| {
            sensitives
                .iter()
                .map(move |sensitive| format!("{active}:{sensitive}"))
        })
        .collect()
}

/// The values a boolean filter lets through: only its value, or both when it is open.
fn allowed(filter: Option<bool>) -> Vec<bool> {
    filter.map_or_else(|| vec![false, true], |value| vec![value])
}

/// A unique violation of a created entry means that another activation created the key first: a
/// conflict; everything else is an unavailable repository.
pub(crate) fn translate_entry(error: sqlx::Error) -> RepositoryError {
    let duplicate = error
        .as_database_error()
        .is_some_and(sqlx::error::DatabaseError::is_unique_violation);
    if duplicate {
        RepositoryError::Conflict
    } else {
        RepositoryError::Unavailable(Box::new(error))
    }
}

/// The grants to deactivate as parallel columns, one element per grant.
#[derive(Debug, Default, PartialEq, Eq)]
struct OrphanColumns {
    roles: Vec<SqlUuid>,
    keys: Vec<String>,
}

impl OrphanColumns {
    fn of(orphaned: &[OrphanedGrant]) -> Self {
        let mut columns = Self::default();
        for grant in orphaned {
            columns.roles.push(grant.role.as_uuid().as_uuid());
            columns.keys.push(grant.key.to_string());
        }
        columns
    }
}

/// The grants to move as parallel columns, one element per grant of every rename.
#[derive(Debug, Default, PartialEq, Eq)]
struct RenameColumns {
    roles: Vec<SqlUuid>,
    from: Vec<String>,
    to: Vec<String>,
}

impl RenameColumns {
    fn of(renames: &[KeyRename]) -> Self {
        let mut columns = Self::default();
        for rename in renames {
            for role in &rename.roles {
                columns.roles.push(role.as_uuid().as_uuid());
                columns.from.push(rename.from.to_string());
                columns.to.push(rename.to.to_string());
            }
        }
        columns
    }
}

/// Makes the grants that lose their key inactive and stamps `orphaned_at`.
async fn orphan_grants(
    connection: &mut PgConnection,
    parts: &CatalogueStatementParts,
) -> Result<(), RepositoryError> {
    let columns = OrphanColumns::of(&parts.orphaned);
    let written = sqlx::query!(
        "UPDATE iam_role_permissions AS grants SET active = FALSE, orphaned_at = $3
        FROM UNNEST($1::uuid[], $2::text[]) AS orphaned (role_id, permission_key)
        WHERE grants.role_id = orphaned.role_id AND grants.permission_key = orphaned.permission_key",
        columns.roles.as_slice(),
        columns.keys.as_slice(),
        OffsetDateTime::from(parts.at),
    )
    .execute(&mut *connection)
    .await
    .map_err(translate)?;
    expect_rows(written.rows_affected(), columns.keys.len())
}

/// Moves the grants of the renames to their new keys.
async fn rename_grants(
    connection: &mut PgConnection,
    parts: &CatalogueStatementParts,
) -> Result<(), RepositoryError> {
    let columns = RenameColumns::of(&parts.renames);
    let written = sqlx::query!(
        "UPDATE iam_role_permissions AS grants SET permission_key = renamed.new_key
        FROM UNNEST($1::uuid[], $2::text[], $3::text[]) AS renamed (role_id, old_key, new_key)
        WHERE grants.role_id = renamed.role_id AND grants.permission_key = renamed.old_key",
        columns.roles.as_slice(),
        columns.from.as_slice(),
        columns.to.as_slice(),
    )
    .execute(&mut *connection)
    .await
    .map_err(translate)?;
    expect_rows(written.rows_affected(), columns.roles.len())
}

/// Takes the next catalogue epoch of the single policy epoch row, which the transaction locked.
async fn bump_catalog_epoch(
    connection: &mut PgConnection,
    changed_at: OffsetDateTime,
) -> Result<(), RepositoryError> {
    let written = sqlx::query!(
        "UPDATE iam_policy_epoch SET catalog_epoch = catalog_epoch + 1, updated_at = $1
        WHERE id = 1",
        changed_at,
    )
    .execute(&mut *connection)
    .await
    .map_err(translate)?;
    expect_rows(written.rows_affected(), 1)
}

#[cfg(test)]
mod tests;
