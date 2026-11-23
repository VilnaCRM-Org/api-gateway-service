//! PostgreSQL implementation of the policy read repository port.
//!
//! It reads the subject's assignments, the compiled role sets, the active REST operations and
//! GraphQL type graphs of a service and the policy epoch, each group in one
//! `REPEATABLE READ READ ONLY` snapshot.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    AssignmentScope, CompiledRoleSet, GrantStatus, GraphQlTypeGraph, PermissionGrant, PolicyEpoch,
    PolicyReadRepository, ProjectId, RepositoryError, RestOperationSet, RoleAssignment, RoleId,
    ServiceCatalog, ServiceName, SubjectPolicy, SubjectRef,
};
use shared_domain::Uuid;
use sqlx::types::Uuid as SqlUuid;
use sqlx::types::time::OffsetDateTime;
use sqlx::{PgConnection, Postgres, Transaction};

use crate::persistence::graphql_spec::{self, FieldRow, PossibleTypeRow};
use crate::persistence::openapi_spec::{self, OperationRow};
use crate::persistence::role::translate;

/// Runs between the reads of one snapshot. A test installs one to commit a write after the
/// assignment rows are read and before the epoch is read, which the snapshot must not show.
#[async_trait::async_trait]
pub trait PolicyReadHook: std::fmt::Debug + Send + Sync {
    /// Called once per subject read, after the assignments are read and before the role sets and
    /// the epoch are.
    async fn after_assignments_read(&self);
}

/// Reads the policy data of the decision path in repeatable-read snapshots.
#[derive(Debug)]
pub struct PgPolicyReadRepository {
    pool: sqlx::PgPool,
    hook: Option<Arc<dyn PolicyReadHook>>,
}

/// The stored assignment row; it never leaves this module.
struct AssignmentRow {
    role_id: SqlUuid,
    scope_kind: String,
    project_id: Option<SqlUuid>,
    expires_at: Option<OffsetDateTime>,
}

/// One stored grant of a role that exists, or the role alone when it has no grant; it never leaves
/// this module.
struct RoleGrantRow {
    role_id: SqlUuid,
    permission_key: Option<String>,
    active: Option<bool>,
}

impl PgPolicyReadRepository {
    /// Builds the repository over a pool; no connection is opened here.
    #[must_use]
    pub const fn new(pool: sqlx::PgPool) -> Self {
        Self { pool, hook: None }
    }

    /// The same repository that runs `hook` between the reads of a subject snapshot.
    #[must_use]
    pub fn with_hook(mut self, hook: Arc<dyn PolicyReadHook>) -> Self {
        self.hook = Some(hook);
        self
    }

    async fn select_subject_policy(
        &self,
        subject: &SubjectRef,
    ) -> Result<SubjectPolicy, RepositoryError> {
        let mut snapshot = self.snapshot().await?;
        let rows = select_assignments(&mut snapshot, subject).await?;
        if let Some(hook) = &self.hook {
            hook.after_assignments_read().await;
        }
        let role_ids: BTreeSet<SqlUuid> = rows.iter().map(|row| row.role_id).collect();
        let grants = select_role_grants(&mut snapshot, &role_ids).await?;
        let epoch = select_epoch(&mut snapshot).await?;
        snapshot.commit().await.map_err(translate)?;
        Ok(SubjectPolicy::new(
            epoch,
            restore_assignments(&rows)?,
            compile_role_sets(grants)?,
        ))
    }

    async fn select_service_catalog(
        &self,
        service: &ServiceName,
    ) -> Result<Option<ServiceCatalog>, RepositoryError> {
        let mut snapshot = self.snapshot().await?;
        let rest = select_rest_operations(&mut snapshot, service).await?;
        let graphql = select_type_graphs(&mut snapshot, service).await?;
        let epoch = select_epoch(&mut snapshot).await?;
        snapshot.commit().await.map_err(translate)?;
        if rest.is_empty() && graphql.is_empty() {
            return Ok(None);
        }
        Ok(Some(ServiceCatalog::new(
            service.clone(),
            epoch,
            rest,
            graphql,
        )))
    }

    /// Opens the transaction whose reads all see the state of its first statement.
    async fn snapshot(&self) -> Result<Transaction<'static, Postgres>, RepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(translate)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *transaction)
            .await
            .map_err(translate)?;
        Ok(transaction)
    }
}

/// The assignments of the subject that are not revoked, expired ones included.
async fn select_assignments(
    connection: &mut PgConnection,
    subject: &SubjectRef,
) -> Result<Vec<AssignmentRow>, RepositoryError> {
    sqlx::query_as!(
        AssignmentRow,
        "SELECT role_id, scope_kind, project_id, expires_at
        FROM iam_user_roles
        WHERE subject_kind = $1 AND subject_id = $2 AND revoked_at IS NULL
        ORDER BY id",
        subject.kind().as_str(),
        subject.id().to_string(),
    )
    .fetch_all(connection)
    .await
    .map_err(translate)
}

/// The roles that are not deleted with their grants, active or orphaned.
async fn select_role_grants(
    connection: &mut PgConnection,
    role_ids: &BTreeSet<SqlUuid>,
) -> Result<Vec<RoleGrantRow>, RepositoryError> {
    let ids: Vec<SqlUuid> = role_ids.iter().copied().collect();
    sqlx::query_as!(
        RoleGrantRow,
        r#"SELECT r.id AS "role_id!", p.permission_key AS "permission_key?", p.active AS "active?"
        FROM iam_roles r
        LEFT JOIN iam_role_permissions p ON p.role_id = r.id
        WHERE r.deleted_at IS NULL AND r.id = ANY($1::uuid[])
        ORDER BY r.id, p.permission_key"#,
        ids.as_slice(),
    )
    .fetch_all(connection)
    .await
    .map_err(translate)
}

/// The current policy epoch.
async fn select_epoch(connection: &mut PgConnection) -> Result<PolicyEpoch, RepositoryError> {
    let row = sqlx::query_as!(
        super::Row,
        "SELECT version, digest, log_epoch, relay_epoch, catalog_epoch FROM iam_policy_epoch WHERE id = 1",
    )
    .fetch_one(connection)
    .await
    .map_err(super::translate)?;
    super::restore(&row)
}

/// The operation sets of the active `OpenAPI` versions of the service, in the order of their ids.
async fn select_rest_operations(
    connection: &mut PgConnection,
    service: &ServiceName,
) -> Result<Vec<RestOperationSet>, RepositoryError> {
    let specs = sqlx::query!(
        "SELECT id FROM iam_openapi_specs WHERE service = $1 AND status = 'active' ORDER BY id",
        service.as_str(),
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(translate)?;
    if specs.is_empty() {
        return Ok(Vec::new());
    }
    let ids: Vec<SqlUuid> = specs.iter().map(|spec| spec.id).collect();
    let rows: Vec<OperationRow> = sqlx::query_as!(
        OperationRow,
        "SELECT spec_id, method, path_template, label, sensitive, audit_always
            FROM iam_openapi_spec_operations WHERE spec_id = ANY($1)",
        ids.as_slice(),
    )
    .fetch_all(connection)
    .await
    .map_err(translate)?;
    let mut grouped = openapi_spec::group(rows, |row| row.spec_id);
    ids.iter()
        .map(|id| openapi_spec::operation_set(&grouped.remove(id).unwrap_or_default()))
        .collect()
}

/// The type graphs of the active GraphQL versions of the service, in the order of their ids.
async fn select_type_graphs(
    connection: &mut PgConnection,
    service: &ServiceName,
) -> Result<Vec<GraphQlTypeGraph>, RepositoryError> {
    let specs = sqlx::query!(
        "SELECT id FROM iam_graphql_specs WHERE service = $1 AND status = 'active' ORDER BY id",
        service.as_str(),
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(translate)?;
    if specs.is_empty() {
        return Ok(Vec::new());
    }
    let ids: Vec<SqlUuid> = specs.iter().map(|spec| spec.id).collect();
    let fields: Vec<FieldRow> = sqlx::query_as!(
        FieldRow,
        "SELECT spec_id, type_name, field_name, return_type, sensitive, audit_always
            FROM iam_graphql_spec_fields WHERE spec_id = ANY($1)",
        ids.as_slice(),
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(translate)?;
    let possible: Vec<PossibleTypeRow> = sqlx::query_as!(
        PossibleTypeRow,
        "SELECT spec_id, abstract_type, possible_type
            FROM iam_graphql_spec_possible_types WHERE spec_id = ANY($1)",
        ids.as_slice(),
    )
    .fetch_all(connection)
    .await
    .map_err(translate)?;
    let mut fields = graphql_spec::group(fields, |row| row.spec_id);
    let mut possible = graphql_spec::group(possible, |row| row.spec_id);
    ids.iter()
        .map(|id| {
            graphql_spec::graph(
                &fields.remove(id).unwrap_or_default(),
                &possible.remove(id).unwrap_or_default(),
            )
        })
        .collect()
}

/// Rebuilds the assignments through the value objects; a value that breaks an invariant is
/// unusable data. The expiry travels with the assignment: the `Clock` port decides at evaluation.
fn restore_assignments(rows: &[AssignmentRow]) -> Result<Vec<RoleAssignment>, RepositoryError> {
    rows.iter().map(restore_assignment).collect()
}

fn restore_assignment(row: &AssignmentRow) -> Result<RoleAssignment, RepositoryError> {
    let project_id = row
        .project_id
        .map(|id| ProjectId::from_uuid(Uuid::from_uuid(id)));
    Ok(RoleAssignment::new(
        RoleId::from_uuid(Uuid::from_uuid(row.role_id)),
        AssignmentScope::from_parts(&row.scope_kind, project_id).map_err(unusable)?,
        row.expires_at.map(SystemTime::from),
    ))
}

/// Compiles the grants of every role; the grants of a role that no longer is active are marked
/// orphaned and left out by the compilation, and a role without grants gets the empty set.
fn compile_role_sets(
    rows: Vec<RoleGrantRow>,
) -> Result<BTreeMap<RoleId, CompiledRoleSet>, RepositoryError> {
    let mut grants: BTreeMap<RoleId, Vec<(PermissionGrant, GrantStatus)>> = BTreeMap::new();
    for row in rows {
        let entry = grants
            .entry(RoleId::from_uuid(Uuid::from_uuid(row.role_id)))
            .or_default();
        if let Some(key) = row.permission_key {
            let status = if row.active == Some(true) {
                GrantStatus::Active
            } else {
                GrantStatus::Orphaned
            };
            entry.push((PermissionGrant::parse(&key).map_err(unusable)?, status));
        }
    }
    Ok(grants
        .into_iter()
        .map(|(role, grants)| (role, CompiledRoleSet::compile(grants)))
        .collect())
}

/// A stored value that breaks a domain invariant is unusable data.
fn unusable<E>(error: E) -> RepositoryError
where
    E: std::error::Error + Send + Sync + 'static,
{
    RepositoryError::Unavailable(Box::new(error))
}

#[async_trait::async_trait]
impl PolicyReadRepository for PgPolicyReadRepository {
    async fn read_subject_policy(
        &self,
        subject: &SubjectRef,
    ) -> Result<SubjectPolicy, RepositoryError> {
        self.select_subject_policy(subject).await
    }

    async fn read_service_catalog(
        &self,
        service: &ServiceName,
    ) -> Result<Option<ServiceCatalog>, RepositoryError> {
        self.select_service_catalog(service).await
    }
}

#[cfg(test)]
mod tests;
