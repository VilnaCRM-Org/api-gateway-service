//! The catalogue statement of `PgIamUnitOfWork` and the permission repositories: an activation
//! commits the version status, the entries, the orphan marks, the renames and both epochs together
//! or not at all.

use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, CatalogueStatement, CatalogueStatementParts, ContentHash, DecisionEffect, EntryFlags,
    EntryInsert, EventEnvelope, GrantRecord, GrantStatus, GraphQlPermissionRepository as _,
    GraphQlPermissionsCreated, GraphQlSpecRepository as _, GraphQlSpecStatement,
    IamUnitOfWork as _, KeyRename, OpenApiSpecRepository as _, OpenApiSpecStatement, OrphanedGrant,
    PermissionFlags, PermissionId, PermissionKey, PermissionKeyKind, PermissionPageQuery,
    PolicyEpochRepository as _, RepositoryError, RestPermissionRepository as _, RoleId,
    RoleRepository as _, ServiceName, SpecId, SpecStatus, SpecTransition,
};
use iam_infrastructure::{
    PgGraphQlPermissionRepository, PgGraphQlSpecRepository, PgIamUnitOfWork,
    PgOpenApiSpecRepository, PgPolicyEpochRepository, PgRestPermissionRepository, PgRoleRepository,
};
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;
use test_support::catalogue::catalogue_change;
use test_support::graphql_spec::{SDL_FIXTURE, graphql_spec, graphql_spec_change};
use test_support::openapi_spec::{DOCUMENT_FIXTURE, openapi_spec, openapi_spec_change};
use test_support::seed::TestRng;
use test_support::unit_of_work::{rebuilt, uuid_v7};

const SERVICE: &str = "billing";
const PAY: &str = "gql:billing:Mutation.pay";
const INVOICES: &str = "gql:billing:Query.invoices";
const OLD: &str = "gql:billing:Query.old";
const OLDER: &str = "gql:billing:Query.older";

fn service() -> ServiceName {
    ServiceName::new(SERVICE).unwrap()
}

fn key(value: &str) -> PermissionKey {
    PermissionKey::parse(value).unwrap()
}

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(1_700_000_000))
        .unwrap()
}

fn hash_of(text: &str) -> ContentHash {
    ContentHash::new(&Sha256::digest(text.as_bytes())).unwrap()
}

fn entry(rng: &mut TestRng, value: &str, flags: PermissionFlags) -> EntryInsert {
    EntryInsert {
        id: PermissionId::from_uuid(uuid_v7(rng)),
        key: key(value),
        flags,
    }
}

fn transition(spec_id: SpecId, from: SpecStatus, to: SpecStatus) -> SpecTransition {
    SpecTransition {
        spec_id,
        from,
        to,
        activated_at: Some(at()),
        retired_at: (to == SpecStatus::Retired).then(at),
    }
}

/// A statement of `kind` that only moves the status of `spec_id`.
fn parts(kind: PermissionKeyKind, spec_id: SpecId) -> CatalogueStatementParts {
    CatalogueStatementParts {
        kind,
        service: service(),
        transition: transition(spec_id, SpecStatus::Draft, SpecStatus::Active),
        created: Vec::new(),
        reflagged: Vec::new(),
        reactivated: Vec::new(),
        deactivated: Vec::new(),
        orphaned: Vec::new(),
        renames: Vec::new(),
        at: at(),
    }
}

/// Stores a draft GraphQL version of the billing service and returns its identifier.
async fn draft_graphql(pool: &PgPool, rng: &mut TestRng) -> SpecId {
    let spec = graphql_spec(rng, &service(), SpecStatus::Draft, hash_of(SDL_FIXTURE));
    let change = graphql_spec_change(
        rng,
        vec![GraphQlSpecStatement::insert(&spec, SDL_FIXTURE.to_owned())],
    );
    PgIamUnitOfWork::new(pool.clone())
        .commit(change)
        .await
        .unwrap();
    spec.parts().id
}

/// Stores a draft `OpenAPI` version of the billing service and returns its identifier.
async fn draft_openapi(pool: &PgPool, rng: &mut TestRng) -> SpecId {
    let spec = openapi_spec(
        rng,
        &service(),
        SpecStatus::Draft,
        hash_of(DOCUMENT_FIXTURE),
    );
    let change = openapi_spec_change(
        rng,
        vec![OpenApiSpecStatement::insert(
            &spec,
            DOCUMENT_FIXTURE.to_owned(),
        )],
    );
    PgIamUnitOfWork::new(pool.clone())
        .commit(change)
        .await
        .unwrap();
    spec.parts().id
}

async fn commit(
    pool: &PgPool,
    rng: &mut TestRng,
    statements: Vec<CatalogueStatementParts>,
) -> Result<(), RepositoryError> {
    let statements = statements
        .into_iter()
        .map(|given| CatalogueStatement::new(given).unwrap())
        .collect();
    PgIamUnitOfWork::new(pool.clone())
        .commit(catalogue_change(rng, DecisionEffect::Affected, statements))
        .await
        .map(|_receipt| ())
}

/// Inserts a role with active grants of `keys`, as a fixture writes them.
async fn seed_role(pool: &PgPool, rng: &mut TestRng, keys: &[&str]) -> RoleId {
    let role = RoleId::from_uuid(uuid_v7(rng));
    sqlx::query(
        "INSERT INTO iam_roles (id, name, kind, grant_count, version, created_at, updated_at)
        VALUES ($1, $2, 'custom', $3, 1, now(), now())",
    )
    .bind(role.as_uuid().as_uuid())
    .bind(format!("role-{role}"))
    .bind(i32::try_from(keys.len()).unwrap())
    .execute(pool)
    .await
    .unwrap();
    for grant in keys {
        sqlx::query(
            "INSERT INTO iam_role_permissions (role_id, permission_key, key_kind, service,
                is_wildcard, active, granted_by, granted_at)
            VALUES ($1, $2, 'gql', $3, FALSE, TRUE, 'system:test', now())",
        )
        .bind(role.as_uuid().as_uuid())
        .bind(*grant)
        .bind(SERVICE)
        .execute(pool)
        .await
        .unwrap();
    }
    role
}

/// `(active, orphaned)` of the grant of `role` to `grant`; `None` when the role has no such grant.
async fn grant_state(pool: &PgPool, role: RoleId, grant: &str) -> Option<(bool, bool)> {
    sqlx::query_as::<_, (bool, bool)>(
        "SELECT active, orphaned_at IS NOT NULL FROM iam_role_permissions
        WHERE role_id = $1 AND permission_key = $2",
    )
    .bind(role.as_uuid().as_uuid())
    .bind(grant)
    .fetch_optional(pool)
    .await
    .unwrap()
}

async fn epochs(pool: &PgPool) -> (i64, i64) {
    let epoch = PgPolicyEpochRepository::new(pool.clone())
        .current()
        .await
        .unwrap();
    (epoch.version().value(), epoch.catalog_epoch())
}

fn query() -> PermissionPageQuery {
    PermissionPageQuery {
        limit: 100,
        after: None,
        service: None,
        active: None,
        sensitive: None,
        key_prefix: None,
        type_name: None,
        method: None,
    }
}

async fn graphql_keys(pool: &PgPool, query: &PermissionPageQuery) -> Vec<String> {
    PgGraphQlPermissionRepository::new(pool.clone())
        .find_page(query)
        .await
        .unwrap()
        .iter()
        .map(|found| found.parts().key.to_string())
        .collect()
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn an_activation_makes_the_entries_the_status_and_both_epochs_visible_together(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let spec_id = draft_graphql(&pool, &mut rng).await;
    let before = epochs(&pool).await;
    let mut activation = parts(PermissionKeyKind::Gql, spec_id);
    activation.created = vec![
        entry(&mut rng, INVOICES, PermissionFlags::NONE),
        entry(&mut rng, PAY, PermissionFlags::NONE.with_sensitive()),
    ];

    commit(&pool, &mut rng, vec![activation]).await.unwrap();

    let stored = PgGraphQlPermissionRepository::new(pool.clone())
        .find_by_service(&service())
        .await
        .unwrap();
    let keys: Vec<String> = stored
        .iter()
        .map(|found| found.parts().key.to_string())
        .collect();
    assert_eq!(keys, [PAY, INVOICES]);
    assert!(stored.iter().all(|found| found.parts().active));
    assert!(stored[0].parts().flags.is_sensitive());
    let version = PgGraphQlSpecRepository::new(pool.clone())
        .find_by_id(spec_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(version.parts().status, SpecStatus::Active);
    assert_eq!(version.parts().activated_at, Some(at()));
    assert_eq!(
        epochs(&pool).await,
        (before.0.saturating_add(1), before.1.saturating_add(1))
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_failing_statement_leaves_none_of_the_activation_visible(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let spec_id = draft_graphql(&pool, &mut rng).await;
    let before = epochs(&pool).await;
    let mut first = parts(PermissionKeyKind::Gql, spec_id);
    first.created = vec![entry(&mut rng, INVOICES, PermissionFlags::NONE)];
    // The first statement activates the version, so the second no longer finds a draft.
    let second = parts(PermissionKeyKind::Gql, spec_id);

    let error = commit(&pool, &mut rng, vec![first, second])
        .await
        .unwrap_err();

    assert!(matches!(error, RepositoryError::Conflict));
    assert_eq!(graphql_keys(&pool, &query()).await.len(), 0);
    let version = PgGraphQlSpecRepository::new(pool.clone())
        .find_by_id(spec_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(version.parts().status, SpecStatus::Draft);
    assert_eq!(epochs(&pool).await, before);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn grants_on_keys_that_leave_the_catalogue_are_inactive_with_the_orphan_mark(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let spec_id = draft_graphql(&pool, &mut rng).await;
    let role = seed_role(&pool, &mut rng, &[OLD, INVOICES]).await;
    let mut activation = parts(PermissionKeyKind::Gql, spec_id);
    activation.created = vec![entry(&mut rng, OLD, PermissionFlags::NONE)];
    commit(&pool, &mut rng, vec![activation]).await.unwrap();
    let mut retirement = parts(PermissionKeyKind::Gql, spec_id);
    retirement.transition = transition(spec_id, SpecStatus::Active, SpecStatus::Retired);
    retirement.deactivated = vec![key(OLD)];
    retirement.orphaned = vec![OrphanedGrant {
        role,
        key: key(OLD),
    }];

    commit(&pool, &mut rng, vec![retirement]).await.unwrap();

    assert_eq!(grant_state(&pool, role, OLD).await, Some((false, true)));
    assert_eq!(
        grant_state(&pool, role, INVOICES).await,
        Some((true, false))
    );
    let entries = PgGraphQlPermissionRepository::new(pool.clone())
        .find_by_keys(&service(), &[key(OLD)])
        .await
        .unwrap();
    assert!(!entries[0].parts().active);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn an_orphaned_grant_that_is_not_stored_refuses_the_whole_activation(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let spec_id = draft_graphql(&pool, &mut rng).await;
    let role = seed_role(&pool, &mut rng, &[INVOICES]).await;
    let before = epochs(&pool).await;
    let mut activation = parts(PermissionKeyKind::Gql, spec_id);
    activation.created = vec![entry(&mut rng, PAY, PermissionFlags::NONE)];
    activation.orphaned = vec![OrphanedGrant {
        role,
        key: key(OLD),
    }];

    let error = commit(&pool, &mut rng, vec![activation]).await.unwrap_err();

    assert!(matches!(error, RepositoryError::Conflict));
    assert_eq!(graphql_keys(&pool, &query()).await.len(), 0);
    assert_eq!(epochs(&pool).await, before);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_rename_moves_the_grants_of_the_roles_to_the_new_key(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let spec_id = draft_graphql(&pool, &mut rng).await;
    let holder = seed_role(&pool, &mut rng, &[OLDER]).await;
    let bystander = seed_role(&pool, &mut rng, &[OLDER]).await;
    let mut activation = parts(PermissionKeyKind::Gql, spec_id);
    activation.created = vec![entry(&mut rng, OLD, PermissionFlags::NONE)];
    activation.renames = vec![KeyRename {
        from: key(OLDER),
        to: key(OLD),
        roles: vec![holder],
    }];

    commit(&pool, &mut rng, vec![activation]).await.unwrap();

    assert_eq!(grant_state(&pool, holder, OLD).await, Some((true, false)));
    assert_eq!(grant_state(&pool, holder, OLDER).await, None);
    assert_eq!(
        grant_state(&pool, bystander, OLDER).await,
        Some((true, false))
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_created_key_that_is_stored_already_is_a_conflict(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let spec_id = draft_graphql(&pool, &mut rng).await;
    let mut first = parts(PermissionKeyKind::Gql, spec_id);
    first.created = vec![entry(&mut rng, INVOICES, PermissionFlags::NONE)];
    commit(&pool, &mut rng, vec![first]).await.unwrap();
    let mut second = parts(PermissionKeyKind::Gql, spec_id);
    second.transition = transition(spec_id, SpecStatus::Active, SpecStatus::Active);
    second.created = vec![entry(&mut rng, INVOICES, PermissionFlags::NONE)];

    let error = commit(&pool, &mut rng, vec![second]).await.unwrap_err();

    assert!(matches!(error, RepositoryError::Conflict));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn flags_and_activity_of_stored_entries_follow_the_activation(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let first = draft_graphql(&pool, &mut rng).await;
    let mut activation = parts(PermissionKeyKind::Gql, first);
    activation.created = vec![
        entry(&mut rng, PAY, PermissionFlags::NONE.with_sensitive()),
        entry(&mut rng, INVOICES, PermissionFlags::NONE),
        entry(&mut rng, OLD, PermissionFlags::NONE),
    ];
    commit(&pool, &mut rng, vec![activation]).await.unwrap();
    let mut change = parts(PermissionKeyKind::Gql, first);
    change.transition = transition(first, SpecStatus::Active, SpecStatus::Active);
    change.reflagged = vec![EntryFlags {
        key: key(PAY),
        flags: PermissionFlags::NONE.with_audit_always(),
    }];
    change.deactivated = vec![key(OLD)];
    commit(&pool, &mut rng, vec![change.clone()]).await.unwrap();
    change.reflagged = Vec::new();
    change.deactivated = Vec::new();
    change.reactivated = vec![key(OLD)];

    commit(&pool, &mut rng, vec![change]).await.unwrap();

    let found = PgGraphQlPermissionRepository::new(pool.clone())
        .find_by_keys(&service(), &[key(PAY), key(OLD)])
        .await
        .unwrap();
    assert_eq!(
        found[0].parts().flags,
        PermissionFlags::NONE.with_audit_always()
    );
    assert!(found[1].parts().active);
    let mut sensitive = query();
    sensitive.sensitive = Some(true);
    assert_eq!(graphql_keys(&pool, &sensitive).await.len(), 0);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn graphql_pages_are_filtered_by_service_state_flag_prefix_and_type(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let spec_id = draft_graphql(&pool, &mut rng).await;
    let mut activation = parts(PermissionKeyKind::Gql, spec_id);
    activation.created = vec![
        entry(&mut rng, PAY, PermissionFlags::NONE.with_sensitive()),
        entry(&mut rng, INVOICES, PermissionFlags::NONE),
        entry(
            &mut rng,
            "gql:billing:__introspection",
            PermissionFlags::NONE,
        ),
    ];
    commit(&pool, &mut rng, vec![activation]).await.unwrap();
    let keys = |change: &dyn Fn(&mut PermissionPageQuery)| {
        let mut filtered = query();
        change(&mut filtered);
        let pool = pool.clone();
        async move { graphql_keys(&pool, &filtered).await }
    };

    assert_eq!(keys(&|_q| {}).await.len(), 3);
    assert_eq!(
        keys(&|q| q.service = Some(ServiceName::new("orders").unwrap()))
            .await
            .len(),
        0
    );
    assert_eq!(keys(&|q| q.active = Some(false)).await.len(), 0);
    assert_eq!(keys(&|q| q.sensitive = Some(true)).await, [PAY]);
    assert_eq!(
        keys(&|q| q.key_prefix = Some("gql:billing:Query.".to_owned())).await,
        [INVOICES]
    );
    assert_eq!(
        keys(&|q| q.type_name = iam_domain::GqlName::parse("Mutation")).await,
        [PAY]
    );
    let mut paged = query();
    paged.limit = 2;
    let first = PgGraphQlPermissionRepository::new(pool.clone())
        .find_page(&paged)
        .await
        .unwrap();
    paged.after = first.last().map(|found| found.parts().id);
    let rest = PgGraphQlPermissionRepository::new(pool.clone())
        .find_page(&paged)
        .await
        .unwrap();
    assert_eq!((first.len(), rest.len()), (2, 1));
    let by_id = PgGraphQlPermissionRepository::new(pool.clone())
        .find_by_id(first[0].parts().id)
        .await
        .unwrap();
    assert_eq!(by_id.as_ref(), Some(&first[0]));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_rest_activation_stores_the_operations_and_pages_filter_by_method(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let spec_id = draft_openapi(&pool, &mut rng).await;
    let before = epochs(&pool).await;
    let mut activation = parts(PermissionKeyKind::Rest, spec_id);
    activation.created = vec![
        entry(
            &mut rng,
            "rest:billing:GET /invoices",
            PermissionFlags::NONE,
        ),
        entry(
            &mut rng,
            "rest:billing:POST /invoices/{}",
            PermissionFlags::NONE.with_sensitive(),
        ),
    ];

    commit(&pool, &mut rng, vec![activation]).await.unwrap();

    let repository = PgRestPermissionRepository::new(pool.clone());
    let all = repository.find_by_service(&service()).await.unwrap();
    assert_eq!(all.len(), 2);
    let mut posts = query();
    posts.method = Some(iam_domain::HttpMethod::Post);
    let found = repository.find_page(&posts).await.unwrap();
    assert_eq!(found.len(), 1);
    assert!(found[0].parts().flags.is_sensitive());
    let mut prefixed = query();
    prefixed.key_prefix = Some("rest:billing:GET ".to_owned());
    prefixed.active = Some(true);
    prefixed.sensitive = Some(false);
    prefixed.service = Some(service());
    assert_eq!(repository.find_page(&prefixed).await.unwrap().len(), 1);
    let mut paged = query();
    paged.limit = 1;
    let first = repository.find_page(&paged).await.unwrap();
    paged.after = first.last().map(|found| found.parts().id);
    let second = repository.find_page(&paged).await.unwrap();
    paged.after = second.last().map(|found| found.parts().id);
    let past_the_end = repository.find_page(&paged).await.unwrap();
    assert_eq!((first.len(), second.len(), past_the_end.len()), (1, 1, 0));
    assert_ne!(first[0].parts().id, second[0].parts().id);
    let by_keys = repository
        .find_by_keys(&service(), &[key("rest:billing:GET /invoices")])
        .await
        .unwrap();
    assert_eq!(by_keys.len(), 1);
    assert_eq!(
        repository
            .find_by_id(by_keys[0].parts().id)
            .await
            .unwrap()
            .as_ref(),
        Some(&by_keys[0])
    );
    let version = PgOpenApiSpecRepository::new(pool.clone())
        .find_by_id(spec_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(version.parts().status, SpecStatus::Active);
    assert_eq!(
        epochs(&pool).await,
        (before.0.saturating_add(1), before.1.saturating_add(1))
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_catalogue_grants_of_a_service_are_its_exact_keys_with_their_status(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let role = seed_role(&pool, &mut rng, &[PAY, OLD]).await;
    sqlx::query(
        "UPDATE iam_role_permissions SET active = FALSE, orphaned_at = now()
        WHERE role_id = $1 AND permission_key = $2",
    )
    .bind(role.as_uuid().as_uuid())
    .bind(OLD)
    .execute(&pool)
    .await
    .unwrap();
    for (grant, kind, grant_service, wildcard) in [
        ("gql:billing:Query.*", "gql", SERVICE, true),
        ("gql:other:Query.users", "gql", "other", false),
        ("rest:billing:GET /invoices", "rest", SERVICE, false),
    ] {
        sqlx::query(
            "INSERT INTO iam_role_permissions (role_id, permission_key, key_kind, service,
                is_wildcard, active, granted_by, granted_at)
            VALUES ($1, $2, $3, $4, $5, TRUE, 'system:test', now())",
        )
        .bind(role.as_uuid().as_uuid())
        .bind(grant)
        .bind(kind)
        .bind(grant_service)
        .bind(wildcard)
        .execute(&pool)
        .await
        .unwrap();
    }
    let roles = PgRoleRepository::new(pool);

    let graphql = roles
        .find_catalogue_grants(&service(), PermissionKeyKind::Gql)
        .await
        .unwrap();
    let rest = roles
        .find_catalogue_grants(&service(), PermissionKeyKind::Rest)
        .await
        .unwrap();

    assert_eq!(
        graphql,
        vec![
            GrantRecord {
                role,
                key: key(PAY),
                status: GrantStatus::Active,
            },
            GrantRecord {
                role,
                key: key(OLD),
                status: GrantStatus::Orphaned,
            },
        ]
    );
    assert_eq!(
        rest,
        vec![GrantRecord {
            role,
            key: key("rest:billing:GET /invoices"),
            status: GrantStatus::Active,
        }]
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_created_keys_of_an_activation_are_read_from_its_event(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let spec_id = draft_graphql(&pool, &mut rng).await;
    let event = GraphQlPermissionsCreated {
        event_id: uuid_v7(&mut rng),
        spec_id,
        service: service(),
        created_keys: vec![key(PAY), key(INVOICES)],
        renamed: Vec::new(),
        flag_changes: Vec::new(),
        actor: ActorRef::User(uuid_v7(&mut rng)),
        occurred_at: at(),
    };
    let statement = CatalogueStatement::new(parts(PermissionKeyKind::Gql, spec_id)).unwrap();
    let change = rebuilt(
        &catalogue_change(&mut rng, DecisionEffect::Affected, vec![statement]),
        |change| change.events = vec![EventEnvelope::of(&event).unwrap()],
    );
    PgIamUnitOfWork::new(pool.clone())
        .commit(change)
        .await
        .unwrap();
    let permissions = PgGraphQlPermissionRepository::new(pool);

    let found = permissions.find_created_keys(spec_id).await.unwrap();
    let unknown = permissions
        .find_created_keys(SpecId::from_uuid(uuid_v7(&mut rng)))
        .await
        .unwrap();

    assert_eq!(found, Some(vec![key(PAY), key(INVOICES)]));
    assert_eq!(unknown, None);
}
