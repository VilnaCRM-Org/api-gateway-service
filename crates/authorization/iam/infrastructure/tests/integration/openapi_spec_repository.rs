//! `PgOpenApiSpecRepository` and the specification statement of `PgIamUnitOfWork`: the hash
//! computed by SQL, the uniqueness of the service and the hash, the immutable content and the
//! filters of pages.

use iam_domain::{
    ContentHash, IamUnitOfWork as _, OpenApiSpec, OpenApiSpecPageQuery, OpenApiSpecParts,
    OpenApiSpecRepository as _, OpenApiSpecStatement, RepositoryError, ServiceName, SpecId,
    SpecStatus,
};
use iam_infrastructure::{PgIamUnitOfWork, PgOpenApiSpecRepository};
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;
use test_support::openapi_spec::{
    DOCUMENT_FIXTURE, openapi_spec, openapi_spec_change, operations_fixture,
};
use test_support::seed::TestRng;

fn service(name: &str) -> ServiceName {
    ServiceName::new(name).unwrap()
}

/// A stored operation row: method, path template, label, sensitive and audit-always.
type StoredOperation = (String, String, Option<String>, bool, bool);

/// The SHA-256 hash of `document`, as SQL `sha256()` computes it.
fn hash_of(document: &str) -> ContentHash {
    ContentHash::new(&Sha256::digest(document.as_bytes())).unwrap()
}

/// The fixture document with trailing spaces that make it a different document.
fn document_variant(variant: u32) -> String {
    let spaces = usize::try_from(variant).unwrap_or(0).saturating_add(1);
    format!("{DOCUMENT_FIXTURE}{}", " ".repeat(spaces))
}

/// A version of `service` in `status` that holds `document` with its true hash.
fn version(rng: &mut TestRng, name: &str, status: SpecStatus, document: &str) -> OpenApiSpec {
    openapi_spec(rng, &service(name), status, hash_of(document))
}

/// Commits one change that inserts `spec` with `document`.
async fn insert(
    pool: &PgPool,
    rng: &mut TestRng,
    spec: &OpenApiSpec,
    document: &str,
) -> Result<(), RepositoryError> {
    let statement = OpenApiSpecStatement::insert(spec, document.to_owned());
    PgIamUnitOfWork::new(pool.clone())
        .commit(openapi_spec_change(rng, vec![statement]))
        .await
        .map(|_receipt| ())
}

/// Stores a new version and returns its state.
async fn stored(
    pool: &PgPool,
    rng: &mut TestRng,
    name: &str,
    status: SpecStatus,
    document: &str,
) -> OpenApiSpecParts {
    let spec = version(rng, name, status, document);
    insert(pool, rng, &spec, document).await.unwrap();
    spec.parts().clone()
}

fn repository(pool: &PgPool) -> PgOpenApiSpecRepository {
    PgOpenApiSpecRepository::new(pool.clone())
}

fn query() -> OpenApiSpecPageQuery {
    OpenApiSpecPageQuery {
        limit: 100,
        after: None,
        service: None,
        status: None,
    }
}

async fn page(pool: &PgPool, query: &OpenApiSpecPageQuery) -> Vec<SpecId> {
    repository(pool)
        .find_page(query)
        .await
        .unwrap()
        .into_iter()
        .map(|found| found.parts().id)
        .collect()
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_stored_version_comes_back_with_its_operations_and_its_document(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let document = document_variant(1);

    let parts = stored(&pool, &mut rng, "billing", SpecStatus::Active, &document).await;

    let found = repository(&pool)
        .find_by_id(parts.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.parts(), &parts);
    assert_eq!(found.operations(), &operations_fixture());
    assert_eq!(found.operations().len(), 3);
    assert_eq!(
        repository(&pool)
            .find_document(parts.id)
            .await
            .unwrap()
            .as_deref(),
        Some(document.as_str())
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn an_unknown_version_is_not_found(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let absent = version(&mut rng, "billing", SpecStatus::Draft, &document_variant(1));

    assert!(
        repository(&pool)
            .find_by_id(absent.parts().id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repository(&pool)
            .find_document(absent.parts().id)
            .await
            .unwrap()
            .is_none()
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn identical_content_of_the_same_service_is_found_and_another_service_has_its_own(
    pool: PgPool,
) {
    let mut rng = TestRng::from_env();
    let document = document_variant(1);
    let billing = stored(&pool, &mut rng, "billing", SpecStatus::Draft, &document).await;
    let orders = stored(&pool, &mut rng, "orders", SpecStatus::Draft, &document).await;

    let found_billing = repository(&pool)
        .find_by_content_hash(&service("billing"), &hash_of(&document))
        .await
        .unwrap()
        .unwrap();
    let found_orders = repository(&pool)
        .find_by_content_hash(&service("orders"), &hash_of(&document))
        .await
        .unwrap()
        .unwrap();
    let other_content = repository(&pool)
        .find_by_content_hash(&service("billing"), &hash_of(&document_variant(2)))
        .await
        .unwrap();
    let other_service = repository(&pool)
        .find_by_content_hash(&service("shipping"), &hash_of(&document))
        .await
        .unwrap();

    assert_eq!(found_billing.parts(), &billing);
    assert_eq!(found_orders.parts(), &orders);
    assert_ne!(billing.id, orders.id);
    assert!(other_content.is_none());
    assert!(other_service.is_none());
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_same_content_of_the_same_service_is_refused_as_a_duplicate(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let document = document_variant(1);
    stored(&pool, &mut rng, "billing", SpecStatus::Draft, &document).await;
    let again = version(&mut rng, "billing", SpecStatus::Draft, &document);

    let refused = insert(&pool, &mut rng, &again, &document).await;

    assert!(matches!(refused, Err(RepositoryError::AlreadyExists)));
    assert_eq!(page(&pool, &query()).await.len(), 1);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_stored_identifier_is_refused_as_a_duplicate(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let document = document_variant(1);
    let spec = version(&mut rng, "billing", SpecStatus::Draft, &document);
    insert(&pool, &mut rng, &spec, &document).await.unwrap();
    let other = document_variant(2);
    let same_id = OpenApiSpec::restore(OpenApiSpecParts {
        content: iam_domain::OpenApiSpecContent {
            content_hash: hash_of(&other),
            ..spec.parts().content.clone()
        },
        ..spec.parts().clone()
    });

    let refused = insert(&pool, &mut rng, &same_id, &other).await;

    assert!(matches!(refused, Err(RepositoryError::AlreadyExists)));
    assert_eq!(page(&pool, &query()).await.len(), 1);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_hash_that_is_not_the_hash_of_the_document_is_refused_and_nothing_is_written(
    pool: PgPool,
) {
    let mut rng = TestRng::from_env();
    let spec = openapi_spec(
        &mut rng,
        &service("billing"),
        SpecStatus::Draft,
        hash_of("another document"),
    );

    let refused = insert(&pool, &mut rng, &spec, &document_variant(1)).await;

    assert!(matches!(refused, Err(RepositoryError::Unavailable(_))));
    assert_eq!(page(&pool, &query()).await, Vec::<SpecId>::new());
    let operations: i64 = sqlx::query_scalar("SELECT count(*) FROM iam_openapi_spec_operations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(operations, 0);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_content_of_a_stored_version_cannot_change(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let document = document_variant(1);
    let parts = stored(&pool, &mut rng, "billing", SpecStatus::Draft, &document).await;

    let document_update = sqlx::query("UPDATE iam_openapi_specs SET document = '{}'")
        .execute(&pool)
        .await;
    let service_update = sqlx::query("UPDATE iam_openapi_specs SET service = 'orders'")
        .execute(&pool)
        .await;
    let hash_update = sqlx::query("UPDATE iam_openapi_specs SET content_hash = '\\x00'::bytea")
        .execute(&pool)
        .await;

    assert!(document_update.is_err());
    assert!(service_update.is_err());
    assert!(hash_update.is_err());
    assert_eq!(
        repository(&pool)
            .find_document(parts.id)
            .await
            .unwrap()
            .as_deref(),
        Some(document.as_str())
    );
    let found = repository(&pool)
        .find_by_id(parts.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.parts(), &parts);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_stored_operation_that_is_not_normalised_makes_the_version_unavailable(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let parts = stored(
        &pool,
        &mut rng,
        "billing",
        SpecStatus::Active,
        &document_variant(1),
    )
    .await;

    sqlx::query(
        "INSERT INTO iam_openapi_spec_operations
            (spec_id, method, path_template, label, sensitive, audit_always)
        SELECT id, 'GET', '/orders/{id}', NULL, FALSE, FALSE FROM iam_openapi_specs",
    )
    .execute(&pool)
    .await
    .unwrap();

    assert!(matches!(
        repository(&pool).find_by_id(parts.id).await,
        Err(RepositoryError::Unavailable(_))
    ));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_stored_method_outside_the_http_methods_is_refused_by_the_table(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let parts = stored(
        &pool,
        &mut rng,
        "billing",
        SpecStatus::Active,
        &document_variant(1),
    )
    .await;

    let refused = sqlx::query(
        "INSERT INTO iam_openapi_spec_operations
            (spec_id, method, path_template, label, sensitive, audit_always)
        VALUES ($1, 'TRACE', '/orders', NULL, FALSE, FALSE)",
    )
    .bind(parts.id.as_uuid().as_uuid())
    .execute(&pool)
    .await;

    assert!(refused.is_err());
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_operations_of_a_stored_version_are_stored_with_their_labels_and_flags(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let parts = stored(
        &pool,
        &mut rng,
        "billing",
        SpecStatus::Draft,
        &document_variant(1),
    )
    .await;

    let rows: Vec<StoredOperation> = sqlx::query_as(
        "SELECT method, path_template, label, sensitive, audit_always
        FROM iam_openapi_spec_operations WHERE spec_id = $1 ORDER BY method, path_template",
    )
    .bind(parts.id.as_uuid().as_uuid())
    .fetch_all(&pool)
    .await
    .unwrap();

    assert_eq!(
        rows,
        [
            (
                "DELETE".to_owned(),
                "/invoices/{}".to_owned(),
                None,
                false,
                true
            ),
            (
                "GET".to_owned(),
                "/invoices".to_owned(),
                Some("listInvoices".to_owned()),
                false,
                false
            ),
            (
                "POST".to_owned(),
                "/invoices/{}".to_owned(),
                Some("payInvoice".to_owned()),
                true,
                false
            ),
        ]
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_rest_catalogue_table_refuses_a_second_row_for_a_key(pool: PgPool) {
    let insert = "INSERT INTO iam_rest_permissions
        (id, permission_key, service, method, path_template, sensitive, audit_always, created_at)
        VALUES ($1, 'rest:billing:GET /invoices', 'billing', 'GET', '/invoices', FALSE, FALSE, now())";
    let mut rng = TestRng::from_env();
    let first = version(&mut rng, "billing", SpecStatus::Draft, &document_variant(1))
        .parts()
        .id;
    let second = version(&mut rng, "billing", SpecStatus::Draft, &document_variant(2))
        .parts()
        .id;

    let written = sqlx::query(insert)
        .bind(first.as_uuid().as_uuid())
        .execute(&pool)
        .await;
    let refused = sqlx::query(insert)
        .bind(second.as_uuid().as_uuid())
        .execute(&pool)
        .await;

    assert!(written.is_ok());
    assert!(refused.is_err());
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_sql_hash_equals_the_sha256_of_the_stored_document(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let document = document_variant(1);
    let parts = stored(&pool, &mut rng, "billing", SpecStatus::Draft, &document).await;

    let matches: bool = sqlx::query_scalar(
        "SELECT content_hash = sha256(convert_to(document, 'UTF8')) FROM iam_openapi_specs WHERE id = $1",
    )
    .bind(parts.id.as_uuid().as_uuid())
    .fetch_one(&pool)
    .await
    .unwrap();

    assert!(matches);
    assert_eq!(parts.content.content_hash, hash_of(&document));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn pages_filter_by_service_and_status_in_id_order(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let billing_draft = stored(
        &pool,
        &mut rng,
        "billing",
        SpecStatus::Draft,
        &document_variant(1),
    )
    .await;
    let billing_active = stored(
        &pool,
        &mut rng,
        "billing",
        SpecStatus::Active,
        &document_variant(2),
    )
    .await;
    let orders_active = stored(
        &pool,
        &mut rng,
        "orders",
        SpecStatus::Active,
        &document_variant(3),
    )
    .await;
    let orders_retired = stored(
        &pool,
        &mut rng,
        "orders",
        SpecStatus::Retired,
        &document_variant(4),
    )
    .await;
    let mut every = vec![
        billing_draft.id,
        billing_active.id,
        orders_active.id,
        orders_retired.id,
    ];
    every.sort();

    let all = page(&pool, &query()).await;
    let billing = page(
        &pool,
        &OpenApiSpecPageQuery {
            service: Some(service("billing")),
            ..query()
        },
    )
    .await;
    let active = page(
        &pool,
        &OpenApiSpecPageQuery {
            status: Some(SpecStatus::Active),
            ..query()
        },
    )
    .await;
    let orders_active_only = page(
        &pool,
        &OpenApiSpecPageQuery {
            service: Some(service("orders")),
            status: Some(SpecStatus::Active),
            ..query()
        },
    )
    .await;
    let none = page(
        &pool,
        &OpenApiSpecPageQuery {
            service: Some(service("shipping")),
            ..query()
        },
    )
    .await;

    assert_eq!(all, every);
    assert_eq!(billing.len(), 2);
    assert!(billing.contains(&billing_draft.id) && billing.contains(&billing_active.id));
    assert_eq!(active.len(), 2);
    assert!(active.contains(&billing_active.id) && active.contains(&orders_active.id));
    assert_eq!(orders_active_only, [orders_active.id]);
    assert_eq!(none, Vec::<SpecId>::new());
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn pages_hold_each_version_exactly_once_across_cursors(pool: PgPool) {
    let mut rng = TestRng::from_env();
    for variant in 0..5 {
        stored(
            &pool,
            &mut rng,
            "billing",
            SpecStatus::Draft,
            &document_variant(variant),
        )
        .await;
    }
    let everything = page(&pool, &query()).await;

    let first = page(
        &pool,
        &OpenApiSpecPageQuery {
            limit: 2,
            ..query()
        },
    )
    .await;
    let second = page(
        &pool,
        &OpenApiSpecPageQuery {
            limit: 2,
            after: first.last().copied(),
            ..query()
        },
    )
    .await;
    let third = page(
        &pool,
        &OpenApiSpecPageQuery {
            limit: 2,
            after: second.last().copied(),
            ..query()
        },
    )
    .await;

    assert_eq!(first.len(), 2);
    assert_eq!(second.len(), 2);
    assert_eq!(third.len(), 1);
    assert_eq!([first, second, third].concat(), everything);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_document_is_read_only_when_asked_for(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let document = document_variant(1);
    let parts = stored(&pool, &mut rng, "billing", SpecStatus::Draft, &document).await;

    let listed = repository(&pool).find_page(&query()).await.unwrap();

    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].parts(), &parts);
    assert_eq!(
        repository(&pool)
            .find_document(parts.id)
            .await
            .unwrap()
            .as_deref(),
        Some(document.as_str())
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_active_versions_of_a_service_are_its_catalogue(pool: PgPool) {
    let mut rng = TestRng::from_env();
    stored(
        &pool,
        &mut rng,
        "billing",
        SpecStatus::Draft,
        &document_variant(1),
    )
    .await;
    let first = stored(
        &pool,
        &mut rng,
        "billing",
        SpecStatus::Active,
        &document_variant(2),
    )
    .await;
    let second = stored(
        &pool,
        &mut rng,
        "billing",
        SpecStatus::Active,
        &document_variant(3),
    )
    .await;
    stored(
        &pool,
        &mut rng,
        "billing",
        SpecStatus::Retired,
        &document_variant(4),
    )
    .await;
    stored(
        &pool,
        &mut rng,
        "orders",
        SpecStatus::Active,
        &document_variant(5),
    )
    .await;
    let mut expected = vec![first.id, second.id];
    expected.sort();

    let active: Vec<SpecId> = repository(&pool)
        .find_active(&service("billing"))
        .await
        .unwrap()
        .into_iter()
        .map(|found| found.parts().id)
        .collect();

    assert_eq!(active, expected);
    assert!(
        repository(&pool)
            .find_active(&service("shipping"))
            .await
            .unwrap()
            .is_empty()
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_closed_pool_makes_every_read_unavailable(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let absent = version(&mut rng, "billing", SpecStatus::Draft, &document_variant(1));
    let repository = repository(&pool);
    pool.close().await;

    assert!(matches!(
        repository.find_by_id(absent.parts().id).await,
        Err(RepositoryError::Unavailable(_))
    ));
    assert!(matches!(
        repository.find_document(absent.parts().id).await,
        Err(RepositoryError::Unavailable(_))
    ));
    assert!(matches!(
        repository
            .find_by_content_hash(&service("billing"), &hash_of(&document_variant(1)))
            .await,
        Err(RepositoryError::Unavailable(_))
    ));
    assert!(matches!(
        repository.find_active(&service("billing")).await,
        Err(RepositoryError::Unavailable(_))
    ));
    assert!(matches!(
        repository.find_page(&query()).await,
        Err(RepositoryError::Unavailable(_))
    ));
}
