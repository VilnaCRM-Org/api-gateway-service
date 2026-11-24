//! `PgPolicyStateInventory`: every entity that has a state record, listed in a stable order and
//! cut into pages.

use iam_domain::{
    AssignmentScope, ChangeStatement, IamUnitOfWork as _, InventoryEntry,
    PolicyStateInventory as _, RoleKind, ServiceName, StateKey,
};
use iam_infrastructure::{PgIamUnitOfWork, PgPolicyStateInventory};
use sqlx::PgPool;
use test_support::role::{role, role_writer};
use test_support::seed::TestRng;
use test_support::unit_of_work::{iam_change, rebuilt};
use test_support::user_role::{user_role, user_subject};

async fn seeded(pool: &PgPool, rng: &mut TestRng) -> (Vec<StateKey>, StateKey) {
    let unit = PgIamUnitOfWork::new(pool.clone());
    let first = role(rng, "First", RoleKind::Custom);
    let second = role(rng, "Second", RoleKind::Custom);
    let subject = user_subject(rng);
    let assignment = user_role(
        rng,
        first.parts().id,
        subject.clone(),
        AssignmentScope::Global,
    );
    let statements = vec![
        ChangeStatement::SaveRole(Box::new(iam_domain::RoleStatement::insert(
            &first,
            role_writer(rng),
        ))),
        ChangeStatement::SaveRole(Box::new(iam_domain::RoleStatement::insert(
            &second,
            role_writer(rng),
        ))),
        ChangeStatement::SaveUserRole(Box::new(iam_domain::UserRoleStatement::insert(&assignment))),
    ];
    let change = rebuilt(
        &iam_change(rng, iam_domain::DecisionEffect::Affected, 0),
        |parts| parts.statements = statements,
    );
    unit.commit(change, iam_domain::WriteMode::Published)
        .await
        .unwrap();
    let mut roles = vec![
        StateKey::Role(first.parts().id),
        StateKey::Role(second.parts().id),
    ];
    roles.sort();
    (roles, StateKey::Subject(subject))
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn an_empty_policy_has_no_entries(pool: PgPool) {
    let inventory = PgPolicyStateInventory::new(pool);

    assert_eq!(inventory.count().await.unwrap(), 0);
    assert_eq!(inventory.page(0, 10).await.unwrap().len(), 0);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn roles_and_subjects_are_listed_in_a_stable_order(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let (roles, subject) = seeded(&pool, &mut rng).await;
    let inventory = PgPolicyStateInventory::new(pool);

    let all = inventory.page(0, 100).await.unwrap();

    let expected: Vec<InventoryEntry> = roles
        .into_iter()
        .chain([subject])
        .map(InventoryEntry::State)
        .collect();
    assert_eq!(inventory.count().await.unwrap(), 3);
    assert_eq!(all, expected);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn pages_follow_each_other_without_a_gap_or_an_overlap(pool: PgPool) {
    let mut rng = TestRng::from_env();
    seeded(&pool, &mut rng).await;
    let inventory = PgPolicyStateInventory::new(pool);

    let all = inventory.page(0, 100).await.unwrap();
    let first = inventory.page(0, 2).await.unwrap();
    let rest = inventory.page(2, 2).await.unwrap();
    let beyond = inventory.page(3, 2).await.unwrap();

    assert_eq!([first, rest.clone()].concat(), all);
    assert_eq!(rest.len(), 1);
    assert_eq!(beyond.len(), 0);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_service_with_active_permissions_is_one_catalogue_entry_after_the_records(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let (roles, subject) = seeded(&pool, &mut rng).await;
    let insert = "INSERT INTO iam_rest_permissions
        (id, permission_key, service, method, path_template, sensitive, audit_always, active,
         created_at)
        VALUES ($1::uuid, $2, 'billing', 'GET', $3, FALSE, FALSE, $4, now())";
    for (id, path, active) in [
        ("0190f2a8-7b3c-7d4e-8f10-0000000000a1", "/invoices", true),
        ("0190f2a8-7b3c-7d4e-8f10-0000000000a2", "/receipts", true),
        ("0190f2a8-7b3c-7d4e-8f10-0000000000a3", "/archive", false),
    ] {
        sqlx::query(insert)
            .bind(id)
            .bind(format!("rest:billing:GET {path}"))
            .bind(path)
            .bind(active)
            .execute(&pool)
            .await
            .unwrap();
    }
    let inventory = PgPolicyStateInventory::new(pool);

    let all = inventory.page(0, 100).await.unwrap();

    let mut expected: Vec<InventoryEntry> = roles
        .into_iter()
        .chain([subject])
        .map(InventoryEntry::State)
        .collect();
    expected.push(InventoryEntry::Catalogue(
        ServiceName::new("billing").unwrap(),
    ));
    assert_eq!(inventory.count().await.unwrap(), 4);
    assert_eq!(all, expected);
}
