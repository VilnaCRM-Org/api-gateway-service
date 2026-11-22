use std::time::SystemTime;

use iam_domain::{
    ChangeStatement, RepositoryError, RoleKind, RolePageQuery, RoleParts, RoleRepository as _,
    RoleStatement,
};

use super::{FakeRoleRepository, role, role_change, role_writer};
use crate::block_on;
use crate::seed::TestRng;

fn parts(rng: &mut TestRng, name: &str, kind: RoleKind) -> RoleParts {
    role(rng, name, kind).parts().clone()
}

fn query(limit: u32) -> RolePageQuery {
    RolePageQuery {
        limit,
        after: None,
        name_prefix: None,
        kind: None,
    }
}

#[test]
fn the_fixture_builds_a_role_of_the_kind_at_version_one() {
    let role = role(&mut TestRng::from_seed(3), "Billing", RoleKind::System);

    assert_eq!(role.parts().name.as_str(), "Billing");
    assert_eq!(role.parts().kind, RoleKind::System);
    assert_eq!(role.parts().version.value(), 1);
    assert!(role.parts().grants.is_empty());
    assert_eq!(role.parts().created_at, role.parts().updated_at);
}

#[test]
fn the_fixture_is_reproducible_from_its_seed() {
    let first = parts(&mut TestRng::from_seed(9), "Billing", RoleKind::Custom);
    let second = parts(&mut TestRng::from_seed(9), "Billing", RoleKind::Custom);

    assert_eq!(first, second);
}

#[test]
fn a_role_change_runs_one_save_per_statement() {
    let mut rng = TestRng::from_seed(5);
    let role = role(&mut rng, "Billing", RoleKind::Custom);
    let writer = role_writer(&mut rng);

    let change = role_change(&mut rng, vec![RoleStatement::insert(&role, writer.clone())]);

    assert_eq!(
        change.parts().statements,
        vec![ChangeStatement::SaveRole(Box::new(RoleStatement::insert(
            &role, writer
        )))]
    );
}

#[test]
fn an_empty_repository_finds_nothing() {
    let repository = FakeRoleRepository::default();
    let id = role(&mut TestRng::from_seed(1), "Billing", RoleKind::Custom)
        .parts()
        .id;

    assert!(block_on(repository.find_by_id(id)).unwrap().is_none());
    assert!(
        block_on(repository.find_page(&query(10)))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_held_role_is_found_unless_it_is_deleted() {
    let mut rng = TestRng::from_seed(2);
    let live = parts(&mut rng, "Billing", RoleKind::Custom);
    let mut deleted = parts(&mut rng, "Support", RoleKind::Custom);
    deleted.deleted_at = Some(SystemTime::UNIX_EPOCH);
    let repository = FakeRoleRepository::holding(vec![live.clone(), deleted.clone()]);

    let found = block_on(repository.find_by_id(live.id)).unwrap().unwrap();

    assert_eq!(found.parts(), &live);
    assert!(
        block_on(repository.find_by_id(deleted.id))
            .unwrap()
            .is_none()
    );
}

#[test]
fn pages_follow_the_identifiers_and_apply_the_filters() {
    let mut rng = TestRng::from_seed(4);
    let roles: Vec<RoleParts> = [
        ("Team-a", RoleKind::Custom),
        ("TEAM-b", RoleKind::Custom),
        ("team-c", RoleKind::System),
        ("Other", RoleKind::Custom),
        ("team-d", RoleKind::Custom),
    ]
    .iter()
    .map(|(name, kind)| parts(&mut rng, name, *kind))
    .collect();
    let mut expected: Vec<_> = roles
        .iter()
        .filter(|role| {
            role.kind == RoleKind::Custom && role.name.comparison_form().starts_with("team")
        })
        .map(|role| role.id)
        .collect();
    expected.sort();
    let repository = FakeRoleRepository::holding(roles);
    let mut seen = Vec::new();
    let mut after = None;

    loop {
        let page = block_on(repository.find_page(&RolePageQuery {
            limit: 2,
            after,
            name_prefix: Some("tEaM".to_owned()),
            kind: Some(RoleKind::Custom),
        }))
        .unwrap();
        let Some(last) = page.last() else { break };
        after = Some(last.parts().id);
        seen.extend(page.iter().map(|role| role.parts().id));
    }

    assert_eq!(seen, expected);
}

#[test]
fn a_failing_repository_is_unavailable() {
    let repository = FakeRoleRepository::failing();
    let id = role(&mut TestRng::from_seed(1), "Billing", RoleKind::Custom)
        .parts()
        .id;

    assert!(matches!(
        block_on(repository.find_by_id(id)),
        Err(RepositoryError::Unavailable(_))
    ));
    assert!(matches!(
        block_on(repository.find_page(&query(1))),
        Err(RepositoryError::Unavailable(_))
    ));
}
