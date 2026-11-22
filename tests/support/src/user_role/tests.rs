use std::time::{Duration, SystemTime};

use iam_domain::{
    AssignmentExpiry, AssignmentScope, ChangeStatement, EntityVersion, ProjectId, RepositoryError,
    RoleId, ServiceName, SubjectKind, SubjectRef, UserRolePageQuery, UserRoleParts,
    UserRoleRepository as _, UserRoleStatement,
};

use super::{FakeUserRoleRepository, user_role, user_role_change, user_subject};
use crate::block_on;
use crate::seed::TestRng;
use crate::unit_of_work::uuid_v7;

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn role_id(rng: &mut TestRng) -> RoleId {
    RoleId::from_uuid(uuid_v7(rng))
}

fn project(rng: &mut TestRng) -> AssignmentScope {
    AssignmentScope::Project(ProjectId::from_uuid(uuid_v7(rng)))
}

fn parts(
    rng: &mut TestRng,
    role: RoleId,
    subject: SubjectRef,
    scope: AssignmentScope,
) -> UserRoleParts {
    user_role(rng, role, subject, scope).parts().clone()
}

fn revoked(parts: UserRoleParts) -> UserRoleParts {
    UserRoleParts {
        revoked_at: Some(parts.updated_at),
        version: EntityVersion::new(2).unwrap(),
        ..parts
    }
}

fn insert(parts: &UserRoleParts) -> UserRoleStatement {
    UserRoleStatement::insert(&iam_domain::UserRole::restore(parts.clone()))
}

fn query(now: SystemTime) -> UserRolePageQuery {
    UserRolePageQuery {
        limit: 100,
        after: None,
        subject_kind: None,
        subject_id: None,
        role_id: None,
        project_id: None,
        include_expired: false,
        now,
    }
}

fn ids(repository: &FakeUserRoleRepository, query: &UserRolePageQuery) -> Vec<UserRoleParts> {
    block_on(repository.find_page(query))
        .unwrap()
        .into_iter()
        .map(|found| found.parts().clone())
        .collect()
}

#[test]
fn the_fixture_builds_an_active_assignment_at_version_one() {
    let mut rng = TestRng::from_seed(3);
    let role = role_id(&mut rng);
    let subject = user_subject(&mut rng);

    let assignment = user_role(&mut rng, role, subject.clone(), AssignmentScope::Global);

    assert_eq!(assignment.parts().role_id, role);
    assert_eq!(assignment.parts().subject, subject);
    assert_eq!(assignment.parts().scope, AssignmentScope::Global);
    assert_eq!(assignment.parts().version, EntityVersion::INITIAL);
    assert_eq!(assignment.parts().expires_at, None);
    assert_eq!(assignment.parts().revoked_at, None);
    assert_eq!(assignment.parts().created_at, assignment.parts().updated_at);
}

#[test]
fn the_fixture_is_reproducible_from_its_seed() {
    let build = |seed| {
        let mut rng = TestRng::from_seed(seed);
        let role = role_id(&mut rng);
        let subject = user_subject(&mut rng);
        parts(&mut rng, role, subject, AssignmentScope::Global)
    };

    assert_eq!(build(9), build(9));
}

#[test]
fn a_user_role_change_runs_one_save_per_statement() {
    let mut rng = TestRng::from_seed(5);
    let role = role_id(&mut rng);
    let subject = user_subject(&mut rng);
    let stored = parts(&mut rng, role, subject, AssignmentScope::Global);

    let change = user_role_change(&mut rng, vec![insert(&stored)]);

    assert_eq!(
        change.parts().statements,
        vec![ChangeStatement::SaveUserRole(Box::new(insert(&stored)))]
    );
}

#[test]
fn an_inserted_assignment_is_found() {
    let mut rng = TestRng::from_seed(1);
    let role = role_id(&mut rng);
    let subject = user_subject(&mut rng);
    let stored = parts(&mut rng, role, subject, AssignmentScope::Global);
    let repository = FakeUserRoleRepository::default();

    repository.save(&insert(&stored)).unwrap();

    let found = block_on(repository.find_by_id(stored.id)).unwrap().unwrap();
    assert_eq!(found.parts(), &stored);
    assert_eq!(repository.stored(), vec![stored]);
}

#[test]
fn an_active_duplicate_of_subject_role_and_scope_already_exists() {
    let mut rng = TestRng::from_seed(2);
    let role = role_id(&mut rng);
    let subject = user_subject(&mut rng);
    let scope = project(&mut rng);
    let first = parts(&mut rng, role, subject.clone(), scope);
    let again = parts(&mut rng, role, subject, scope);
    let repository = FakeUserRoleRepository::holding(vec![first.clone()]);

    assert!(matches!(
        repository.save(&insert(&again)),
        Err(RepositoryError::AlreadyExists)
    ));
    assert_eq!(repository.stored(), vec![first]);
}

#[test]
fn a_stored_id_already_exists() {
    let mut rng = TestRng::from_seed(4);
    let role = role_id(&mut rng);
    let subject = user_subject(&mut rng);
    let first = parts(&mut rng, role, subject, AssignmentScope::Global);
    let other_subject = user_subject(&mut rng);
    let same_id = UserRoleParts {
        subject: other_subject,
        ..first.clone()
    };
    let repository = FakeUserRoleRepository::holding(vec![first]);

    assert!(matches!(
        repository.save(&insert(&same_id)),
        Err(RepositoryError::AlreadyExists)
    ));
}

#[test]
fn the_triple_of_a_revoked_assignment_can_be_assigned_again() {
    let mut rng = TestRng::from_seed(6);
    let role = role_id(&mut rng);
    let subject = user_subject(&mut rng);
    let scope = project(&mut rng);
    let first = revoked(parts(&mut rng, role, subject.clone(), scope));
    let again = parts(&mut rng, role, subject, scope);
    let repository = FakeUserRoleRepository::holding(vec![first.clone()]);

    repository.save(&insert(&again)).unwrap();

    assert_eq!(repository.stored(), vec![first, again.clone()]);
    let found = block_on(repository.find_by_id(again.id)).unwrap().unwrap();
    assert_eq!(found.parts(), &again);
}

#[test]
fn an_update_at_the_expected_version_replaces_the_assignment() {
    let mut rng = TestRng::from_seed(7);
    let role = role_id(&mut rng);
    let subject = user_subject(&mut rng);
    let first = parts(&mut rng, role, subject, AssignmentScope::Global);
    let changed = UserRoleParts {
        expires_at: Some(AssignmentExpiry::restore(at(4_200_000_000))),
        version: EntityVersion::new(2).unwrap(),
        ..first.clone()
    };
    let repository = FakeUserRoleRepository::holding(vec![first]);

    repository
        .save(&UserRoleStatement::update(
            &iam_domain::UserRole::restore(changed.clone()),
            EntityVersion::INITIAL,
        ))
        .unwrap();

    assert_eq!(repository.stored(), vec![changed]);
}

#[test]
fn an_update_of_a_stale_revoked_or_unknown_assignment_is_a_conflict() {
    let mut rng = TestRng::from_seed(8);
    let role = role_id(&mut rng);
    let subject = user_subject(&mut rng);
    let live = parts(&mut rng, role, subject.clone(), AssignmentScope::Global);
    let gone = revoked(parts(
        &mut rng,
        role,
        subject.clone(),
        AssignmentScope::Global,
    ));
    let unknown = parts(&mut rng, role, subject, AssignmentScope::Global);
    let repository = FakeUserRoleRepository::holding(vec![live.clone(), gone.clone()]);

    for (written, expected) in [(&live, 2), (&gone, 2), (&unknown, 1)] {
        let statement = UserRoleStatement::update(
            &iam_domain::UserRole::restore(written.clone()),
            EntityVersion::new(expected).unwrap(),
        );
        assert!(matches!(
            repository.save(&statement),
            Err(RepositoryError::Conflict)
        ));
    }
    assert_eq!(repository.stored(), vec![live, gone]);
}

#[test]
fn revoked_assignments_are_never_found_and_expired_ones_only_when_requested() {
    let mut rng = TestRng::from_seed(10);
    let role = role_id(&mut rng);
    let subject = user_subject(&mut rng);
    let scope = project(&mut rng);
    let active = parts(&mut rng, role, subject.clone(), AssignmentScope::Global);
    let expired = UserRoleParts {
        expires_at: Some(AssignmentExpiry::restore(at(100))),
        ..parts(&mut rng, role, subject.clone(), scope)
    };
    let gone = revoked(parts(&mut rng, role, subject, AssignmentScope::Global));
    let repository =
        FakeUserRoleRepository::holding(vec![gone.clone(), expired.clone(), active.clone()]);

    let mut both = vec![active.clone(), expired.clone()];
    both.sort_by_key(|parts| parts.id);
    assert_eq!(ids(&repository, &query(at(200))), vec![active]);
    assert_eq!(
        ids(
            &repository,
            &UserRolePageQuery {
                include_expired: true,
                ..query(at(200))
            }
        ),
        both
    );
    assert_eq!(ids(&repository, &query(at(99))).len(), 2);
    assert!(block_on(repository.find_by_id(gone.id)).unwrap().is_none());
    assert!(
        block_on(repository.find_by_id(expired.id))
            .unwrap()
            .is_some()
    );
}

#[test]
fn every_filter_narrows_the_page() {
    let mut rng = TestRng::from_seed(11);
    let role = role_id(&mut rng);
    let other_role = role_id(&mut rng);
    let user = user_subject(&mut rng);
    let service = SubjectRef::service(ServiceName::new("billing-service").unwrap());
    let scope = project(&mut rng);
    let user_global = parts(&mut rng, role, user.clone(), AssignmentScope::Global);
    let user_project = parts(&mut rng, other_role, user.clone(), scope);
    let service_global = parts(&mut rng, role, service, AssignmentScope::Global);
    let repository = FakeUserRoleRepository::holding(vec![
        user_global.clone(),
        user_project.clone(),
        service_global.clone(),
    ]);
    let now = at(0);

    let by_kind = ids(
        &repository,
        &UserRolePageQuery {
            subject_kind: Some(SubjectKind::Service),
            ..query(now)
        },
    );
    let by_subject = ids(
        &repository,
        &UserRolePageQuery {
            subject_id: Some(user.id().to_string()),
            ..query(now)
        },
    );
    let by_role = ids(
        &repository,
        &UserRolePageQuery {
            role_id: Some(other_role),
            ..query(now)
        },
    );
    let by_project = ids(
        &repository,
        &UserRolePageQuery {
            project_id: scope.project_id(),
            ..query(now)
        },
    );

    assert_eq!(by_kind, vec![service_global]);
    assert_eq!(by_subject.len(), 2);
    assert!(by_subject.contains(&user_global));
    assert!(by_subject.contains(&user_project));
    assert_eq!(by_role, vec![user_project.clone()]);
    assert_eq!(by_project, vec![user_project]);
}

#[test]
fn pages_follow_the_identifiers_after_the_cursor() {
    let mut rng = TestRng::from_seed(12);
    let role = role_id(&mut rng);
    let mut all: Vec<UserRoleParts> = (0..5)
        .map(|_index| {
            let subject = user_subject(&mut rng);
            parts(&mut rng, role, subject, AssignmentScope::Global)
        })
        .collect();
    let repository = FakeUserRoleRepository::holding(all.clone());
    all.sort_by_key(|parts| parts.id);

    let first = ids(
        &repository,
        &UserRolePageQuery {
            limit: 2,
            ..query(at(0))
        },
    );
    let second = ids(
        &repository,
        &UserRolePageQuery {
            limit: 2,
            after: first.last().map(|parts| parts.id),
            ..query(at(0))
        },
    );

    assert_eq!(first, all[..2].to_vec());
    assert_eq!(second, all[2..4].to_vec());
}

#[test]
fn a_failing_repository_is_unavailable() {
    let mut rng = TestRng::from_seed(13);
    let role = role_id(&mut rng);
    let subject = user_subject(&mut rng);
    let stored = parts(&mut rng, role, subject, AssignmentScope::Global);
    let repository = FakeUserRoleRepository::failing();

    assert!(matches!(
        repository.save(&insert(&stored)),
        Err(RepositoryError::Unavailable(_))
    ));
    assert!(matches!(
        block_on(repository.find_by_id(stored.id)),
        Err(RepositoryError::Unavailable(_))
    ));
    assert!(matches!(
        block_on(repository.find_page(&query(at(0)))),
        Err(RepositoryError::Unavailable(_))
    ));
    assert_eq!(repository.stored(), Vec::<UserRoleParts>::new());
}
