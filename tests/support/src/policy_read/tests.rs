use std::collections::BTreeMap;

use iam_domain::{
    GraphQlTypeGraph, PolicyReadRepository as _, RepositoryError, RestOperationSet, ServiceCatalog,
    ServiceName, SubjectPolicy, SubjectRef,
};

use super::FakePolicyReadRepository;
use crate::block_on;
use crate::policy_epoch::seeded_policy_epoch;

fn subject() -> SubjectRef {
    SubjectRef::service(ServiceName::new("orders").unwrap())
}

fn catalog(name: &str) -> ServiceCatalog {
    ServiceCatalog::new(
        ServiceName::new(name).unwrap(),
        seeded_policy_epoch(),
        vec![RestOperationSet::new()],
        vec![GraphQlTypeGraph::default()],
    )
}

#[test]
fn an_empty_repository_knows_no_assignment_and_no_service() {
    let repository = FakePolicyReadRepository::new();

    let policy = block_on(repository.read_subject_policy(&subject())).unwrap();
    let found = block_on(repository.read_service_catalog(&ServiceName::new("orders").unwrap()));

    assert_eq!(policy.assignments(), []);
    assert!(policy.role_sets().is_empty());
    assert_eq!(policy.epoch(), seeded_policy_epoch());
    assert!(found.unwrap().is_none());
}

#[test]
fn a_held_subject_and_a_held_catalogue_are_answered() {
    let held = SubjectPolicy::new(seeded_policy_epoch(), Vec::new(), BTreeMap::new());
    let repository = FakePolicyReadRepository::default()
        .with_subject(subject(), held.clone())
        .with_catalog(catalog("orders"));

    let policy = block_on(repository.read_subject_policy(&subject())).unwrap();
    let found =
        block_on(repository.read_service_catalog(&ServiceName::new("orders").unwrap())).unwrap();
    let other =
        block_on(repository.read_service_catalog(&ServiceName::new("billing").unwrap())).unwrap();

    assert_eq!(policy, held);
    assert_eq!(found, Some(catalog("orders")));
    assert!(other.is_none());
}

#[test]
fn a_failing_repository_is_unavailable_for_both_reads() {
    let repository = FakePolicyReadRepository::failing();

    let policy = block_on(repository.read_subject_policy(&subject())).unwrap_err();
    let found = block_on(repository.read_service_catalog(&ServiceName::new("orders").unwrap()))
        .unwrap_err();

    assert!(matches!(policy, RepositoryError::Unavailable(_)));
    assert!(matches!(found, RepositoryError::Unavailable(_)));
}
