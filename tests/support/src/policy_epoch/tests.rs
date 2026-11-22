use iam_domain::{PolicyEpochRepository, RepositoryError};

use super::{FakePolicyEpochRepository, policy_epoch, seeded_policy_epoch};
use crate::block_on;
use crate::seed::TestRng;

#[test]
fn the_seeded_epoch_is_all_zeros() {
    let epoch = seeded_policy_epoch();

    assert_eq!(epoch.version().value(), 0);
    assert_eq!(epoch.digest().as_bytes(), &[0; 16]);
    assert_eq!(epoch.log_epoch().value(), 0);
    assert_eq!(epoch.relay_epoch().value(), 0);
    assert_eq!(epoch.catalog_epoch(), 0);
}

#[test]
fn the_same_seed_gives_equal_epochs() {
    let first = policy_epoch(&mut TestRng::from_seed(7));
    let second = policy_epoch(&mut TestRng::from_seed(7));

    assert_eq!(first, second);
}

#[test]
fn different_seeds_give_different_epochs() {
    let first = policy_epoch(&mut TestRng::from_seed(1));
    let second = policy_epoch(&mut TestRng::from_seed(2));

    assert_ne!(first, second);
}

#[test]
fn generated_epochs_are_not_the_seeded_one() {
    let mut rng = TestRng::from_seed(20_261_122);

    for _round in 0..200 {
        let epoch = policy_epoch(&mut rng);

        assert_ne!(epoch, seeded_policy_epoch());
        assert!(epoch.version().value() >= 0);
        assert!(epoch.log_epoch().value() >= 0);
        assert!(epoch.relay_epoch().value() >= 0);
        assert!(epoch.catalog_epoch() >= 0);
    }
}

#[test]
fn the_new_and_the_default_repository_hold_the_seeded_epoch() {
    for repository in [
        FakePolicyEpochRepository::new(),
        FakePolicyEpochRepository::default(),
    ] {
        let port: &dyn PolicyEpochRepository = &repository;

        assert_eq!(block_on(port.current()).unwrap(), seeded_policy_epoch());
    }
}

#[test]
fn a_repository_holds_the_epoch_it_was_given() {
    let epoch = policy_epoch(&mut TestRng::from_seed(3));
    let repository = FakePolicyEpochRepository::holding(epoch);
    let port: &dyn PolicyEpochRepository = &repository;

    assert_eq!(block_on(port.current()).unwrap(), epoch);
    assert_eq!(block_on(port.current()).unwrap(), epoch);
}

#[test]
fn the_empty_repository_does_not_find_the_epoch() {
    let repository = FakePolicyEpochRepository::empty();
    let port: &dyn PolicyEpochRepository = &repository;

    assert!(matches!(
        block_on(port.current()),
        Err(RepositoryError::NotFound)
    ));
}

#[test]
fn the_failing_repository_is_unavailable() {
    let repository = FakePolicyEpochRepository::failing();
    let port: &dyn PolicyEpochRepository = &repository;

    let error = block_on(port.current()).unwrap_err();

    assert!(matches!(error, RepositoryError::Unavailable(_)));
    assert_eq!(
        std::error::Error::source(&error).unwrap().to_string(),
        "in-memory repository failure"
    );
}
