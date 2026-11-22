use iam_domain::{ChangeReceiptRepository, RepositoryError};

use super::{FakeChangeReceiptRepository, change_receipt};
use crate::block_on;
use crate::seed::TestRng;

#[test]
fn the_same_seed_gives_equal_receipts() {
    let first = change_receipt(&mut TestRng::from_seed(7));
    let second = change_receipt(&mut TestRng::from_seed(7));

    assert_eq!(first, second);
}

#[test]
fn different_seeds_give_different_receipts() {
    let first = change_receipt(&mut TestRng::from_seed(1));
    let second = change_receipt(&mut TestRng::from_seed(2));

    assert_ne!(first, second);
    assert_eq!(first.target().target_type(), "role");
    assert!(first.policy_version().is_some());
}

#[test]
fn the_new_and_the_default_repository_find_nothing() {
    let receipt = change_receipt(&mut TestRng::from_seed(3));

    for repository in [
        FakeChangeReceiptRepository::new(),
        FakeChangeReceiptRepository::default(),
    ] {
        let port: &dyn ChangeReceiptRepository = &repository;

        let error = block_on(port.find(receipt.change_id())).unwrap_err();

        assert!(matches!(error, RepositoryError::NotFound));
    }
}

#[test]
fn a_holding_repository_finds_its_receipts_by_change() {
    let mut rng = TestRng::from_seed(4);
    let first = change_receipt(&mut rng);
    let second = change_receipt(&mut rng);
    let repository = FakeChangeReceiptRepository::holding(vec![first.clone(), second.clone()]);

    assert_eq!(
        block_on(repository.find(second.change_id())).unwrap(),
        second
    );
    assert_eq!(block_on(repository.find(first.change_id())).unwrap(), first);
}

#[test]
fn a_failing_repository_is_unavailable() {
    let receipt = change_receipt(&mut TestRng::from_seed(5));
    let repository = FakeChangeReceiptRepository::failing();

    let error = block_on(repository.find(receipt.change_id())).unwrap_err();

    assert!(matches!(error, RepositoryError::Unavailable(_)));
}
