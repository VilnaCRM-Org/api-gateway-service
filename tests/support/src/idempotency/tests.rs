use std::time::{Duration, SystemTime};

use iam_domain::{ActorRef, IdempotencyKey, IdempotencyRepository, RepositoryError};

use super::{FakeIdempotencyRepository, idempotency_record, idempotency_request};
use crate::block_on;
use crate::seed::TestRng;
use crate::unit_of_work::uuid_v7;

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

#[test]
fn the_same_seed_gives_equal_requests() {
    let first = idempotency_request(&mut TestRng::from_seed(7));
    let second = idempotency_request(&mut TestRng::from_seed(7));

    assert_eq!(first, second);
}

#[test]
fn different_seeds_give_different_requests() {
    let first = idempotency_request(&mut TestRng::from_seed(1));
    let second = idempotency_request(&mut TestRng::from_seed(2));

    assert_ne!(first, second);
    assert!(first.key.as_str().starts_with("key-"));
}

#[test]
fn the_new_and_the_default_repository_find_nothing_and_remember_the_lookup() {
    let mut rng = TestRng::from_seed(3);
    let actor = ActorRef::User(uuid_v7(&mut rng));
    let request = idempotency_request(&mut rng);

    for repository in [
        FakeIdempotencyRepository::new(),
        FakeIdempotencyRepository::default(),
    ] {
        let port: &dyn IdempotencyRepository = &repository;

        let found = block_on(port.find_since(&actor, &request.key, at(10))).unwrap();

        assert_eq!(found, None);
        assert_eq!(repository.asked_since(), vec![at(10)]);
    }
}

#[test]
fn a_holding_repository_finds_a_record_of_the_actor_and_key_created_since() {
    let mut rng = TestRng::from_seed(4);
    let actor = ActorRef::User(uuid_v7(&mut rng));
    let request = idempotency_request(&mut rng);
    let record = idempotency_record(&mut rng, actor.clone(), request.clone());
    let repository = FakeIdempotencyRepository::holding(vec![(record.clone(), at(100))]);

    let at_creation = block_on(repository.find_since(&actor, &request.key, at(100))).unwrap();
    let after = block_on(repository.find_since(&actor, &request.key, at(101))).unwrap();

    assert_eq!(at_creation, Some(record));
    assert_eq!(after, None);
    assert_eq!(repository.asked_since(), vec![at(100), at(101)]);
}

#[test]
fn a_holding_repository_ignores_another_actor_or_key() {
    let mut rng = TestRng::from_seed(5);
    let actor = ActorRef::User(uuid_v7(&mut rng));
    let other_actor = ActorRef::User(uuid_v7(&mut rng));
    let request = idempotency_request(&mut rng);
    let record = idempotency_record(&mut rng, actor.clone(), request.clone());
    let repository = FakeIdempotencyRepository::holding(vec![(record, at(100))]);
    let other_key = IdempotencyKey::new("other").unwrap();

    let by_other_actor =
        block_on(repository.find_since(&other_actor, &request.key, at(0))).unwrap();
    let by_other_key = block_on(repository.find_since(&actor, &other_key, at(0))).unwrap();

    assert_eq!(by_other_actor, None);
    assert_eq!(by_other_key, None);
}

#[test]
fn a_failing_repository_is_unavailable() {
    let mut rng = TestRng::from_seed(6);
    let actor = ActorRef::User(uuid_v7(&mut rng));
    let request = idempotency_request(&mut rng);
    let repository = FakeIdempotencyRepository::failing();

    let error = block_on(repository.find_since(&actor, &request.key, at(0))).unwrap_err();

    assert!(matches!(error, RepositoryError::Unavailable(_)));
    assert_eq!(repository.asked_since(), vec![at(0)]);
}
