use iam_domain::{
    ChangeStatement, RatePolicyPageQuery, RatePolicyRepository as _, RatePolicyStatement,
    RepositoryError,
};

use super::{FakeRatePolicyRepository, rate_policy, rate_policy_change};
use crate::block_on;
use crate::seed::TestRng;

fn held(names: &[&str]) -> FakeRatePolicyRepository {
    let mut rng = TestRng::from_seed(7);
    FakeRatePolicyRepository::holding(
        names
            .iter()
            .map(|name| rate_policy(&mut rng, name).parts().clone())
            .collect(),
    )
}

#[test]
fn the_fixture_builds_a_rate_policy_at_version_one() {
    let policy = rate_policy(&mut TestRng::from_seed(3), "per-ip");

    assert_eq!(policy.parts().fields.name(), "per-ip");
    assert_eq!(policy.parts().version.value(), 1);
    assert_eq!(policy.parts().created_at, policy.parts().updated_at);
}

#[test]
fn a_rate_policy_change_runs_one_save_per_statement() {
    let mut rng = TestRng::from_seed(5);
    let policy = rate_policy(&mut rng, "per-ip");

    let change = rate_policy_change(&mut rng, vec![RatePolicyStatement::insert(&policy)]);

    assert_eq!(
        change.parts().statements,
        vec![ChangeStatement::from(RatePolicyStatement::insert(&policy))]
    );
}

#[test]
fn many_policies_come_back_in_the_order_asked_and_unknown_ones_are_left_out() {
    let repository = held(&["a", "b", "c"]);
    let all = block_on(repository.find_page(&RatePolicyPageQuery {
        limit: 10,
        after: None,
    }))
    .unwrap();
    let ids: Vec<_> = all.iter().map(|policy| policy.parts().id).collect();
    let unknown = rate_policy(&mut TestRng::from_seed(99), "x").parts().id;
    let asked = [ids[2], unknown, ids[0]];

    let found = block_on(repository.find_many(&asked)).unwrap();

    let found_ids: Vec<_> = found.iter().map(|policy| policy.parts().id).collect();
    assert_eq!(found_ids, [ids[2], ids[0]]);
    assert!(block_on(repository.find_by_id(unknown)).unwrap().is_none());
    assert!(block_on(repository.find_by_id(ids[1])).unwrap().is_some());
}

#[test]
fn pages_follow_the_order_of_the_identifiers_and_never_repeat_a_policy() {
    let repository = held(&["a", "b", "c", "d"]);

    let first = block_on(repository.find_page(&RatePolicyPageQuery {
        limit: 3,
        after: None,
    }))
    .unwrap();
    let second = block_on(repository.find_page(&RatePolicyPageQuery {
        limit: 3,
        after: first.last().map(|policy| policy.parts().id),
    }))
    .unwrap();

    assert_eq!(first.len(), 3);
    assert_eq!(second.len(), 1);
    assert!(first[2].parts().id < second[0].parts().id);
}

#[test]
fn a_failing_repository_is_unavailable() {
    let repository = FakeRatePolicyRepository::failing();

    assert!(matches!(
        block_on(repository.find_many(&[])),
        Err(RepositoryError::Unavailable(_))
    ));
}
