use iam_domain::{ChangeStatement, PolicyVersion};

use super::{gateway_change, random_time};
use crate::seed::TestRng;

#[test]
fn a_random_time_is_reproducible_from_its_seed() {
    assert_eq!(
        random_time(&mut TestRng::from_seed(4)),
        random_time(&mut TestRng::from_seed(4))
    );
}

#[test]
fn a_gateway_change_runs_the_statements_and_affects_decisions() {
    let statement = ChangeStatement::ExpectPolicyVersion(PolicyVersion::new(1).unwrap());

    let change = gateway_change(&mut TestRng::from_seed(5), vec![statement.clone()]);

    assert_eq!(change.parts().statements, vec![statement]);
    assert!(change.affects_decisions());
}
