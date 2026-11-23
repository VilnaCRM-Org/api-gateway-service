use std::time::SystemTime;

use iam_domain::{
    CatalogueStatement, CatalogueStatementParts, ChangeStatement, DecisionEffect,
    PermissionKeyKind, ServiceName, SpecId, SpecStatus, SpecTransition,
};

use super::catalogue_change;
use crate::seed::TestRng;

#[test]
fn a_catalogue_change_runs_the_statements_with_the_effect() {
    let mut rng = TestRng::from_seed(11);
    let statement = CatalogueStatement::new(CatalogueStatementParts {
        kind: PermissionKeyKind::Gql,
        service: ServiceName::new("billing").unwrap(),
        transition: SpecTransition {
            spec_id: SpecId::parse("5b2e8c1d-3f4a-4b6c-8d9e-0a1b2c3d4e5f").unwrap(),
            from: SpecStatus::Draft,
            to: SpecStatus::Active,
            activated_at: Some(SystemTime::UNIX_EPOCH),
            retired_at: None,
        },
        created: Vec::new(),
        reflagged: Vec::new(),
        reactivated: Vec::new(),
        deactivated: Vec::new(),
        orphaned: Vec::new(),
        renames: Vec::new(),
        at: SystemTime::UNIX_EPOCH,
    })
    .unwrap();

    let change = catalogue_change(&mut rng, DecisionEffect::Affected, vec![statement]);

    assert!(change.affects_decisions());
    assert!(matches!(
        change.parts().statements.as_slice(),
        [ChangeStatement::ApplyCatalogue(_)]
    ));
}
