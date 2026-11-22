//! Property tests of the union and of the non-reactivation rule.
//!
//! Failures replay from `PROPTEST_RNG_SEED`.

use std::collections::BTreeMap;

use proptest::collection::vec;
use proptest::prelude::*;

use super::{GrantStatus, NONE, RenameMap, apply, billing, catalogue, grant, version};
use crate::policy::catalogue_activation::{GrantRecord, OrphanedGrant};
use crate::policy::orphan_policy::OrphanPolicy;
use crate::policy::permission_catalogue::PermissionCatalogue;
use crate::value_object::coordinate_set::CoordinateSet;
use crate::value_object::graphql_coordinate::GraphQlCoordinate;
use crate::value_object::permission_flags::PermissionFlags;

const ROLES: [&str; 2] = [
    "00000000-0000-4000-8000-000000000001",
    "00000000-0000-4000-8000-000000000002",
];
const FIELDS: usize = 5;

fn field_set() -> impl Strategy<Value = Vec<usize>> {
    vec(0..FIELDS, 0..FIELDS)
}

fn fields_version(fields: &[usize]) -> CoordinateSet {
    let entries: Vec<(String, PermissionFlags)> = fields
        .iter()
        .map(|index| (format!("Query.f{index}"), NONE))
        .collect();
    let borrowed: Vec<(&str, PermissionFlags)> = entries
        .iter()
        .map(|(coordinate, flags)| (coordinate.as_str(), *flags))
        .collect();
    version(&borrowed)
}

/// One grant per `(role, field)`: the last status listed wins.
fn grants(statuses: &[(usize, usize, bool)]) -> Vec<GrantRecord> {
    let unique: BTreeMap<(usize, usize), bool> = statuses
        .iter()
        .map(|(role, field, active)| ((*role, *field), *active))
        .collect();
    unique
        .into_iter()
        .map(|((role, field), active)| {
            grant(
                ROLES[role.checked_rem(ROLES.len()).unwrap()],
                &format!("gql:billing:Query.f{field}"),
                if active {
                    GrantStatus::Active
                } else {
                    GrantStatus::Orphaned
                },
            )
        })
        .collect()
}

fn random_grants() -> impl Strategy<Value = Vec<(usize, usize, bool)>> {
    vec((0..ROLES.len(), 0..FIELDS, any::<bool>()), 0..8)
}

proptest! {
    #[test]
    fn the_union_of_versions_holds_exactly_the_keys_of_some_version(
        first in field_set(),
        second in field_set(),
    ) {
        let one = fields_version(&first);
        let two = fields_version(&second);

        let union = catalogue(&[&one, &two]);

        for index in 0..FIELDS {
            let coordinate = GraphQlCoordinate::parse(&format!("Query.f{index}")).unwrap();
            let in_a_version = one.contains(&coordinate) || two.contains(&coordinate);
            prop_assert_eq!(
                union.contains(&coordinate.permission_key(&billing())),
                in_a_version
            );
        }
    }

    #[test]
    fn an_orphaned_grant_never_becomes_active(
        before_fields in field_set(),
        after_fields in field_set(),
        held in random_grants(),
    ) {
        let before = catalogue(&[&fields_version(&before_fields)]);
        let after = catalogue(&[&fields_version(&after_fields)]);
        let records = grants(&held);

        let result = apply(&before, &after, &RenameMap::empty(), &records);

        for record in &records {
            if record.status == GrantStatus::Orphaned {
                let kept = result
                    .grants
                    .iter()
                    .find(|resolved| resolved.role == record.role && resolved.key == record.key);
                prop_assert_ne!(kept.map(|resolved| resolved.status), Some(GrantStatus::Active));
            }
        }
    }

    #[test]
    fn a_grant_is_active_afterwards_exactly_when_it_was_and_its_key_stays(
        before_fields in field_set(),
        after_fields in field_set(),
        held in random_grants(),
    ) {
        let before = catalogue(&[&fields_version(&before_fields)]);
        let after = catalogue(&[&fields_version(&after_fields)]);
        let records = grants(&held);

        let result = apply(&before, &after, &RenameMap::empty(), &records);

        prop_assert_eq!(result.grants.len(), records.len());
        for (record, resolved) in records.iter().zip(&result.grants) {
            let stays_active =
                record.status == GrantStatus::Active && after.contains(&record.key);
            prop_assert_eq!(resolved.status == GrantStatus::Active, stays_active);
        }
    }

    #[test]
    fn applying_the_same_catalogue_twice_changes_nothing(
        fields in field_set(),
        held in random_grants(),
    ) {
        let current = catalogue(&[&fields_version(&fields)]);
        let first = apply(&current, &current, &RenameMap::empty(), &grants(&held));

        let second = OrphanPolicy::apply(&current, &current, &RenameMap::empty(), &first.grants)
            .unwrap();

        prop_assert!(second.is_empty());
        prop_assert_eq!(second.grants, first.grants);
    }
}

#[test]
fn the_empty_catalogue_of_another_form_orphans_nothing() {
    let rest = PermissionCatalogue::for_rest(&billing(), []);
    let records = [grant(ROLES[0], "gql:billing:Query.f0", GrantStatus::Active)];

    let result = apply(&rest, &rest, &RenameMap::empty(), &records);

    assert_eq!(result.orphaned_grants, Vec::<OrphanedGrant>::new());
    assert_eq!(result.grants, records);
}
