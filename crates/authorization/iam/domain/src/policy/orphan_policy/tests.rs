mod properties;

use rstest::rstest;

use super::{OrphanPolicy, RenameMap};
use crate::error::RenameRefused;
use crate::policy::catalogue_activation::{
    CatalogueActivation, FlagChange, GrantRecord, KeyRename, OrphanedGrant,
};
use crate::policy::compiled_role_set::GrantStatus;
use crate::policy::permission_catalogue::PermissionCatalogue;
use crate::value_object::coordinate_set::CoordinateSet;
use crate::value_object::graphql_coordinate::GraphQlCoordinate;
use crate::value_object::identifier::RoleId;
use crate::value_object::permission_flags::PermissionFlags;
use crate::value_object::permission_key::PermissionKey;
use crate::value_object::service_name::ServiceName;

const NONE: PermissionFlags = PermissionFlags::NONE;
const SENSITIVE: PermissionFlags = PermissionFlags::NONE.with_sensitive();
const AUDIT: PermissionFlags = PermissionFlags::NONE.with_audit_always();

const ADMIN: &str = "00000000-0000-4000-8000-000000000001";
const VIEWER: &str = "00000000-0000-4000-8000-000000000002";

fn billing() -> ServiceName {
    ServiceName::new("billing").unwrap()
}

fn role(id: &str) -> RoleId {
    RoleId::parse(id).unwrap()
}

fn key(value: &str) -> PermissionKey {
    PermissionKey::parse(value).unwrap()
}

fn version(entries: &[(&str, PermissionFlags)]) -> CoordinateSet {
    entries
        .iter()
        .map(|(coordinate, flags)| (GraphQlCoordinate::parse(coordinate).unwrap(), *flags))
        .collect()
}

fn catalogue(versions: &[&CoordinateSet]) -> PermissionCatalogue {
    PermissionCatalogue::for_graphql(&billing(), versions.iter().copied())
}

fn grant(role_id: &str, text: &str, status: GrantStatus) -> GrantRecord {
    GrantRecord {
        role: role(role_id),
        key: key(text),
        status,
    }
}

fn renames(pairs: &[(&str, &str)]) -> RenameMap {
    RenameMap::new(pairs.iter().map(|(from, to)| (key(from), key(to)))).unwrap()
}

fn apply(
    previous: &PermissionCatalogue,
    next: &PermissionCatalogue,
    map: &RenameMap,
    grants: &[GrantRecord],
) -> CatalogueActivation {
    OrphanPolicy::apply(previous, next, map, grants).unwrap()
}

#[test]
fn a_key_that_leaves_every_active_version_orphans_its_grants() {
    let first = version(&[("Query.invoice", NONE), ("Query.old", NONE)]);
    let second = version(&[("Query.invoice", NONE)]);
    let before = catalogue(&[&first, &second]);
    let after = catalogue(&[&second]);
    let grants = [
        grant(ADMIN, "gql:billing:Query.old", GrantStatus::Active),
        grant(VIEWER, "gql:billing:Query.old", GrantStatus::Active),
        grant(VIEWER, "gql:billing:Query.invoice", GrantStatus::Active),
    ];

    let result = apply(&before, &after, &RenameMap::empty(), &grants);

    assert_eq!(
        result.orphaned_grants,
        [
            OrphanedGrant {
                role: role(ADMIN),
                key: key("gql:billing:Query.old")
            },
            OrphanedGrant {
                role: role(VIEWER),
                key: key("gql:billing:Query.old")
            },
        ]
    );
    assert_eq!(result.orphaned_keys(), [key("gql:billing:Query.old")]);
    assert_eq!(result.affected_roles(), [role(ADMIN), role(VIEWER)]);
    assert_eq!(
        result.grants,
        [
            grant(ADMIN, "gql:billing:Query.old", GrantStatus::Orphaned),
            grant(VIEWER, "gql:billing:Query.invoice", GrantStatus::Active),
            grant(VIEWER, "gql:billing:Query.old", GrantStatus::Orphaned),
        ]
    );
    assert!(!result.is_empty());
}

#[test]
fn a_key_that_stays_in_one_active_version_keeps_its_grants() {
    let first = version(&[("Query.invoice", NONE), ("Query.old", NONE)]);
    let second = version(&[("Query.invoice", NONE)]);
    let before = catalogue(&[&first, &second]);
    let after = catalogue(&[&first]);
    let grants = [grant(ADMIN, "gql:billing:Query.old", GrantStatus::Active)];

    let result = apply(&before, &after, &RenameMap::empty(), &grants);

    assert_eq!(result.orphaned_grants, Vec::<OrphanedGrant>::new());
    assert_eq!(result.grants, grants);
    assert!(result.is_empty());
}

#[test]
fn an_orphaned_grant_stays_inactive_when_its_key_reappears() {
    let without = version(&[("Query.invoice", NONE)]);
    let with = version(&[("Query.invoice", NONE), ("Query.old", NONE)]);
    let grants = [grant(ADMIN, "gql:billing:Query.old", GrantStatus::Orphaned)];

    let result = apply(
        &catalogue(&[&without]),
        &catalogue(&[&with]),
        &RenameMap::empty(),
        &grants,
    );

    assert_eq!(result.created_keys, [key("gql:billing:Query.old")]);
    assert_eq!(result.orphaned_grants, Vec::<OrphanedGrant>::new());
    assert_eq!(result.grants, grants);
}

#[test]
fn only_grants_of_the_catalogue_service_and_form_are_orphaned() {
    let before = catalogue(&[&version(&[("Query.invoice", NONE)])]);
    let after = catalogue(&[]);
    let grants = [
        grant(ADMIN, "gql:orders:Query.order", GrantStatus::Active),
        grant(ADMIN, "rest:billing:GET /invoices", GrantStatus::Active),
        grant(ADMIN, "iam:audit:read", GrantStatus::Active),
        grant(ADMIN, "gql:billing:__introspection", GrantStatus::Active),
    ];

    let result = apply(&before, &after, &RenameMap::empty(), &grants);

    assert_eq!(
        result.orphaned_grants,
        [OrphanedGrant {
            role: role(ADMIN),
            key: key("gql:billing:__introspection")
        }]
    );
    assert_eq!(
        result
            .grants
            .iter()
            .filter(|record| record.status == GrantStatus::Active)
            .count(),
        3
    );
}

#[test]
fn a_rename_moves_the_grants_and_is_part_of_the_result() {
    let before = catalogue(&[&version(&[("Query.invoice", NONE), ("Query.bill", NONE)])]);
    let after = catalogue(&[&version(&[
        ("Query.invoice", NONE),
        ("Query.statement", NONE),
    ])]);
    let map = renames(&[("gql:billing:Query.bill", "gql:billing:Query.statement")]);
    let grants = [
        grant(ADMIN, "gql:billing:Query.bill", GrantStatus::Active),
        grant(VIEWER, "gql:billing:Query.bill", GrantStatus::Active),
        grant(VIEWER, "gql:billing:Query.invoice", GrantStatus::Active),
    ];

    let result = apply(&before, &after, &map, &grants);

    assert_eq!(
        result.renames,
        [KeyRename {
            from: key("gql:billing:Query.bill"),
            to: key("gql:billing:Query.statement"),
            roles: vec![role(ADMIN), role(VIEWER)],
        }]
    );
    assert_eq!(result.created_keys, [key("gql:billing:Query.statement")]);
    assert_eq!(result.orphaned_grants, Vec::<OrphanedGrant>::new());
    assert_eq!(
        result.grants,
        [
            grant(ADMIN, "gql:billing:Query.statement", GrantStatus::Active),
            grant(VIEWER, "gql:billing:Query.invoice", GrantStatus::Active),
            grant(VIEWER, "gql:billing:Query.statement", GrantStatus::Active),
        ]
    );
    assert!(!result.is_empty());
}

#[test]
fn a_rename_without_grants_is_still_reported() {
    let before = catalogue(&[&version(&[("Query.bill", NONE)])]);
    let after = catalogue(&[&version(&[("Query.statement", NONE)])]);
    let map = renames(&[("gql:billing:Query.bill", "gql:billing:Query.statement")]);

    let result = apply(&before, &after, &map, &[]);

    assert_eq!(result.renames.len(), 1);
    assert!(result.renames.iter().all(|rename| rename.roles.is_empty()));
}

#[test]
fn a_role_that_holds_the_new_key_already_keeps_that_grant() {
    let before = catalogue(&[&version(&[("Query.bill", NONE)])]);
    let after = catalogue(&[&version(&[("Query.statement", NONE)])]);
    let map = renames(&[("gql:billing:Query.bill", "gql:billing:Query.statement")]);
    let grants = [
        grant(ADMIN, "gql:billing:Query.bill", GrantStatus::Active),
        grant(ADMIN, "gql:billing:Query.statement", GrantStatus::Orphaned),
    ];

    let result = apply(&before, &after, &map, &grants);

    assert_eq!(
        result.grants,
        [grant(
            ADMIN,
            "gql:billing:Query.statement",
            GrantStatus::Orphaned
        )]
    );
}

#[rstest]
#[case(GrantStatus::Active, GrantStatus::Orphaned, GrantStatus::Active)]
#[case(GrantStatus::Orphaned, GrantStatus::Active, GrantStatus::Active)]
#[case(GrantStatus::Orphaned, GrantStatus::Orphaned, GrantStatus::Orphaned)]
#[case(GrantStatus::Active, GrantStatus::Active, GrantStatus::Active)]
fn grants_that_move_to_one_key_merge_to_active_when_any_is_active(
    #[case] first: GrantStatus,
    #[case] second: GrantStatus,
    #[case] merged: GrantStatus,
) {
    let before = catalogue(&[&version(&[("Query.a", NONE), ("Query.b", NONE)])]);
    let after = catalogue(&[&version(&[("Query.c", NONE)])]);
    let map = renames(&[
        ("gql:billing:Query.a", "gql:billing:Query.c"),
        ("gql:billing:Query.b", "gql:billing:Query.c"),
    ]);
    let grants = [
        grant(ADMIN, "gql:billing:Query.a", first),
        grant(ADMIN, "gql:billing:Query.b", second),
    ];

    let result = apply(&before, &after, &map, &grants);

    assert_eq!(result.grants, [grant(ADMIN, "gql:billing:Query.c", merged)]);
}

#[test]
fn an_orphaned_grant_moves_with_a_rename_but_stays_inactive() {
    let before = catalogue(&[&version(&[("Query.bill", NONE)])]);
    let after = catalogue(&[&version(&[("Query.statement", NONE)])]);
    let map = renames(&[("gql:billing:Query.bill", "gql:billing:Query.statement")]);
    let grants = [grant(
        ADMIN,
        "gql:billing:Query.bill",
        GrantStatus::Orphaned,
    )];

    let result = apply(&before, &after, &map, &grants);

    assert_eq!(
        result.grants,
        [grant(
            ADMIN,
            "gql:billing:Query.statement",
            GrantStatus::Orphaned
        )]
    );
    assert_eq!(result.orphaned_grants, Vec::<OrphanedGrant>::new());
}

#[test]
fn a_union_flag_that_would_be_removed_is_a_downgrade_recorded_with_old_and_new_flags() {
    let flagged = version(&[("Mutation.pay", SENSITIVE), ("Query.invoice", AUDIT)]);
    let plain = version(&[("Mutation.pay", NONE), ("Query.invoice", NONE)]);
    let before = catalogue(&[&flagged, &plain]);
    let after = catalogue(&[&plain]);

    let result = apply(&before, &after, &RenameMap::empty(), &[]);

    let mut expected = vec![
        FlagChange {
            key: key("gql:billing:Query.invoice"),
            before: AUDIT,
            after: NONE,
        },
        FlagChange {
            key: key("gql:billing:Mutation.pay"),
            before: SENSITIVE,
            after: NONE,
        },
    ];
    expected.sort_by(|left, right| left.key.cmp(&right.key));
    assert_eq!(result.flag_changes, expected);
    assert_eq!(result.flag_downgrades, expected);
    assert!(result.flag_changes.iter().all(FlagChange::is_downgrade));
}

#[test]
fn a_flag_that_is_added_is_a_change_and_not_a_downgrade() {
    let plain = version(&[("Mutation.pay", NONE)]);
    let flagged = version(&[("Mutation.pay", SENSITIVE)]);

    let result = apply(
        &catalogue(&[&plain]),
        &catalogue(&[&plain, &flagged]),
        &RenameMap::empty(),
        &[],
    );

    assert_eq!(
        result.flag_changes,
        [FlagChange {
            key: key("gql:billing:Mutation.pay"),
            before: NONE,
            after: SENSITIVE
        }]
    );
    assert_eq!(result.flag_downgrades, Vec::<FlagChange>::new());
    assert!(!result.flag_changes.iter().any(FlagChange::is_downgrade));
}

#[test]
fn unchanged_flags_are_not_reported() {
    let flagged = version(&[("Mutation.pay", SENSITIVE)]);
    let both = catalogue(&[&flagged]);

    let result = apply(&both, &both, &RenameMap::empty(), &[]);

    assert_eq!(result.flag_changes, Vec::<FlagChange>::new());
    assert!(result.is_empty());
}

#[test]
fn a_retirement_of_the_last_version_orphans_every_grant_including_the_introspection() {
    let only = version(&[("Query.invoice", NONE)]);
    let grants = [
        grant(ADMIN, "gql:billing:Query.invoice", GrantStatus::Active),
        grant(ADMIN, "gql:billing:__introspection", GrantStatus::Active),
    ];

    let result = apply(
        &catalogue(&[&only]),
        &catalogue(&[]),
        &RenameMap::empty(),
        &grants,
    );

    assert_eq!(result.orphaned_grants.len(), 2);
    assert!(
        result
            .grants
            .iter()
            .all(|record| record.status == GrantStatus::Orphaned)
    );
}

#[rstest]
#[case("gql:billing:Query.bill", "gql:orders:Query.bill")]
#[case("gql:billing:Query.bill", "rest:billing:GET /bill")]
#[case("iam:audit:read", "iam:policy:resync")]
fn a_rename_that_leaves_its_service_or_form_is_refused(#[case] from: &str, #[case] to: &str) {
    let refused = RenameMap::new([(key(from), key(to))]).unwrap_err();

    assert_eq!(
        refused,
        RenameRefused::Scope {
            from: key(from).to_string(),
            to: key(to).to_string()
        }
    );
}

#[test]
fn a_key_renamed_to_itself_is_refused() {
    let refused = RenameMap::new([(key("gql:billing:Query.bill"), key("gql:billing:Query.bill"))])
        .unwrap_err();

    assert_eq!(
        refused,
        RenameRefused::Unchanged {
            key: key("gql:billing:Query.bill").to_string()
        }
    );
}

#[test]
fn a_key_renamed_twice_is_refused() {
    let refused = RenameMap::new([
        (key("gql:billing:Query.a"), key("gql:billing:Query.b")),
        (key("gql:billing:Query.a"), key("gql:billing:Query.c")),
    ])
    .unwrap_err();

    assert_eq!(
        refused,
        RenameRefused::Duplicate {
            key: key("gql:billing:Query.a").to_string()
        }
    );
}

#[test]
fn a_chain_of_renames_is_refused() {
    let refused = RenameMap::new([
        (key("gql:billing:Query.a"), key("gql:billing:Query.b")),
        (key("gql:billing:Query.b"), key("gql:billing:Query.c")),
    ])
    .unwrap_err();

    assert_eq!(
        refused,
        RenameRefused::Chained {
            key: key("gql:billing:Query.b").to_string()
        }
    );
}

#[test]
fn the_map_reports_its_renames() {
    let empty = RenameMap::empty();
    let map = renames(&[("gql:billing:Query.a", "gql:billing:Query.b")]);

    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
    assert!(!map.is_empty());
    assert_eq!(map.len(), 1);
    assert_eq!(map.iter().count(), 1);
    assert_eq!(
        map.target(&key("gql:billing:Query.a")),
        Some(&key("gql:billing:Query.b"))
    );
    assert_eq!(map.target(&key("gql:billing:Query.b")), None);
}

#[rstest]
#[case(
    "gql:orders:Query.a", "gql:orders:Query.b",
    RenameRefused::OutsideCatalogue { key: key("gql:orders:Query.a").to_string() }
)]
#[case(
    "gql:billing:Query.a", "gql:billing:Query.missing",
    RenameRefused::TargetMissing { to: key("gql:billing:Query.missing").to_string() }
)]
#[case(
    "gql:billing:Query.kept", "gql:billing:Query.b",
    RenameRefused::SourceStillPresent { from: key("gql:billing:Query.kept").to_string() }
)]
fn a_rename_that_does_not_fit_the_catalogue_is_refused_and_nothing_applies(
    #[case] from: &str,
    #[case] to: &str,
    #[case] expected: RenameRefused,
) {
    let before = catalogue(&[&version(&[("Query.a", NONE), ("Query.kept", NONE)])]);
    let after = catalogue(&[&version(&[("Query.b", NONE), ("Query.kept", NONE)])]);
    let map = renames(&[(from, to)]);

    let refused = OrphanPolicy::apply(&before, &after, &map, &[]).unwrap_err();

    assert_eq!(refused, expected);
}

#[test]
fn a_rename_of_another_service_is_outside_the_catalogue() {
    let before = catalogue(&[&version(&[("Query.a", NONE)])]);
    let map = renames(&[("gql:billing:Query.a", "gql:billing:Query.b")]);
    let other = PermissionCatalogue::for_graphql(
        &ServiceName::new("orders").unwrap(),
        [&version(&[("Query.b", NONE)])],
    );

    let refused = OrphanPolicy::apply(&before, &other, &map, &[]).unwrap_err();

    assert_eq!(
        refused,
        RenameRefused::OutsideCatalogue {
            key: key("gql:billing:Query.a").to_string()
        }
    );
}
