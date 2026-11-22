use std::any::Any;
use std::time::{Duration, SystemTime};

use rstest::rstest;
use shared_domain::{AggregateRoot as _, DomainEvent, Uuid};

use super::event::{RoleCreated, RoleDeleted, RolePermissionsChanged, RoleUpdated};
use super::{Role, RoleDescriptionChange, RoleFields, RoleParts, RolePatch, RoleStamp};
use crate::entity::event_envelope::EventEnvelope;
use crate::error::{
    InvalidEventEnvelope, InvalidIamValue, InvalidRole, RoleChangeRefused, VersionConflict,
};
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::identifier::RoleId;
use crate::value_object::permission_grant::PermissionGrant;
use crate::value_object::permission_grant_set::PermissionGrantSet;
use crate::value_object::role_description::RoleDescription;
use crate::value_object::role_kind::RoleKind;
use crate::value_object::role_name::RoleName;

const ROLE: &str = "7f1c2a4e-1d0b-4f5e-9a3c-2b6d8e0f1a2b";
const USER: &str = "3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a";
const EVENT: &str = "01890a5d-ac96-774b-bcce-b302099a8057";

fn role_id() -> RoleId {
    RoleId::parse(ROLE).unwrap()
}

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn stamp(seconds: u64) -> RoleStamp {
    RoleStamp {
        event_id: Uuid::parse(EVENT).unwrap(),
        actor: ActorRef::User(Uuid::parse(USER).unwrap()),
        occurred_at: at(seconds),
    }
}

fn version(value: i64) -> EntityVersion {
    EntityVersion::new(value).unwrap()
}

fn name(value: &str) -> RoleName {
    RoleName::new(value.to_owned()).unwrap()
}

fn description(value: &str) -> RoleDescription {
    RoleDescription::new(value.to_owned()).unwrap()
}

fn grants(values: &[&str]) -> PermissionGrantSet {
    PermissionGrantSet::new(
        values
            .iter()
            .map(|value| PermissionGrant::parse(value).unwrap()),
    )
    .unwrap()
}

fn grant(value: &str) -> PermissionGrant {
    PermissionGrant::parse(value).unwrap()
}

/// The grants in the order of a grant set.
fn sorted(mut grants: Vec<PermissionGrant>) -> Vec<PermissionGrant> {
    grants.sort();
    grants
}

fn parts(kind: RoleKind, current: i64) -> RoleParts {
    RoleParts {
        id: role_id(),
        name: name("Billing"),
        description: Some(description("Manages invoices.")),
        kind,
        grants: grants(&["gql:billing:Query.invoices", "rest:billing:GET /invoices"]),
        version: version(current),
        created_at: at(10),
        updated_at: at(20),
        deleted_at: None,
    }
}

fn stored(kind: RoleKind, current: i64) -> Role {
    Role::restore(parts(kind, current))
}

/// The single event the role recorded, downcast to its type.
fn single_event<E: DomainEvent + Clone>(role: &mut Role) -> E {
    let events = role.pull_domain_events();
    assert_eq!(events.len(), 1);
    let event: &dyn Any = events[0].as_ref();
    event.downcast_ref::<E>().unwrap().clone()
}

#[test]
fn valid_fields_are_kept() {
    let fields =
        RoleFields::new("Billing".to_owned(), Some("Manages invoices.".to_owned())).unwrap();

    assert_eq!(fields.name(), &name("Billing"));
    assert_eq!(
        fields.description(),
        Some(&description("Manages invoices."))
    );
    assert_eq!(
        RoleFields::new("Billing".to_owned(), None)
            .unwrap()
            .description(),
        None
    );
}

#[rstest]
#[case::empty_name(String::new(), None, vec![InvalidRole::NameLength])]
#[case::long_name("a".repeat(101), None, vec![InvalidRole::NameLength])]
#[case::control_character("Bill\u{7}ing".to_owned(), None, vec![InvalidRole::NameControlCharacter])]
#[case::long_description(
    "Billing".to_owned(),
    Some("d".repeat(1_001)),
    vec![InvalidRole::DescriptionLength]
)]
#[case::every_property(
    String::new(),
    Some("d".repeat(1_001)),
    vec![InvalidRole::NameLength, InvalidRole::DescriptionLength]
)]
fn invalid_fields_report_each_violation(
    #[case] name: String,
    #[case] description: Option<String>,
    #[case] expected: Vec<InvalidRole>,
) {
    let violations = RoleFields::new(name, description).unwrap_err();

    assert_eq!(violations, expected);
    let paths: Vec<(&str, &str)> = violations
        .iter()
        .map(|violation| (violation.property_path(), violation.code()))
        .collect();
    let expected_paths: Vec<(&str, &str)> = expected
        .iter()
        .map(|violation| (violation.property_path(), violation.code()))
        .collect();
    assert_eq!(paths, expected_paths);
}

#[test]
fn a_created_role_is_custom_without_grants_at_version_one_with_one_event() {
    let fields =
        RoleFields::new("Billing".to_owned(), Some("Manages invoices.".to_owned())).unwrap();

    let mut role = Role::create(role_id(), fields, stamp(100));

    assert_eq!(
        role.parts(),
        &RoleParts {
            id: role_id(),
            name: name("Billing"),
            description: Some(description("Manages invoices.")),
            kind: RoleKind::Custom,
            grants: PermissionGrantSet::default(),
            version: EntityVersion::INITIAL,
            created_at: at(100),
            updated_at: at(100),
            deleted_at: None,
        }
    );
    let event: RoleCreated = single_event(&mut role);
    assert_eq!(
        event,
        RoleCreated {
            event_id: stamp(100).event_id,
            role_id: role_id(),
            version: EntityVersion::INITIAL,
            name: name("Billing"),
            kind: RoleKind::Custom,
            actor: stamp(100).actor,
            occurred_at: at(100),
        }
    );
    assert!(role.pull_domain_events().is_empty());
}

#[test]
fn a_restored_role_keeps_its_state_and_records_no_event() {
    let mut role = stored(RoleKind::System, 7);

    assert_eq!(role.parts(), &parts(RoleKind::System, 7));
    assert!(role.pull_domain_events().is_empty());
}

#[test]
fn an_update_changes_the_name_and_the_description() {
    let mut role = stored(RoleKind::Custom, 3);
    let patch = RolePatch {
        name: Some(name("Invoicing")),
        description: RoleDescriptionChange::Remove,
    };

    role.update(Some(version(3)), patch, stamp(200)).unwrap();

    let expected = RoleParts {
        name: name("Invoicing"),
        description: None,
        version: version(4),
        updated_at: at(200),
        ..parts(RoleKind::Custom, 3)
    };
    assert_eq!(role.parts(), &expected);
    let event: RoleUpdated = single_event(&mut role);
    assert_eq!(
        event,
        RoleUpdated {
            event_id: stamp(200).event_id,
            role_id: role_id(),
            version: version(4),
            name: Some(name("Invoicing")),
            changed_fields: vec!["name", "description"],
            actor: stamp(200).actor,
            occurred_at: at(200),
        }
    );
}

#[test]
fn an_update_of_the_description_alone_keeps_the_name() {
    let mut role = stored(RoleKind::Custom, 1);
    let patch = RolePatch {
        name: None,
        description: RoleDescriptionChange::Set(description("Reads payments.")),
    };

    role.update(Some(version(1)), patch, stamp(300)).unwrap();

    assert_eq!(role.parts().name, name("Billing"));
    assert_eq!(
        role.parts().description,
        Some(description("Reads payments."))
    );
    let event: RoleUpdated = single_event(&mut role);
    assert_eq!(event.name, None);
    assert_eq!(event.changed_fields, vec!["description"]);
    assert_eq!(event.version, version(2));
}

#[test]
fn an_empty_update_still_takes_the_next_version() {
    let mut role = stored(RoleKind::Custom, 1);

    role.update(Some(version(1)), RolePatch::default(), stamp(300))
        .unwrap();

    assert_eq!(role.parts().version, version(2));
    assert_eq!(
        role.parts().description,
        Some(description("Manages invoices."))
    );
    let event: RoleUpdated = single_event(&mut role);
    assert_eq!(event.changed_fields, Vec::<&str>::new());
}

#[test]
fn a_deletion_marks_the_role_deleted_and_counts_the_revoked_assignments() {
    let mut role = stored(RoleKind::Custom, 5);

    role.delete(Some(version(5)), 12, stamp(400)).unwrap();

    let expected = RoleParts {
        version: version(6),
        updated_at: at(400),
        deleted_at: Some(at(400)),
        ..parts(RoleKind::Custom, 5)
    };
    assert_eq!(role.parts(), &expected);
    let event: RoleDeleted = single_event(&mut role);
    assert_eq!(
        event,
        RoleDeleted {
            event_id: stamp(400).event_id,
            role_id: role_id(),
            version: version(6),
            name: name("Billing"),
            revoked_assignments: 12,
            actor: stamp(400).actor,
            occurred_at: at(400),
        }
    );
}

#[test]
fn a_grant_replacement_records_the_added_and_removed_grants_and_takes_the_next_version() {
    let mut role = stored(RoleKind::Custom, 2);
    let replacement = grants(&[
        "rest:billing:GET /invoices",
        "rest:payments:*",
        "gql:billing:Query.payments",
    ]);

    role.replace_permissions(Some(version(2)), replacement.clone(), stamp(500))
        .unwrap();

    assert_eq!(role.parts().grants, replacement);
    assert_eq!(role.parts().version, version(3));
    assert_eq!(role.parts().updated_at, at(500));
    let event: RolePermissionsChanged = single_event(&mut role);
    assert_eq!(
        event,
        RolePermissionsChanged {
            event_id: stamp(500).event_id,
            role_id: role_id(),
            version: version(3),
            added: sorted(vec![
                grant("rest:payments:*"),
                grant("gql:billing:Query.payments")
            ]),
            removed: vec![grant("gql:billing:Query.invoices")],
            actor: stamp(500).actor,
            occurred_at: at(500),
        }
    );
}

#[test]
fn a_system_role_accepts_a_grant_replacement() {
    let mut role = stored(RoleKind::System, 1);

    role.replace_permissions(Some(version(1)), PermissionGrantSet::default(), stamp(600))
        .unwrap();

    assert!(role.parts().grants.is_empty());
    let event: RolePermissionsChanged = single_event(&mut role);
    assert_eq!(event.added, Vec::<PermissionGrant>::new());
    assert_eq!(event.removed.len(), 2);
}

/// Every change of the aggregate, applied with the given expected version.
#[derive(Debug, Clone, Copy)]
enum Change {
    Update,
    Delete,
    ReplaceGrants,
}

fn apply(
    role: &mut Role,
    change: Change,
    expected: Option<EntityVersion>,
) -> Result<(), RoleChangeRefused> {
    match change {
        Change::Update => role.update(
            expected,
            RolePatch {
                name: Some(name("Invoicing")),
                description: RoleDescriptionChange::Keep,
            },
            stamp(900),
        ),
        Change::Delete => role.delete(expected, 0, stamp(900)),
        Change::ReplaceGrants => role.replace_permissions(expected, grants(&[]), stamp(900)),
    }
}

#[rstest]
#[case::rename(Change::Update)]
#[case::deletion(Change::Delete)]
fn a_system_role_refuses_a_rename_and_a_deletion(#[case] change: Change) {
    let mut role = stored(RoleKind::System, 1);

    let refused = apply(&mut role, change, Some(version(1)));

    assert_eq!(refused, Err(RoleChangeRefused::SystemRole));
    assert_eq!(refused.unwrap_err().code(), "system_role");
    assert_eq!(role.parts(), &parts(RoleKind::System, 1));
    assert!(role.pull_domain_events().is_empty());
}

#[rstest]
#[case::update(Change::Update)]
#[case::deletion(Change::Delete)]
#[case::grant_replacement(Change::ReplaceGrants)]
fn a_stale_version_is_refused_without_an_event(#[case] change: Change) {
    let mut role = stored(RoleKind::Custom, 4);

    let refused = apply(&mut role, change, Some(version(3)));

    assert_eq!(
        refused,
        Err(RoleChangeRefused::Version(VersionConflict::Stale {
            expected: version(3),
            current: version(4),
        }))
    );
    assert_eq!(role.parts(), &parts(RoleKind::Custom, 4));
    assert!(role.pull_domain_events().is_empty());
}

#[rstest]
#[case::update(Change::Update)]
#[case::deletion(Change::Delete)]
#[case::grant_replacement(Change::ReplaceGrants)]
fn a_missing_version_is_refused_without_an_event(#[case] change: Change) {
    let mut role = stored(RoleKind::Custom, 4);

    let refused = apply(&mut role, change, None);

    assert_eq!(
        refused,
        Err(RoleChangeRefused::Version(VersionConflict::Missing))
    );
    assert!(role.pull_domain_events().is_empty());
}

#[rstest]
#[case::update(Change::Update)]
#[case::deletion(Change::Delete)]
#[case::grant_replacement(Change::ReplaceGrants)]
fn a_deleted_role_refuses_every_change(#[case] change: Change) {
    let mut role = Role::restore(RoleParts {
        deleted_at: Some(at(30)),
        ..parts(RoleKind::Custom, 2)
    });

    let refused = apply(&mut role, change, Some(version(2)));

    assert_eq!(refused, Err(RoleChangeRefused::Deleted));
    assert_eq!(role.parts().version, version(2));
    assert!(role.pull_domain_events().is_empty());
}

#[rstest]
#[case::update(Change::Update)]
#[case::deletion(Change::Delete)]
#[case::grant_replacement(Change::ReplaceGrants)]
fn the_largest_version_cannot_be_increased(#[case] change: Change) {
    let mut role = stored(RoleKind::Custom, i64::MAX);

    let refused = apply(&mut role, change, Some(version(i64::MAX)));

    assert_eq!(
        refused,
        Err(RoleChangeRefused::Invalid(
            InvalidIamValue::EntityVersionRange
        ))
    );
    assert_eq!(role.parts(), &parts(RoleKind::Custom, i64::MAX));
    assert!(role.pull_domain_events().is_empty());
}

/// An event that is not one of the four events of a role.
#[derive(Debug)]
struct Foreign;

impl DomainEvent for Foreign {
    fn event_id(&self) -> Uuid {
        Uuid::parse(EVENT).unwrap()
    }

    fn aggregate_id(&self) -> Uuid {
        Uuid::parse(ROLE).unwrap()
    }

    fn occurred_at(&self) -> SystemTime {
        at(1)
    }

    fn event_name(&self) -> &'static str {
        "iam.foreign.happened"
    }
}

#[test]
fn the_events_of_each_change_are_pulled_as_envelopes_in_recording_order() {
    let mut role = stored(RoleKind::Custom, 1);
    role.update(
        Some(version(1)),
        RolePatch {
            name: Some(name("Finance")),
            description: RoleDescriptionChange::Keep,
        },
        stamp(30),
    )
    .unwrap();
    role.replace_permissions(
        Some(version(2)),
        grants(&["rest:billing:GET /invoices"]),
        stamp(40),
    )
    .unwrap();
    role.delete(Some(version(3)), 2, stamp(50)).unwrap();

    let envelopes = role.pull_envelopes().unwrap();

    let types: Vec<&str> = envelopes
        .iter()
        .map(|envelope| envelope.parts().event_type.as_str())
        .collect();
    assert_eq!(
        types,
        [
            "iam.role.updated",
            "iam.role_permissions.changed",
            "iam.role.deleted"
        ]
    );
    assert_eq!(role.pull_envelopes().unwrap(), Vec::<EventEnvelope>::new());
}

#[test]
fn a_created_role_is_pulled_as_one_created_envelope_of_its_aggregate() {
    let fields = RoleFields::new("Billing".to_owned(), None).unwrap();
    let mut role = Role::create(role_id(), fields, stamp(100));

    let envelopes = role.pull_envelopes().unwrap();

    assert_eq!(envelopes.len(), 1);
    let parts = envelopes[0].parts();
    assert_eq!(parts.event_type.as_str(), "iam.role.created");
    assert_eq!(parts.id, stamp(100).event_id);
    assert_eq!(parts.aggregate_id, role_id().as_uuid());
    assert_eq!(parts.entity_version, Some(EntityVersion::INITIAL));
    assert_eq!(parts.actor, stamp(100).actor);
}

#[test]
fn an_event_that_a_role_does_not_record_is_refused() {
    let mut role = stored(RoleKind::Custom, 1);
    role.recorded_events().record(Foreign);

    let refused = role.pull_envelopes();

    assert_eq!(refused, Err(InvalidEventEnvelope::EventType));
}
