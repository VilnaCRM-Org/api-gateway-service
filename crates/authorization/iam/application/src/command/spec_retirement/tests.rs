use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, ChangeId, GrantRecord, GrantStatus, PermissionCatalogue, PermissionFlags,
    PermissionKey, PermissionKeyKind, PolicyVersion, RoleId, ServiceName, SpecId, SpecStatus,
};
use shared_domain::Uuid;
use test_support::id::SequenceUuidGenerator;

use super::{Retirement, RetirementChange, StoredEntry, plan_retirement, retirement_change};
use crate::error::{Confirmation, IamError};

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap()
}

fn service() -> ServiceName {
    ServiceName::new("billing").unwrap()
}

fn key(text: &str) -> PermissionKey {
    PermissionKey::parse(text).unwrap()
}

fn role(number: u8) -> RoleId {
    RoleId::parse(&format!("0190f2a8-7b3c-7d4e-8f11-1234567890{number:02x}")).unwrap()
}

fn stored(text: &str, active: bool) -> StoredEntry {
    StoredEntry {
        key: key(text),
        flags: PermissionFlags::NONE,
        active,
    }
}

fn retirement(confirm_orphans: bool) -> Retirement {
    Retirement {
        kind: PermissionKeyKind::Rest,
        spec_id: SpecId::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ad").unwrap(),
        service: service(),
        activated_at: Some(at()),
        previous: PermissionCatalogue::empty(service(), PermissionKeyKind::Rest),
        next: PermissionCatalogue::empty(service(), PermissionKeyKind::Rest),
        stored: vec![stored("rest:billing:GET /invoices", true)],
        grants: vec![GrantRecord {
            role: role(1),
            key: key("rest:billing:GET /invoices"),
            status: GrantStatus::Active,
        }],
        confirm_orphans,
        at: at(),
    }
}

#[test]
fn a_grant_of_a_key_that_leaves_the_catalogue_needs_the_confirmation() {
    let error = plan_retirement(retirement(false)).err().unwrap();

    assert!(matches!(
        error,
        IamError::ConfirmationRequired(Confirmation::Orphans, _)
    ));
}

#[test]
fn a_confirmed_retirement_moves_the_version_to_retired_and_orphans_the_grant() {
    let plan = plan_retirement(retirement(true)).unwrap();

    let parts = plan.statement.parts();
    assert_eq!(parts.transition.from, SpecStatus::Active);
    assert_eq!(parts.transition.to, SpecStatus::Retired);
    assert_eq!(parts.transition.retired_at, Some(at()));
    assert_eq!(parts.orphaned.len(), 1);
    assert_eq!(plan.activation.orphaned_grants.len(), 1);
    assert_eq!(parts.deactivated, [key("rest:billing:GET /invoices")]);
}

#[test]
fn an_entry_that_is_inactive_already_is_not_deactivated_again() {
    let mut input = retirement(true);
    input.stored = vec![stored("rest:billing:GET /invoices", false)];

    let plan = plan_retirement(input).unwrap();

    assert_eq!(plan.statement.parts().deactivated.len(), 0);
}

#[test]
fn a_retirement_dated_before_1970_cannot_be_audited_and_builds_no_change() {
    let mut input = retirement(true);
    input.grants = Vec::new();
    let plan = plan_retirement(input).unwrap();
    let before_1970 = SystemTime::UNIX_EPOCH
        .checked_sub(Duration::from_secs(1))
        .unwrap();

    let error = retirement_change(RetirementChange {
        change_id: ChangeId::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ac").unwrap(),
        actor: ActorRef::User(Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap()),
        locked: PolicyVersion::new(0).unwrap(),
        idempotency: None,
        spec_events: Vec::new(),
        plan,
        action: "openapi_spec.retire",
        target_type: "openapi_spec",
        spec_id: SpecId::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ad").unwrap(),
        service: service(),
        at: before_1970,
        uuid_generator: &SequenceUuidGenerator::starting_at(1),
    })
    .err()
    .unwrap();

    assert!(matches!(error, IamError::Internal(_)), "{error:?}");
}
