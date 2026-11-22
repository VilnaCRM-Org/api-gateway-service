use shared_domain::Uuid;

use super::{
    ChangeId, DecisionId, PermissionId, ProjectId, RoleId, SecurityAuditEventId,
    SessionRevocationId, SpecId, UserRoleId,
};
use crate::error::InvalidIamValue;

const TEXT: &str = "0190f2a8-7b3c-7d4e-8f00-123456789abc";

macro_rules! identifier_cases {
    ($($test:ident => $type:ident),+ $(,)?) => {
        $(
            #[test]
            fn $test() {
                let uuid = Uuid::parse(TEXT).unwrap();
                let id = $type::parse(TEXT).unwrap();

                assert_eq!(id, $type::from_uuid(uuid));
                assert_eq!(id.as_uuid(), uuid);
                assert_eq!(id.to_string(), TEXT);
                assert_eq!($type::parse("not-a-uuid"), Err(InvalidIamValue::Identifier));
                assert_eq!($type::parse(""), Err(InvalidIamValue::Identifier));
            }
        )+
    };
}

identifier_cases! {
    a_role_id_wraps_a_uuid => RoleId,
    a_user_role_id_wraps_a_uuid => UserRoleId,
    a_spec_id_wraps_a_uuid => SpecId,
    a_permission_id_wraps_a_uuid => PermissionId,
    a_decision_id_wraps_a_uuid => DecisionId,
    a_change_id_wraps_a_uuid => ChangeId,
    a_project_id_wraps_a_uuid => ProjectId,
    a_security_audit_event_id_wraps_a_uuid => SecurityAuditEventId,
    a_session_revocation_id_wraps_a_uuid => SessionRevocationId,
}

#[test]
fn identifiers_are_ordered_by_their_uuid() {
    let low = ProjectId::parse("00000000-0000-7000-8000-000000000001").unwrap();
    let high = ProjectId::parse("00000000-0000-7000-8000-000000000002").unwrap();

    assert!(low < high);
}
