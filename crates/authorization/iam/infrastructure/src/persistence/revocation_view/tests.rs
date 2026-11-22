use iam_domain::ServiceName;
use shared_domain::Uuid;

use super::*;

#[test]
fn a_user_subject_is_read_with_its_user_cutoff() {
    let user = Uuid::parse("0190f2a8-7b3c-7d4e-8f00-123456789abc").unwrap();

    assert_eq!(user_of(&SubjectId::User(user)), Some(user.as_uuid()));
}

#[test]
fn a_service_principal_has_no_user_cutoff() {
    let service = SubjectId::Service(ServiceName::new("user-service").unwrap());

    assert_eq!(user_of(&service), None);
}
