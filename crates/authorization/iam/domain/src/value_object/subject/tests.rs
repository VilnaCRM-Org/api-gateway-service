use rstest::rstest;
use shared_domain::Uuid;

use super::{SubjectId, SubjectKind, SubjectRef};
use crate::error::InvalidIamValue;
use crate::value_object::service_name::ServiceName;

const USER: &str = "0190f2a8-7b3c-7d4e-8f00-123456789abc";

#[rstest]
#[case("user", SubjectKind::User)]
#[case("service", SubjectKind::Service)]
fn a_kind_round_trips_through_its_text(#[case] text: &str, #[case] kind: SubjectKind) {
    assert_eq!(SubjectKind::parse(text), Ok(kind));
    assert_eq!(kind.as_str(), text);
}

#[rstest]
#[case("")]
#[case("User")]
#[case("system")]
fn rejects_an_unknown_kind(#[case] text: &str) {
    assert_eq!(SubjectKind::parse(text), Err(InvalidIamValue::SubjectKind));
}

#[test]
fn accepts_a_user_with_a_uuid() {
    let subject = SubjectRef::new(SubjectKind::User, USER).unwrap();

    assert_eq!(subject.kind(), SubjectKind::User);
    assert_eq!(subject.id(), &SubjectId::User(Uuid::parse(USER).unwrap()));
    assert_eq!(subject.id().kind(), SubjectKind::User);
    assert_eq!(subject.id().to_string(), USER);
    assert_eq!(subject.to_string(), format!("user:{USER}"));
    assert_eq!(subject, SubjectRef::user(Uuid::parse(USER).unwrap()));
}

#[test]
fn accepts_a_service_with_a_service_name() {
    let subject = SubjectRef::new(SubjectKind::Service, "user-service").unwrap();
    let name = ServiceName::new("user-service").unwrap();

    assert_eq!(subject.kind(), SubjectKind::Service);
    assert_eq!(subject.id(), &SubjectId::Service(name.clone()));
    assert_eq!(subject.id().kind(), SubjectKind::Service);
    assert_eq!(subject.id().to_string(), "user-service");
    assert_eq!(subject.to_string(), "service:user-service");
    assert_eq!(subject, SubjectRef::service(name));
}

#[test]
fn rejects_a_user_whose_id_is_not_a_uuid() {
    assert_eq!(
        SubjectRef::new(SubjectKind::User, "user-service"),
        Err(InvalidIamValue::SubjectUserId)
    );
}

#[rstest]
#[case(USER, InvalidIamValue::ServiceNamePattern)]
#[case("Bad_Name", InvalidIamValue::ServiceNamePattern)]
#[case("", InvalidIamValue::ServiceNameLength)]
fn rejects_a_service_whose_name_is_invalid(#[case] id: &str, #[case] error: InvalidIamValue) {
    assert_eq!(SubjectRef::new(SubjectKind::Service, id), Err(error));
}
