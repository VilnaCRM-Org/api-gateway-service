use rstest::rstest;

use super::EventType;
use crate::error::InvalidEventEnvelope;

#[rstest]
#[case("iam.role.created")]
#[case("iam.user_role.assigned")]
#[case("iam.role_permissions.changed")]
#[case("iam.user_tokens.cut_off")]
#[case("iam.security_audit.anchored")]
#[case("iam.route-configuration.applied")]
#[case("iam.v2.role.created")]
fn accepts_the_catalogue_types(#[case] value: &str) {
    let event_type = EventType::new(value).unwrap();

    assert_eq!(event_type.as_str(), value);
    assert_eq!(event_type.to_string(), value);
}

#[rstest]
#[case::empty("")]
#[case::other_prefix("user.session.revoked")]
#[case::two_words("iam.role")]
#[case::upper_case("iam.Role.created")]
#[case::empty_word("iam..created")]
#[case::trailing_separator("iam.role.created.")]
#[case::double_separator("iam.role__x.created")]
#[case::space("iam.role.created now")]
#[case::non_ascii("iam.rôle.created")]
fn rejects_a_text_outside_the_pattern(#[case] value: &str) {
    assert_eq!(EventType::new(value), Err(InvalidEventEnvelope::EventType));
}

#[test]
fn accepts_100_characters_and_rejects_101() {
    let longest = format!("iam.role.{}", "a".repeat(91));
    let longer = format!("{longest}a");

    assert_eq!(EventType::new(&longest).unwrap().as_str().len(), 100);
    assert_eq!(
        EventType::new(&longer),
        Err(InvalidEventEnvelope::EventType)
    );
}
