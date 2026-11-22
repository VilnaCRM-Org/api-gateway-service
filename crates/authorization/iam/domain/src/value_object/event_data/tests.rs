use rstest::rstest;

use super::{EventData, EventValue};
use crate::error::InvalidEventEnvelope;

const TOKEN: &str = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl";

fn text(value: &str) -> EventValue {
    EventValue::Text(value.to_owned())
}

#[test]
fn keeps_every_kind_of_value_in_order() {
    let nested = EventData::new().with("kind", text("user")).unwrap();

    let data = EventData::new()
        .with("roleId", text("r-1"))
        .unwrap()
        .with("expiresAt", EventValue::Null)
        .unwrap()
        .with("system", EventValue::Bool(true))
        .unwrap()
        .with("grantCount", EventValue::Integer(-3))
        .unwrap()
        .with(
            "addedKeys",
            EventValue::List(vec![text("rest:core:GET /a")]),
        )
        .unwrap()
        .with("subject", EventValue::Object(nested.clone()))
        .unwrap();

    let names: Vec<&str> = data
        .fields()
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    assert_eq!(
        names,
        [
            "roleId",
            "expiresAt",
            "system",
            "grantCount",
            "addedKeys",
            "subject"
        ]
    );
    assert_eq!(data.fields()[5].1, EventValue::Object(nested));
    assert!(data.contains("grantCount"));
    assert!(!data.contains("grantcount"));
    assert_eq!(EventData::default(), EventData::new());
}

#[rstest]
#[case::empty("")]
#[case::upper_first("RoleId")]
#[case::digit_first("1role")]
#[case::underscore("role_id")]
#[case::dash("role-id")]
#[case::too_long(&"a".repeat(65))]
fn rejects_a_name_that_is_not_lower_camel_case(#[case] name: &str) {
    assert_eq!(
        EventData::new().with(name, EventValue::Null),
        Err(InvalidEventEnvelope::FieldName)
    );
}

#[test]
fn accepts_a_name_of_64_characters() {
    let name = "a".repeat(64);

    assert!(
        EventData::new()
            .with(&name, EventValue::Null)
            .unwrap()
            .contains(&name)
    );
}

#[rstest]
#[case("token")]
#[case("accessToken")]
#[case("refreshToken")]
#[case("idToken")]
#[case("jwt")]
#[case("bearer")]
#[case("authorization")]
#[case("credential")]
#[case("credentials")]
#[case("password")]
#[case("secret")]
#[case("body")]
#[case("content")]
#[case("document")]
#[case("schema")]
#[case("sdl")]
#[case("spec")]
#[case("specBody")]
#[case("specification")]
fn rejects_the_name_of_a_credential_or_a_specification_body(#[case] name: &str) {
    assert_eq!(
        EventData::new().with(name, text("x")),
        Err(InvalidEventEnvelope::FieldForbidden)
    );
}

#[rstest]
#[case("tokensValidAfter")]
#[case("contentHash")]
#[case("specId")]
fn accepts_a_name_that_only_contains_a_forbidden_word(#[case] name: &str) {
    assert!(EventData::new().with(name, text("x")).is_ok());
}

#[test]
fn rejects_a_name_used_twice() {
    let data = EventData::new().with("roleId", text("r-1")).unwrap();

    assert_eq!(
        data.with("roleId", text("r-2")),
        Err(InvalidEventEnvelope::FieldDuplicate)
    );
}

#[rstest]
#[case::token(text(TOKEN), InvalidEventEnvelope::Credential)]
#[case::token_in_a_word(text(&format!("jwt={TOKEN}")), InvalidEventEnvelope::Credential)]
#[case::bearer(text("Bearer abc"), InvalidEventEnvelope::Credential)]
#[case::bearer_lower(text("bearer abc"), InvalidEventEnvelope::Credential)]
#[case::token_in_a_list(
    EventValue::List(vec![text("ok"), text(TOKEN)]),
    InvalidEventEnvelope::Credential
)]
#[case::nested_list(
    EventValue::List(vec![EventValue::List(vec![text(TOKEN)])]),
    InvalidEventEnvelope::Credential
)]
#[case::specification(
    text("openapi: 3.1.0\ninfo:\n  title: core"),
    InvalidEventEnvelope::ControlCharacter
)]
#[case::tab(text("a\tb"), InvalidEventEnvelope::ControlCharacter)]
fn rejects_a_text_with_a_credential_or_a_control_character(
    #[case] value: EventValue,
    #[case] error: InvalidEventEnvelope,
) {
    assert_eq!(EventData::new().with("value", value), Err(error));
}

#[rstest]
#[case(text(""))]
#[case(text("bear"))]
#[case(text("bearers of rôles"))]
#[case(text("abc.def.ghi"))]
#[case(EventValue::List(vec![]))]
fn accepts_a_text_without_a_credential(#[case] value: EventValue) {
    assert!(EventData::new().with("value", value).is_ok());
}
