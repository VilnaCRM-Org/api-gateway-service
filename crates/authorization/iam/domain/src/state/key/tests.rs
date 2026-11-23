use rstest::rstest;

use super::*;

const ROLE: &str = "role/0192f6a0-0000-7000-8000-000000000001";
const USER: &str = "subject/user/0192f6a0-0000-7000-8000-000000000002";
const CHUNK: &str = "catalog/user-service/1/00ff00ff00ff00ff00ff00ff00ff00ff";

#[rstest]
#[case::role(ROLE)]
#[case::user_subject(USER)]
#[case::service_subject("subject/service/billing")]
#[case::manifest("catalog/user-service/manifest")]
#[case::chunk(CHUNK)]
#[case::route("route/0192f6a0-0000-7000-8000-000000000003")]
#[case::upstream("upstream/user-service")]
#[case::rate_policy("ratepolicy/0192f6a0-0000-7000-8000-000000000004")]
#[case::session("revocation/session/abc/def-123")]
#[case::user("revocation/user/0192f6a0-0000-7000-8000-000000000005")]
#[case::global("revocation/global")]
#[case::head("__head")]
fn a_key_prints_the_text_it_was_parsed_from(#[case] text: &str) {
    let key = StateKey::parse(text).unwrap();

    assert_eq!(key.to_string(), text);
}

#[rstest]
#[case::empty("")]
#[case::unknown_kind("group/1")]
#[case::bad_uuid("role/not-a-uuid")]
#[case::bad_subject_kind("subject/robot/1")]
#[case::user_subject_without_uuid("subject/user/1")]
#[case::manifest_with_tail("catalog/user-service/manifest/extra")]
#[case::chunk_with_upper_case("catalog/user-service/1/00FF")]
#[case::chunk_without_version("catalog/user-service/abc/def/ghi")]
#[case::bad_service("catalog/User Service/manifest")]
#[case::global_with_tail("revocation/global/1")]
#[case::empty_session("revocation/session/")]
#[case::head_with_tail("__head/1")]
fn a_text_that_is_not_a_key_is_refused(#[case] text: &str) {
    let error = StateKey::parse(text).unwrap_err();

    assert_eq!(
        error,
        InvalidStateRecord::Key {
            text: text.to_owned()
        }
    );
}

#[test]
fn a_chunk_key_of_the_current_format_names_its_version() {
    let key = StateKey::chunk(
        ServiceName::new("user-service").unwrap(),
        ChunkId::new("00ff").unwrap(),
    );

    assert_eq!(key.to_string(), "catalog/user-service/1/00ff");
}

#[rstest]
#[case::empty("")]
#[case::upper_case("AB")]
#[case::not_hexadecimal("xyz")]
#[case::too_long(&"a".repeat(65))]
fn a_chunk_id_that_is_not_hexadecimal_text_is_refused(#[case] text: &str) {
    assert_eq!(ChunkId::new(text), Err(InvalidStateRecord::ChunkId));
}

#[test]
fn keys_order_by_kind_then_by_content() {
    let mut keys = [
        StateKey::Head,
        StateKey::parse(USER).unwrap(),
        StateKey::parse(ROLE).unwrap(),
    ];
    keys.sort();

    assert_eq!(keys[0].to_string(), ROLE);
    assert_eq!(keys[1].to_string(), USER);
    assert_eq!(keys[2], StateKey::Head);
}

#[test]
fn a_chunk_id_can_be_the_hexadecimal_form_of_a_digest() {
    let id = ChunkId::from_digest(PolicyDigestValue::from_bytes([0x0f; 16]));

    assert_eq!(id.as_str(), "0f".repeat(16));
    assert_eq!(ChunkId::new(id.as_str()), Ok(id));
}
