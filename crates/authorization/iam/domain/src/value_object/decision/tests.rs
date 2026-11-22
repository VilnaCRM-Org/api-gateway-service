use super::Decision;

#[test]
fn prints_its_stable_text_form() {
    assert_eq!(Decision::Allow.as_str(), "allow");
    assert_eq!(Decision::Deny.as_str(), "deny");
    assert_eq!(Decision::Allow.to_string(), "allow");
    assert_eq!(Decision::Deny.to_string(), "deny");
}

#[test]
fn only_allow_is_an_allow() {
    assert!(Decision::Allow.is_allow());
    assert!(!Decision::Deny.is_allow());
}
