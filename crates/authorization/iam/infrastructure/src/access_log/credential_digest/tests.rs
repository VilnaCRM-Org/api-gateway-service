use iam_domain::Credential;

use super::credential_digest_prefix;

#[test]
fn the_prefix_is_the_first_eight_hex_characters_of_the_sha256_digest() {
    let prefix = credential_digest_prefix(&Credential::new("abc".to_owned())).unwrap();

    assert_eq!(prefix, "ba7816bf");
}

#[test]
fn the_prefix_is_eight_lower_case_hexadecimal_characters_whatever_the_credential() {
    for raw in ["x", "a very long bearer token with spaces", "ünïcode"] {
        let prefix = credential_digest_prefix(&Credential::new(raw.to_owned())).unwrap();

        assert_eq!(prefix.len(), 8);
        assert!(
            prefix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        assert!(!raw.contains(&prefix));
    }
}

#[test]
fn different_credentials_have_different_prefixes() {
    let first = credential_digest_prefix(&Credential::new("token-1".to_owned()));
    let second = credential_digest_prefix(&Credential::new("token-2".to_owned()));

    assert_ne!(first, second);
}

#[test]
fn a_missing_or_blank_credential_has_no_prefix() {
    assert_eq!(
        credential_digest_prefix(&Credential::new(String::new())),
        None
    );
    assert_eq!(
        credential_digest_prefix(&Credential::new("  \t".to_owned())),
        None
    );
}
