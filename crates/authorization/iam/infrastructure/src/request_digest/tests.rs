use iam_domain::RequestDigester as _;

use super::Sha256RequestDigester;

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .concat()
}

#[test]
fn the_digest_is_the_sha256_of_the_text() {
    let empty = Sha256RequestDigester.digest("");
    let abc = Sha256RequestDigester.digest("abc");

    assert_eq!(
        hex(empty.as_bytes()),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        hex(abc.as_bytes()),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn equal_texts_have_equal_digests_and_different_texts_different_ones() {
    let digester = Sha256RequestDigester;

    assert_eq!(
        digester.digest("role.create:(\"a\", None)"),
        digester.digest("role.create:(\"a\", None)")
    );
    assert_ne!(
        digester.digest("role.create:(\"a\", None)"),
        digester.digest("role.create:(\"b\", None)")
    );
}
