use iam_domain::RequestDigester as _;

use super::FakeRequestDigester;

#[test]
fn equal_texts_give_equal_digests() {
    assert_eq!(
        FakeRequestDigester.digest("role.create:(\"a\", None)"),
        FakeRequestDigester.digest("role.create:(\"a\", None)")
    );
}

#[test]
fn different_texts_give_different_digests_even_beyond_the_digest_length() {
    let long = "x".repeat(100);
    let longer = format!("{long}y");

    assert_ne!(
        FakeRequestDigester.digest("a"),
        FakeRequestDigester.digest("b")
    );
    assert_ne!(
        FakeRequestDigester.digest("a"),
        FakeRequestDigester.digest("")
    );
    assert_ne!(
        FakeRequestDigester.digest(&long),
        FakeRequestDigester.digest(&longer)
    );
}
