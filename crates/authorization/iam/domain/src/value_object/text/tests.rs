use rstest::rstest;

use super::{holds_token, is_visible_ascii};

#[rstest]
#[case("a", 1, true)]
#[case("abc", 3, true)]
#[case("!~", 2, true)]
#[case("abcd", 3, false)]
#[case("", 3, false)]
#[case("a b", 3, false)]
#[case("a\tb", 3, false)]
#[case("a\u{7f}", 3, false)]
#[case("é", 3, false)]
fn accepts_one_to_max_visible_ascii_bytes(
    #[case] value: &str,
    #[case] max: usize,
    #[case] expected: bool,
) {
    assert_eq!(is_visible_ascii(value, max), expected);
}

#[rstest]
#[case("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln", true)]
#[case("token=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln;", true)]
#[case("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0", false)]
#[case("eyJhbGciOiJSUzI1NiJ9..c2ln", false)]
#[case("abc.def.ghi", false)]
#[case("role=readers", false)]
fn finds_a_word_shaped_like_a_token(#[case] value: &str, #[case] expected: bool) {
    assert_eq!(holds_token(value), expected);
}
