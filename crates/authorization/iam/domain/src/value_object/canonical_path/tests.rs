use rstest::rstest;

use super::CanonicalPath;

fn encode(segments: &[&str]) -> CanonicalPath {
    let owned: Vec<String> = segments
        .iter()
        .map(|segment| (*segment).to_owned())
        .collect();
    CanonicalPath::encode(&owned)
}

#[rstest]
#[case(&[], "/")]
#[case(&["api", "roles"], "/api/roles")]
#[case(&["a-b._~9Z"], "/a-b._~9Z")]
#[case(&["a b"], "/a%20b")]
#[case(&["?#"], "/%3F%23")]
#[case(&["é"], "/%C3%A9")]
#[case(&["{}"], "/%7B%7D")]
fn writes_every_byte_outside_the_unreserved_set_as_an_upper_case_escape(
    #[case] segments: &[&str],
    #[case] expected: &str,
) {
    let path = encode(segments);

    assert_eq!(path.as_str(), expected);
    assert_eq!(path.to_string(), expected);
}
