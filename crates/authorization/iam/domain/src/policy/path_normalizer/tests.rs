use proptest::collection::vec;
use proptest::prelude::{Strategy, any};
use rstest::rstest;

use super::{MalformedPath, PathNormalizer};
use crate::value_object::decision_reason::DecisionReason;

fn normalized(target: &str) -> String {
    PathNormalizer::normalize(target).unwrap().to_string()
}

#[rstest]
#[case("/", "/")]
#[case("//", "/")]
#[case("/api/roles", "/api/roles")]
#[case("//api///roles//", "/api/roles")]
#[case("/api/roles/", "/api/roles")]
#[case("/api/roles?limit=5", "/api/roles")]
#[case("/api/roles/?limit=5&x=%zz", "/api/roles")]
#[case("/?q=1", "/")]
#[case("/api/a%20b", "/api/a b")]
#[case("/api/%C3%A9", "/api/é")]
#[case("/api/%c3%a9", "/api/é")]
#[case("/api/%7Bid%7D", "/api/{id}")]
#[case("/api/%3Fx", "/api/?x")]
#[case("/api/%E2%82%AC", "/api/€")]
fn yields_the_single_leading_slash_form(#[case] target: &str, #[case] expected: &str) {
    assert_eq!(normalized(target), expected);
}

#[rstest]
#[case("")]
#[case("api/roles")]
#[case("?x=/api")]
fn refuses_a_path_without_a_leading_slash(#[case] target: &str) {
    assert_eq!(
        PathNormalizer::normalize(target),
        Err(MalformedPath::MissingLeadingSlash)
    );
}

#[rstest]
#[case("/.")]
#[case("/..")]
#[case("/api/./roles")]
#[case("/api/../roles")]
#[case("/api/roles/..")]
#[case("/api/%2e/roles")]
#[case("/api/%2E%2E/roles")]
#[case("/api/.%2e/roles")]
fn refuses_dot_segments_plain_or_encoded(#[case] target: &str) {
    let result = PathNormalizer::normalize(target);

    assert_eq!(result, Err(MalformedPath::DotSegment));
    assert_eq!(
        DecisionReason::from(result.unwrap_err()),
        DecisionReason::MalformedOperation
    );
}

#[rstest]
#[case("/api/a%2Fb")]
#[case("/api/a%2fb")]
#[case("/api/a\\b")]
#[case("/api/a%5Cb")]
#[case("/api/a%00b")]
#[case("/api/a\0b")]
#[case("/api/a%0Ab")]
#[case("/api/%252e%252e/roles")]
#[case("/api/%252F")]
#[case("/api/%25")]
fn refuses_a_slash_backslash_nul_control_or_residual_percent(#[case] target: &str) {
    let result = PathNormalizer::normalize(target);

    assert_eq!(result, Err(MalformedPath::ForbiddenCharacter));
    assert_eq!(
        DecisionReason::from(result.unwrap_err()),
        DecisionReason::MalformedOperation
    );
}

#[rstest]
#[case("/api/%")]
#[case("/api/%2")]
#[case("/api/%zz")]
#[case("/api/%G0")]
#[case("/api/%FF")]
#[case("/api/%C3")]
fn refuses_a_broken_escape_or_non_utf8_bytes(#[case] target: &str) {
    assert_eq!(
        PathNormalizer::normalize(target),
        Err(MalformedPath::InvalidEncoding)
    );
}

#[test]
fn accepts_two_thousand_and_forty_eight_bytes_and_refuses_one_more() {
    let limit = format!("/{}", "a".repeat(PathNormalizer::MAX_BYTES - 1));
    let over = format!("/{}", "a".repeat(PathNormalizer::MAX_BYTES));

    assert_eq!(
        PathNormalizer::normalize(&limit).unwrap().segments().len(),
        1
    );
    assert_eq!(
        PathNormalizer::normalize(&over),
        Err(MalformedPath::TooLong)
    );
}

#[test]
fn the_query_does_not_count_towards_the_length() {
    let target = format!("/a?{}", "q".repeat(PathNormalizer::MAX_BYTES * 2));

    assert_eq!(normalized(&target), "/a");
}

#[test]
fn every_error_prints_a_message() {
    for error in [
        MalformedPath::MissingLeadingSlash,
        MalformedPath::TooLong,
        MalformedPath::InvalidEncoding,
        MalformedPath::DotSegment,
        MalformedPath::ForbiddenCharacter,
    ] {
        assert_ne!(error.to_string(), "");
    }
}

/// Independent percent-decoder of the tests: decodes every `%XX` once.
fn decode_once(text: &str) -> String {
    let mut decoded = Vec::new();
    let mut bytes = text.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let hex: String = [bytes.next().unwrap(), bytes.next().unwrap()]
                .into_iter()
                .map(char::from)
                .collect();
            decoded.push(u8::from_str_radix(&hex, 16).unwrap());
        } else {
            decoded.push(byte);
        }
    }
    String::from_utf8(decoded).unwrap()
}

fn escape_all(segment: &str, lower: bool) -> String {
    segment
        .bytes()
        .map(|byte| {
            if lower {
                format!("%{byte:02x}")
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

fn segments() -> impl Strategy<Value = Vec<String>> {
    vec("[a-zA-Z0-9 _.~!$&'()*+,;=:@{}é€-]{1,6}", 0..6).prop_map(|list| {
        list.into_iter()
            .filter(|s| s.as_str() != "." && s.as_str() != "..")
            .collect()
    })
}

proptest::proptest! {
    #[test]
    fn normalisation_is_idempotent_on_the_canonical_form(
        list in segments(),
        lower in any::<bool>(),
        query in "[a-z0-9=&%]{0,8}",
    ) {
        let raw = format!(
            "//{}/?{query}",
            list.iter().map(|s| escape_all(s, lower)).collect::<Vec<_>>().join("//"),
        );

        let first = PathNormalizer::normalize(&raw).unwrap();
        let again = PathNormalizer::normalize(first.canonical().as_str()).unwrap();

        proptest::prop_assert_eq!(first.segments(), list.as_slice());
        proptest::prop_assert_eq!(&again, &first);
        proptest::prop_assert_eq!(again.canonical(), first.canonical());
    }

    #[test]
    fn decoding_the_canonical_path_once_returns_the_matched_path(list in segments()) {
        let raw = format!("/{}", list.join("/"));

        let first = PathNormalizer::normalize(&raw).unwrap();
        let canonical = first.canonical();

        proptest::prop_assert_eq!(decode_once(canonical.as_str()), first.to_string());
    }

    #[test]
    fn arbitrary_text_never_panics_and_accepted_text_is_stable(target in "\\PC{0,60}") {
        if let Ok(first) = PathNormalizer::normalize(&target) {
            let again = PathNormalizer::normalize(first.canonical().as_str());

            proptest::prop_assert_eq!(again, Ok(first));
        }
    }
}
