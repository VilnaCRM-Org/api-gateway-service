use proptest::prelude::{Just, Strategy, prop_assert, prop_oneof, proptest};
use rstest::rstest;

use super::{PathPattern, PathSegment};
use crate::error::InvalidRoute;

fn pattern(text: &str) -> PathPattern {
    PathPattern::new(text).unwrap()
}

#[test]
fn segments_are_literals_parameters_and_a_catch_all() {
    let parsed = pattern("/api/orders/{id}/{rest:*}");

    assert_eq!(parsed.as_str(), "/api/orders/{id}/{rest:*}");
    assert_eq!(parsed.to_string(), "/api/orders/{id}/{rest:*}");
    assert_eq!(
        parsed.segments(),
        [
            PathSegment::Literal("api".to_owned()),
            PathSegment::Literal("orders".to_owned()),
            PathSegment::Parameter("id".to_owned()),
            PathSegment::CatchAll("rest".to_owned()),
        ]
    );
}

#[test]
fn the_root_has_no_segments() {
    assert_eq!(pattern("/").segments().len(), 0);
}

#[rstest]
#[case("", InvalidRoute::PathPrefix)]
#[case("api", InvalidRoute::PathPrefix)]
#[case("/api//orders", InvalidRoute::PathFormat)]
#[case("/api/", InvalidRoute::PathFormat)]
#[case("/api/{Id}", InvalidRoute::PathFormat)]
#[case("/api/{}", InvalidRoute::PathFormat)]
#[case("/api/{id", InvalidRoute::PathFormat)]
#[case("/api/a{id}", InvalidRoute::PathFormat)]
#[case("/api/{rest:*}/more", InvalidRoute::PathFormat)]
#[case("/api/white space", InvalidRoute::PathFormat)]
fn an_invalid_pattern_is_refused(#[case] text: &str, #[case] expected: InvalidRoute) {
    assert_eq!(PathPattern::new(text), Err(expected));
}

#[test]
fn a_pattern_has_at_most_2048_characters() {
    let longest = format!("/{}", "a".repeat(PathPattern::MAX_LENGTH - 1));

    assert!(PathPattern::new(&longest).is_ok());
    assert_eq!(
        PathPattern::new(&format!("{longest}a")),
        Err(InvalidRoute::PathFormat)
    );
}

#[rstest]
#[case("/api/orders", "/api/orders", true)]
#[case("/api/{id}", "/api/{name}", true)]
#[case("/api/{rest:*}", "/api/{other:*}", true)]
#[case("/api/orders", "/api/{id}", false)]
#[case("/api/{id}", "/api/orders", false)]
#[case("/api/orders", "/api/orders/{id}", false)]
#[case("/api/{id}", "/api/{rest:*}", false)]
fn shapes_ignore_parameter_names(#[case] left: &str, #[case] right: &str, #[case] same: bool) {
    assert_eq!(pattern(left).same_shape(&pattern(right)), same);
}

#[rstest]
#[case("/api/{rest:*}", "/api/orders", true)]
#[case("/api/{rest:*}", "/api/orders/{id}", true)]
#[case("/api/{rest:*}", "/api/{other:*}", true)]
#[case("/api/{rest:*}", "/api", false)]
#[case("/api/{rest:*}", "/other/orders", false)]
#[case("/api/{id}", "/api/orders", true)]
#[case("/api/{id}", "/api/{rest:*}", false)]
#[case("/api/{id}", "/api/orders/more", false)]
#[case("/api/orders", "/api/{id}", false)]
#[case("/api/orders", "/api/orders", true)]
#[case("/api/orders", "/api/orders/more", false)]
#[case("/api/orders/more", "/api/orders", false)]
#[case("/", "/", true)]
#[case("/{rest:*}", "/api", true)]
fn covering_follows_what_each_pattern_matches(
    #[case] broad: &str,
    #[case] narrow: &str,
    #[case] covers: bool,
) {
    assert_eq!(pattern(broad).covers(&pattern(narrow)), covers);
}

#[rstest]
#[case("/api/{rest:*}", "/api/orders", true)]
#[case("/api/{id}", "/api/orders", true)]
#[case("/api/orders", "/api/orders", false)]
#[case("/api/{id}", "/api/{name}", false)]
#[case("/api/orders", "/api/{id}", false)]
fn broader_means_covering_with_another_shape(
    #[case] broad: &str,
    #[case] narrow: &str,
    #[case] broader: bool,
) {
    assert_eq!(pattern(broad).is_broader_than(&pattern(narrow)), broader);
}

fn segment() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("a".to_owned()),
        Just("b".to_owned()),
        Just("{id}".to_owned()),
    ]
}

proptest! {
    #[test]
    fn every_pattern_covers_itself(segments in proptest::collection::vec(segment(), 0..5)) {
        let text = format!("/{}", segments.join("/"));
        let parsed = pattern(&text);

        prop_assert!(parsed.covers(&parsed));
        prop_assert!(!parsed.is_broader_than(&parsed));
    }

    #[test]
    fn a_catch_all_covers_every_longer_path(
        prefix in proptest::collection::vec(segment(), 0..3),
        tail in proptest::collection::vec(segment(), 1..3),
    ) {
        let broad = pattern(&format!("/{}/{{rest:*}}", prefix.join("/")).replace("//", "/"));
        let narrow = pattern(&format!("/{}/{}", prefix.join("/"), tail.join("/")).replace("//", "/"));

        prop_assert!(broad.covers(&narrow));
    }
}
