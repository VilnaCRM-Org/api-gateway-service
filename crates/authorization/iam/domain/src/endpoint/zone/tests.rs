use rstest::rstest;

use super::{InvalidZone, Zone};

#[rstest]
#[case("eu-central-1a")]
#[case("zone_b.1")]
#[case("a")]
fn a_zone_label_is_accepted(#[case] text: &str) {
    let zone = Zone::new(text).unwrap();

    assert_eq!(zone.as_str(), text);
    assert_eq!(zone.to_string(), text);
}

#[rstest]
#[case("")]
#[case(&"z".repeat(64))]
#[case("zone a")]
#[case("zöne")]
#[case("zone/a")]
fn an_invalid_zone_label_is_refused(#[case] text: &str) {
    assert_eq!(Zone::new(text), Err(InvalidZone));
}

#[test]
fn the_longest_zone_label_is_accepted() {
    assert!(Zone::new(&"z".repeat(63)).is_ok());
}

#[test]
fn the_refusal_names_the_rule() {
    assert!(InvalidZone.to_string().contains("1 to 63"));
}
