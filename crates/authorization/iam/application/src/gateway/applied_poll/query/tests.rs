use std::time::Duration;

use iam_domain::PolicyVersion;
use validator::Validate as _;

use super::AppliedQuery;

fn parsed(query: &str) -> AppliedQuery {
    serde_json::from_value(serde_json::Value::Object(
        query
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .map(|(key, value)| (key.to_owned(), value.parse::<i64>().unwrap().into()))
            .collect(),
    ))
    .unwrap()
}

#[test]
fn the_query_names_the_version_the_offset_and_the_wait() {
    let query = parsed("atLeast=7&offset=12&wait=2500");

    assert_eq!(query.version(), PolicyVersion::new(7).unwrap());
    assert_eq!(query.offset, 12);
    assert_eq!(query.wait(), Duration::from_millis(2500));
    assert!(query.validate().is_ok());
}

#[test]
fn a_negative_version_or_offset_is_a_violation() {
    assert!(parsed("atLeast=-1&offset=0&wait=0").validate().is_err());
    assert!(parsed("atLeast=0&offset=-1&wait=0").validate().is_err());
}
