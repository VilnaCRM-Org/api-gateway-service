use std::error::Error as _;

use super::RateLimitStoreError;

#[test]
fn an_unavailable_store_chains_its_cause() {
    let unavailable = RateLimitStoreError::Unavailable("valkey is down".into());

    assert_eq!(
        unavailable.to_string(),
        "the rate limit store is unavailable"
    );
    assert_eq!(unavailable.source().unwrap().to_string(), "valkey is down");
}
