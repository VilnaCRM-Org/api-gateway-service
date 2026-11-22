use std::time::{Duration, SystemTime};

use rstest::rstest;

use super::{TokenLifetimeRule, TokenTimes};
use crate::value_object::token_rejection::TokenRejection;

const NOW: u64 = 1_800_000_000;

fn rule() -> TokenLifetimeRule {
    TokenLifetimeRule::new(Duration::from_mins(15), Duration::from_secs(30))
}

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn times(issued_at: u64, not_before: Option<u64>, expires_at: u64) -> TokenTimes {
    TokenTimes {
        issued_at,
        not_before,
        expires_at,
    }
}

#[test]
fn exposes_its_bounds() {
    assert_eq!(rule().max_lifetime(), Duration::from_mins(15));
    assert_eq!(rule().clock_skew(), Duration::from_secs(30));
}

#[rstest]
#[case::fresh(times(NOW, None, NOW + 900))]
#[case::with_nbf_now(times(NOW, Some(NOW), NOW + 600))]
#[case::lifetime_exactly_the_maximum(times(NOW - 100, None, NOW + 800))]
#[case::issued_within_the_skew_ahead(times(NOW + 30, None, NOW + 300))]
#[case::nbf_within_the_skew_ahead(times(NOW, Some(NOW + 30), NOW + 300))]
#[case::expired_within_the_skew(times(NOW - 900, None, NOW - 30))]
#[case::zero_lifetime(times(NOW, None, NOW))]
fn accepts_tokens_inside_every_bound(#[case] claims: TokenTimes) {
    assert_eq!(rule().check(claims, at(NOW)), Ok(()));
}

#[rstest]
#[case::lifetime_above_the_maximum(times(NOW, None, NOW + 901))]
#[case::exp_before_iat(times(NOW, None, NOW - 1))]
#[case::issued_beyond_the_skew_ahead(times(NOW + 31, None, NOW + 300))]
#[case::nbf_beyond_the_skew_ahead(times(NOW, Some(NOW + 31), NOW + 300))]
#[case::long_and_expired(times(NOW - 5_000, None, NOW - 1_000))]
fn rejects_a_broken_time_claim_as_invalid(#[case] claims: TokenTimes) {
    assert_eq!(rule().check(claims, at(NOW)), Err(TokenRejection::Invalid));
}

#[test]
fn rejects_an_expiry_beyond_the_skew_as_expired() {
    let claims = times(NOW - 900, None, NOW - 31);

    assert_eq!(rule().check(claims, at(NOW)), Err(TokenRejection::Expired));
}

#[test]
fn a_clock_before_the_epoch_counts_as_the_epoch() {
    let before_epoch = SystemTime::UNIX_EPOCH
        .checked_sub(Duration::from_secs(10))
        .unwrap();

    assert_eq!(rule().check(times(0, None, 60), before_epoch), Ok(()));
    assert_eq!(
        rule().check(times(31, None, 60), before_epoch),
        Err(TokenRejection::Invalid)
    );
}

#[test]
fn saturates_instead_of_overflowing() {
    let claims = times(u64::MAX - 10, None, u64::MAX);

    assert_eq!(
        rule().check(claims, at(u64::MAX >> 30)),
        Err(TokenRejection::Invalid)
    );
    let at_the_end = times(NOW, None, NOW + 1);
    let lenient = TokenLifetimeRule::new(Duration::from_mins(15), Duration::MAX);
    assert_eq!(lenient.check(at_the_end, at(NOW + 10_000)), Ok(()));
}
