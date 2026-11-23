use std::hash::{DefaultHasher, Hash as _, Hasher as _};

use rstest::rstest;

use super::{InvalidRateKey, RateKey, RateKeyParts};
use crate::port::request_digester::RequestDigester;
use crate::rate_policy::fields::RateKeyKind;
use crate::value_object::request_digest::RequestDigest;

/// A deterministic digester that is not a security hash.
#[derive(Debug)]
struct TestDigester;

impl RequestDigester for TestDigester {
    fn digest(&self, canonical: &str) -> RequestDigest {
        let mut bytes = [0_u8; RequestDigest::LENGTH];
        for (salt, chunk) in (0_u8..).zip(bytes.chunks_mut(8)) {
            let mut hasher = DefaultHasher::new();
            salt.hash(&mut hasher);
            canonical.hash(&mut hasher);
            chunk.copy_from_slice(&hasher.finish().to_be_bytes());
        }
        RequestDigest::from_bytes(bytes)
    }
}

const SUBJECT: &str = "user:0197b6c4-5d4a-7a52-8f0e-2d2f4f1c9a11";
const IP: &str = "203.0.113.77";
const ROUTE: &str = "0197b6c4-5d4a-7a52-8f0e-aaaaaaaaaaaa";

fn full() -> RateKeyParts<'static> {
    RateKeyParts {
        subject: Some(SUBJECT),
        ip: Some(IP),
        route: Some(ROUTE),
    }
}

fn key(kind: RateKeyKind, parts: &RateKeyParts<'_>) -> RateKey {
    RateKey::new(kind, parts, &TestDigester).unwrap()
}

const KINDS: [RateKeyKind; 4] = [
    RateKeyKind::Ip,
    RateKeyKind::Subject,
    RateKeyKind::SubjectRoute,
    RateKeyKind::Route,
];

#[test]
fn keys_of_different_kinds_with_the_same_parts_differ() {
    let hashes: Vec<String> = KINDS
        .iter()
        .map(|kind| key(*kind, &full()).key_hash().to_owned())
        .collect();

    for (index, hash) in hashes.iter().enumerate() {
        assert!(!hashes[..index].contains(hash));
    }
}

#[test]
fn a_key_keeps_its_kind_and_a_hex_hash_without_the_raw_values() {
    for kind in KINDS {
        let key = key(kind, &full());

        assert_eq!(key.kind(), kind);
        assert_eq!(key.key_hash().len(), 64);
        assert!(
            key.key_hash()
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        );
        for raw in [SUBJECT, IP, ROUTE] {
            assert!(!key.key_hash().contains(raw));
        }
    }
}

#[test]
fn equal_parts_give_equal_keys() {
    assert_eq!(
        key(RateKeyKind::SubjectRoute, &full()),
        key(RateKeyKind::SubjectRoute, &full())
    );
}

#[rstest]
#[case::ip_ignores_subject_and_route(RateKeyKind::Ip, RateKeyParts { ip: Some(IP), ..RateKeyParts::default() })]
#[case::subject_ignores_ip_and_route(RateKeyKind::Subject, RateKeyParts { subject: Some(SUBJECT), ..RateKeyParts::default() })]
#[case::subject_route_ignores_ip(RateKeyKind::SubjectRoute, RateKeyParts { subject: Some(SUBJECT), route: Some(ROUTE), ..RateKeyParts::default() })]
#[case::route_ignores_subject_and_ip(RateKeyKind::Route, RateKeyParts { route: Some(ROUTE), ..RateKeyParts::default() })]
fn a_kind_reads_only_the_parts_it_counts_by(
    #[case] kind: RateKeyKind,
    #[case] needed: RateKeyParts<'_>,
) {
    assert_eq!(key(kind, &needed), key(kind, &full()));
}

#[rstest]
#[case::another_ip(RateKeyKind::Ip, RateKeyParts { ip: Some("203.0.113.78"), ..full() })]
#[case::another_subject(RateKeyKind::Subject, RateKeyParts { subject: Some("user:other"), ..full() })]
#[case::another_route_for_the_pair(RateKeyKind::SubjectRoute, RateKeyParts { route: Some("other"), ..full() })]
#[case::another_subject_for_the_pair(RateKeyKind::SubjectRoute, RateKeyParts { subject: Some("user:other"), ..full() })]
#[case::another_route(RateKeyKind::Route, RateKeyParts { route: Some("other"), ..full() })]
fn a_different_part_gives_a_different_key(
    #[case] kind: RateKeyKind,
    #[case] other: RateKeyParts<'_>,
) {
    assert_ne!(key(kind, &full()), key(kind, &other));
}

#[test]
fn the_boundary_between_parts_cannot_be_shifted() {
    let left = RateKeyParts {
        subject: Some("ab"),
        route: Some("c"),
        ..RateKeyParts::default()
    };
    let right = RateKeyParts {
        subject: Some("a"),
        route: Some("bc"),
        ..RateKeyParts::default()
    };

    assert_ne!(
        key(RateKeyKind::SubjectRoute, &left),
        key(RateKeyKind::SubjectRoute, &right)
    );
}

#[rstest]
#[case(RateKeyKind::Ip, RateKeyParts { subject: Some(SUBJECT), route: Some(ROUTE), ..RateKeyParts::default() }, InvalidRateKey::Ip)]
#[case(RateKeyKind::Subject, RateKeyParts { ip: Some(IP), route: Some(ROUTE), ..RateKeyParts::default() }, InvalidRateKey::Subject)]
#[case(RateKeyKind::SubjectRoute, RateKeyParts { ip: Some(IP), route: Some(ROUTE), ..RateKeyParts::default() }, InvalidRateKey::Subject)]
#[case(RateKeyKind::SubjectRoute, RateKeyParts { subject: Some(SUBJECT), ip: Some(IP), ..RateKeyParts::default() }, InvalidRateKey::Route)]
#[case(RateKeyKind::Route, RateKeyParts { subject: Some(SUBJECT), ip: Some(IP), ..RateKeyParts::default() }, InvalidRateKey::Route)]
fn refuses_a_key_without_a_part_its_kind_counts_by(
    #[case] kind: RateKeyKind,
    #[case] parts: RateKeyParts<'_>,
    #[case] expected: InvalidRateKey,
) {
    assert_eq!(RateKey::new(kind, &parts, &TestDigester), Err(expected));
}

#[rstest]
#[case(InvalidRateKey::Ip, "a rate key of this kind needs the client address")]
#[case(
    InvalidRateKey::Subject,
    "a rate key of this kind needs the authenticated subject"
)]
#[case(InvalidRateKey::Route, "a rate key of this kind needs the route")]
fn describes_what_is_missing(#[case] error: InvalidRateKey, #[case] message: &str) {
    assert_eq!(error.to_string(), message);
}
