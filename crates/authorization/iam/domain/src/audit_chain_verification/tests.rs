use rstest::rstest;

use super::{ChainBreak, ChainBreakCause, ChainVerdict, ChainVerification};
use crate::value_object::identifier::SecurityAuditEventId;

const ID: &str = "0190f2a8-7b3c-7d4e-8f00-000000000001";

#[test]
fn a_valid_verification_reports_the_records_it_checked() {
    let verification = ChainVerification::valid(7);

    assert!(verification.is_valid());
    assert_eq!(verification.records_checked(), 7);
    assert_eq!(verification.verdict(), &ChainVerdict::Valid);
}

#[test]
fn an_invalid_verification_names_the_record_where_the_chain_breaks() {
    let id = SecurityAuditEventId::parse(ID).unwrap();
    let broken = ChainBreak::new(3, Some(id), ChainBreakCause::Digest);

    let verification = ChainVerification::invalid(3, broken);

    assert!(!verification.is_valid());
    assert_eq!(verification.records_checked(), 3);
    assert_eq!(verification.verdict(), &ChainVerdict::Invalid(broken));
    assert_eq!(broken.seq(), 3);
    assert_eq!(broken.record(), Some(id));
    assert_eq!(broken.cause(), ChainBreakCause::Digest);
}

#[test]
fn a_missing_record_has_no_id() {
    let broken = ChainBreak::new(9, None, ChainBreakCause::AnchorMissing);

    assert_eq!(broken.record(), None);
}

#[rstest]
#[case(ChainBreakCause::Gap, "gap")]
#[case(ChainBreakCause::Link, "link")]
#[case(ChainBreakCause::Digest, "digest")]
#[case(ChainBreakCause::Unreadable, "unreadable")]
#[case(ChainBreakCause::Anchor, "anchor")]
#[case(ChainBreakCause::AnchorMissing, "anchor_missing")]
fn every_cause_has_a_stable_name(#[case] cause: ChainBreakCause, #[case] name: &str) {
    assert_eq!(cause.as_str(), name);
}
