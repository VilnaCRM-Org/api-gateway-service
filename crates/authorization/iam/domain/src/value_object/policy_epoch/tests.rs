use proptest::prelude::any;
use rstest::rstest;

use super::PolicyEpoch;
use crate::error::InvalidIamValue;
use crate::value_object::log_epoch::LogEpoch;
use crate::value_object::policy_digest_value::PolicyDigestValue;
use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::relay_epoch::RelayEpoch;

fn parts() -> (PolicyVersion, PolicyDigestValue, LogEpoch, RelayEpoch) {
    (
        PolicyVersion::new(3).unwrap(),
        PolicyDigestValue::new(&[9; 16]).unwrap(),
        LogEpoch::new(5).unwrap(),
        RelayEpoch::new(7).unwrap(),
    )
}

fn epoch(catalog_epoch: i64) -> Result<PolicyEpoch, InvalidIamValue> {
    let (version, digest, log_epoch, relay_epoch) = parts();
    PolicyEpoch::new(version, digest, log_epoch, relay_epoch, catalog_epoch)
}

#[test]
fn returns_each_part_it_was_built_from() {
    let epoch = epoch(11).unwrap();

    assert_eq!(epoch.version().value(), 3);
    assert_eq!(epoch.digest().as_bytes(), &[9; 16]);
    assert_eq!(epoch.log_epoch().value(), 5);
    assert_eq!(epoch.relay_epoch().value(), 7);
    assert_eq!(epoch.catalog_epoch(), 11);
}

#[rstest]
#[case(0)]
#[case(i64::MAX)]
fn accepts_a_catalogue_epoch_of_zero_or_more(#[case] catalog_epoch: i64) {
    assert_eq!(
        epoch(catalog_epoch).map(|epoch| epoch.catalog_epoch()),
        Ok(catalog_epoch)
    );
}

#[rstest]
#[case(-1)]
#[case(i64::MIN)]
fn rejects_a_negative_catalogue_epoch(#[case] catalog_epoch: i64) {
    assert_eq!(
        epoch(catalog_epoch),
        Err(InvalidIamValue::CatalogEpochNegative)
    );
}

#[test]
fn epochs_with_the_same_parts_are_equal() {
    assert_eq!(epoch(1), epoch(1));
    assert_ne!(epoch(1), epoch(2));
}

proptest::proptest! {
    #[test]
    fn keeps_every_valid_combination_of_parts(
        version in 0..=i64::MAX,
        digest in proptest::array::uniform16(any::<u8>()),
        log_epoch in 0..=i64::MAX,
        relay_epoch in 0..=i64::MAX,
        catalog_epoch in 0..=i64::MAX,
    ) {
        let epoch = PolicyEpoch::new(
            PolicyVersion::new(version).unwrap(),
            PolicyDigestValue::new(&digest).unwrap(),
            LogEpoch::new(log_epoch).unwrap(),
            RelayEpoch::new(relay_epoch).unwrap(),
            catalog_epoch,
        )
        .unwrap();

        proptest::prop_assert_eq!(epoch.version().value(), version);
        proptest::prop_assert_eq!(*epoch.digest().as_bytes(), digest);
        proptest::prop_assert_eq!(epoch.log_epoch().value(), log_epoch);
        proptest::prop_assert_eq!(epoch.relay_epoch().value(), relay_epoch);
        proptest::prop_assert_eq!(epoch.catalog_epoch(), catalog_epoch);
    }
}
