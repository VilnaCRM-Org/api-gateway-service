use shared_domain::Uuid;

use super::*;
use crate::state::fakes::HashDigest;
use crate::state::model::{CatalogueEntryState, GrantState, RoleState};
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::identifier::RoleId;
use crate::value_object::role_kind::RoleKind;

/// Reads `head <version> <digest hex>`.
#[derive(Debug)]
struct HeadCodec;

impl StateRecordCodec for HeadCodec {
    fn encode(&self, _state: &PolicyState) -> Result<String, InvalidStateRecord> {
        Err(InvalidStateRecord::Encoding)
    }

    fn decode(&self, _key: &StateKey, payload: &str) -> Result<PolicyState, InvalidStateRecord> {
        if payload == "role" {
            return Ok(PolicyState::Role(RoleState {
                id: RoleId::from_uuid(
                    Uuid::parse("0192f6a0-0000-7000-8000-000000000001")
                        .map_err(|_error| InvalidStateRecord::Encoding)?,
                ),
                name: "role".to_owned(),
                description: None,
                kind: RoleKind::Custom,
                version: EntityVersion::new(1).map_err(|_error| InvalidStateRecord::Encoding)?,
                grants: vec![GrantState {
                    key: "iam:role:read".to_owned(),
                    active: true,
                }],
            }));
        }
        let mut parts = payload.split(' ');
        let (Some("head"), Some(version), Some(digest)) =
            (parts.next(), parts.next(), parts.next())
        else {
            return Err(InvalidStateRecord::Encoding);
        };
        let version = version
            .parse()
            .ok()
            .and_then(|number| PolicyVersion::new(number).ok())
            .ok_or(InvalidStateRecord::Encoding)?;
        let digest =
            PolicyDigestValue::from_hex(digest).map_err(|_error| InvalidStateRecord::Encoding)?;
        Ok(PolicyState::Head(PolicyHead { version, digest }))
    }

    fn entry_size(&self, _entry: &CatalogueEntryState) -> usize {
        0
    }
}

const ROLE_ONE: &str = "role/0192f6a0-0000-7000-8000-000000000001";
const ROLE_TWO: &str = "role/0192f6a0-0000-7000-8000-000000000002";

fn record(offset: i64, key: &str, payload: Option<&str>, version: i64, epoch: i64) -> TailRecord {
    TailRecord {
        offset,
        key: key.to_owned(),
        payload: payload.map(str::to_owned),
        version: PolicyVersion::new(version).unwrap(),
        relay_epoch: RelayEpoch::new(epoch).unwrap(),
    }
}

fn hash_of(key: &str, canonical: &str) -> PolicyDigestValue {
    HashDigest.entity_hash(&StateKey::parse(key).unwrap(), canonical)
}

fn head_record(offset: i64, version: i64, digest: PolicyDigestValue, epoch: i64) -> TailRecord {
    let payload = format!("head {version} {}", digest.to_hex());
    record(offset, "__head", Some(&payload), version, epoch)
}

fn applied(records: &[TailRecord]) -> ShadowState {
    let mut state = ShadowState::new();
    for item in records {
        state.apply(item, (&HeadCodec, &HashDigest)).unwrap();
    }
    state
}

#[test]
fn a_topic_without_records_is_empty() {
    assert_eq!(ShadowState::default().verdict(), ShadowVerdict::Empty);
}

#[test]
fn records_without_a_head_are_incomplete() {
    let state = applied(&[record(0, ROLE_ONE, Some("a"), 1, 1)]);

    assert_eq!(state.verdict(), ShadowVerdict::Incomplete);
}

#[test]
fn a_rebuilt_digest_equal_to_the_head_is_consistent() {
    let digest = hash_of(ROLE_ONE, "a").combined(hash_of(ROLE_TWO, "b"));
    let state = applied(&[
        record(0, ROLE_ONE, Some("a"), 1, 1),
        record(1, ROLE_TWO, Some("b"), 1, 1),
        head_record(2, 1, digest, 1),
    ]);

    let head = PolicyHead {
        version: PolicyVersion::new(1).unwrap(),
        digest,
    };
    assert_eq!(state.verdict(), ShadowVerdict::Consistent(head));
    assert_eq!(state.computed_digest(), digest);
}

#[test]
fn the_highest_version_of_a_key_wins() {
    let digest = hash_of(ROLE_ONE, "b");
    let state = applied(&[
        record(0, ROLE_ONE, Some("a"), 1, 1),
        head_record(1, 1, hash_of(ROLE_ONE, "a"), 1),
        record(2, ROLE_ONE, Some("b"), 2, 1),
        head_record(3, 2, digest, 1),
    ]);

    assert!(matches!(state.verdict(), ShadowVerdict::Consistent(_)));
    assert_eq!(state.computed_digest(), digest);
}

#[test]
fn a_lower_version_appended_later_does_not_win() {
    let digest = hash_of(ROLE_ONE, "b");
    let state = applied(&[
        record(0, ROLE_ONE, Some("b"), 2, 1),
        record(1, ROLE_ONE, Some("a"), 1, 1),
        head_record(2, 2, digest, 1),
    ]);

    assert!(matches!(state.verdict(), ShadowVerdict::Consistent(_)));
}

#[test]
fn a_tombstone_deletes_the_key() {
    let digest = hash_of(ROLE_TWO, "b");
    let state = applied(&[
        record(0, ROLE_ONE, Some("a"), 1, 1),
        record(1, ROLE_TWO, Some("b"), 1, 1),
        record(2, ROLE_ONE, None, 2, 1),
        head_record(3, 2, digest, 1),
    ]);

    assert!(matches!(state.verdict(), ShadowVerdict::Consistent(_)));
}

#[test]
fn a_record_of_a_lower_relay_epoch_after_a_higher_one_is_ignored() {
    let digest = hash_of(ROLE_ONE, "b");
    let state = applied(&[
        record(0, ROLE_ONE, Some("b"), 2, 2),
        record(1, ROLE_ONE, Some("zombie"), 1, 1),
        head_record(2, 2, digest, 2),
    ]);

    assert_eq!(state.ignored(), 1);
    assert!(matches!(state.verdict(), ShadowVerdict::Consistent(_)));
}

#[test]
fn a_corrupted_value_is_reported_with_both_digests() {
    let expected = hash_of(ROLE_ONE, "a");
    let state = applied(&[
        record(0, ROLE_ONE, Some("corrupted"), 1, 1),
        head_record(1, 1, expected, 1),
    ]);

    assert_eq!(
        state.verdict(),
        ShadowVerdict::Corrupt {
            head: PolicyHead {
                version: PolicyVersion::new(1).unwrap(),
                digest: expected,
            },
            computed: hash_of(ROLE_ONE, "corrupted"),
        }
    );
}

#[test]
fn a_key_above_the_newest_head_is_incomplete() {
    let state = applied(&[
        record(0, ROLE_ONE, Some("a"), 1, 1),
        head_record(1, 1, hash_of(ROLE_ONE, "a"), 1),
        record(2, ROLE_TWO, Some("b"), 2, 1),
    ]);

    assert_eq!(state.verdict(), ShadowVerdict::Incomplete);
}

#[test]
fn an_older_head_does_not_replace_a_newer_one() {
    let digest = hash_of(ROLE_ONE, "b");
    let state = applied(&[
        record(0, ROLE_ONE, Some("b"), 2, 1),
        head_record(1, 2, digest, 1),
        head_record(2, 1, hash_of(ROLE_ONE, "a"), 1),
    ]);

    assert!(matches!(state.verdict(), ShadowVerdict::Consistent(head) if head.digest == digest));
}

#[test]
fn a_key_that_is_not_a_state_key_is_refused() {
    let mut state = ShadowState::new();

    let refused = state.apply(
        &record(0, "nonsense", Some("a"), 1, 1),
        (&HeadCodec, &HashDigest),
    );

    assert!(matches!(refused, Err(InvalidStateRecord::Key { .. })));
}

#[test]
fn a_head_without_a_value_is_refused() {
    let mut state = ShadowState::new();

    let refused = state.apply(&record(0, "__head", None, 1, 1), (&HeadCodec, &HashDigest));

    assert_eq!(refused, Err(InvalidStateRecord::Encoding));
}

#[test]
fn a_head_that_decodes_to_another_entity_is_refused() {
    let mut state = ShadowState::new();

    let refused = state.apply(
        &record(0, "__head", Some("role"), 1, 1),
        (&HeadCodec, &HashDigest),
    );

    assert_eq!(refused, Err(InvalidStateRecord::Encoding));
}

#[test]
fn a_head_the_codec_cannot_read_is_refused() {
    let mut state = ShadowState::new();

    let refused = state.apply(
        &record(0, "__head", Some("x"), 1, 1),
        (&HeadCodec, &HashDigest),
    );

    assert_eq!(refused, Err(InvalidStateRecord::Encoding));
}
