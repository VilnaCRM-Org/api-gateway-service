use shared_domain::Uuid;

use super::{OutboxKind, OutboxRow, PublishedRow, RelayTakeover};
use crate::{LogEpoch, PolicyVersion, RelayEpoch};

fn row() -> OutboxRow {
    OutboxRow {
        id: Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ad").unwrap(),
        kind: OutboxKind::Event,
        topic: "iam.events.v1".to_owned(),
        record_key: "aggregate".to_owned(),
        payload: Some("{}".to_owned()),
        policy_version: PolicyVersion::new(3).unwrap(),
        seq: None,
        count: None,
        digest_after: None,
        log_epoch: LogEpoch::new(0).unwrap(),
        event_type: Some("iam.role.created".to_owned()),
    }
}

#[test]
fn a_row_is_equal_to_its_clone() {
    let original = row();

    assert_eq!(original.clone(), original);
}

#[test]
fn a_published_row_keeps_its_offset() {
    let published = PublishedRow {
        id: row().id,
        offset: 7,
    };

    assert_eq!(published.id, row().id);
    assert_eq!(published.offset, 7);
}

#[test]
fn a_takeover_names_its_epoch_and_the_rows_to_send_again() {
    let takeover = RelayTakeover {
        epoch: RelayEpoch::new(2).unwrap(),
        republish: vec![row()],
    };

    assert_eq!(takeover.epoch.value(), 2);
    assert_eq!(takeover.republish, vec![row()]);
}
