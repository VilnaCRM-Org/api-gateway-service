use std::error::Error as _;

use iam_domain::{InvalidIamValue, OutboxKind, RepositoryError};
use sqlx::types::Uuid as SqlUuid;

use super::{Stored, framing_number, kind_of, relay_epoch, restore, unavailable, unusable};

const ID: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ad";

fn stored() -> Stored {
    Stored {
        id: SqlUuid::parse_str(ID).unwrap(),
        kind: "state".to_owned(),
        topic: "iam.policy.state.v1".to_owned(),
        record_key: "role/1".to_owned(),
        payload: Some("{}".to_owned()),
        policy_version: 4,
        seq: Some(1),
        count: Some(2),
        digest_after: Some(vec![0; 16]),
        log_epoch: 3,
        event_type: None,
    }
}

#[test]
fn a_stored_state_row_becomes_an_outbox_row() {
    let row = restore(stored()).unwrap();

    assert_eq!(row.id.to_string(), ID);
    assert_eq!(row.kind, OutboxKind::State);
    assert_eq!(row.topic, "iam.policy.state.v1");
    assert_eq!(row.record_key, "role/1");
    assert_eq!(row.payload.as_deref(), Some("{}"));
    assert_eq!(row.policy_version.value(), 4);
    assert_eq!((row.seq, row.count), (Some(1), Some(2)));
    assert!(row.digest_after.is_some());
    assert_eq!(row.log_epoch.value(), 3);
}

#[test]
fn a_stored_event_row_has_no_framing() {
    let row = restore(Stored {
        kind: "event".to_owned(),
        seq: None,
        count: None,
        digest_after: None,
        event_type: Some("iam.role.created".to_owned()),
        ..stored()
    })
    .unwrap();

    assert_eq!(row.kind, OutboxKind::Event);
    assert_eq!((row.seq, row.count, row.digest_after), (None, None, None));
    assert_eq!(row.event_type.as_deref(), Some("iam.role.created"));
}

#[test]
fn a_stored_tombstone_keeps_its_missing_value() {
    let row = restore(Stored {
        payload: None,
        ..stored()
    })
    .unwrap();

    assert_eq!(row.payload, None);
}

#[test]
fn a_row_that_breaks_an_invariant_is_unusable_data() {
    let rows = [
        Stored {
            kind: "other".to_owned(),
            ..stored()
        },
        Stored {
            policy_version: -1,
            ..stored()
        },
        Stored {
            seq: Some(-1),
            ..stored()
        },
        Stored {
            count: Some(-1),
            ..stored()
        },
        Stored {
            digest_after: Some(vec![1, 2]),
            ..stored()
        },
        Stored {
            log_epoch: -1,
            ..stored()
        },
    ];

    for row in rows {
        assert!(matches!(restore(row), Err(RepositoryError::Unavailable(_))));
    }
}

#[test]
fn the_kinds_of_the_outbox_are_state_and_event() {
    assert_eq!(kind_of("state").unwrap(), OutboxKind::State);
    assert_eq!(kind_of("event").unwrap(), OutboxKind::Event);
    let unknown = kind_of("other").unwrap_err();
    assert_eq!(
        unknown.source().unwrap().to_string(),
        "the outbox row has the unknown kind `other`"
    );
}

#[test]
fn a_negative_framing_number_is_unusable_data() {
    assert_eq!(framing_number(7).unwrap(), 7);
    let error = framing_number(-1).unwrap_err();
    assert_eq!(
        error.source().unwrap().to_string(),
        "the outbox row has a negative framing number"
    );
}

#[test]
fn a_negative_relay_epoch_is_unusable_data() {
    assert_eq!(relay_epoch(2).unwrap().value(), 2);
    assert!(matches!(
        relay_epoch(-1),
        Err(RepositoryError::Unavailable(_))
    ));
}

#[test]
fn failures_are_unavailable_repositories_with_their_cause() {
    let database = unavailable(sqlx::Error::PoolTimedOut);
    let value = unusable(InvalidIamValue::RelayEpochNegative);

    assert!(matches!(database, RepositoryError::Unavailable(_)));
    assert!(database.source().is_some());
    assert!(matches!(value, RepositoryError::Unavailable(_)));
}
