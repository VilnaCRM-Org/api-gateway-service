use super::{AntiEntropyAlert, RESYNC_RUNBOOK, TOPIC_AHEAD_RUNBOOK};

#[test]
fn a_topic_ahead_names_its_own_runbook() {
    let alert = AntiEntropyAlert::TopicAhead { topic: 7, store: 5 };

    assert_eq!(alert.runbook(), TOPIC_AHEAD_RUNBOOK);
    assert!(alert.to_string().contains("version 7"));
}

#[test]
fn every_other_alert_names_the_resync() {
    let alerts = [
        AntiEntropyAlert::DigestMismatch {
            version: 1,
            expected: "a".to_owned(),
            found: "b".to_owned(),
        },
        AntiEntropyAlert::UnreadableRecord {
            offset: 3,
            reason: "x".to_owned(),
        },
        AntiEntropyAlert::LossBeyondRetention {
            key: "role/1".to_owned(),
        },
        AntiEntropyAlert::TopicBehind { store: 4 },
    ];

    for alert in alerts {
        assert_eq!(alert.runbook(), RESYNC_RUNBOOK);
        assert_ne!(alert.to_string().len(), 0);
    }
}
