use iam_domain::ProbeError;
use krafka::KrafkaError;
use krafka::error::ErrorCode;

use super::{Leadership, Seen, agreed, failure, quorum_needed};

const LEADER: Leadership = Leadership {
    leader: 1,
    epoch: 4,
};

#[test]
fn a_majority_of_the_replicas_must_answer() {
    assert_eq!(quorum_needed(1), 1);
    assert_eq!(quorum_needed(2), 2);
    assert_eq!(quorum_needed(3), 2);
    assert_eq!(quorum_needed(5), 3);
}

#[test]
fn identical_views_agree() {
    assert_eq!(agreed(LEADER, &[LEADER, LEADER]), Ok(LEADER));
    assert_eq!(agreed(LEADER, &[]), Ok(LEADER));
}

#[test]
fn two_brokers_naming_different_leaders_or_epochs_disagree() {
    let other_leader = Leadership {
        leader: 2,
        epoch: 4,
    };
    let other_epoch = Leadership {
        leader: 1,
        epoch: 5,
    };

    assert_eq!(
        agreed(LEADER, &[LEADER, other_leader]),
        Err(ProbeError::LeaderDisagreement)
    );
    assert_eq!(
        agreed(LEADER, &[other_epoch]),
        Err(ProbeError::LeaderDisagreement)
    );
}

#[test]
fn an_epoch_lower_than_one_seen_is_refused_and_does_not_lower_the_mark() {
    let mut seen = Seen::default();

    assert_eq!(seen.admit_epoch(4), Ok(()));
    assert_eq!(seen.admit_epoch(4), Ok(()));
    assert_eq!(seen.admit_epoch(7), Ok(()));
    assert_eq!(
        seen.admit_epoch(6),
        Err(ProbeError::EpochRegressed {
            seen: 7,
            reported: 6
        })
    );
    assert_eq!(seen.admit_epoch(7), Ok(()));
}

#[test]
fn a_watermark_lower_than_one_seen_is_refused() {
    let mut seen = Seen::default();

    assert_eq!(seen.admit_watermark(10), Ok(()));
    assert_eq!(seen.admit_watermark(10), Ok(()));
    assert_eq!(seen.admit_watermark(12), Ok(()));
    assert_eq!(
        seen.admit_watermark(11),
        Err(ProbeError::WatermarkRegressed {
            seen: 12,
            reported: 11
        })
    );
}

#[test]
fn the_three_codes_that_void_the_answer_have_their_own_variants() {
    let broker = |code| KrafkaError::broker(code, "injected");

    assert_eq!(
        failure(&broker(ErrorCode::OffsetNotAvailable)),
        ProbeError::OffsetNotAvailable
    );
    assert_eq!(
        failure(&broker(ErrorCode::FencedLeaderEpoch)),
        ProbeError::FencedLeaderEpoch
    );
    assert_eq!(
        failure(&broker(ErrorCode::UnknownLeaderEpoch)),
        ProbeError::UnknownLeaderEpoch
    );
}

#[test]
fn any_other_error_is_an_unavailable_cluster() {
    let error = KrafkaError::broker(ErrorCode::NotLeaderForPartition, "moved");

    assert!(
        matches!(failure(&error), ProbeError::Unavailable(message) if message.contains("moved"))
    );
}
