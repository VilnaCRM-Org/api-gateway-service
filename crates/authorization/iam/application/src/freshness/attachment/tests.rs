use std::time::Duration;

use iam_domain::BootInstant;
use iam_domain::freshness::proof::FreshnessProof;

use super::ProofAttachment;

fn proof(second: u64, watermark: i64) -> FreshnessProof {
    FreshnessProof {
        taken_at: BootInstant::from_elapsed(Duration::from_secs(second)),
        watermark,
    }
}

#[test]
fn a_proof_whose_watermark_lies_beyond_the_applied_versions_waits() {
    let mut attachment = ProofAttachment::starting_at(10);
    attachment.offer(proof(1, 14));

    assert_eq!(attachment.take_attachable(), None);

    attachment.record_complete(12);
    assert_eq!(attachment.take_attachable(), None);

    attachment.record_complete(13);
    assert_eq!(attachment.take_attachable(), Some(proof(1, 14)));
    assert_eq!(attachment.waiting(), 0);
}

#[test]
fn a_proof_is_attached_to_the_first_snapshot_that_covers_every_version_below_its_watermark() {
    let mut attachment = ProofAttachment::starting_at(0);
    attachment.offer(proof(1, 6));
    attachment.record_held(0);
    attachment.record_held(1);
    assert_eq!(attachment.take_attachable(), None);

    attachment.record_complete(2);
    assert_eq!(attachment.take_attachable(), None);

    attachment.record_complete(5);
    assert_eq!(attachment.take_attachable(), Some(proof(1, 6)));
}

#[test]
fn the_newest_attachable_proof_supersedes_the_older_ones() {
    let mut attachment = ProofAttachment::starting_at(8);
    attachment.offer(proof(1, 5));
    attachment.offer(proof(2, 7));
    attachment.offer(proof(3, 20));

    assert_eq!(attachment.take_attachable(), Some(proof(2, 7)));
    assert_eq!(attachment.waiting(), 1);
    assert_eq!(attachment.take_attachable(), None);
}

#[test]
fn an_idle_poll_covers_the_commit_markers_behind_the_last_record() {
    let mut attachment = ProofAttachment::starting_at(0);
    attachment.record_complete(3);
    attachment.offer(proof(1, 5));
    assert_eq!(attachment.take_attachable(), None);

    attachment.caught_up(4, 5);

    assert_eq!(attachment.take_attachable(), Some(proof(1, 5)));
}

#[test]
fn an_idle_poll_at_another_position_covers_nothing() {
    let mut attachment = ProofAttachment::starting_at(0);
    attachment.record_complete(3);
    attachment.offer(proof(1, 5));

    attachment.caught_up(2, 5);

    assert_eq!(attachment.take_attachable(), None);
}

#[test]
fn an_idle_poll_covers_nothing_while_a_version_is_incomplete() {
    let mut attachment = ProofAttachment::starting_at(0);
    attachment.record_held(0);
    attachment.offer(proof(1, 2));

    attachment.caught_up(1, 2);

    assert_eq!(attachment.take_attachable(), None);
}

#[test]
fn a_repeat_below_an_incomplete_version_does_not_extend_the_cover() {
    let mut attachment = ProofAttachment::starting_at(0);
    attachment.record_held(0);
    attachment.record_skipped(1);
    attachment.offer(proof(1, 2));

    assert_eq!(attachment.take_attachable(), None);
}

#[test]
fn a_repeat_extends_the_cover_when_no_version_is_incomplete() {
    let mut attachment = ProofAttachment::starting_at(0);
    attachment.record_skipped(0);
    attachment.offer(proof(1, 1));

    assert_eq!(attachment.take_attachable(), Some(proof(1, 1)));
}

#[test]
fn replacing_the_state_drops_the_waiting_proofs() {
    let mut attachment = ProofAttachment::starting_at(0);
    attachment.offer(proof(1, 100));

    let restarted = ProofAttachment::starting_at(50);

    assert_eq!(restarted.waiting(), 0);
}

#[test]
fn only_the_newest_proofs_wait() {
    let mut attachment = ProofAttachment::starting_at(0);
    for second in 0..40 {
        attachment.offer(proof(second, 1_000));
    }

    assert_eq!(attachment.waiting(), 16);
}

#[test]
fn without_an_idle_proof_the_cover_stops_at_the_applied_records() {
    let mut attachment = ProofAttachment::starting_at(0);
    attachment.record_complete(3);
    attachment.offer(proof(1, 5));

    assert_eq!(attachment.take_attachable(), None);
}
