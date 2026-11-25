use iam_domain::{
    AuditChainHead, AuditHash, AuditOutcome, ChainBreak, ChainBreakCause, ChainVerification,
    RepositoryError, SecurityAuditFilter, SecurityAuditLog, SecurityAuditSearch,
    StoredSecurityAuditEvent,
};

use super::{FakeSecurityAuditLog, break_of, link, security_audit_event};
use crate::block_on;
use crate::seed::TestRng;

#[test]
fn the_same_seed_gives_equal_events_and_different_seeds_different_ones() {
    let first = security_audit_event(&mut TestRng::from_seed(7));
    let second = security_audit_event(&mut TestRng::from_seed(7));
    let other = security_audit_event(&mut TestRng::from_seed(8));

    assert_eq!(first, second);
    assert_ne!(first, other);
}

#[test]
fn the_new_and_the_default_log_start_at_the_genesis_head() {
    for log in [FakeSecurityAuditLog::new(), FakeSecurityAuditLog::default()] {
        let port: &dyn SecurityAuditLog = &log;

        assert_eq!(
            block_on(port.chain_head()).unwrap(),
            AuditChainHead::GENESIS
        );
        assert_eq!(log.recorded().len(), 0);
    }
}

#[test]
fn appended_records_are_chained_in_order() {
    let mut rng = TestRng::from_seed(11);
    let events = [
        security_audit_event(&mut rng),
        security_audit_event(&mut rng),
    ];
    let third = security_audit_event(&mut rng);
    let log = FakeSecurityAuditLog::new();
    let port: &dyn SecurityAuditLog = &log;

    block_on(port.append_batch(&events)).unwrap();
    let head = block_on(port.append_batch(std::slice::from_ref(&third))).unwrap();

    let recorded = log.recorded();
    assert_eq!(recorded.len(), 3);
    assert_eq!(head.seq(), 3);
    assert_eq!(head.hash(), recorded[2].hash());
    assert_eq!(recorded[0].prev_hash(), AuditChainHead::GENESIS.hash());
    assert_eq!(recorded[1].prev_hash(), recorded[0].hash());
    assert_eq!(recorded[2].prev_hash(), recorded[1].hash());
    assert_eq!(recorded[2].event(), &third);
    assert_eq!(block_on(port.chain_head()).unwrap(), head);
}

#[test]
fn records_are_found_by_id_and_after_a_sequence_number() {
    let mut rng = TestRng::from_seed(12);
    let events = [
        security_audit_event(&mut rng),
        security_audit_event(&mut rng),
        security_audit_event(&mut rng),
    ];
    let log = FakeSecurityAuditLog::new();
    let port: &dyn SecurityAuditLog = &log;
    block_on(port.append_batch(&events)).unwrap();

    let found = block_on(port.find_by_id(events[1].parts().id)).unwrap();
    let page = block_on(port.find_after(1, 1)).unwrap();
    let rest = block_on(port.find_after(1, 10)).unwrap();

    assert_eq!(found.seq(), 2);
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].seq(), 2);
    assert_eq!(rest.len(), 2);
}

#[test]
fn an_unknown_id_is_not_found() {
    let event = security_audit_event(&mut TestRng::from_seed(13));
    let log = FakeSecurityAuditLog::new();
    let port: &dyn SecurityAuditLog = &log;

    let error = block_on(port.find_by_id(event.parts().id)).unwrap_err();

    assert!(matches!(error, RepositoryError::NotFound));
}

#[test]
fn a_batch_with_a_stored_id_appends_nothing() {
    let mut rng = TestRng::from_seed(14);
    let first = security_audit_event(&mut rng);
    let fresh = security_audit_event(&mut rng);
    let log = FakeSecurityAuditLog::new();
    let port: &dyn SecurityAuditLog = &log;
    block_on(port.append_batch(std::slice::from_ref(&first))).unwrap();

    let error = block_on(port.append_batch(&[fresh, first])).unwrap_err();

    assert!(matches!(error, RepositoryError::AlreadyExists));
    assert_eq!(log.recorded().len(), 1);
}

#[test]
fn the_failing_log_is_unavailable_for_every_call() {
    let event = security_audit_event(&mut TestRng::from_seed(15));
    let log = FakeSecurityAuditLog::failing();
    let port: &dyn SecurityAuditLog = &log;

    let errors = [
        block_on(port.append_batch(std::slice::from_ref(&event))).unwrap_err(),
        block_on(port.chain_head()).unwrap_err(),
        block_on(port.find_by_id(event.parts().id)).unwrap_err(),
        block_on(port.find_after(0, 1)).unwrap_err(),
        block_on(port.search(&search(SecurityAuditFilter::new(), None, 1))).unwrap_err(),
    ];

    for error in errors {
        assert!(matches!(error, RepositoryError::Unavailable(_)));
        assert_eq!(
            std::error::Error::source(&error).unwrap().to_string(),
            "in-memory security audit log failure"
        );
    }
    assert_eq!(log.recorded().len(), 0);
}

fn search(filter: SecurityAuditFilter, before_seq: Option<i64>, limit: u32) -> SecurityAuditSearch {
    SecurityAuditSearch {
        filter,
        before_seq,
        limit,
    }
}

fn seqs(records: &[StoredSecurityAuditEvent]) -> Vec<i64> {
    records.iter().map(StoredSecurityAuditEvent::seq).collect()
}

#[test]
fn a_search_returns_the_newest_records_first_and_follows_the_cursor() {
    let mut rng = TestRng::from_seed(16);
    let events: Vec<_> = (0..4).map(|_| security_audit_event(&mut rng)).collect();
    let log = FakeSecurityAuditLog::new();
    let port: &dyn SecurityAuditLog = &log;
    block_on(port.append_batch(&events)).unwrap();

    let first = block_on(port.search(&search(SecurityAuditFilter::new(), None, 3))).unwrap();
    let second = block_on(port.search(&search(SecurityAuditFilter::new(), Some(2), 3))).unwrap();

    assert_eq!(seqs(&first), [4, 3, 2]);
    assert_eq!(seqs(&second), [1]);
}

#[test]
fn a_search_keeps_only_the_records_that_meet_the_filter() {
    let mut rng = TestRng::from_seed(17);
    let events = [
        security_audit_event(&mut rng),
        security_audit_event(&mut rng),
    ];
    let log = FakeSecurityAuditLog::new();
    let port: &dyn SecurityAuditLog = &log;
    block_on(port.append_batch(&events)).unwrap();
    let by_second_actor = SecurityAuditFilter::new().by_actor(events[1].parts().actor.clone());
    let rejected = SecurityAuditFilter::new().with_outcome(AuditOutcome::Rejected);

    let one = block_on(port.search(&search(by_second_actor, None, 10))).unwrap();
    let none = block_on(port.search(&search(rejected, None, 10))).unwrap();

    assert_eq!(seqs(&one), [2]);
    assert_eq!(seqs(&none), Vec::<i64>::new());
}

#[test]
fn an_intact_chain_verifies_and_a_matching_anchor_keeps_it_valid() {
    let mut rng = TestRng::from_seed(18);
    let events: Vec<_> = (0..3).map(|_| security_audit_event(&mut rng)).collect();
    let log = FakeSecurityAuditLog::new();
    let port: &dyn SecurityAuditLog = &log;
    block_on(port.append_batch(&events)).unwrap();
    let anchor = AuditChainHead::new(2, log.recorded()[1].hash()).unwrap();

    let plain = block_on(port.verify_chain(&[])).unwrap();
    let anchored = block_on(port.verify_chain(&[anchor])).unwrap();

    assert_eq!(plain, ChainVerification::valid(3));
    assert_eq!(anchored, ChainVerification::valid(3));
}

#[test]
fn an_empty_log_verifies_with_no_record_checked() {
    let log = FakeSecurityAuditLog::new();
    let port: &dyn SecurityAuditLog = &log;

    assert_eq!(
        block_on(port.verify_chain(&[])).unwrap(),
        ChainVerification::valid(0)
    );
}

#[test]
fn an_anchor_with_another_hash_breaks_the_chain_at_the_anchored_record() {
    let mut rng = TestRng::from_seed(19);
    let events: Vec<_> = (0..3).map(|_| security_audit_event(&mut rng)).collect();
    let log = FakeSecurityAuditLog::new();
    let port: &dyn SecurityAuditLog = &log;
    block_on(port.append_batch(&events)).unwrap();
    let anchor = AuditChainHead::new(2, log.recorded()[2].hash()).unwrap();

    let verification = block_on(port.verify_chain(&[anchor])).unwrap();

    let id = events[1].parts().id;
    assert_eq!(
        verification,
        ChainVerification::invalid(2, ChainBreak::new(2, Some(id), ChainBreakCause::Anchor))
    );
}

#[test]
fn an_anchor_beyond_the_newest_record_means_records_are_missing() {
    let mut rng = TestRng::from_seed(20);
    let events = [security_audit_event(&mut rng)];
    let log = FakeSecurityAuditLog::new();
    let port: &dyn SecurityAuditLog = &log;
    block_on(port.append_batch(&events)).unwrap();
    let anchor = AuditChainHead::new(4, log.recorded()[0].hash()).unwrap();

    let verification = block_on(port.verify_chain(&[anchor])).unwrap();

    assert_eq!(
        verification,
        ChainVerification::invalid(1, ChainBreak::new(4, None, ChainBreakCause::AnchorMissing))
    );
}

#[test]
fn the_failing_log_cannot_verify() {
    let log = FakeSecurityAuditLog::failing();
    let port: &dyn SecurityAuditLog = &log;

    assert!(matches!(
        block_on(port.verify_chain(&[])).unwrap_err(),
        RepositoryError::Unavailable(_)
    ));
}

#[test]
fn a_record_that_breaks_the_gap_link_or_digest_rule_is_named_by_its_cause() {
    let event = security_audit_event(&mut TestRng::from_seed(21));
    let stored = |seq: i64, prev: AuditHash, hash: AuditHash| {
        StoredSecurityAuditEvent::new(seq, event.clone(), prev, hash).unwrap()
    };
    let genesis = AuditHash::GENESIS;

    let intact = break_of(&stored(1, genesis, link(1)), 1, genesis, &[]);
    let gap = break_of(&stored(3, genesis, link(3)), 1, genesis, &[]);
    let wrong_link = break_of(&stored(1, link(9), link(1)), 1, genesis, &[]);
    let wrong_digest = break_of(&stored(1, genesis, link(9)), 1, genesis, &[]);

    assert_eq!(intact, None);
    assert_eq!(gap, Some(ChainBreakCause::Gap));
    assert_eq!(wrong_link, Some(ChainBreakCause::Link));
    assert_eq!(wrong_digest, Some(ChainBreakCause::Digest));
}
