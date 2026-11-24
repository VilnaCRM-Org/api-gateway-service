use iam_domain::PolicyDigestValue;

use super::*;

const INTERVAL: Duration = Duration::from_secs(1);

#[derive(Default)]
struct Audit {
    groups: Vec<usize>,
    fail_on: Option<usize>,
}

impl DerivedStateAudit for Audit {
    fn audit_group(&mut self, group: usize) -> Result<usize, DerivedMismatch> {
        self.groups.push(group);
        if self.fail_on == Some(group) {
            return Err(DerivedMismatch {
                shard: group,
                rebuilt: PolicyDigestValue::ZERO,
                held: PolicyDigestValue::from_bytes([1; PolicyDigestValue::LENGTH]),
            });
        }
        Ok(256)
    }
}

fn at(seconds: u64) -> BootInstant {
    BootInstant::from_elapsed(Duration::from_secs(seconds))
}

#[test]
fn the_first_call_only_starts_counting() {
    let mut checker = DerivedStateChecker::new(INTERVAL);
    let mut audit = Audit::default();

    assert_eq!(checker.run(at(5), &mut audit), CheckOutcome::NotDue);
    assert_eq!(audit.groups.len(), 0);
}

#[test]
fn nothing_runs_before_the_interval_has_passed() {
    let mut checker = DerivedStateChecker::new(INTERVAL);
    let mut audit = Audit::default();
    checker.run(at(5), &mut audit);

    let outcome = checker.run(
        BootInstant::from_elapsed(Duration::from_millis(5_999)),
        &mut audit,
    );

    assert_eq!(outcome, CheckOutcome::NotDue);
    assert_eq!(audit.groups.len(), 0);
}

#[test]
fn sixteen_intervals_check_every_group_exactly_once() {
    let mut checker = DerivedStateChecker::new(INTERVAL);
    let mut audit = Audit::default();
    checker.run(at(0), &mut audit);

    let outcomes: Vec<_> = (1..=16)
        .map(|second| checker.run(at(second), &mut audit))
        .collect();

    assert_eq!(audit.groups, (0..16).collect::<Vec<_>>());
    assert!(
        outcomes
            .iter()
            .all(|outcome| matches!(outcome, CheckOutcome::Passed { shards: 256, .. }))
    );
    assert_eq!(
        checker.run(at(17), &mut audit),
        CheckOutcome::Passed {
            group: 0,
            shards: 256
        }
    );
}

#[test]
fn a_mismatch_stops_the_checks_until_the_restart() {
    let mut checker = DerivedStateChecker::new(INTERVAL);
    let mut audit = Audit {
        fail_on: Some(1),
        ..Audit::default()
    };
    checker.run(at(0), &mut audit);
    checker.run(at(1), &mut audit);

    let outcome = checker.run(at(2), &mut audit);
    assert!(matches!(outcome, CheckOutcome::Mismatch(mismatch) if mismatch.shard == 1));
    assert_eq!(checker.run(at(10), &mut audit), CheckOutcome::NotDue);

    checker.restart();
    assert_eq!(checker.run(at(11), &mut audit), CheckOutcome::NotDue);
    assert!(matches!(
        checker.run(at(12), &mut audit),
        CheckOutcome::Passed { group: 2, .. }
    ));
}
