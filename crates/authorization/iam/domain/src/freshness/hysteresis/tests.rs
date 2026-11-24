use super::{
    RESTORE_AFTER, ReadinessHysteresis, ReadinessPressure, ReadinessTransition, SHED_AFTER,
};

fn steps(hysteresis: &mut ReadinessHysteresis, pressure: ReadinessPressure, times: u8) {
    for _ in 0..times {
        hysteresis.step(pressure);
    }
}

#[test]
fn a_new_pod_is_ready() {
    assert!(ReadinessHysteresis::new().is_ready());
    assert!(ReadinessHysteresis::default().is_ready());
}

#[test]
fn two_consecutive_shed_verdicts_withdraw_the_readiness_and_one_does_not() {
    let mut hysteresis = ReadinessHysteresis::new();

    let first = hysteresis.step(ReadinessPressure::Shed);
    assert_eq!(first, ReadinessTransition::Unchanged);
    assert!(hysteresis.is_ready());

    let second = hysteresis.step(ReadinessPressure::Shed);
    assert_eq!(second, ReadinessTransition::BecameUnready);
    assert!(!hysteresis.is_ready());
    assert_eq!(SHED_AFTER, 2);
}

#[test]
fn a_verdict_in_between_resets_the_shed_streak() {
    let mut hysteresis = ReadinessHysteresis::new();

    hysteresis.step(ReadinessPressure::Shed);
    hysteresis.step(ReadinessPressure::Settled);
    let after_reset = hysteresis.step(ReadinessPressure::Shed);

    assert_eq!(after_reset, ReadinessTransition::Unchanged);
    assert!(hysteresis.is_ready());
}

#[test]
fn a_hold_verdict_resets_the_shed_streak_too() {
    let mut hysteresis = ReadinessHysteresis::new();

    hysteresis.step(ReadinessPressure::Shed);
    hysteresis.step(ReadinessPressure::Hold);
    hysteresis.step(ReadinessPressure::Shed);

    assert!(hysteresis.is_ready());
}

#[test]
fn three_consecutive_fresh_verdicts_restore_the_readiness_and_two_do_not() {
    let mut hysteresis = ReadinessHysteresis::new();
    steps(&mut hysteresis, ReadinessPressure::Shed, SHED_AFTER);

    steps(&mut hysteresis, ReadinessPressure::Settled, 2);
    assert!(!hysteresis.is_ready());

    let third = hysteresis.step(ReadinessPressure::Settled);
    assert_eq!(third, ReadinessTransition::BecameReady);
    assert!(hysteresis.is_ready());
    assert_eq!(RESTORE_AFTER, 3);
}

#[test]
fn a_shed_verdict_resets_the_restore_streak() {
    let mut hysteresis = ReadinessHysteresis::new();
    steps(&mut hysteresis, ReadinessPressure::Shed, SHED_AFTER);

    steps(&mut hysteresis, ReadinessPressure::Settled, 2);
    hysteresis.step(ReadinessPressure::Shed);
    steps(&mut hysteresis, ReadinessPressure::Settled, 2);

    assert!(!hysteresis.is_ready());
}

#[test]
fn a_hold_verdict_brings_an_unready_pod_back_at_once() {
    let mut hysteresis = ReadinessHysteresis::new();
    steps(&mut hysteresis, ReadinessPressure::Shed, SHED_AFTER);

    let transition = hysteresis.step(ReadinessPressure::Hold);

    assert_eq!(transition, ReadinessTransition::BecameReady);
    assert!(hysteresis.is_ready());
}

#[test]
fn the_streak_restarts_after_a_restore() {
    let mut hysteresis = ReadinessHysteresis::new();
    steps(&mut hysteresis, ReadinessPressure::Shed, SHED_AFTER);
    steps(&mut hysteresis, ReadinessPressure::Settled, RESTORE_AFTER);

    let first = hysteresis.step(ReadinessPressure::Shed);

    assert_eq!(first, ReadinessTransition::Unchanged);
    assert!(hysteresis.is_ready());
}
