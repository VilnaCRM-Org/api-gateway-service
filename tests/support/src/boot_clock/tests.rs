use std::time::Duration;

use iam_domain::{BootClock, BootInstant};

use super::FakeBootClock;

#[test]
fn starts_at_boot_and_stands_still_until_advanced() {
    let clock = FakeBootClock::new();

    assert_eq!(clock.now(), BootInstant::from_elapsed(Duration::ZERO));
    assert_eq!(clock.now(), clock.now());
}

#[test]
fn elapsed_time_never_decreases_and_the_jump_is_one_gap() {
    let clock = FakeBootClock::starting_at(BootInstant::from_elapsed(Duration::from_secs(5)));
    let step = Duration::from_millis(100);
    let gap = Duration::from_secs(3_600);
    let mut readings = vec![clock.now()];

    for _ in 0..3 {
        clock.advance(step);
        readings.push(clock.now());
    }
    clock.jump(gap);
    readings.push(clock.now());
    clock.advance(step);
    readings.push(clock.now());

    let gaps: Vec<Duration> = readings
        .windows(2)
        .map(|pair| pair[1].saturating_since(pair[0]))
        .collect();
    assert!(readings.windows(2).all(|pair| pair[0] <= pair[1]));
    assert_eq!(gaps, vec![step, step, step, gap, step]);
    assert_eq!(gaps.iter().filter(|each| **each > step).count(), 1);
    assert_eq!(
        clock.now().elapsed(),
        Duration::from_secs(5) + step * 4 + gap
    );
}

#[test]
fn saturates_instead_of_overflowing() {
    let clock = FakeBootClock::starting_at(BootInstant::from_elapsed(Duration::MAX));

    clock.advance(Duration::from_secs(1));

    assert_eq!(clock.now().elapsed(), Duration::MAX);
}

#[test]
fn serves_as_the_port() {
    let clock = FakeBootClock::new();
    let port: &dyn BootClock = &clock;

    clock.advance(Duration::from_secs(2));

    assert_eq!(port.now().elapsed(), Duration::from_secs(2));
}
