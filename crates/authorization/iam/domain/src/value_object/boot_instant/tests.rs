use std::time::Duration;

use super::BootInstant;

#[test]
fn holds_the_elapsed_time_since_boot() {
    let instant = BootInstant::from_elapsed(Duration::from_millis(1_500));

    assert_eq!(instant.elapsed(), Duration::from_millis(1_500));
}

#[test]
fn measures_the_time_since_an_earlier_instant() {
    let earlier = BootInstant::from_elapsed(Duration::from_secs(10));
    let later = BootInstant::from_elapsed(Duration::from_secs(25));

    assert_eq!(later.saturating_since(earlier), Duration::from_secs(15));
    assert_eq!(earlier.saturating_since(later), Duration::ZERO);
    assert_eq!(later.saturating_since(later), Duration::ZERO);
}

#[test]
fn adds_a_duration_unless_it_overflows() {
    let instant = BootInstant::from_elapsed(Duration::from_secs(1));

    assert_eq!(
        instant.checked_add(Duration::from_secs(2)),
        Some(BootInstant::from_elapsed(Duration::from_secs(3)))
    );
    assert_eq!(
        BootInstant::from_elapsed(Duration::MAX).checked_add(Duration::from_nanos(1)),
        None
    );
}

#[test]
fn instants_are_ordered_by_their_elapsed_time() {
    assert!(
        BootInstant::from_elapsed(Duration::from_secs(1))
            < BootInstant::from_elapsed(Duration::from_secs(2))
    );
}
