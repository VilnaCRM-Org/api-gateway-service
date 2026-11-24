use super::ReadinessGate;

#[test]
fn a_new_gate_is_ready_and_does_not_shed() {
    let gate = ReadinessGate::default();

    assert!(gate.is_ready());
    assert!(!*gate.shedding().borrow());
}

#[test]
fn a_pod_that_is_not_ready_sheds_until_it_is_ready_again() {
    let gate = ReadinessGate::new();
    let shedding = gate.shedding();

    gate.set_ready(false);
    assert!(!gate.is_ready());
    assert!(*shedding.borrow());

    gate.set_ready(true);
    assert!(gate.is_ready());
    assert!(!*shedding.borrow());
}

#[tokio::test]
async fn a_receiver_is_woken_when_the_pod_starts_to_shed() {
    let gate = ReadinessGate::new();
    let mut shedding = gate.shedding();

    gate.set_ready(false);

    assert!(shedding.wait_for(|shedding| *shedding).await.is_ok());
}
