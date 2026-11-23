use super::SingletonTask;

#[test]
fn a_task_keeps_its_name_and_its_lock_key() {
    let task = SingletonTask::new("relay", 7_001);

    assert_eq!(task.name(), "relay");
    assert_eq!(task.lock_key(), 7_001);
}

#[test]
fn tasks_with_different_keys_are_different() {
    assert_ne!(SingletonTask::new("a", 1), SingletonTask::new("a", 2));
}
