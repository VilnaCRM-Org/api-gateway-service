use std::time::Duration;

use super::{Pending, join_all};

fn after(millis: u64, value: u32) -> Pending<'static, u32> {
    Box::pin(async move {
        tokio::time::sleep(Duration::from_millis(millis)).await;
        value
    })
}

#[tokio::test(start_paused = true)]
async fn every_future_runs_at_once_and_the_outputs_keep_their_order() {
    let started = tokio::time::Instant::now();

    let outputs = join_all(vec![after(300, 1), after(100, 2), after(200, 3)]).await;

    assert_eq!(outputs, vec![1, 2, 3]);
    assert_eq!(started.elapsed(), Duration::from_millis(300));
}

#[tokio::test]
async fn nothing_to_run_is_nothing_back() {
    let outputs: Vec<u32> = join_all(Vec::new()).await;

    assert_eq!(outputs, Vec::<u32>::new());
}
