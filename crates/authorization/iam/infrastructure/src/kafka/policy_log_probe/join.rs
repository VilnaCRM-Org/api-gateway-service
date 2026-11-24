//! Runs a few futures at once without a runtime of its own: the replica brokers are asked
//! together, so that one that does not answer delays the probe by its timeout only once.

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::Poll;

/// A boxed future the join polls.
pub(super) type Pending<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A future still running, or its output once it is done.
type Slot<'a, T> = (Option<Pending<'a, T>>, Option<T>);

/// Polls every future until all are done; the outputs come in the order of the futures.
pub(super) async fn join_all<T>(futures: Vec<Pending<'_, T>>) -> Vec<T> {
    let mut slots: Vec<Slot<'_, T>> = futures
        .into_iter()
        .map(|future| (Some(future), None))
        .collect();
    poll_fn(|context| {
        let mut waiting = false;
        for (future, output) in &mut slots {
            let Some(running) = future.as_mut() else {
                continue;
            };
            match running.as_mut().poll(context) {
                Poll::Ready(value) => {
                    *output = Some(value);
                    *future = None;
                }
                Poll::Pending => waiting = true,
            }
        }
        if waiting {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    })
    .await;
    slots
        .into_iter()
        .filter_map(|(_future, output)| output)
        .collect()
}

#[cfg(test)]
mod tests;
