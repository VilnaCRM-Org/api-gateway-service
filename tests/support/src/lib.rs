//! Test doubles, fixtures and seeded random data shared by the unit, integration and end-to-end
//! tests. This crate is test code: it is excluded from coverage and mutation by path.

pub mod access_token;
pub mod boot_clock;
pub mod bus;
pub mod cache;
pub mod change_receipt;
pub mod clock;
pub mod fixture;
pub mod id;
pub mod idempotency;
pub mod log;
pub mod policy_epoch;
pub mod probe;
pub mod repository;
pub mod rng;
pub mod security_audit;
pub mod seed;
pub mod unit_of_work;

/// Runs a future that completes without waiting for anything, such as the doubles of this crate.
#[cfg(test)]
fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    loop {
        if let std::task::Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
    }
}
