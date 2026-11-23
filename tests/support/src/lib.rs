//! Test doubles, fixtures and seeded random data shared by the unit, integration and end-to-end
//! tests. This crate is test code: it is excluded from coverage and mutation by path.

pub mod access_token;
pub mod boot_clock;
pub mod bus;
pub mod cache;
pub mod catalogue;
pub mod change_receipt;
pub mod clock;
pub mod fixture;
pub mod graphql_permission;
pub mod graphql_spec;
pub mod id;
pub mod idempotency;
pub mod log;
pub mod openapi_spec;
pub mod policy_epoch;
pub mod policy_read;
pub mod probe;
pub mod repository;
pub mod request_digester;
pub mod rest_permission;
pub mod revocation;
pub mod rng;
pub mod role;
pub mod security_audit;
pub mod seed;
pub mod singleton_leadership;
pub mod startup_lock;
pub mod token;
pub mod unit_of_work;
pub mod user_role;

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
