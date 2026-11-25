//! End-to-end suite: the Gherkin runner for the features of the repository.

#[cfg(test)]
mod administrator_policy;
#[cfg(test)]
mod events_topic;
#[cfg(test)]
mod gateway_proxy;
#[cfg(test)]
mod gateway_streams;
#[cfg(test)]
mod steps;
#[cfg(test)]
mod tokens;
#[cfg(test)]
mod world;

use cucumber::World as _;
use world::AppWorld;

#[tokio::main]
async fn main() {
    world::drop_leftover_databases().await;
    AppWorld::cucumber()
        .max_concurrent_scenarios(8)
        // Every skipped step fails the run, also in a scenario, rule or feature tagged `@allow.skipped`, which
        // the plain `fail_on_skipped()` would let pass (FR55).
        .fail_on_skipped_with(|_feature, _rule, _scenario| true)
        .after(|_feature, _rule, _scenario, _event, world| {
            Box::pin(async move {
                if let Some(world) = world {
                    // The final step of every scenario: the audit chain must still verify. A failed
                    // verification panics before the database is dropped, and
                    // `drop_leftover_databases` removes that database at the next start.
                    world.verify_audit_chain().await;
                    world.drop_database().await;
                }
            })
        })
        .run_and_exit(concat!(env!("CARGO_MANIFEST_DIR"), "/../../features"))
        .await;
}
