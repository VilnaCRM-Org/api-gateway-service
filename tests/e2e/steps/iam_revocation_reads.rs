//! The steps of the revocation read scenarios: revocations and cut-offs that the User service
//! consumer and the operators leave in the scenario database.

use cucumber::given;
use iam_domain::RevocationSource;

use crate::world::AppWorld;

/// The source that a scenario names.
fn source_of(name: &str) -> RevocationSource {
    RevocationSource::parse(name).expect("a source such as user-service or operator")
}

#[given(
    expr = "the revocation {string} of the session {string} from {string} recorded {int} minutes ago"
)]
async fn revocation_is_seeded(
    world: &mut AppWorld,
    id: String,
    session: String,
    source: String,
    minutes_ago: u64,
) {
    world
        .seed_session_revocation(&id, &session, source_of(&source), minutes_ago)
        .await;
}

#[given(expr = "a token cut-off of the user from {string}")]
async fn user_cutoff_is_seeded(world: &mut AppWorld, source: String) {
    world.seed_user_cutoff(source_of(&source)).await;
}

#[given("a global token cut-off set by the bootstrapped administrator")]
async fn global_cutoff_is_seeded(world: &mut AppWorld) {
    world.seed_global_cutoff().await;
}
