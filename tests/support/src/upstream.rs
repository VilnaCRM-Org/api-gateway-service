//! Upstream repository double and upstream fixtures of the IAM context.

use async_trait::async_trait;
use iam_domain::{
    ChangeStatement, EntityVersion, IamChange, RepositoryError, Upstream, UpstreamFields,
    UpstreamId, UpstreamName, UpstreamPageQuery, UpstreamParts, UpstreamProtocol,
    UpstreamRepository, UpstreamSettingsDraft, UpstreamStatement,
};

use crate::gateway_configuration::{gateway_change, random_time};
use crate::seed::TestRng;
use crate::unit_of_work::uuid_v7;

/// A stored upstream named `name` that serves the catalogue service `catalog_service`, at version 1,
/// created and updated at a random time after 2020.
///
/// # Panics
///
/// Panics when `name` is not a valid upstream name or `catalog_service` is not a valid service name.
#[expect(
    clippy::expect_used,
    reason = "a fixture with an invalid name is a defect of the test"
)]
pub fn upstream(rng: &mut TestRng, name: &str, catalog_service: &str) -> Upstream {
    let (name, settings) = UpstreamFields::new(
        name,
        &UpstreamSettingsDraft {
            namespace: "platform".to_owned(),
            service_name: format!("{name}-service"),
            catalog_service: catalog_service.to_owned(),
            port: 8080,
            protocol: UpstreamProtocol::Http1,
            forward_credentials: false,
            connect_timeout_ms: 1_000,
            response_timeout_ms: 30_000,
            concurrency_limit: 256,
            retry_budget_percent: 20,
            outlier_threshold: 5,
        },
    )
    .expect("a valid upstream")
    .into_parts();
    let at = random_time(rng);
    Upstream::restore(UpstreamParts {
        id: UpstreamId::from_uuid(uuid_v7(rng)),
        name,
        settings,
        system: false,
        version: EntityVersion::INITIAL,
        created_at: at,
        updated_at: at,
        deleted_at: None,
    })
}

/// A random committed change that runs `statements`.
pub fn upstream_change(rng: &mut TestRng, statements: Vec<UpstreamStatement>) -> IamChange {
    gateway_change(
        rng,
        statements.into_iter().map(ChangeStatement::from).collect(),
    )
}

/// What the double answers with.
#[derive(Debug)]
enum Answer {
    Holding(Vec<UpstreamParts>),
    Failing,
}

/// An upstream repository that answers from memory with the rules of the port: deleted upstreams
/// are never found, and pages follow the order of the identifiers.
#[derive(Debug)]
pub struct FakeUpstreamRepository {
    answer: Answer,
}

impl FakeUpstreamRepository {
    /// A repository without upstreams.
    #[must_use]
    pub const fn new() -> Self {
        Self::holding(Vec::new())
    }

    /// A repository that holds the state of each upstream.
    #[must_use]
    pub const fn holding(upstreams: Vec<UpstreamParts>) -> Self {
        Self {
            answer: Answer::Holding(upstreams),
        }
    }

    /// A repository that answers `Unavailable`.
    #[must_use]
    pub const fn failing() -> Self {
        Self {
            answer: Answer::Failing,
        }
    }

    /// The upstreams that are not deleted, in the order of their identifiers.
    fn live(&self) -> Result<Vec<&UpstreamParts>, RepositoryError> {
        match &self.answer {
            Answer::Holding(upstreams) => {
                let mut live: Vec<&UpstreamParts> = upstreams
                    .iter()
                    .filter(|upstream| upstream.deleted_at.is_none())
                    .collect();
                live.sort_by_key(|upstream| upstream.id);
                Ok(live)
            }
            Answer::Failing => Err(RepositoryError::Unavailable(
                "in-memory repository failure".into(),
            )),
        }
    }
}

impl Default for FakeUpstreamRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl UpstreamRepository for FakeUpstreamRepository {
    async fn find_by_id(&self, id: UpstreamId) -> Result<Option<Upstream>, RepositoryError> {
        Ok(self
            .live()?
            .into_iter()
            .find(|upstream| upstream.id == id)
            .map(|upstream| Upstream::restore(upstream.clone())))
    }

    async fn find_by_name(&self, name: &UpstreamName) -> Result<Option<Upstream>, RepositoryError> {
        Ok(self
            .live()?
            .into_iter()
            .find(|upstream| &upstream.name == name)
            .map(|upstream| Upstream::restore(upstream.clone())))
    }

    async fn find_page(&self, query: &UpstreamPageQuery) -> Result<Vec<Upstream>, RepositoryError> {
        let limit = usize::try_from(query.limit).unwrap_or(usize::MAX);
        Ok(self
            .live()?
            .into_iter()
            .filter(|upstream| query.after.is_none_or(|after| upstream.id > after))
            .take(limit)
            .map(|upstream| Upstream::restore(upstream.clone()))
            .collect())
    }
}

#[cfg(test)]
mod tests;
