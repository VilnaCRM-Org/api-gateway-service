//! GraphQL specification repository double and specification fixtures of the IAM context.

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use iam_domain::{
    ActorRef, ChangeStatement, ContentHash, DecisionEffect, GqlName, GraphQlCoordinate,
    GraphQlField, GraphQlSpec, GraphQlSpecContent, GraphQlSpecPageQuery, GraphQlSpecParts,
    GraphQlSpecRepository, GraphQlSpecStatement, GraphQlTypeGraph, IamChange, PermissionFlags,
    RepositoryError, ServiceName, SpecId, SpecStatus,
};
use rand::RngExt as _;

use crate::seed::TestRng;
use crate::unit_of_work::{iam_change, rebuilt, uuid_v7};

/// A small SDL document: two root fields, an interface with two implementations and one sensitive
/// field.
pub const SDL_FIXTURE: &str = "type Query {\n  invoices: [Invoice!]!\n  node: Node\n}\n\ntype Mutation {\n  pay(id: ID!): Invoice! @iamSensitive\n}\n\ninterface Node {\n  id: ID!\n}\n\ntype Invoice implements Node {\n  id: ID!\n}\n\ntype Customer implements Node {\n  id: ID!\n}\n";

/// The type graph that [`SDL_FIXTURE`] parses to.
///
/// # Panics
///
/// Never in practice: the fixed names and the small graph satisfy the invariants.
#[expect(
    clippy::expect_used,
    reason = "the fixed names satisfy the invariants; a failure is a defect of the fixture"
)]
#[must_use]
pub fn type_graph_fixture() -> GraphQlTypeGraph {
    let name = |text: &str| GqlName::parse(text).expect("a GraphQL name");
    let field = |type_name: &str, field: &str, return_type: &str, flags: PermissionFlags| {
        (
            GraphQlCoordinate::new(name(type_name), name(field)),
            GraphQlField {
                return_type: name(return_type),
                flags,
            },
        )
    };
    GraphQlTypeGraph::new(
        [
            field("Query", "invoices", "Invoice", PermissionFlags::NONE),
            field("Query", "node", "Node", PermissionFlags::NONE),
            field(
                "Mutation",
                "pay",
                "Invoice",
                PermissionFlags::NONE.with_sensitive(),
            ),
            field("Node", "id", "ID", PermissionFlags::NONE),
            field("Invoice", "id", "ID", PermissionFlags::NONE),
            field("Customer", "id", "ID", PermissionFlags::NONE),
        ],
        [
            (name("Node"), name("Invoice")),
            (name("Node"), name("Customer")),
        ],
    )
    .expect("a valid type graph")
}

/// A stored version of `service` in `status` with the hash `content_hash`, the type graph of
/// [`SDL_FIXTURE`], a random uploader and a random creation time after 2020.
///
/// # Panics
///
/// Never in practice: the generated time lies before the year 2100.
#[expect(
    clippy::expect_used,
    reason = "the generated time lies before the year 2100; a failure is a defect of the fixture"
)]
pub fn graphql_spec(
    rng: &mut TestRng,
    service: &ServiceName,
    status: SpecStatus,
    content_hash: ContentHash,
) -> GraphQlSpec {
    let micros = rng
        .rng()
        .random_range(1_577_836_800_000_000_u64..4_102_444_800_000_000);
    let at = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_micros(micros))
        .expect("a time before the year 2100");
    let later = at
        .checked_add(Duration::from_secs(60))
        .expect("a time before the year 2100");
    GraphQlSpec::restore(GraphQlSpecParts {
        id: SpecId::from_uuid(uuid_v7(rng)),
        content: GraphQlSpecContent {
            service: service.clone(),
            content_hash,
            type_graph: type_graph_fixture(),
        },
        status,
        uploaded_by: ActorRef::User(uuid_v7(rng)),
        created_at: at,
        activated_at: (status != SpecStatus::Draft).then_some(later),
        retired_at: (status == SpecStatus::Retired).then_some(later),
    })
}

/// A random committed change that runs `statements`, written by a random user.
pub fn graphql_spec_change(rng: &mut TestRng, statements: Vec<GraphQlSpecStatement>) -> IamChange {
    rebuilt(&iam_change(rng, DecisionEffect::Unaffected, 0), |parts| {
        parts.statements = statements
            .into_iter()
            .map(|statement| ChangeStatement::SaveGraphQlSpec(Box::new(statement)))
            .collect();
    })
}

/// One stored version with its SDL.
#[derive(Debug, Clone)]
struct Stored {
    parts: GraphQlSpecParts,
    sdl: String,
}

/// A specification repository that keeps the versions in memory with the rules of the port and of
/// the storage.
///
/// Pages follow the order of the identifiers, and [`FakeGraphQlSpecRepository::save`] applies the
/// uniqueness rules of the unit of work. No operation changes the SDL or the coordinates of a
/// stored version.
#[derive(Debug)]
pub struct FakeGraphQlSpecRepository {
    stored: Option<Mutex<Vec<Stored>>>,
}

impl FakeGraphQlSpecRepository {
    /// A repository without versions.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            stored: Some(Mutex::new(Vec::new())),
        }
    }

    /// A repository that answers `Unavailable`.
    #[must_use]
    pub const fn failing() -> Self {
        Self { stored: None }
    }

    /// Runs one specification statement as the unit of work does.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::AlreadyExists`] when the id is stored or the service already has a
    /// version with the same content hash, and [`RepositoryError::Unavailable`] for the failing
    /// repository; nothing changes then.
    pub fn save(&self, statement: &GraphQlSpecStatement) -> Result<(), RepositoryError> {
        let mut stored = self.lock()?;
        let written = statement.spec();
        let taken = stored.iter().any(|version| {
            version.parts.id == written.id
                || (version.parts.content.service == written.content.service
                    && version.parts.content.content_hash == written.content.content_hash)
        });
        if taken {
            return Err(RepositoryError::AlreadyExists);
        }
        stored.push(Stored {
            parts: written.clone(),
            sdl: statement.sdl().to_owned(),
        });
        drop(stored);
        Ok(())
    }

    /// The state of every stored version, in the order they were stored; empty for the failing
    /// repository.
    #[must_use]
    pub fn stored(&self) -> Vec<GraphQlSpecParts> {
        self.lock()
            .map(|stored| stored.iter().map(|version| version.parts.clone()).collect())
            .unwrap_or_default()
    }

    /// The versions in the order of their identifiers.
    fn sorted(&self) -> Result<Vec<Stored>, RepositoryError> {
        let mut versions = self.lock()?.clone();
        versions.sort_by_key(|version| version.parts.id);
        Ok(versions)
    }

    /// The stored versions, or `Unavailable` for the failing repository.
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Vec<Stored>>, RepositoryError> {
        self.stored
            .as_ref()
            .map(|stored| stored.lock().unwrap_or_else(PoisonError::into_inner))
            .ok_or_else(|| RepositoryError::Unavailable("in-memory repository failure".into()))
    }
}

impl Default for FakeGraphQlSpecRepository {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether `parts` matches the filters and comes after the cursor of `query`.
fn selected(parts: &GraphQlSpecParts, query: &GraphQlSpecPageQuery) -> bool {
    query.after.is_none_or(|after| parts.id > after)
        && query
            .service
            .as_ref()
            .is_none_or(|service| &parts.content.service == service)
        && query.status.is_none_or(|status| parts.status == status)
}

#[async_trait]
impl GraphQlSpecRepository for FakeGraphQlSpecRepository {
    async fn find_by_id(&self, id: SpecId) -> Result<Option<GraphQlSpec>, RepositoryError> {
        Ok(self
            .sorted()?
            .into_iter()
            .find(|version| version.parts.id == id)
            .map(|version| GraphQlSpec::restore(version.parts)))
    }

    async fn find_sdl(&self, id: SpecId) -> Result<Option<String>, RepositoryError> {
        Ok(self
            .sorted()?
            .into_iter()
            .find(|version| version.parts.id == id)
            .map(|version| version.sdl))
    }

    async fn find_by_content_hash(
        &self,
        service: &ServiceName,
        content_hash: &ContentHash,
    ) -> Result<Option<GraphQlSpec>, RepositoryError> {
        Ok(self
            .sorted()?
            .into_iter()
            .find(|version| {
                &version.parts.content.service == service
                    && &version.parts.content.content_hash == content_hash
            })
            .map(|version| GraphQlSpec::restore(version.parts)))
    }

    async fn find_active(
        &self,
        service: &ServiceName,
    ) -> Result<Vec<GraphQlSpec>, RepositoryError> {
        Ok(self
            .sorted()?
            .into_iter()
            .filter(|version| {
                &version.parts.content.service == service
                    && version.parts.status == SpecStatus::Active
            })
            .map(|version| GraphQlSpec::restore(version.parts))
            .collect())
    }

    async fn find_page(
        &self,
        query: &GraphQlSpecPageQuery,
    ) -> Result<Vec<GraphQlSpec>, RepositoryError> {
        let limit = usize::try_from(query.limit).unwrap_or(usize::MAX);
        Ok(self
            .sorted()?
            .into_iter()
            .filter(|version| selected(&version.parts, query))
            .take(limit)
            .map(|version| GraphQlSpec::restore(version.parts))
            .collect())
    }
}

#[cfg(test)]
mod tests;
