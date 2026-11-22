//! GraphQL SDL parser port.

use crate::error::InvalidSpec;
use crate::value_object::graphql_type_graph::GraphQlTypeGraph;

/// Turns an SDL document into a [`GraphQlTypeGraph`].
///
/// The adapter refuses a document over
/// [`GraphQlSpec::MAX_SDL_BYTES`](crate::GraphQlSpec::MAX_SDL_BYTES) before it starts parsing
/// and enforces the type and field limits of [`GraphQlTypeGraph`]. Parsing is pure computation,
/// so the port is synchronous.
pub trait GraphQlSchemaParser: std::fmt::Debug + Send + Sync {
    /// Parses the document.
    ///
    /// # Errors
    ///
    /// [`InvalidSpec::TooLarge`], [`InvalidSpec::TooManyTypes`] or [`InvalidSpec::TooManyFields`]
    /// for a document over a limit, [`InvalidSpec::Malformed`] with the line and column of a syntax
    /// or schema error and [`InvalidSpec::DuplicateField`] for a field defined twice.
    fn parse(&self, sdl: &str) -> Result<GraphQlTypeGraph, InvalidSpec>;
}
