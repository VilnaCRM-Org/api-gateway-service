//! Port that compiles the routes of one host into the matcher the gateway uses.

use crate::error::RouteConflict;
use crate::route::RouteParts;
use crate::value_object::http_method::HttpMethod;
use crate::value_object::identifier::RouteId;
use crate::value_object::route_host::RouteHost;

/// The compiled routes of one host: finds the route that serves a request.
pub trait RouteMatcher: std::fmt::Debug + Send + Sync {
    /// The route that serves `method` and `path`: the most specific route whose pattern matches
    /// and whose methods include `method`; `None` when no route matches.
    fn find(&self, method: HttpMethod, path: &str) -> Option<RouteId>;
}

/// Compiles the full route configuration of one host into a [`RouteMatcher`].
pub trait RouteTableCompiler: std::fmt::Debug + Send + Sync {
    /// Compiles `routes`, all of `host`, after validating them as a set.
    ///
    /// # Errors
    ///
    /// The [`RouteConflict`] of the first pair of routes that conflict.
    fn compile(
        &self,
        host: &RouteHost,
        routes: &[RouteParts],
    ) -> Result<Box<dyn RouteMatcher>, RouteConflict>;
}
