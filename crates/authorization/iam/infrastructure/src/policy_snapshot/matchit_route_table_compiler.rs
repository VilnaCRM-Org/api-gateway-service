//! The per-host route matcher: one `matchit` router per method (FR-56).

use std::collections::BTreeMap;

use iam_domain::{
    HttpMethod, PathSegment, RouteConflict, RouteHost, RouteId, RouteMatcher, RouteParts,
    RouteTableCompiler,
};

/// Compiles the routes of one host into `matchit` routers.
#[derive(Debug, Default, Clone, Copy)]
pub struct MatchitRouteTableCompiler;

#[derive(Debug)]
struct MatchitRouteMatcher {
    routers: BTreeMap<HttpMethod, matchit::Router<RouteId>>,
}

impl RouteMatcher for MatchitRouteMatcher {
    fn find(&self, method: HttpMethod, path: &str) -> Option<RouteId> {
        self.routers
            .get(&method)?
            .at(path)
            .ok()
            .map(|matched| *matched.value)
    }
}

/// The `matchit` spelling of a route pattern.
///
/// `matchit` refuses two routes that name the parameter of one position differently, such as
/// `/a/{x}` and `/a/{y}/b`, although they are no conflict of the gateway. A parameter is therefore
/// named by its position in its own route (`p0`, `p1`, ...), never by the name the route gave it;
/// the route's own names stay in its pattern, and the matcher returns only the route.
fn pattern_of(route: &RouteParts) -> String {
    let segments = route.fields.path_pattern().segments();
    if segments.is_empty() {
        return "/".to_owned();
    }
    let mut position = 0_usize;
    let mut pattern = String::new();
    for segment in segments {
        pattern.push('/');
        match segment {
            PathSegment::Literal(text) => {
                pattern.push_str(&text.replace('{', "{{").replace('}', "}}"));
            }
            PathSegment::Parameter(_) => {
                pattern.push_str(&parameter(false, position));
                position = position.saturating_add(1);
            }
            PathSegment::CatchAll(_) => {
                pattern.push_str(&parameter(true, position));
                position = position.saturating_add(1);
            }
        }
    }
    pattern
}

/// The positional `matchit` parameter: `{p<position>}`, or `{*p<position>}` for a catch-all.
fn parameter(catch_all: bool, position: usize) -> String {
    let star = if catch_all { "*" } else { "" };
    format!("{{{star}p{position}}}")
}

impl RouteTableCompiler for MatchitRouteTableCompiler {
    fn compile(
        &self,
        host: &RouteHost,
        routes: &[RouteParts],
    ) -> Result<Box<dyn RouteMatcher>, RouteConflict> {
        let mut ordered: Vec<&RouteParts> = routes
            .iter()
            .filter(|route| route.fields.host() == host)
            .collect();
        ordered.sort_by_key(|route| route.id);
        let mut by_method: BTreeMap<HttpMethod, matchit::Router<RouteId>> = BTreeMap::new();
        let mut last: BTreeMap<HttpMethod, RouteId> = BTreeMap::new();
        for route in ordered {
            let pattern = pattern_of(route);
            for method in route.fields.methods() {
                let inserted = by_method
                    .entry(*method)
                    .or_default()
                    .insert(pattern.clone(), route.id);
                if inserted.is_err() {
                    return Err(RouteConflict::SamePattern {
                        first: last.get(method).copied().unwrap_or(route.id),
                        second: route.id,
                    });
                }
                last.insert(*method, route.id);
            }
        }
        Ok(Box::new(MatchitRouteMatcher { routers: by_method }))
    }
}

#[cfg(test)]
mod tests;
