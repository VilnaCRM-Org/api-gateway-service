//! `RouteSetVersion`: the version of the full route set of one host, the `ETag` of
//! `GET /api/route-configurations/{host}` (FR-58).

use crate::route::RouteParts;
use crate::value_object::entity_version::EntityVersion;

/// The offset basis of the 64-bit FNV-1a hash.
const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;

/// The prime of the 64-bit FNV-1a hash.
const PRIME: u64 = 0x0000_0100_0000_01b3;

/// Names the version of a set of routes.
///
/// The version follows the routes and the versions they hold, not their order: it changes when a
/// route is created, changed or deleted, and a client that read it can tell whether the set is
/// still the one it read.
#[derive(Debug, Clone, Copy)]
pub struct RouteSetVersion;

impl RouteSetVersion {
    /// The version of the set of `routes`: a positive number of at most 52 bits, so that a client
    /// that reads JSON numbers as doubles keeps it exact, derived from the identifier and the
    /// version of every route, in the order of the identifiers.
    #[must_use]
    pub fn of(routes: &[RouteParts]) -> EntityVersion {
        let mut entries: Vec<(String, i64)> = routes
            .iter()
            .map(|route| (route.id.to_string(), route.version.value()))
            .collect();
        entries.sort();
        let hash = entries.iter().fold(OFFSET_BASIS, |hash, (id, version)| {
            format!("{id}:{version};").bytes().fold(hash, |hash, byte| {
                (hash ^ u64::from(byte)).wrapping_mul(PRIME)
            })
        });
        let positive = i64::try_from(hash >> 12).unwrap_or(i64::MAX) | 1;
        EntityVersion::new(positive).unwrap_or(EntityVersion::INITIAL)
    }
}

#[cfg(test)]
mod tests;
