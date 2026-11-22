//! A set of GraphQL field coordinates with their flags.

use std::collections::BTreeMap;

use crate::value_object::graphql_coordinate::GraphQlCoordinate;
use crate::value_object::permission_flags::PermissionFlags;

/// Distinct coordinates in their natural order, each with its sensitive and always-audit flags.
///
/// A coordinate added twice keeps the most restrictive flags of both, which is also how the union
/// of several active versions combines flags.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CoordinateSet(BTreeMap<GraphQlCoordinate, PermissionFlags>);

impl CoordinateSet {
    /// A set without coordinates.
    #[must_use]
    pub const fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Adds a coordinate; when it is already present its flags become the most restrictive
    /// combination of both.
    pub fn insert(&mut self, coordinate: GraphQlCoordinate, flags: PermissionFlags) {
        self.0
            .entry(coordinate)
            .and_modify(|stored| *stored = stored.most_restrictive(flags))
            .or_insert(flags);
    }

    /// The union of both sets, flags combined most restrictively.
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        let mut union = self.clone();
        other
            .iter()
            .for_each(|(coordinate, flags)| union.insert(coordinate.clone(), flags));
        union
    }

    /// Whether the set holds the coordinate.
    #[must_use]
    pub fn contains(&self, coordinate: &GraphQlCoordinate) -> bool {
        self.0.contains_key(coordinate)
    }

    /// The flags of the coordinate, when the set holds it.
    #[must_use]
    pub fn flags(&self, coordinate: &GraphQlCoordinate) -> Option<PermissionFlags> {
        self.0.get(coordinate).copied()
    }

    /// The number of coordinates.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the set holds no coordinate.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The coordinates with their flags, in order.
    pub fn iter(&self) -> impl Iterator<Item = (&GraphQlCoordinate, PermissionFlags)> {
        self.0
            .iter()
            .map(|(coordinate, flags)| (coordinate, *flags))
    }
}

impl FromIterator<(GraphQlCoordinate, PermissionFlags)> for CoordinateSet {
    fn from_iter<I: IntoIterator<Item = (GraphQlCoordinate, PermissionFlags)>>(iter: I) -> Self {
        let mut set = Self::new();
        iter.into_iter()
            .for_each(|(coordinate, flags)| set.insert(coordinate, flags));
        set
    }
}

#[cfg(test)]
mod tests;
