//! The type graph of a GraphQL schema, as far as authorization needs it.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::InvalidSpec;
use crate::value_object::coordinate_set::CoordinateSet;
use crate::value_object::gql_name::GqlName;
use crate::value_object::graphql_coordinate::GraphQlCoordinate;
use crate::value_object::permission_flags::PermissionFlags;

/// What a schema says about one field: the named type it returns (list and non-null wrappers
/// removed) and its `@iamSensitive` and `@iamAuditAlways` flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphQlField {
    /// The named type the field returns.
    pub return_type: GqlName,
    /// The flags the field directives set.
    pub flags: PermissionFlags,
}

/// The fields of the object and interface types of a schema and the possible types of its
/// interfaces and unions.
///
/// At most [`GraphQlTypeGraph::MAX_FIELDS`] fields over at
/// most [`GraphQlTypeGraph::MAX_TYPES`] types.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GraphQlTypeGraph {
    fields: BTreeMap<GraphQlCoordinate, GraphQlField>,
    possible_types: BTreeMap<GqlName, BTreeSet<GqlName>>,
}

impl GraphQlTypeGraph {
    /// The largest number of types of a schema (FR-30).
    pub const MAX_TYPES: usize = 10_000;

    /// The largest number of fields of a schema (FR-30).
    pub const MAX_FIELDS: usize = 100_000;

    /// Builds the graph from the fields and the `(abstract type, possible type)` pairs.
    ///
    /// # Errors
    ///
    /// [`InvalidSpec::TooManyFields`] past [`Self::MAX_FIELDS`] fields,
    /// [`InvalidSpec::DuplicateField`] for a coordinate given twice and
    /// [`InvalidSpec::TooManyTypes`] when the fields and the possible types name more than
    /// [`Self::MAX_TYPES`] types.
    pub fn new<F, P>(fields: F, possible_types: P) -> Result<Self, InvalidSpec>
    where
        F: IntoIterator<Item = (GraphQlCoordinate, GraphQlField)>,
        P: IntoIterator<Item = (GqlName, GqlName)>,
    {
        let mut graph = Self::default();
        for (coordinate, field) in fields {
            graph.insert_field(coordinate, field)?;
        }
        for (abstract_type, possible_type) in possible_types {
            graph
                .possible_types
                .entry(abstract_type)
                .or_default()
                .insert(possible_type);
        }
        if graph.type_count() > Self::MAX_TYPES {
            return Err(InvalidSpec::TooManyTypes {
                limit: Self::MAX_TYPES,
            });
        }
        Ok(graph)
    }

    /// Adds one field, refusing a duplicate and the field past the limit.
    fn insert_field(
        &mut self,
        coordinate: GraphQlCoordinate,
        field: GraphQlField,
    ) -> Result<(), InvalidSpec> {
        if self.fields.len() >= Self::MAX_FIELDS {
            return Err(InvalidSpec::TooManyFields {
                limit: Self::MAX_FIELDS,
            });
        }
        if self.fields.contains_key(&coordinate) {
            return Err(InvalidSpec::DuplicateField {
                coordinate: coordinate.to_string(),
            });
        }
        self.fields.insert(coordinate, field);
        Ok(())
    }

    /// The number of distinct types that declare a field, are abstract or are a possible type.
    #[must_use]
    pub fn type_count(&self) -> usize {
        let declaring = self.fields.keys().map(GraphQlCoordinate::type_name);
        let abstract_types = self.possible_types.keys();
        let members = self.possible_types.values().flatten();
        declaring
            .chain(abstract_types)
            .chain(members)
            .collect::<BTreeSet<_>>()
            .len()
    }

    /// The number of fields.
    #[must_use]
    pub fn field_count(&self) -> usize {
        self.fields.len()
    }

    /// The field at a coordinate.
    #[must_use]
    pub fn field(&self, coordinate: &GraphQlCoordinate) -> Option<&GraphQlField> {
        self.fields.get(coordinate)
    }

    /// Whether the type declares at least one field.
    #[must_use]
    pub fn declares_fields(&self, type_name: &GqlName) -> bool {
        // `A` sorts before every other valid name, so the first coordinate at or after
        // `{type}.A` is the first field of the type, if it has one.
        GqlName::parse("A").is_some_and(|lowest| {
            self.fields
                .range(GraphQlCoordinate::new(type_name.clone(), lowest)..)
                .next()
                .is_some_and(|(coordinate, _)| coordinate.type_name() == type_name)
        })
    }

    /// Whether selections on the type name fields: it declares fields or is an interface or union
    /// with possible types.
    #[must_use]
    pub fn is_composite(&self, type_name: &GqlName) -> bool {
        self.possible_types.contains_key(type_name) || self.declares_fields(type_name)
    }

    /// Whether a fragment on `condition` can apply where the type is `parent`: the names are
    /// equal, one is a possible type of the other or both share a possible type.
    #[must_use]
    pub fn types_overlap(&self, parent: &GqlName, condition: &GqlName) -> bool {
        parent == condition
            || self
                .possible_types(parent)
                .any(|member| member == condition)
            || self
                .possible_types(condition)
                .any(|member| member == parent)
            || self
                .possible_types(parent)
                .any(|member| self.possible_types(condition).any(|other| other == member))
    }

    /// The fields in coordinate order.
    pub fn fields(&self) -> impl Iterator<Item = (&GraphQlCoordinate, &GraphQlField)> {
        self.fields.iter()
    }

    /// The possible types of an interface or a union, in name order; empty for any other type.
    pub fn possible_types(&self, abstract_type: &GqlName) -> impl Iterator<Item = &GqlName> {
        self.possible_types.get(abstract_type).into_iter().flatten()
    }

    /// Every pair of an abstract type and one of its possible types, in the order of the names.
    pub fn possible_type_pairs(&self) -> impl Iterator<Item = (&GqlName, &GqlName)> {
        self.possible_types
            .iter()
            .flat_map(|(abstract_type, members)| {
                members.iter().map(move |member| (abstract_type, member))
            })
    }

    /// Every coordinate with its flags.
    #[must_use]
    pub fn coordinates(&self) -> CoordinateSet {
        self.fields
            .iter()
            .map(|(coordinate, field)| (coordinate.clone(), field.flags))
            .collect()
    }
}

#[cfg(test)]
mod tests;
