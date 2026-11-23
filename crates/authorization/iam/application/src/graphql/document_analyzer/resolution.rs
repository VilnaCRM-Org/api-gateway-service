//! Resolution of a selected operation against the type graph.

use std::collections::HashMap;

use async_graphql::Name;
use async_graphql::parser::Positioned;
use async_graphql::parser::types::{
    ExecutableDocument, Field, FragmentDefinition, InlineFragment, OperationDefinition,
    OperationType, Selection, SelectionSet,
};
use iam_domain::{
    AnalyzedDocument, CoordinateSet, DocumentRefusal, GqlName, GraphQlCoordinate, GraphQlTypeGraph,
};

const TYPENAME_FIELD: &str = "__typename";
const INTROSPECTION_FIELDS: [&str; 2] = ["__schema", "__type"];
const QUERY_ROOT: &str = "Query";

/// Resolves the selected operation.
///
/// Fields of an interface outside a concrete fragment keep the interface coordinate, fields under
/// a type condition take the coordinate of that type, `__typename` is ignored and `__schema` and
/// `__type` on the query root set the introspection flag.
pub(super) fn resolve(
    document: &ExecutableDocument,
    operation: &OperationDefinition,
    graph: &GraphQlTypeGraph,
) -> Result<AnalyzedDocument, DocumentRefusal> {
    let root = root_type(operation.ty)?;
    let mut resolver = Resolver {
        graph,
        fragments: &document.fragments,
        memo: HashMap::new(),
    };
    let mut found = Found::default();
    resolver.collect(&operation.selection_set.node, &root, &mut found)?;
    Ok(AnalyzedDocument::new(
        found.coordinates,
        found.introspection,
    ))
}

/// The canonical root type of an operation type.
fn root_type(operation_type: OperationType) -> Result<GqlName, DocumentRefusal> {
    let name = match operation_type {
        OperationType::Query => QUERY_ROOT,
        OperationType::Mutation => "Mutation",
        OperationType::Subscription => "Subscription",
    };
    type_name(name)
}

fn type_name(name: &str) -> Result<GqlName, DocumentRefusal> {
    GqlName::parse(name).ok_or(DocumentRefusal::MalformedOperation)
}

#[derive(Default)]
struct Found {
    coordinates: CoordinateSet,
    introspection: bool,
}

impl Found {
    fn merge(&mut self, other: &Self) {
        for (coordinate, flags) in other.coordinates.iter() {
            self.coordinates.insert(coordinate.clone(), flags);
        }
        self.introspection |= other.introspection;
    }
}

/// The refusal for a field the graph lacks: unknown when its type declares fields, malformed when
/// the type has none (a union, a leaf or no type at all).
fn missing_field(graph: &GraphQlTypeGraph, parent: &GqlName) -> DocumentRefusal {
    if graph.declares_fields(parent) {
        DocumentRefusal::UnknownOperation
    } else {
        DocumentRefusal::MalformedOperation
    }
}

struct Resolver<'a> {
    graph: &'a GraphQlTypeGraph,
    fragments: &'a HashMap<Name, Positioned<FragmentDefinition>>,
    memo: HashMap<&'a str, Found>,
}

impl<'a> Resolver<'a> {
    /// Adds what `set` selects on `parent` to `found`.
    fn collect(
        &mut self,
        set: &'a SelectionSet,
        parent: &GqlName,
        found: &mut Found,
    ) -> Result<(), DocumentRefusal> {
        for item in &set.items {
            match &item.node {
                Selection::Field(field) => self.collect_field(&field.node, parent, found)?,
                Selection::InlineFragment(fragment) => {
                    self.collect_inline(&fragment.node, parent, found)?;
                }
                Selection::FragmentSpread(spread) => {
                    self.collect_spread(spread.node.fragment_name.node.as_str(), parent, found)?;
                }
            }
        }
        Ok(())
    }

    fn collect_field(
        &mut self,
        field: &'a Field,
        parent: &GqlName,
        found: &mut Found,
    ) -> Result<(), DocumentRefusal> {
        let name = field.name.node.as_str();
        if name == TYPENAME_FIELD {
            return Ok(());
        }
        if parent.as_str() == QUERY_ROOT && INTROSPECTION_FIELDS.contains(&name) {
            found.introspection = true;
            return Ok(());
        }
        let coordinate = GqlName::parse(name)
            .map(|field_name| GraphQlCoordinate::new(parent.clone(), field_name))
            .ok_or(DocumentRefusal::MalformedOperation)?;
        let graph = self.graph;
        let declared = graph
            .field(&coordinate)
            .ok_or_else(|| missing_field(graph, parent))?;
        found.coordinates.insert(coordinate, declared.flags);
        self.collect_below(&field.selection_set.node, &declared.return_type, found)
    }

    /// Resolves the selection below a field of type `returned`: a composite type needs one and a
    /// leaf type takes none.
    fn collect_below(
        &mut self,
        set: &'a SelectionSet,
        returned: &GqlName,
        found: &mut Found,
    ) -> Result<(), DocumentRefusal> {
        if self.graph.is_composite(returned) == set.items.is_empty() {
            return Err(DocumentRefusal::MalformedOperation);
        }
        self.collect(set, returned, found)
    }

    fn collect_inline(
        &mut self,
        fragment: &'a InlineFragment,
        parent: &GqlName,
        found: &mut Found,
    ) -> Result<(), DocumentRefusal> {
        let selection = &fragment.selection_set.node;
        match &fragment.type_condition {
            None => self.collect(selection, parent, found),
            Some(condition) => {
                let condition = self.applicable(condition.node.on.node.as_str(), parent)?;
                self.collect(selection, &condition, found)
            }
        }
    }

    fn collect_spread(
        &mut self,
        name: &'a str,
        parent: &GqlName,
        found: &mut Found,
    ) -> Result<(), DocumentRefusal> {
        let definition = self
            .fragments
            .get(name)
            .ok_or(DocumentRefusal::MalformedOperation)?;
        let condition =
            self.applicable(definition.node.type_condition.node.on.node.as_str(), parent)?;
        if !self.memo.contains_key(name) {
            let mut resolved = Found::default();
            self.collect(
                &definition.node.selection_set.node,
                &condition,
                &mut resolved,
            )?;
            self.memo.insert(name, resolved);
        }
        if let Some(resolved) = self.memo.get(name) {
            found.merge(resolved);
        }
        Ok(())
    }

    /// The type of a type condition when it is composite and can apply where the type is
    /// `parent`.
    fn applicable(&self, condition: &str, parent: &GqlName) -> Result<GqlName, DocumentRefusal> {
        let condition = type_name(condition)?;
        if self.graph.is_composite(&condition) && self.graph.types_overlap(parent, &condition) {
            Ok(condition)
        } else {
            Err(DocumentRefusal::MalformedOperation)
        }
    }
}
