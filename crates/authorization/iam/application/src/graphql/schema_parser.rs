//! The `async-graphql` adapter of the [`GraphQlSchemaParser`] port.

use async_graphql::parser::types::{
    BaseType, ConstDirective, FieldDefinition, SchemaDefinition, Type, TypeDefinition, TypeKind,
    TypeSystemDefinition,
};
use async_graphql::parser::{Pos, Positioned, parse_schema};
use iam_domain::{
    GqlName, GraphQlCoordinate, GraphQlField, GraphQlSchemaParser, GraphQlSpec, GraphQlTypeGraph,
    InvalidSpec, PermissionFlags, SpecPosition,
};

const SENSITIVE_DIRECTIVE: &str = "iamSensitive";
const AUDIT_ALWAYS_DIRECTIVE: &str = "iamAuditAlways";

/// Parses SDL with the parser of `async-graphql`.
///
/// The size limit is checked before the parser sees the document, the type limit while the
/// definitions are walked and the field limit by [`GraphQlTypeGraph::new`].
#[derive(Debug, Default, Clone, Copy)]
pub struct AsyncGraphQlSchemaParser;

impl GraphQlSchemaParser for AsyncGraphQlSchemaParser {
    fn parse(&self, sdl: &str) -> Result<GraphQlTypeGraph, InvalidSpec> {
        if sdl.len() > GraphQlSpec::MAX_SDL_BYTES {
            return Err(InvalidSpec::TooLarge {
                limit: GraphQlSpec::MAX_SDL_BYTES,
            });
        }
        let document = parse_schema(sdl).map_err(|error| {
            let position = error
                .positions()
                .next()
                .unwrap_or(Pos { line: 1, column: 1 });
            malformed(error.to_string(), position)
        })?;
        let roots = RootNames::of(&document.definitions);
        let mut collector = Collector::default();
        for definition in &document.definitions {
            if let TypeSystemDefinition::Type(type_definition) = definition {
                collector.add_type(type_definition, &roots)?;
            }
        }
        GraphQlTypeGraph::new(collector.fields, collector.possible_types)
    }
}

/// The names of the root types, which a `schema` definition may change.
struct RootNames {
    query: String,
    mutation: String,
    subscription: String,
}

impl RootNames {
    fn of(definitions: &[TypeSystemDefinition]) -> Self {
        let mut roots = Self {
            query: "Query".to_owned(),
            mutation: "Mutation".to_owned(),
            subscription: "Subscription".to_owned(),
        };
        for definition in definitions {
            if let TypeSystemDefinition::Schema(schema) = definition {
                roots.apply(&schema.node);
            }
        }
        roots
    }

    fn apply(&mut self, schema: &SchemaDefinition) {
        if let Some(root) = &schema.query {
            self.query = root.node.to_string();
        }
        if let Some(root) = &schema.mutation {
            self.mutation = root.node.to_string();
        }
        if let Some(root) = &schema.subscription {
            self.subscription = root.node.to_string();
        }
    }

    /// The name a type has in a coordinate: `Query`, `Mutation` or `Subscription` for a root.
    fn coordinate_type<'a>(&self, name: &'a str) -> &'a str {
        if name == self.query {
            "Query"
        } else if name == self.mutation {
            "Mutation"
        } else if name == self.subscription {
            "Subscription"
        } else {
            name
        }
    }
}

#[derive(Default)]
struct Collector {
    fields: Vec<(GraphQlCoordinate, GraphQlField)>,
    possible_types: Vec<(GqlName, GqlName)>,
    declared_types: usize,
}

impl Collector {
    fn add_type(
        &mut self,
        definition: &Positioned<TypeDefinition>,
        roots: &RootNames,
    ) -> Result<(), InvalidSpec> {
        let node = &definition.node;
        if !node.extend {
            self.declared_types += 1;
            if self.declared_types > GraphQlTypeGraph::MAX_TYPES {
                return Err(InvalidSpec::TooManyTypes {
                    limit: GraphQlTypeGraph::MAX_TYPES,
                });
            }
        }
        match &node.kind {
            TypeKind::Object(object) => {
                let type_name = graph_name(
                    roots.coordinate_type(node.name.node.as_str()),
                    node.name.pos,
                )?;
                for interface in &object.implements {
                    let interface_name = graph_name(interface.node.as_str(), interface.pos)?;
                    self.possible_types
                        .push((interface_name, type_name.clone()));
                }
                self.add_fields(&type_name, &object.fields)
            }
            TypeKind::Interface(interface) => {
                let type_name = graph_name(node.name.node.as_str(), node.name.pos)?;
                self.add_fields(&type_name, &interface.fields)
            }
            TypeKind::Union(union) => {
                let type_name = graph_name(node.name.node.as_str(), node.name.pos)?;
                for member in &union.members {
                    let member_name = graph_name(member.node.as_str(), member.pos)?;
                    self.possible_types.push((type_name.clone(), member_name));
                }
                Ok(())
            }
            TypeKind::Scalar | TypeKind::Enum(_) | TypeKind::InputObject(_) => Ok(()),
        }
    }

    fn add_fields(
        &mut self,
        type_name: &GqlName,
        fields: &[Positioned<FieldDefinition>],
    ) -> Result<(), InvalidSpec> {
        for field in fields {
            let node = &field.node;
            let name = graph_name(node.name.node.as_str(), node.name.pos)?;
            let return_type = graph_name(named_type(&node.ty.node), node.ty.pos)?;
            self.fields.push((
                GraphQlCoordinate::new(type_name.clone(), name),
                GraphQlField {
                    return_type,
                    flags: flags_of(&node.directives),
                },
            ));
        }
        Ok(())
    }
}

/// The named type below the list wrappers of a type.
fn named_type(mut ty: &Type) -> &str {
    loop {
        match &ty.base {
            BaseType::Named(name) => return name.as_str(),
            BaseType::List(inner) => ty = inner,
        }
    }
}

fn flags_of(directives: &[Positioned<ConstDirective>]) -> PermissionFlags {
    directives
        .iter()
        .fold(PermissionFlags::NONE, |flags, directive| {
            match directive.node.name.node.as_str() {
                SENSITIVE_DIRECTIVE => flags.with_sensitive(),
                AUDIT_ALWAYS_DIRECTIVE => flags.with_audit_always(),
                _ => flags,
            }
        })
}

fn graph_name(value: &str, pos: Pos) -> Result<GqlName, InvalidSpec> {
    GqlName::parse(value).ok_or_else(|| {
        malformed(
            format!("The name {value} is not allowed in a coordinate."),
            pos,
        )
    })
}

fn malformed(message: String, pos: Pos) -> InvalidSpec {
    InvalidSpec::Malformed {
        message,
        position: SpecPosition::LineColumn {
            line: u32::try_from(pos.line).unwrap_or(u32::MAX),
            column: u32::try_from(pos.column).unwrap_or(u32::MAX),
        },
    }
}

#[cfg(test)]
mod tests;
