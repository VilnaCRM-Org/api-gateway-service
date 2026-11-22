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

/// The deepest nesting of `[`, `{` and `(` the recursive parser is given; deeper input is refused
/// before parsing, because the size limit alone does not bound the parser's stack depth.
const MAX_NESTING: usize = 64;

/// Parses SDL with the parser of `async-graphql`.
///
/// The size and nesting limits are checked before the parser sees the document, the type limit while the
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
        check_nesting(sdl)?;
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

    /// Whether `name` is one of the names `Query`, `Mutation` or `Subscription` while the root of
    /// that name was renamed and `name` is no root at all: its coordinates would read as a root's.
    fn takes_a_root_name(&self, name: &str) -> bool {
        let renamed = [
            ("Query", &self.query),
            ("Mutation", &self.mutation),
            ("Subscription", &self.subscription),
        ]
        .iter()
        .any(|(canonical, root)| name == *canonical && root.as_str() != *canonical);
        renamed && self.coordinate_type(name) == name
    }

    /// The type name of a coordinate, refusing a type that takes a renamed root's name.
    fn graph_type(&self, name: &str, pos: Pos) -> Result<GqlName, InvalidSpec> {
        if self.takes_a_root_name(name) {
            return Err(malformed(
                format!("The type {name} has the name of a renamed root type."),
                pos,
            ));
        }
        graph_name(self.coordinate_type(name), pos)
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
            self.declared_types = self.declared_types.saturating_add(1);
            if self.declared_types > GraphQlTypeGraph::MAX_TYPES {
                return Err(InvalidSpec::TooManyTypes {
                    limit: GraphQlTypeGraph::MAX_TYPES,
                });
            }
        }
        match &node.kind {
            TypeKind::Object(object) => {
                let type_name = roots.graph_type(node.name.node.as_str(), node.name.pos)?;
                for interface in &object.implements {
                    let interface_name =
                        roots.graph_type(interface.node.as_str(), interface.pos)?;
                    self.possible_types
                        .push((interface_name, type_name.clone()));
                }
                self.add_fields(&type_name, &object.fields, roots)
            }
            TypeKind::Interface(interface) => {
                let type_name = roots.graph_type(node.name.node.as_str(), node.name.pos)?;
                self.add_fields(&type_name, &interface.fields, roots)
            }
            TypeKind::Union(union) => {
                let type_name = roots.graph_type(node.name.node.as_str(), node.name.pos)?;
                for member in &union.members {
                    let member_name = roots.graph_type(member.node.as_str(), member.pos)?;
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
        roots: &RootNames,
    ) -> Result<(), InvalidSpec> {
        for field in fields {
            let node = &field.node;
            let name = graph_name(node.name.node.as_str(), node.name.pos)?;
            let return_type = roots.graph_type(named_type(&node.ty.node), node.ty.pos)?;
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

/// Refuses SDL whose `[`, `{` or `(` nesting outside strings and comments exceeds
/// [`MAX_NESTING`], at the opener that crosses it.
fn check_nesting(sdl: &str) -> Result<(), InvalidSpec> {
    let bytes = sdl.as_bytes();
    let mut depth = 0_usize;
    let mut index = 0_usize;
    while let Some(byte) = bytes.get(index) {
        index = match byte {
            b'#' => skip_comment(bytes, index),
            b'"' => skip_string(bytes, index),
            b'[' | b'{' | b'(' => {
                depth = depth.saturating_add(1);
                if depth > MAX_NESTING {
                    return Err(malformed(
                        format!("The document nests deeper than {MAX_NESTING} levels."),
                        position_of(sdl, index),
                    ));
                }
                index.saturating_add(1)
            }
            b']' | b'}' | b')' => {
                depth = depth.saturating_sub(1);
                index.saturating_add(1)
            }
            _ => index.saturating_add(1),
        };
    }
    Ok(())
}

/// The bytes from `start` on, empty past the end.
fn rest_of(bytes: &[u8], start: usize) -> &[u8] {
    bytes.get(start..).unwrap_or_default()
}

/// The index after the comment that starts at `start`.
fn skip_comment(bytes: &[u8], start: usize) -> usize {
    rest_of(bytes, start)
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(bytes.len(), |offset| {
            start.saturating_add(offset).saturating_add(1)
        })
}

/// The index after the string or block string that starts at `start`.
fn skip_string(bytes: &[u8], start: usize) -> usize {
    if rest_of(bytes, start).starts_with(b"\"\"\"") {
        skip_block_string(bytes, start.saturating_add(3))
    } else {
        skip_line_string(bytes, start.saturating_add(1))
    }
}

/// The index after the closing `"""`; `\"""` is an escaped quote run.
fn skip_block_string(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() {
        let rest = rest_of(bytes, index);
        if rest.starts_with(b"\\\"\"\"") {
            index = index.saturating_add(4);
        } else if rest.starts_with(b"\"\"\"") {
            return index.saturating_add(3);
        } else {
            index = index.saturating_add(1);
        }
    }
    bytes.len()
}

/// The index after the closing `"` or the end of the line of an unterminated string.
fn skip_line_string(bytes: &[u8], mut index: usize) -> usize {
    while let Some(byte) = bytes.get(index) {
        match byte {
            b'\\' => index = index.saturating_add(2),
            b'"' | b'\n' => return index.saturating_add(1),
            _ => index = index.saturating_add(1),
        }
    }
    bytes.len()
}

/// The one-based line and column of a byte index.
fn position_of(sdl: &str, index: usize) -> Pos {
    let before = sdl.as_bytes().get(..index).unwrap_or(sdl.as_bytes());
    let mut lines = before.split(|byte| *byte == b'\n');
    let current_line = lines.next_back().unwrap_or_default();
    Pos {
        line: lines.count().saturating_add(1),
        column: current_line.len().saturating_add(1),
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
