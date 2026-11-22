//! The JSON adapter of the [`OpenApiDocumentParser`] port.

use async_graphql::Value as ConstValue;
use axum::Json;
use iam_domain::{
    HttpMethod, InvalidSpec, OpenApiDocumentParser, OpenApiSpec, PathTemplate, PermissionFlags,
    RestOperation, RestOperationSet, SpecPosition,
};

/// The operation members of a path item that name a permission key, with their methods. `trace`
/// has no [`HttpMethod`] and is not a permission key.
const METHODS: [(&str, HttpMethod); 7] = [
    ("get", HttpMethod::Get),
    ("put", HttpMethod::Put),
    ("post", HttpMethod::Post),
    ("delete", HttpMethod::Delete),
    ("options", HttpMethod::Options),
    ("head", HttpMethod::Head),
    ("patch", HttpMethod::Patch),
];

/// The longest chain of path items that refer to one another.
const MAX_REFERENCE_HOPS: usize = 8;

/// Parses `OpenAPI` 3.0.x and 3.1.x JSON documents.
///
/// The document is decoded through the JSON decoding of `axum`'s `Json` type into the value type of
/// the GraphQL adapter, so no crate joins the allow-list of the application layer. Only internal
/// references (`#/...`) are accepted and none is ever fetched; the path items that are references
/// are resolved inside the document. YAML is not accepted.
#[derive(Debug, Default, Clone, Copy)]
pub struct JsonOpenApiDocumentParser;

impl OpenApiDocumentParser for JsonOpenApiDocumentParser {
    fn parse(&self, document: &str) -> Result<RestOperationSet, InvalidSpec> {
        if document.len() > OpenApiSpec::MAX_DOCUMENT_BYTES {
            return Err(InvalidSpec::DocumentTooLarge {
                limit: OpenApiSpec::MAX_DOCUMENT_BYTES,
            });
        }
        let root = decode(document)?;
        check_version(&root)?;
        reject_external_references(&root)?;
        collect_operations(&root)
    }
}

/// A fault at a JSON pointer of the document.
fn malformed(message: &str, pointer: impl Into<String>) -> InvalidSpec {
    InvalidSpec::Malformed {
        message: message.to_owned(),
        position: SpecPosition::JsonPointer(pointer.into()),
    }
}

/// Decodes the text; content that does not start like a JSON object is reported as the YAML or
/// other text that it most likely is.
fn decode(document: &str) -> Result<ConstValue, InvalidSpec> {
    Json::<ConstValue>::from_bytes(document.as_bytes())
        .map(|Json(value)| value)
        .map_err(|_decode_error| {
            let message = if document.trim_start().starts_with('{') {
                "The document is not valid JSON."
            } else {
                "The document must be a JSON object; YAML is not accepted."
            };
            malformed(message, "")
        })
}

/// The member of an object; `None` for any other value.
fn member<'a>(value: &'a ConstValue, key: &str) -> Option<&'a ConstValue> {
    match value {
        ConstValue::Object(members) => members.get(key),
        ConstValue::Null
        | ConstValue::Number(_)
        | ConstValue::String(_)
        | ConstValue::Boolean(_)
        | ConstValue::Binary(_)
        | ConstValue::Enum(_)
        | ConstValue::List(_) => None,
    }
}

/// The text of a JSON pointer token (RFC 6901).
fn escape(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

/// Accepts `3.0.x` and `3.1.x`.
fn check_version(root: &ConstValue) -> Result<(), InvalidSpec> {
    let supported = matches!(
        member(root, "openapi"),
        Some(ConstValue::String(version)) if is_supported_version(version)
    );
    if supported {
        Ok(())
    } else {
        Err(malformed(
            "The document must declare OpenAPI 3.0.x or 3.1.x in `openapi`.",
            "/openapi",
        ))
    }
}

fn is_supported_version(version: &str) -> bool {
    ["3.0.", "3.1."].iter().any(|prefix| {
        version
            .strip_prefix(prefix)
            .is_some_and(|patch| !patch.is_empty() && patch.chars().all(|c| c.is_ascii_digit()))
    })
}

/// Whether a reference points inside the document.
fn is_internal(reference: &str) -> bool {
    reference == "#" || reference.starts_with("#/")
}

/// Refuses the first `$ref` that is not internal, at the pointer of the `$ref` member.
fn reject_external_references(root: &ConstValue) -> Result<(), InvalidSpec> {
    let mut pending = vec![(String::new(), root)];
    while let Some((pointer, value)) = pending.pop() {
        match value {
            ConstValue::Object(members) => {
                for (name, child) in members {
                    let child_pointer = format!("{pointer}/{}", escape(name));
                    if is_external_reference(name, child) {
                        return Err(malformed(
                            "External references are not supported.",
                            child_pointer,
                        ));
                    }
                    pending.push((child_pointer, child));
                }
            }
            ConstValue::List(items) => pending.extend(
                items
                    .iter()
                    .enumerate()
                    .map(|(index, child)| (format!("{pointer}/{index}"), child)),
            ),
            ConstValue::Null
            | ConstValue::Number(_)
            | ConstValue::String(_)
            | ConstValue::Boolean(_)
            | ConstValue::Binary(_)
            | ConstValue::Enum(_) => {}
        }
    }
    Ok(())
}

fn is_external_reference(name: &str, value: &ConstValue) -> bool {
    name == "$ref" && matches!(value, ConstValue::String(target) if !is_internal(target))
}

/// The value an internal reference points to.
fn resolve_pointer<'a>(root: &'a ConstValue, reference: &str) -> Option<&'a ConstValue> {
    let pointer = reference.strip_prefix('#')?;
    if pointer.is_empty() {
        return Some(root);
    }
    pointer
        .strip_prefix('/')?
        .split('/')
        .map(|token| token.replace("~1", "/").replace("~0", "~"))
        .try_fold(root, |value, token| match value {
            ConstValue::Object(members) => members.get(token.as_str()),
            ConstValue::List(items) => token
                .parse::<usize>()
                .ok()
                .and_then(|index| items.get(index)),
            ConstValue::Null
            | ConstValue::Number(_)
            | ConstValue::String(_)
            | ConstValue::Boolean(_)
            | ConstValue::Binary(_)
            | ConstValue::Enum(_) => None,
        })
}

/// Follows the `$ref` of a path item until a path item without one.
fn resolve_path_item<'a>(
    root: &'a ConstValue,
    item: &'a ConstValue,
    pointer: &str,
) -> Result<&'a ConstValue, InvalidSpec> {
    let mut current = item;
    for _ in 0..=MAX_REFERENCE_HOPS {
        let Some(ConstValue::String(target)) = member(current, "$ref") else {
            return Ok(current);
        };
        current = resolve_pointer(root, target).ok_or_else(|| {
            malformed("The reference does not resolve.", format!("{pointer}/$ref"))
        })?;
    }
    Err(malformed(
        "The reference chain is too long.",
        format!("{pointer}/$ref"),
    ))
}

/// The operations of every path item of `paths`.
fn collect_operations(root: &ConstValue) -> Result<RestOperationSet, InvalidSpec> {
    let mut operations = RestOperationSet::new();
    let Some(paths) = member(root, "paths") else {
        return Ok(operations);
    };
    let ConstValue::Object(paths) = paths else {
        return Err(malformed("`paths` must be an object.", "/paths"));
    };
    for (path, item) in paths {
        if path.starts_with("x-") {
            continue;
        }
        let pointer = format!("/paths/{}", escape(path));
        let template = PathTemplate::from_openapi_path(path)
            .ok_or_else(|| malformed("The path is not a valid path template.", pointer.clone()))?;
        let item = resolve_path_item(root, item, &pointer)?;
        add_operations(&mut operations, &template, item, &pointer)?;
    }
    Ok(operations)
}

/// Adds the operations of one path item.
fn add_operations(
    operations: &mut RestOperationSet,
    template: &PathTemplate,
    item: &ConstValue,
    pointer: &str,
) -> Result<(), InvalidSpec> {
    if !matches!(item, ConstValue::Object(_)) {
        return Err(malformed("A path item must be an object.", pointer));
    }
    for (name, method) in METHODS {
        let Some(operation) = member(item, name) else {
            continue;
        };
        if !matches!(operation, ConstValue::Object(_)) {
            return Err(malformed(
                "An operation must be an object.",
                format!("{pointer}/{name}"),
            ));
        }
        operations.insert(RestOperation {
            method,
            template: template.clone(),
            label: operation_id(operation),
            flags: flags_of(operation),
        })?;
    }
    Ok(())
}

fn operation_id(operation: &ConstValue) -> Option<String> {
    match member(operation, "operationId") {
        Some(ConstValue::String(label)) => Some(label.clone()),
        _ => None,
    }
}

/// `x-iam-sensitive: true` and `x-iam-audit: always`.
fn flags_of(operation: &ConstValue) -> PermissionFlags {
    let mut flags = PermissionFlags::NONE;
    if matches!(
        member(operation, "x-iam-sensitive"),
        Some(ConstValue::Boolean(true))
    ) {
        flags = flags.with_sensitive();
    }
    if matches!(
        member(operation, "x-iam-audit"),
        Some(ConstValue::String(value)) if value == "always"
    ) {
        flags = flags.with_audit_always();
    }
    flags
}

#[cfg(test)]
mod tests;
