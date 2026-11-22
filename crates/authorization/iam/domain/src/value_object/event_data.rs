//! The `data` object of an event of `iam.events.v1`, as an abstract tree that the infrastructure
//! encodes as JSON.

use crate::error::InvalidEventEnvelope;
use crate::value_object::text::holds_token;

/// Field names that name a credential or a specification body; compared without regard to case.
/// An event carries identifiers, names and keys, never a token or a specification document.
const FORBIDDEN_NAMES: [&str; 19] = [
    "token",
    "accesstoken",
    "refreshtoken",
    "idtoken",
    "jwt",
    "bearer",
    "authorization",
    "credential",
    "credentials",
    "password",
    "secret",
    "body",
    "content",
    "document",
    "schema",
    "sdl",
    "spec",
    "specbody",
    "specification",
];

/// One value of an event field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventValue {
    /// No value.
    Null,
    /// A truth value.
    Bool(bool),
    /// A whole number.
    Integer(i64),
    /// One line of text without a credential.
    Text(String),
    /// An ordered list of values.
    List(Vec<Self>),
    /// A nested object, validated when it was built.
    Object(EventData),
}

/// An ordered object of named event fields.
///
/// Every field name is a lower camel-case word of at most 64 characters, used once and never one
/// of the names of a credential or a specification body; no text value, at any depth, holds a
/// control character (a specification body spans lines), a word shaped like a JSON Web Token or a
/// bearer credential.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventData(Vec<(String, EventValue)>);

impl EventData {
    /// The largest number of characters of a field name.
    pub const MAX_FIELD_NAME_LENGTH: usize = 64;

    /// An object without fields.
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// The object with one more field at the end.
    ///
    /// # Errors
    ///
    /// [`InvalidEventEnvelope::FieldName`] for a name that is not a lower camel-case word,
    /// [`InvalidEventEnvelope::FieldForbidden`] for the name of a credential or a specification
    /// body, [`InvalidEventEnvelope::FieldDuplicate`] for a name already used,
    /// [`InvalidEventEnvelope::ControlCharacter`] and [`InvalidEventEnvelope::Credential`] for a
    /// text value that holds a control character or a credential.
    pub fn with(mut self, name: &str, value: EventValue) -> Result<Self, InvalidEventEnvelope> {
        check_name(name)?;
        if self.contains(name) {
            return Err(InvalidEventEnvelope::FieldDuplicate);
        }
        check_value(&value)?;
        self.0.push((name.to_owned(), value));
        Ok(self)
    }

    /// Whether a field is named `name`.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.0.iter().any(|(field, _value)| field == name)
    }

    /// The fields in the order they were added.
    #[must_use]
    pub fn fields(&self) -> &[(String, EventValue)] {
        &self.0
    }
}

/// Checks the form of a field name and refuses the names of credentials and specification bodies.
fn check_name(name: &str) -> Result<(), InvalidEventEnvelope> {
    let well_formed = name.len() <= EventData::MAX_FIELD_NAME_LENGTH
        && name
            .bytes()
            .next()
            .is_some_and(|first| first.is_ascii_lowercase())
        && name.bytes().all(|byte| byte.is_ascii_alphanumeric());
    if !well_formed {
        return Err(InvalidEventEnvelope::FieldName);
    }
    let lower = name.to_ascii_lowercase();
    if FORBIDDEN_NAMES.contains(&lower.as_str()) {
        return Err(InvalidEventEnvelope::FieldForbidden);
    }
    Ok(())
}

/// Checks every text value of `value`; a nested object was checked when it was built.
fn check_value(value: &EventValue) -> Result<(), InvalidEventEnvelope> {
    match value {
        EventValue::Text(text) => check_text(text),
        EventValue::List(items) => items.iter().try_for_each(check_value),
        EventValue::Null | EventValue::Bool(_) | EventValue::Integer(_) | EventValue::Object(_) => {
            Ok(())
        }
    }
}

/// Refuses a control character, a word shaped like a token and a bearer credential.
fn check_text(text: &str) -> Result<(), InvalidEventEnvelope> {
    if text.chars().any(char::is_control) {
        return Err(InvalidEventEnvelope::ControlCharacter);
    }
    let bearer = text
        .get(..BEARER.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(BEARER));
    if bearer || holds_token(text) {
        return Err(InvalidEventEnvelope::Credential);
    }
    Ok(())
}

/// The scheme prefix of a bearer credential.
const BEARER: &str = "bearer ";

#[cfg(test)]
mod tests;
