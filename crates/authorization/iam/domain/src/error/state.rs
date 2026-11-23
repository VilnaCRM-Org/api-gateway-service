//! Domain errors of the policy state records.

/// A state key, a state record or a catalogue chunk that is not valid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidStateRecord {
    /// The text is not a state key of the policy state topic.
    #[error("The text {text} is not a state key.")]
    Key {
        /// The text.
        text: String,
    },
    /// The chunk identifier is empty, longer than 64 characters or not lower-case hexadecimal.
    #[error("A chunk identifier must contain 1 to 64 lower-case hexadecimal characters.")]
    ChunkId,
    /// A field of the state is missing, has the wrong type or holds a value that breaks an
    /// invariant.
    #[error("The state field {field} is missing or invalid.")]
    Field {
        /// The name of the field.
        field: &'static str,
    },
    /// The record carries a schema version this release does not read.
    #[error("The schema version {found} of the state record is not supported.")]
    UnsupportedSchema {
        /// The version the record carries.
        found: i64,
    },
    /// The state cannot be written in its canonical form.
    #[error("The state cannot be encoded.")]
    Encoding,
    /// One catalogue entry is larger than a chunk can hold.
    #[error("A catalogue entry is larger than a chunk of the policy state.")]
    EntryTooLarge,
}
