//! The keys of the policy state topic: parsed and printed.

use std::fmt;

use shared_domain::Uuid;

use crate::error::InvalidStateRecord;
use crate::value_object::identifier::{RatePolicyId, RoleId, RouteId};
use crate::value_object::policy_digest_value::PolicyDigestValue;
use crate::value_object::service_name::ServiceName;
use crate::value_object::session_id::SessionId;
use crate::value_object::subject::{SubjectKind, SubjectRef};
use crate::value_object::upstream_name::UpstreamName;

/// The version of the chunk format that the `<catVer>` segment of a chunk key carries. A chunk is
/// content-addressed, so its key stays the same for as long as its content does.
pub const CATALOGUE_CHUNK_VERSION: u32 = 1;

/// The text of the key of the version head.
const HEAD: &str = "__head";

/// The content address of one catalogue chunk: 1 to 64 lower-case hexadecimal characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChunkId(String);

impl ChunkId {
    /// The largest number of characters.
    pub const MAX_LENGTH: usize = 64;

    /// Validates the text.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidStateRecord::ChunkId`] when the text is empty, longer than
    /// [`Self::MAX_LENGTH`] or holds a character other than `0-9` and `a-f`.
    pub fn new(value: &str) -> Result<Self, InvalidStateRecord> {
        let hexadecimal = |character: char| matches!(character, '0'..='9' | 'a'..='f');
        if value.is_empty() || value.len() > Self::MAX_LENGTH || !value.chars().all(hexadecimal) {
            return Err(InvalidStateRecord::ChunkId);
        }
        Ok(Self(value.to_owned()))
    }

    /// The address that is the hexadecimal form of `digest`.
    #[must_use]
    pub fn from_digest(digest: PolicyDigestValue) -> Self {
        Self(digest.to_hex())
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ChunkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The key of one record of the policy state topic.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum StateKey {
    /// `role/<uuid>`: one role with its grants.
    Role(RoleId),
    /// `subject/<kind>/<id>`: the full assignment list of one subject.
    Subject(SubjectRef),
    /// `catalog/<service>/manifest`: the chunks that make the catalogue of a service.
    CatalogueManifest(ServiceName),
    /// `catalog/<service>/<catVer>/<chunk>`: one content-addressed chunk of a catalogue.
    CatalogueChunk {
        /// The service.
        service: ServiceName,
        /// The version of the chunk format, [`CATALOGUE_CHUNK_VERSION`].
        version: u32,
        /// The content address of the chunk.
        chunk: ChunkId,
    },
    /// `route/<id>`.
    Route(RouteId),
    /// `upstream/<name>`.
    Upstream(UpstreamName),
    /// `ratepolicy/<id>`.
    RatePolicy(RatePolicyId),
    /// `revocation/session/<sid>`.
    SessionRevocation(SessionId),
    /// `revocation/user/<uid>`.
    UserRevocation(Uuid),
    /// `revocation/global`.
    GlobalRevocation,
    /// `__head`: the version and the digest the transaction ended with.
    Head,
}

impl StateKey {
    /// Parses the printed form of a key.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidStateRecord::Key`] for a text that is not a key of section 9.2.
    pub fn parse(text: &str) -> Result<Self, InvalidStateRecord> {
        let key = text.strip_prefix("revocation/session/").map_or_else(
            || Self::from_segments(&text.split('/').collect::<Vec<_>>()),
            |session| SessionId::new(session).ok().map(Self::SessionRevocation),
        );
        key.ok_or_else(|| InvalidStateRecord::Key {
            text: text.to_owned(),
        })
    }

    fn from_segments(parts: &[&str]) -> Option<Self> {
        match parts {
            [HEAD] => Some(Self::Head),
            ["role", id] => RoleId::parse(id).ok().map(Self::Role),
            ["subject", kind, id] => SubjectKind::parse(kind)
                .and_then(|kind| SubjectRef::new(kind, id))
                .ok()
                .map(Self::Subject),
            ["route", id] => RouteId::parse(id).ok().map(Self::Route),
            ["upstream", name] => UpstreamName::new(name).ok().map(Self::Upstream),
            ["ratepolicy", id] => RatePolicyId::parse(id).ok().map(Self::RatePolicy),
            ["catalog", service, rest @ ..] => Self::catalogue(service, rest),
            ["revocation", "user", user] => Uuid::parse(user).ok().map(Self::UserRevocation),
            ["revocation", "global"] => Some(Self::GlobalRevocation),
            _ => None,
        }
    }

    fn catalogue(service: &str, rest: &[&str]) -> Option<Self> {
        let service = ServiceName::new(service).ok()?;
        match rest {
            ["manifest"] => Some(Self::CatalogueManifest(service)),
            [version, chunk] => Some(Self::CatalogueChunk {
                service,
                version: version.parse().ok()?,
                chunk: ChunkId::new(chunk).ok()?,
            }),
            _ => None,
        }
    }

    /// The key of a chunk of the current chunk format.
    #[must_use]
    pub const fn chunk(service: ServiceName, chunk: ChunkId) -> Self {
        Self::CatalogueChunk {
            service,
            version: CATALOGUE_CHUNK_VERSION,
            chunk,
        }
    }
}

impl fmt::Display for StateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Role(id) => write!(f, "role/{id}"),
            Self::Subject(subject) => {
                write!(f, "subject/{}/{}", subject.kind().as_str(), subject.id())
            }
            Self::CatalogueManifest(service) => write!(f, "catalog/{service}/manifest"),
            Self::CatalogueChunk {
                service,
                version,
                chunk,
            } => write!(f, "catalog/{service}/{version}/{chunk}"),
            Self::Route(id) => write!(f, "route/{id}"),
            Self::Upstream(name) => write!(f, "upstream/{name}"),
            Self::RatePolicy(id) => write!(f, "ratepolicy/{id}"),
            Self::SessionRevocation(session) => write!(f, "revocation/session/{session}"),
            Self::UserRevocation(user) => write!(f, "revocation/user/{user}"),
            Self::GlobalRevocation => f.write_str("revocation/global"),
            Self::Head => f.write_str(HEAD),
        }
    }
}

#[cfg(test)]
mod tests;
