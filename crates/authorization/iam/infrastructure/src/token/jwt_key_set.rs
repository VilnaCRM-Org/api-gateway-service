//! The trusted public keys of `JWT_PUBLIC_KEYS_FILE`.

use std::path::Path;

use jsonwebtoken::DecodingKey;

/// A key file that cannot become a trusted key set.
#[derive(Debug, thiserror::Error)]
pub enum JwtKeyFileError {
    /// The file cannot be read.
    #[error("the key file cannot be read")]
    Unreadable(#[source] std::io::Error),
    /// The file holds no PEM block.
    #[error("the key file holds no PEM key")]
    NoKey,
    /// The file holds more keys than [`JwtKeySet::MAX_KEYS`].
    #[error("the key file holds {0} keys, but at most 3 are allowed")]
    TooManyKeys(usize),
    /// The PEM block with this 1-based position is not an RSA public key.
    #[error("key {0} of the key file is not a parsable RSA public key in PEM form")]
    UnparsableKey(usize),
}

/// One to three RSA public keys, newest last in the file and tried newest first.
#[derive(Clone)]
pub struct JwtKeySet {
    newest_first: Vec<DecodingKey>,
}

impl JwtKeySet {
    /// The largest number of keys a file may hold.
    pub const MAX_KEYS: usize = 3;

    /// Reads and parses the key file.
    ///
    /// # Errors
    ///
    /// Returns [`JwtKeyFileError::Unreadable`] when the file cannot be read, and the errors of
    /// [`Self::parse`].
    pub fn load(path: &Path) -> Result<Self, JwtKeyFileError> {
        let text = std::fs::read_to_string(path).map_err(JwtKeyFileError::Unreadable)?;
        Self::parse(&text)
    }

    /// Parses the PEM blocks of a key file.
    ///
    /// # Errors
    ///
    /// Returns [`JwtKeyFileError::NoKey`] for a file without a PEM block,
    /// [`JwtKeyFileError::TooManyKeys`] for more than [`Self::MAX_KEYS`] blocks and
    /// [`JwtKeyFileError::UnparsableKey`] for a block that is not an RSA public key.
    pub fn parse(text: &str) -> Result<Self, JwtKeyFileError> {
        let blocks = pem_blocks(text)?;
        if blocks.is_empty() {
            return Err(JwtKeyFileError::NoKey);
        }
        if blocks.len() > Self::MAX_KEYS {
            return Err(JwtKeyFileError::TooManyKeys(blocks.len()));
        }
        let mut keys = Vec::with_capacity(blocks.len());
        for (position, block) in (1..).zip(&blocks) {
            let key = DecodingKey::from_rsa_pem(block.as_bytes())
                .map_err(|_error| JwtKeyFileError::UnparsableKey(position))?;
            keys.push(key);
        }
        keys.reverse();
        Ok(Self { newest_first: keys })
    }

    /// The number of keys.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.newest_first.len()
    }

    /// Always `false`: a key set holds at least one key.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.newest_first.is_empty()
    }

    /// The keys, the newest (the last in the file) first.
    pub(crate) fn newest_first(&self) -> impl Iterator<Item = &DecodingKey> {
        self.newest_first.iter()
    }
}

impl std::fmt::Debug for JwtKeySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtKeySet")
            .field("keys", &self.newest_first.len())
            .finish()
    }
}

/// The text of every `-----BEGIN …-----` to `-----END …-----` block, in file order.
fn pem_blocks(text: &str) -> Result<Vec<String>, JwtKeyFileError> {
    let mut blocks = Vec::new();
    let mut current: Option<String> = None;
    for line in text.lines().map(str::trim) {
        if line.starts_with("-----BEGIN ") {
            if current.is_some() {
                return Err(JwtKeyFileError::UnparsableKey(
                    blocks.len().saturating_add(1),
                ));
            }
            current = Some(String::new());
        }
        if let Some(block) = current.as_mut() {
            block.push_str(line);
            block.push('\n');
            if line.starts_with("-----END ") {
                blocks.extend(current.take());
            }
        }
    }
    if current.is_some() {
        return Err(JwtKeyFileError::UnparsableKey(
            blocks.len().saturating_add(1),
        ));
    }
    Ok(blocks)
}

#[cfg(test)]
mod tests;
