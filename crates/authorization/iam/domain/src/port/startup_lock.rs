//! Port of the cross-instance lock that serializes the startup registration (FR-45).

use crate::port::RepositoryError;

/// The lock that the registration of IAM's own specifications holds.
pub const OWN_SPECIFICATIONS_LOCK: &str = "iam:own-specifications";

/// The lock that a change of an administrator assignment holds while it counts the other
/// administrators and commits (FR-5).
pub const ADMINISTRATORS_LOCK: &str = "iam:administrators";

/// The lock that the `iam-bootstrap` command holds from the registration of IAM's specifications
/// to its commit (FR-5).
pub const BOOTSTRAP_LOCK: &str = "iam:bootstrap";

/// A held lock; dropping the guard releases it.
pub trait LockGuard: std::fmt::Debug + Send {}

/// Takes named locks that are shared by every instance of the service, so that exactly one
/// instance runs a startup step at a time.
#[async_trait::async_trait]
pub trait StartupLock: std::fmt::Debug + Send + Sync {
    /// Waits until the lock `name` is free and holds it until the guard is dropped.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::Unavailable`] when the storage fails.
    async fn acquire(&self, name: &str) -> Result<Box<dyn LockGuard>, RepositoryError>;
}
