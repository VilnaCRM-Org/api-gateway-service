//! Bounded context `iam`, infrastructure layer: the adapters that implement the ports of the
//! domain layer, such as persistence, cache and messaging.
//!
//! This crate depends on the domain layer of its own context and of the shared kernel, never on the
//! application layer. SQL lives here and nowhere else.

pub mod persistence;
pub mod request_digest;
pub mod token;

pub use persistence::PgPolicyEpochRepository;
pub use persistence::change_receipt::PgChangeReceiptRepository;
pub use persistence::graphql_permission::PgGraphQlPermissionRepository;
pub use persistence::graphql_spec::PgGraphQlSpecRepository;
pub use persistence::idempotency::PgIdempotencyRepository;
pub use persistence::openapi_spec::PgOpenApiSpecRepository;
pub use persistence::policy_read::{PgPolicyReadRepository, PolicyReadHook};
pub use persistence::rest_permission::PgRestPermissionRepository;
pub use persistence::revocation::PgRevocationRepository;
pub use persistence::revocation_view::PgRevocationView;
pub use persistence::role::PgRoleRepository;
pub use persistence::security_audit_log::PgSecurityAuditLog;
pub use persistence::unit_of_work::PgIamUnitOfWork;
pub use persistence::user_role::PgUserRoleRepository;
pub use request_digest::Sha256RequestDigester;
pub use token::caching_token_repository::CachingTokenRepository;
pub use token::jwt_access_token_verifier::{JwtAccessTokenVerifier, JwtSettings};
pub use token::jwt_key_set::{JwtKeyFileError, JwtKeySet};
pub use token::moka_token_memo::{MokaTokenMemo, TokenMemoSettings};
