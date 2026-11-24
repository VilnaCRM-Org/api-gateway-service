//! The production wiring of the pipeline: the token repository over the snapshot, the authorizer
//! and the placeholder forwarder.

use std::any::TypeId;
use std::sync::Arc;

use axum::extract::Request;
use axum::response::Response;
use iam_application::{FreshnessState, RequestAuthorizer};
use iam_domain::{
    AccessTokenVerifier, ForwardError, PolicyView, RevocationView, TokenMemo, TokenRepository,
    UpstreamForwarder, UpstreamTarget,
};
use iam_infrastructure::{
    CachingTokenRepository, JwtAccessTokenVerifier, JwtKeyFileError, MokaTokenMemo,
    SnapshotRevocationView,
};
use shared_domain::{Clock, CommandBus, ErasedBusError, ErasedMessage};
use shared_infrastructure::id::UuidV7Generator;

use super::{Forwarder, Pipeline};
use crate::bootstrap::KEY_FILE_POLL_INTERVAL;
use crate::config::GatewayConfig;

/// The pipeline cannot be wired.
#[derive(Debug, thiserror::Error)]
pub enum PipelineSetupError {
    /// The key file of the token verifier cannot be read or parsed.
    #[error(transparent)]
    Keys(#[from] JwtKeyFileError),
}

/// The forwarder of Story 10.2: no upstream is reachable, so every request that was authorized is
/// answered 502. Story 10.3 replaces it with `HyperUpstreamForwarder`.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnreachableUpstreams;

#[async_trait::async_trait]
impl UpstreamForwarder for UnreachableUpstreams {
    type Request = Request;
    type Response = Response;

    async fn forward(
        &self,
        _target: UpstreamTarget,
        _request: Request,
    ) -> Result<Response, ForwardError> {
        Err(ForwardError::NoEndpoint)
    }
}

/// The command bus of the gateway's authorizer: the gateway keeps no audit log before Story 14.1,
/// so the refusals that the rule table of IAM's own operations offers are dropped.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnauditedCommands;

#[async_trait::async_trait]
impl CommandBus for UnauditedCommands {
    async fn dispatch_erased(
        &self,
        _command_type: TypeId,
        _name: &'static str,
        _command: ErasedMessage,
    ) -> Result<(), ErasedBusError> {
        Ok(())
    }
}

/// The pipeline of the public listener over the snapshot of `view`.
///
/// Tokens are verified by a JWT verifier over `JWT_PUBLIC_KEYS_FILE`, reloaded when the file
/// changes, behind a memo sized by `TOKEN_MEMO_CAPACITY` and `TOKEN_MEMO_MAX_TTL`; the revocation
/// sets come from the snapshot.
///
/// # Errors
///
/// [`PipelineSetupError::Keys`] when the key file holds no valid key set.
pub fn from_config(
    config: &GatewayConfig,
    view: Arc<dyn PolicyView>,
    freshness: Arc<FreshnessState>,
    clock: &Arc<dyn Clock>,
) -> Result<Pipeline, PipelineSetupError> {
    let tokens = &config.tokens;
    let verifier = Arc::new(JwtAccessTokenVerifier::from_file(
        &tokens.public_keys_file,
        &tokens.jwt,
        Arc::clone(clock),
    )?);
    drop(verifier.watch(KEY_FILE_POLL_INTERVAL));
    let memo: Arc<dyn TokenMemo> = Arc::new(MokaTokenMemo::new(tokens.memo, Arc::clone(clock)));
    let revocations: Arc<dyn RevocationView> =
        Arc::new(SnapshotRevocationView::new(Arc::clone(&view)));
    let verifier: Arc<dyn AccessTokenVerifier> = verifier;
    let repository = Arc::new(CachingTokenRepository::new(verifier, memo, revocations));
    let token_port: Arc<dyn TokenRepository> = Arc::<CachingTokenRepository>::clone(&repository);
    let authorizer = RequestAuthorizer::new(
        token_port,
        Arc::clone(clock),
        Arc::new(UuidV7Generator),
        Arc::new(UnauditedCommands),
    );
    let forwarder: Arc<Forwarder> = Arc::new(UnreachableUpstreams);
    Ok(Pipeline::new(
        view,
        freshness,
        repository,
        Arc::new(authorizer),
        forwarder,
    ))
}

#[cfg(test)]
mod tests;
