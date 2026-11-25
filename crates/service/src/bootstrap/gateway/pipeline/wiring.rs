//! The production wiring of the pipeline: the token repository over the snapshot, the authorizer
//! and the forwarder it is given.

use std::any::TypeId;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::Request;
use axum::response::Response;
use iam_application::{FreshnessState, GraphQlRequestAnalyzer, RequestAuthorizer};
use iam_domain::{
    AccessTokenVerifier, DocumentCache, ForwardError, PolicyView, RevocationView, TokenMemo,
    TokenRepository, UpstreamForwarder, UpstreamTarget,
};
use iam_infrastructure::{
    CachingTokenRepository, DocumentCacheSettings, JwtAccessTokenVerifier, JwtKeyFileError,
    MokaDocumentCache, MokaTokenMemo, SnapshotRevocationView,
};
use shared_domain::{Clock, CommandBus, ErasedBusError, ErasedMessage};
use shared_infrastructure::id::UuidV7Generator;

use super::{Forwarder, Pipeline};
use crate::bootstrap::KEY_FILE_POLL_INTERVAL;
use crate::config::GatewayConfig;

/// The weight the cache of analysed GraphQL documents may hold: 64 MiB.
const DOCUMENT_CACHE_BYTES: u64 = 64 * 1024 * 1024;

/// How long an analysed document that nobody sends again stays in the cache.
const DOCUMENT_CACHE_IDLE: Duration = Duration::from_mins(10);

/// The pipeline cannot be wired.
#[derive(Debug, thiserror::Error)]
pub enum PipelineSetupError {
    /// The key file of the token verifier cannot be read or parsed.
    #[error(transparent)]
    Keys(#[from] JwtKeyFileError),
}

/// A forwarder for a gateway that has no upstream to reach, as in the tests of the wiring: every
/// request that was authorized is answered 502. Production uses `HyperUpstreamForwarder`.
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
/// sets come from the snapshot. Authorized requests go to `forwarder`.
///
/// # Errors
///
/// [`PipelineSetupError::Keys`] when the key file holds no valid key set.
pub fn from_config(
    config: &GatewayConfig,
    view: Arc<dyn PolicyView>,
    freshness: Arc<FreshnessState>,
    clock: &Arc<dyn Clock>,
    forwarder: Arc<Forwarder>,
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
    let documents: Arc<dyn DocumentCache> =
        Arc::new(MokaDocumentCache::new(DocumentCacheSettings {
            capacity_bytes: DOCUMENT_CACHE_BYTES,
            time_to_idle: DOCUMENT_CACHE_IDLE,
        }));
    let analyzer = GraphQlRequestAnalyzer::new(documents, config.rate_limit.graphql_parse);
    let authorizer = RequestAuthorizer::new(
        token_port,
        Arc::clone(clock),
        Arc::new(UuidV7Generator),
        Arc::new(UnauditedCommands),
    )
    .with_graphql(Arc::new(analyzer));
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
