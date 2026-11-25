//! Port of the count of ready gateway pods (FR-65).

/// How many gateway pods are ready, as the endpoint watch of `iam-gateway-peers` reports it
/// (`N_ready` of the conservative rate limit).
pub trait ReadyPeers: std::fmt::Debug + Send + Sync {
    /// The number of ready endpoints of the peers Service; 0 while none is known.
    fn ready_endpoints(&self) -> u32;
}
