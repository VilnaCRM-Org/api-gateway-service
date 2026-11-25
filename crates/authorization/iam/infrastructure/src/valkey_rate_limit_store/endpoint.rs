//! Where the Valkey store connects: one server, or the master that Sentinel names.

use redis::IntoConnectionInfo as _;
use redis::aio::MultiplexedConnection;
use redis::sentinel::{SentinelClient, SentinelServerType};

/// The port Sentinel listens on when a node of `redis+sentinel://` names none.
const DEFAULT_SENTINEL_PORT: u16 = 26379;

/// The URL does not name a Valkey server or a Sentinel group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidValkeyUrl {
    /// The scheme is neither `redis` nor `redis+sentinel`.
    #[error("the scheme must be redis:// or redis+sentinel://")]
    Scheme,
    /// A `redis://` URL that the client cannot read.
    #[error("the URL does not name a server")]
    Server,
    /// A `redis+sentinel://` URL without a node list, with a node that has no host or a bad port.
    #[error("the Sentinel URL needs host[:port] nodes separated by commas")]
    SentinelNodes,
    /// A `redis+sentinel://` URL without the name of the monitored service, or with more.
    #[error("the Sentinel URL needs the service name as its only path segment")]
    SentinelService,
}

/// A validated `RATE_LIMIT_STORE_URL`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValkeyEndpoint {
    /// One server at a `redis://` URL.
    Direct(String),
    /// The master of `service` as the Sentinel `nodes` (each a `redis://` URL) report it.
    Sentinel {
        /// The Sentinel nodes.
        nodes: Vec<String>,
        /// The name of the monitored master.
        service: String,
    },
}

impl ValkeyEndpoint {
    /// Reads `redis://host[:port][/db]` or `redis+sentinel://host[:port],host[:port]/service`.
    ///
    /// # Errors
    ///
    /// The [`InvalidValkeyUrl`] of the first part that is wrong.
    pub fn parse(url: &str) -> Result<Self, InvalidValkeyUrl> {
        if let Some(rest) = url.strip_prefix("redis+sentinel://") {
            return sentinel(rest);
        }
        if url.starts_with("redis://") && url.into_connection_info().is_ok() {
            return Ok(Self::Direct(url.to_owned()));
        }
        if url.starts_with("redis://") {
            return Err(InvalidValkeyUrl::Server);
        }
        Err(InvalidValkeyUrl::Scheme)
    }

    /// Opens a connection to the server, or to the master that Sentinel reports now.
    pub(super) async fn connect(&self) -> redis::RedisResult<MultiplexedConnection> {
        match self {
            Self::Direct(url) => {
                redis::Client::open(url.as_str())?
                    .get_multiplexed_async_connection()
                    .await
            }
            Self::Sentinel { nodes, service } => {
                let mut client = SentinelClient::build(
                    nodes.clone(),
                    service.clone(),
                    None,
                    SentinelServerType::Master,
                )?;
                client.get_async_connection().await
            }
        }
    }
}

fn sentinel(rest: &str) -> Result<ValkeyEndpoint, InvalidValkeyUrl> {
    let (hosts, path) = rest
        .split_once('/')
        .ok_or(InvalidValkeyUrl::SentinelService)?;
    if path.is_empty() || path.contains('/') {
        return Err(InvalidValkeyUrl::SentinelService);
    }
    let nodes = hosts.split(',').map(node).collect::<Result<Vec<_>, _>>()?;
    Ok(ValkeyEndpoint::Sentinel {
        nodes,
        service: path.to_owned(),
    })
}

/// One `host[:port]` of the node list as a `redis://` URL.
fn node(text: &str) -> Result<String, InvalidValkeyUrl> {
    let (host, port) = text
        .rsplit_once(':')
        .map_or((text, None), |(host, port)| (host, Some(port)));
    let port = port.map_or(Ok(DEFAULT_SENTINEL_PORT), str::parse::<u16>);
    match port {
        Ok(port) if !host.is_empty() && !host.contains(['@', '/', '?']) => {
            Ok(format!("redis://{host}:{port}"))
        }
        _ => Err(InvalidValkeyUrl::SentinelNodes),
    }
}

#[cfg(test)]
mod tests;
