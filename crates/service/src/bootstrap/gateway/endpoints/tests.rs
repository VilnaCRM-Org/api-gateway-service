use std::path::PathBuf;

use iam_domain::WatchTarget;
use test_support::access_token::DEVELOPMENT_PUBLIC_KEYS_FILE;

use super::{
    EndpointAdapters, EndpointSetupError, PEERS_SERVICE, kubernetes_source, kubernetes_targets,
    peers_target,
};
use crate::cli::GatewayArgs;
use crate::config::GatewayConfig;

/// A file of its own in the temporary directory, removed when the test ends.
struct TempFile(PathBuf);

impl TempFile {
    fn with(name: &str, content: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "gateway-endpoints-{}-{name}.json",
            std::process::id()
        ));
        std::fs::write(&path, content).unwrap();
        Self(path)
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).unwrap_or_default();
    }
}

fn config(edit: impl FnOnce(&mut GatewayArgs)) -> GatewayConfig {
    let mut args = GatewayArgs::default();
    args.service.app_env = Some("test".to_owned());
    args.service.tokens.public_keys_file = Some(DEVELOPMENT_PUBLIC_KEYS_FILE.to_owned());
    args.service.kafka.bootstrap_servers = Some("localhost:9092".to_owned());
    args.service.kafka.security_protocol = Some("PLAINTEXT".to_owned());
    edit(&mut args);
    GatewayConfig::from_args(&args).unwrap()
}

fn static_config(file: &TempFile, edit: impl FnOnce(&mut GatewayArgs)) -> GatewayConfig {
    config(|args| {
        args.upstream_discovery = Some("static".to_owned());
        args.upstream_static_endpoints_file = Some(file.0.to_str().unwrap().to_owned());
        edit(args);
    })
}

const FILE: &str = r#"{
    "user-service": [{"address": "10.0.0.1", "port": 8081, "zone": "zone-a"}],
    "iam-gateway-peers": [{"address": "10.0.9.1", "port": 9090, "zone": "zone-c", "pod": "gateway-0"}]
}"#;

fn services(adapters: &EndpointAdapters) -> Vec<&str> {
    adapters
        .targets
        .iter()
        .map(|target| target.service.as_str())
        .collect()
}

#[test]
fn the_static_discovery_watches_every_service_of_the_file() {
    let file = TempFile::with("services", FILE);

    let adapters = EndpointAdapters::from_config(&static_config(&file, |_| {})).unwrap();

    assert_eq!(services(&adapters), ["iam-gateway-peers", "user-service"]);
    assert!(
        adapters
            .targets
            .iter()
            .all(|target| target.namespace == "default")
    );
    assert!(format!("{adapters:?}").starts_with("EndpointAdapters"));
}

#[test]
fn the_static_targets_take_the_namespace_of_the_pod() {
    let file = TempFile::with("namespace", FILE);

    let adapters = EndpointAdapters::from_config(&static_config(&file, |args| {
        args.pod_namespace = Some("iam".to_owned());
    }))
    .unwrap();

    assert!(
        adapters
            .targets
            .iter()
            .all(|target| target.namespace == "iam")
    );
}

#[test]
fn the_zone_of_the_pod_is_taken_from_its_entry_in_the_peers_slices() {
    let file = TempFile::with("zone", FILE);
    let config = static_config(&file, |args| args.pod_name = Some("gateway-0".to_owned()));
    let adapters = EndpointAdapters::from_config(&config).unwrap();
    let view = adapters.directory.view();
    assert_eq!(view.own_zone(), None);

    let peers = WatchTarget {
        namespace: "default".to_owned(),
        service: PEERS_SERVICE.to_owned(),
    };
    let listing = futures_free_block_on(adapters.watch.list(&peers));
    adapters.directory.replace(&peers, listing.unwrap().slices);

    assert_eq!(view.own_zone().unwrap().as_str(), "zone-c");
}

#[test]
fn an_explicit_gateway_zone_overrides_the_peers_slices() {
    let file = TempFile::with("explicit", FILE);
    let config = static_config(&file, |args| {
        args.pod_name = Some("gateway-0".to_owned());
        args.gateway_zone = Some("zone-x".to_owned());
    });
    let adapters = EndpointAdapters::from_config(&config).unwrap();

    assert_eq!(
        adapters.directory.view().own_zone().unwrap().as_str(),
        "zone-x"
    );
}

#[test]
fn a_static_file_that_vanished_fails_the_setup() {
    let file = TempFile::with("vanished", FILE);
    let config = static_config(&file, |_| {});
    drop(file);

    let error = EndpointAdapters::from_config(&config).unwrap_err();

    assert!(matches!(error, EndpointSetupError::Static(_)));
    assert_eq!(
        error.to_string(),
        "the upstream endpoints file cannot be used"
    );
}

#[test]
fn kubernetes_discovery_without_the_serviceaccount_certificate_fails_the_setup() {
    let config = config(|_| {});

    let outcome = EndpointAdapters::from_config(&config);

    assert!(matches!(outcome, Err(EndpointSetupError::Kubernetes(_))));
}

/// Runs a future that completes without waiting, such as a call of the static adapter.
fn futures_free_block_on<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    loop {
        if let std::task::Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
    }
}

#[test]
fn kubernetes_discovery_watches_the_peers_of_an_identified_pod_whatever_the_source_of_its_zone() {
    let identified = |edit: fn(&mut GatewayArgs)| {
        let config = config(|args| {
            args.pod_name = Some("gateway-0".to_owned());
            args.pod_namespace = Some("iam".to_owned());
            edit(args);
        });
        kubernetes_targets(&config, &peers_target(&config))
    };

    let derived = identified(|_| {});
    let explicit = identified(|args| args.gateway_zone = Some("zone-a".to_owned()));

    assert_eq!(derived.len(), 1);
    let peers = derived.first().unwrap();
    assert_eq!(peers.namespace, "iam");
    assert_eq!(peers.service, PEERS_SERVICE);
    assert_eq!(explicit, derived);
}

#[test]
fn kubernetes_discovery_without_a_pod_identity_watches_nothing() {
    let nameless = config(|args| args.pod_namespace = Some("iam".to_owned()));
    let spaceless = config(|args| args.pod_name = Some("gateway-0".to_owned()));

    assert_eq!(
        kubernetes_targets(&nameless, &peers_target(&nameless)).len(),
        0
    );
    assert_eq!(
        kubernetes_targets(&spaceless, &peers_target(&spaceless)).len(),
        0
    );
    assert_eq!(peers_target(&spaceless).namespace, "default");
}

#[test]
fn kubernetes_discovery_with_usable_settings_watches_the_targets_of_the_pod() {
    let config = config(|args| {
        args.pod_name = Some("gateway-0".to_owned());
        args.pod_namespace = Some("iam".to_owned());
    });
    let peers = peers_target(&config);
    let settings = iam_infrastructure::KubernetesSettings {
        ca_file: None,
        token_file: None,
        ..iam_infrastructure::KubernetesSettings::in_cluster()
    };

    let (_watch, targets) = kubernetes_source(&settings, &config, &peers).unwrap();

    assert_eq!(targets, kubernetes_targets(&config, &peers));
    assert_eq!(targets.len(), 1);
}
