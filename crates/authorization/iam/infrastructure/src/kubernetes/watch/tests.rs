use std::path::{Path, PathBuf};
use std::time::Duration;

use rstest::rstest;

use super::{
    KubernetesEndpointWatch, KubernetesSettings, KubernetesSetupError, complete_lines,
    encode_version,
};

fn settings(api_base: &str) -> KubernetesSettings {
    KubernetesSettings {
        api_base: api_base.to_owned(),
        token_file: None,
        ca_file: None,
        watch_timeout: Duration::from_secs(30),
    }
}

#[test]
fn the_in_cluster_settings_use_the_mounted_serviceaccount() {
    let settings = KubernetesSettings::in_cluster();

    assert_eq!(settings.api_base, "https://kubernetes.default.svc");
    assert!(
        settings
            .token_file
            .unwrap()
            .ends_with("serviceaccount/token")
    );
    assert!(settings.ca_file.unwrap().ends_with("serviceaccount/ca.crt"));
}

#[test]
fn an_api_base_that_is_not_http_is_refused() {
    let error = KubernetesEndpointWatch::new(&settings("ftp://api")).unwrap_err();

    assert!(matches!(error, KubernetesSetupError::ApiBase));
}

#[test]
fn a_missing_certificate_authority_file_is_refused_with_its_reason() {
    let mut missing = settings("https://api");
    missing.ca_file = Some("/nonexistent/ca.crt".into());

    let error = KubernetesEndpointWatch::new(&missing).unwrap_err();

    assert!(matches!(
        error,
        KubernetesSetupError::CertificateAuthority(_)
    ));
}

#[test]
fn the_debug_form_names_the_base_and_no_token() {
    let mut with_token = settings("http://127.0.0.1:1/");
    with_token.token_file = Some("/run/token".into());
    let watch = KubernetesEndpointWatch::new(&with_token).unwrap();

    let debug = format!("{watch:?}");

    assert!(debug.contains("http://127.0.0.1:1"));
    assert!(!debug.contains("/run/token"));
}

#[test]
fn a_resource_version_cannot_add_a_query_parameter() {
    assert_eq!(encode_version("12345"), "12345");
    assert_eq!(encode_version("1&watch=false"), "1%26watch%3Dfalse");
}

#[test]
fn only_complete_lines_are_returned() {
    let lines = complete_lines(b"{\"a\":1}\n\n{\"b\":2}\n{\"c\"");

    assert_eq!(lines, vec![b"{\"a\":1}".to_vec(), b"{\"b\":2}".to_vec()]);
    assert_eq!(complete_lines(b"{\"c\"").len(), 0);
    assert_eq!(complete_lines(b"").len(), 0);
}

/// A directory of its own in the temporary directory, removed when the test ends.
struct Directory(PathBuf);

impl Directory {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "iam-kubernetes-watch-{name}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}

fn with_authority(ca_file: PathBuf) -> KubernetesSettings {
    KubernetesSettings {
        ca_file: Some(ca_file),
        ..settings("https://api")
    }
}

#[test]
fn a_certificate_authority_file_with_a_certificate_is_trusted() {
    let directory = Directory::new("trusted");
    let files = test_support::tls::self_signed(directory.path(), "ca", "kubernetes");

    let built = KubernetesEndpointWatch::new(&with_authority(files.cert));

    assert!(built.is_ok());
}

#[rstest]
#[case::no_certificate("empty", "no certificate in here\n")]
#[case::broken_pem(
    "broken",
    "-----BEGIN CERTIFICATE-----\n@@@@\n-----END CERTIFICATE-----\n"
)]
#[case::not_a_certificate(
    "garbage",
    "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
)]
fn a_certificate_authority_file_without_a_usable_certificate_is_refused(
    #[case] name: &str,
    #[case] content: &str,
) {
    let directory = Directory::new(name);
    let file = directory.path().join("ca.crt");
    std::fs::write(&file, content).unwrap();

    let error = KubernetesEndpointWatch::new(&with_authority(file)).unwrap_err();

    assert!(matches!(
        error,
        KubernetesSetupError::CertificateAuthority(_)
    ));
}

#[test]
fn the_url_selects_the_slices_of_the_service_managed_by_the_cluster_controller() {
    let watch = KubernetesEndpointWatch::new(&settings("http://api")).unwrap();
    let target = iam_domain::WatchTarget {
        namespace: "vilnacrm".to_owned(),
        service: "user-service".to_owned(),
    };

    let uri = watch.url(&target, "&watch=true").unwrap().to_string();

    assert!(
        uri.contains(
            "labelSelector=kubernetes.io%2Fservice-name%3Duser-service%2Cendpointslice.kubernetes.io%2Fmanaged-by%3Dendpointslice-controller.k8s.io&watch=true"
        ),
        "{uri}"
    );
}
