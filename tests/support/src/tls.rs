//! Self-signed certificates for the tests of TLS listeners.

use std::path::{Path, PathBuf};
use std::process::Command;

/// A certificate chain file and the file of its private key.
#[derive(Debug, Clone)]
pub struct CertificateFiles {
    /// The PEM certificate chain.
    pub cert: PathBuf,
    /// The PEM private key (PKCS #8).
    pub key: PathBuf,
}

/// Writes a new self-signed certificate and its key into `directory`.
///
/// The certificate is for `localhost` and `127.0.0.1` with the subject `CN=<common_name>`, the key
/// is ECDSA P-256, and the files are `<name>.crt.pem` and `<name>.key.pem`. They come from the
/// `openssl` command of the test image; no key is committed, every call makes a new one.
///
/// # Panics
///
/// Panics when `openssl` is missing or fails: the test cannot run without a certificate.
#[must_use]
#[expect(
    clippy::expect_used,
    reason = "a test cannot run without a certificate; a missing openssl is a defect of the test image"
)]
pub fn self_signed(directory: &Path, name: &str, common_name: &str) -> CertificateFiles {
    let files = CertificateFiles {
        cert: directory.join(format!("{name}.crt.pem")),
        key: directory.join(format!("{name}.key.pem")),
    };
    let output = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-days",
            "2",
            "-subj",
        ])
        .arg(format!("/CN={common_name}"))
        .args(["-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"])
        .arg("-keyout")
        .arg(&files.key)
        .arg("-out")
        .arg(&files.cert)
        .output()
        .expect("the openssl command must be installed");
    assert!(
        output.status.success(),
        "openssl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    files
}
