//! Strict TLS 1.3 configuration primitives for ANA peer transport.
//!
//! This module is intentionally not wired into the TCP listener yet. The
//! listener remains loopback-only until authenticated ANA URI-SAN identity
//! verification, CRL issuer/freshness policy, handshake deadlines, and the
//! complete positive/negative integration-test matrix are implemented.

use anyhow::{bail, Context, Result};
use rustls::{
    client::WebPkiServerVerifier,
    pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
    ClientConfig, RootCertStore, ServerConfig,
};
use std::{
    fs::File,
    io::BufReader,
    path::Path,
    sync::Arc,
};

const ALPN_PROTOCOL: &[u8] = b"ana-peer/1";

fn read_certificates(path: &Path, label: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)
        .with_context(|| format!("could not open {label} certificate file {}", path.display()))?;
    let certs = rustls_pemfile::certs(&mut BufReader::new(file))
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("could not parse PEM certificates from {}", path.display()))?;
    if certs.is_empty() {
        bail!("{label} certificate file contains no certificates");
    }
    Ok(certs)
}

fn read_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path)
        .with_context(|| format!("could not open node private key {}", path.display()))?;
    rustls_pemfile::private_key(&mut BufReader::new(file))
        .with_context(|| format!("could not parse node private key {}", path.display()))?
        .context("node private key file contains no supported private key")
}

fn read_trust_roots(path: &Path) -> Result<Arc<RootCertStore>> {
    let certs = read_certificates(path, "ANA network CA")?;
    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots.add(cert).context("ANA network CA bundle contains an invalid trust anchor")?;
    }
    if roots.is_empty() {
        bail!("ANA network CA trust store is empty");
    }
    Ok(Arc::new(roots))
}

fn read_required_crls(path: &Path) -> Result<Vec<CertificateRevocationListDer<'static>>> {
    let file = File::open(path)
        .with_context(|| format!("could not open required ANA CRL file {}", path.display()))?;
    let crls = rustls_pemfile::crls(&mut BufReader::new(file))
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("could not parse CRLs from {}", path.display()))?;
    if crls.is_empty() {
        bail!("remote peer TLS requires at least one configured CRL");
    }
    Ok(crls)
}

/// Build a TLS 1.3 server configuration that requires a CA-validated client
/// certificate and rejects unknown or expired revocation status.
pub fn load_server_config(
    ca_bundle: &Path,
    crl_bundle: &Path,
    certificate_chain: &Path,
    private_key: &Path,
) -> Result<Arc<ServerConfig>> {
    let roots = read_trust_roots(ca_bundle)?;
    let crls = read_required_crls(crl_bundle)?;
    let certs = read_certificates(certificate_chain, "node identity")?;
    let key = read_private_key(private_key)?;

    let verifier = WebPkiClientVerifier::builder(roots)
        .with_crls(crls)
        .enforce_revocation_expiration()
        .build()
        .context("could not build strict ANA client-certificate verifier")?;

    let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .context("could not build ANA TLS server identity")?;
    config.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];
    Ok(Arc::new(config))
}

/// Build a TLS 1.3 client configuration that validates the server chain and
/// presents this node's own certificate. No anonymous-client mode is exposed.
pub fn load_client_config(
    ca_bundle: &Path,
    crl_bundle: &Path,
    certificate_chain: &Path,
    private_key: &Path,
) -> Result<Arc<ClientConfig>> {
    let roots = read_trust_roots(ca_bundle)?;
    let crls = read_required_crls(crl_bundle)?;
    let certs = read_certificates(certificate_chain, "node identity")?;
    let key = read_private_key(private_key)?;

    let verifier = WebPkiServerVerifier::builder(roots)
        .with_crls(crls)
        .enforce_revocation_expiration()
        .build()
        .context("could not build strict ANA server-certificate verifier")?;

    let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_webpki_verifier(verifier)
        .with_client_auth_cert(certs, key)
        .context("could not build ANA mutual-TLS client identity")?;
    config.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_ca_configuration_fails_closed() {
        let missing = Path::new("this-file-must-not-exist-ana-ca.pem");
        assert!(read_trust_roots(missing).is_err());
    }

    #[test]
    fn missing_crl_configuration_fails_closed() {
        let missing = Path::new("this-file-must-not-exist-ana-crl.pem");
        assert!(read_required_crls(missing).is_err());
    }

    #[test]
    fn alpn_identifier_is_the_peer_protocol() {
        assert_eq!(ALPN_PROTOCOL, b"ana-peer/1");
    }
}
