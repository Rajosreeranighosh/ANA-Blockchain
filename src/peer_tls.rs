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
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::BufReader,
    path::Path,
    sync::Arc,
};
use x509_parser::prelude::{parse_x509_certificate, GeneralName};

const ALPN_PROTOCOL: &[u8] = b"ana-peer/1";

/// Authenticated identity extracted from a certificate that rustls has already
/// accepted under the configured CA, validity, EKU, key-usage, and CRL policy.
/// This parser does not replace TLS certificate-chain validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerIdentity {
    pub network_id: String,
    pub node_id: String,
}

/// SHA-256 of the network-domain prefix and exact configured network name.
pub fn network_id(network_name: &str) -> Result<String> {
    if network_name.is_empty() || network_name.as_bytes().contains(&0) {
        bail!("ANA network name must be non-empty and contain no NUL bytes");
    }
    let mut digest = Sha256::new();
    digest.update(b"ANA-NETWORK-ID-v1\0");
    digest.update(network_name.as_bytes());
    Ok(hex::encode(digest.finalize()))
}

/// SHA-256 of the DER-encoded SubjectPublicKeyInfo, as specified by the
/// peer-transport certificate profile.
pub fn node_id_from_spki(spki_der: &[u8]) -> String {
    hex::encode(Sha256::digest(spki_der))
}

/// Verify the exact single URI SAN `ana://<network-id>/<node-id>`.
///
/// Call only on the peer end-entity certificate returned by a successful
/// rustls handshake. Chain trust and certificate validity are enforced by
/// the rustls WebPKI verifier before this identity check is applied.
pub fn verify_peer_identity(
    certificate_der: &[u8],
    expected_network_name: &str,
    expected_node_id: Option<&str>,
) -> Result<PeerIdentity> {
    let (remaining, certificate) = parse_x509_certificate(certificate_der)
        .map_err(|error| anyhow::anyhow!("invalid peer X.509 certificate: {error}"))?;
    if !remaining.is_empty() {
        bail!("peer certificate contains trailing DER data");
    }

    let san = certificate
        .subject_alternative_name()
        .context("peer certificate has an invalid or duplicate SAN extension")?
        .context("peer certificate is missing its SAN extension")?;
    let uri_names: Vec<&str> = san
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::URI(uri) => Some(*uri),
            _ => None,
        })
        .collect();
    if uri_names.len() != 1 {
        bail!("peer certificate must contain exactly one URI SAN identity");
    }
    let uri = uri_names[0];

    let value = uri
        .strip_prefix("ana://")
        .context("peer certificate URI SAN must use the ana:// scheme")?;
    let (network, node) = value
        .split_once('/')
        .context("peer certificate URI SAN must contain network and node IDs")?;
    if node.contains('/') || node.chars().any(|ch| matches!(ch, '?' | '#' | '%' | ':')) {
        bail!("peer certificate URI SAN contains forbidden URI components");
    }
    if !is_lower_hex_64(network) || !is_lower_hex_64(node) {
        bail!("peer certificate network and node IDs must be 64 lowercase hex characters");
    }

    let expected_network = network_id(expected_network_name)?;
    if network != expected_network {
        bail!("peer certificate belongs to a different ANA network");
    }

    let computed_node = node_id_from_spki(certificate.public_key().raw);
    if node != computed_node {
        bail!("peer certificate node ID does not match its SPKI");
    }
    if let Some(expected) = expected_node_id {
        if !is_lower_hex_64(expected) || node != expected {
            bail!("peer certificate node ID does not match the expected peer identity");
        }
    }

    Ok(PeerIdentity {
        network_id: network.to_owned(),
        node_id: node.to_owned(),
    })
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

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

    fn fixture_certificate(name: &str) -> Vec<u8> {
        let pem = match name {
            "valid" => include_bytes!("../tests/fixtures/peer-valid.pem").as_slice(),
            "wrong-network" => {
                include_bytes!("../tests/fixtures/peer-wrong-network.pem").as_slice()
            },
            "wrong-node" => {
                include_bytes!("../tests/fixtures/peer-wrong-node.pem").as_slice()
            },
            "malformed" => {
                include_bytes!("../tests/fixtures/peer-malformed-uri.pem").as_slice()
            },
            "missing-san" => {
                include_bytes!("../tests/fixtures/peer-missing-san.pem").as_slice()
            },
            "duplicate-san" => {
                include_bytes!("../tests/fixtures/peer-duplicate-san.pem").as_slice()
            },
            _ => panic!("unknown certificate fixture"),
        };
        rustls_pemfile::certs(&mut BufReader::new(pem))
            .next()
            .expect("fixture certificate")
            .expect("valid PEM")
            .to_vec()
    }

    #[test]
    fn valid_ana_uri_san_and_spki_identity_are_accepted() {
        let cert = fixture_certificate("valid");
        let identity = verify_peer_identity(&cert, "testnet", None).unwrap();
        assert_eq!(
            identity.network_id,
            "aba19fd753205213d37ae64300476339e5128904b547ac0dd2dedc784719909c"
        );
        assert_eq!(
            identity.node_id,
            "4b0efdb350ea60a00def98f5e1817cb36e1dd96431eb5e4af77d439ab5760fcc"
        );
        assert!(verify_peer_identity(&cert, "testnet", Some(&identity.node_id)).is_ok());
    }

    #[test]
    fn wrong_network_is_rejected() {
        assert!(verify_peer_identity(
            &fixture_certificate("wrong-network"),
            "testnet",
            None
        )
        .is_err());
        assert!(verify_peer_identity(&fixture_certificate("valid"), "mainnet", None).is_err());
    }

    #[test]
    fn wrong_node_id_is_rejected() {
        assert!(verify_peer_identity(&fixture_certificate("wrong-node"), "testnet", None).is_err());
        assert!(verify_peer_identity(
            &fixture_certificate("valid"),
            "testnet",
            Some("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        ).is_err());
    }

    #[test]
    fn malformed_and_missing_uri_san_are_rejected() {
        assert!(verify_peer_identity(&fixture_certificate("malformed"), "testnet", None).is_err());
        assert!(verify_peer_identity(&fixture_certificate("missing-san"), "testnet", None).is_err());
    }

    #[test]
    fn duplicate_san_extension_is_rejected() {
        assert!(verify_peer_identity(&fixture_certificate("duplicate-san"), "testnet", None).is_err());
    }

    #[test]
    fn malformed_der_and_invalid_network_name_are_rejected() {
        assert!(verify_peer_identity(b"not a certificate", "testnet", None).is_err());
        assert!(network_id("").is_err());
        assert!(network_id("bad\0network").is_err());
    }

    #[test]
    fn ca_issued_nodes_complete_mutual_tls_and_exchange_framed_data() {
        use std::{
            io::{Read, Write},
            net::{TcpListener, TcpStream},
            thread,
        };
        use rustls::{pki_types::ServerName, ClientConnection, ServerConnection, StreamOwned};

        let fixture = |name: &str| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests")
                .join("fixtures")
                .join(name)
        };
        let ca = fixture("mtls-ca.pem");
        let crl = fixture("mtls-crl.pem");
        let server_cert = fixture("mtls-server.pem");
        let server_key = fixture("mtls-server.key");
        let client_cert = fixture("mtls-client.pem");
        let client_key = fixture("mtls-client.key");

        let server_identity = {
            let cert = read_certificates(&server_cert, "test server").unwrap();
            verify_peer_identity(cert[0].as_ref(), "testnet", None).unwrap()
        };
        let client_identity = {
            let cert = read_certificates(&client_cert, "test client").unwrap();
            verify_peer_identity(cert[0].as_ref(), "testnet", None).unwrap()
        };

        let server_config =
            load_server_config(&ca, &crl, &server_cert, &server_key).unwrap();
        let client_config =
            load_client_config(&ca, &crl, &client_cert, &client_key).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_expected = client_identity.node_id.clone();
        let server_thread = thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            tcp.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
            tcp.set_write_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
            let connection = ServerConnection::new(server_config).unwrap();
            let mut tls = StreamOwned::new(connection, tcp);
            let mut request = [0u8; 5];
            tls.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"hello");
            let peer = tls.conn.peer_certificates().unwrap()[0].as_ref().to_vec();
            let identity =
                verify_peer_identity(&peer, "testnet", Some(&server_expected)).unwrap();
            assert_eq!(tls.conn.alpn_protocol(), Some(ALPN_PROTOCOL));
            tls.write_all(b"world").unwrap();
            identity
        });

        let tcp = TcpStream::connect(address).unwrap();
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
        tcp.set_write_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
        let server_name = ServerName::try_from("ana-peer.invalid").unwrap().to_owned();
        let connection = ClientConnection::new(client_config, server_name).unwrap();
        let mut tls = StreamOwned::new(connection, tcp);
        tls.write_all(b"hello").unwrap();
        let mut response = [0u8; 5];
        tls.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"world");
        let peer = tls.conn.peer_certificates().unwrap()[0].as_ref().to_vec();
        let identity = verify_peer_identity(&peer, "testnet", Some(&server_identity.node_id)).unwrap();
        assert_eq!(tls.conn.alpn_protocol(), Some(ALPN_PROTOCOL));

        assert_eq!(server_thread.join().unwrap(), client_identity);
        assert_eq!(identity, server_identity);
    }

    fn test_fixture(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(name)
    }

    fn assert_tls_handshake_rejected(client_config: Arc<ClientConfig>, server_crl: &str) {
        use std::{
            io::{Read, Write},
            net::{TcpListener, TcpStream},
            thread,
            time::Duration,
        };
        use rustls::{pki_types::ServerName, ClientConnection, ServerConnection, StreamOwned};

        let server_config = load_server_config(
            &test_fixture("mtls-ca.pem"),
            &test_fixture(server_crl),
            &test_fixture("mtls-server.pem"),
            &test_fixture("mtls-server.key"),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_thread = thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            tcp.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            let connection = ServerConnection::new(server_config).unwrap();
            let mut tls = StreamOwned::new(connection, tcp);
            let mut byte = [0u8; 1];
            tls.read_exact(&mut byte).is_err()
        });

        let tcp = TcpStream::connect(address).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        tcp.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let server_name = ServerName::try_from("ana-peer.invalid").unwrap().to_owned();
        let connection = ClientConnection::new(client_config, server_name).unwrap();
        let mut tls = StreamOwned::new(connection, tcp);
        let write_failed = tls.write_all(b"x").is_err();
        let mut byte = [0u8; 1];
        let read_failed = tls.read_exact(&mut byte).is_err();
        assert!(write_failed || read_failed, "client unexpectedly completed TLS handshake");
        assert!(server_thread.join().unwrap(), "server unexpectedly accepted unauthenticated peer");
    }

    #[test]
    fn unknown_ca_is_rejected_during_tls_handshake() {
        let roots = read_trust_roots(&test_fixture("mtls-wrong-ca.pem")).unwrap();
        let certs = read_certificates(&test_fixture("mtls-client.pem"), "test client").unwrap();
        let key = read_private_key(&test_fixture("mtls-client.key")).unwrap();
        let config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates((*roots).clone())
            .with_client_auth_cert(certs, key)
            .unwrap();
        assert_tls_handshake_rejected(Arc::new(config), "mtls-crl.pem");
    }

    #[test]
    fn missing_client_certificate_is_rejected_during_tls_handshake() {
        let roots = read_trust_roots(&test_fixture("mtls-ca.pem")).unwrap();
        let config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates((*roots).clone())
            .with_no_client_auth();
        assert_tls_handshake_rejected(Arc::new(config));
    }

    #[test]
    fn revoked_client_certificate_is_rejected_during_tls_handshake() {
        let roots = read_trust_roots(&test_fixture("mtls-ca.pem")).unwrap();
        let certs = read_certificates(&test_fixture("mtls-client.pem"), "test client").unwrap();
        let key = read_private_key(&test_fixture("mtls-client.key")).unwrap();
        let config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates((*roots).clone())
            .with_client_auth_cert(certs, key)
            .unwrap();
        assert_tls_handshake_rejected(Arc::new(config), "mtls-revoked-client-crl.pem");
    }

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
