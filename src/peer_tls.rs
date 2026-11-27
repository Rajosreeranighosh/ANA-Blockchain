//! Strict TLS 1.3 configuration primitives for ANA peer transport.
//!
//! The live node uses these primitives when all mTLS credentials and explicit
//! per-peer pins are configured. Public deployment remains gated on duplicate
//! identity handling, bounded handshake work, full negative-test coverage,
//! cross-platform CI, operational guidance, and independent security review.

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
    time::{Duration, Instant},
};
use x509_parser::prelude::{parse_x509_certificate, GeneralName};

const ALPN_PROTOCOL: &[u8] = b"ana-peer/1";
/// Maximum DER size accepted for a single ANA peer end-entity certificate.
const MAX_PEER_CERTIFICATE_DER_BYTES: usize = 64 * 1024;
/// Post-handshake policy bounds for the authenticated peer certificate chain.
/// rustls still parses the TLS Certificate message during the handshake; these
/// limits constrain accepted chains before ANA's identity parser/application.
const MAX_PEER_CERTIFICATES: usize = 8;
const MAX_PEER_CERTIFICATE_CHAIN_DER_BYTES: usize = 256 * 1024;

fn validate_peer_certificate_chain(certificates: &[CertificateDer<'_>]) -> Result<()> {
    if certificates.is_empty() {
        bail!("ANA peer certificate chain is empty");
    }
    if certificates.len() > MAX_PEER_CERTIFICATES {
        bail!("ANA peer certificate chain exceeds the certificate-count limit");
    }
    let total = certificates.iter().try_fold(0usize, |sum, certificate| {
        if certificate.len() > MAX_PEER_CERTIFICATE_DER_BYTES {
            bail!("ANA peer certificate exceeds the 64 KiB DER size limit");
        }
        sum.checked_add(certificate.len())
            .context("ANA peer certificate chain size overflow")
    })?;
    if total > MAX_PEER_CERTIFICATE_CHAIN_DER_BYTES {
        bail!("ANA peer certificate chain exceeds the 256 KiB aggregate DER limit");
    }
    Ok(())
}

/// Authenticated identity extracted from a certificate that rustls has already
/// accepted under the configured CA, validity, EKU, and CRL policy. ANA separately
/// enforces the TLS digitalSignature Key Usage requirement before accepting peers.
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

/// Enforce the TLS peer-certificate Key Usage required by ANA's TLS 1.3 profile.
/// rustls-webpki validates the certificate chain and EKU, but the observed
/// verifier behavior does not reject keyEncipherment-only client certificates.
/// Require an explicit Key Usage extension containing digitalSignature.
fn verify_peer_key_usage(certificate_der: &[u8]) -> Result<()> {
    if certificate_der.len() > MAX_PEER_CERTIFICATE_DER_BYTES {
        bail!("ANA peer certificate exceeds the 64 KiB DER size limit");
    }
    let (remaining, certificate) = parse_x509_certificate(certificate_der)
        .map_err(|error| anyhow::anyhow!("invalid peer X.509 certificate: {error}"))?;
    if !remaining.is_empty() {
        bail!("peer certificate contains trailing DER data");
    }
    let key_usage = certificate
        .key_usage()
        .context("peer certificate has an invalid or duplicate Key Usage extension")?
        .context("peer certificate is missing its Key Usage extension")?;
    if !key_usage.value.digital_signature() {
        bail!("ANA TLS peer certificate Key Usage must include digitalSignature");
    }
    Ok(())
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
    if certificate_der.len() > MAX_PEER_CERTIFICATE_DER_BYTES {
        bail!("ANA peer certificate exceeds the 64 KiB DER size limit");
    }
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


/// Strict operator-managed mapping from outbound endpoints to certificate
/// SPKI fingerprints, plus the explicit inbound identity allowlist.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerPinConfig {
    outbound: std::collections::BTreeMap<String, String>,
    inbound: std::collections::HashSet<String>,
}

impl PeerPinConfig {
    pub fn parse(outbound: &str, inbound: &str, configured_peers: &[String]) -> Result<Self> {
        let mut pins = std::collections::BTreeMap::new();
        let mut unique_ids = std::collections::HashSet::new();
        for entry in outbound.split(',') {
            if entry.is_empty() || entry.trim() != entry {
                bail!("ANA_PEER_PINS contains an empty or whitespace-padded entry");
            }
            let (endpoint, node_id) = entry.split_once('=')
                .context("ANA_PEER_PINS entries must be endpoint=node-id")?;
            if endpoint.is_empty() || endpoint.contains('=') || endpoint.chars().any(char::is_whitespace) {
                bail!("ANA_PEER_PINS contains an invalid endpoint");
            }
            if !is_lower_hex_64(node_id) {
                bail!("ANA_PEER_PINS node IDs must be 64 lowercase hexadecimal characters");
            }
            if pins.insert(endpoint.to_owned(), node_id.to_owned()).is_some() {
                bail!("ANA_PEER_PINS contains a duplicate endpoint");
            }
            if !unique_ids.insert(node_id.to_owned()) {
                bail!("ANA_PEER_PINS contains a duplicate node ID");
            }
        }
        let configured: std::collections::HashSet<&str> =
            configured_peers.iter().map(String::as_str).collect();
        if configured.len() != configured_peers.len() {
            bail!("configured outbound peer endpoints contain duplicates");
        }
        if pins.len() != configured.len() || pins.keys().any(|endpoint| !configured.contains(endpoint.as_str())) {
            bail!("ANA_PEER_PINS must contain exactly one entry for every configured outbound peer and no unknown endpoints");
        }

        let mut allowed = std::collections::HashSet::new();
        for node_id in inbound.split(',') {
            if node_id.is_empty() || node_id.trim() != node_id || !is_lower_hex_64(node_id) {
                bail!("ANA_PEER_ALLOWED_NODE_IDS contains an empty, padded, or malformed node ID");
            }
            if !allowed.insert(node_id.to_owned()) {
                bail!("ANA_PEER_ALLOWED_NODE_IDS contains a duplicate node ID");
            }
        }
        if allowed.is_empty() {
            bail!("ANA_PEER_ALLOWED_NODE_IDS must not be empty");
        }
        Ok(Self { outbound: pins, inbound: allowed })
    }

    pub fn outbound_pin(&self, endpoint: &str) -> Result<&str> {
        self.outbound.get(endpoint).map(String::as_str)
            .context("configured outbound peer has no explicit ANA node-ID pin")
    }

    pub fn permits_inbound(&self, node_id: &str) -> bool {
        self.inbound.contains(node_id)
    }

    pub fn inbound_ids(&self) -> &std::collections::HashSet<String> {
        &self.inbound
    }
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


/// Complete a server-side TLS handshake, then enforce the ANA network identity
/// and peer-protocol ALPN before exposing the stream to the message handler.
pub fn accept_authenticated(
    mut tcp: std::net::TcpStream,
    config: Arc<ServerConfig>,
    network_name: &str,
    allowed_node_ids: &std::collections::HashSet<String>,
) -> Result<rustls::StreamOwned<rustls::ServerConnection, std::net::TcpStream>> {
    let mut connection = rustls::ServerConnection::new(config)
        .context("could not create ANA TLS server connection")?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while connection.is_handshaking() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!("ANA peer TLS server handshake exceeded its 10-second deadline");
        }
        tcp.set_read_timeout(Some(remaining))
            .context("could not set ANA TLS server handshake read deadline")?;
        tcp.set_write_timeout(Some(remaining))
            .context("could not set ANA TLS server handshake write deadline")?;
        connection.complete_io(&mut tcp)
            .context("ANA peer TLS server handshake failed")?;
    }
    if connection.alpn_protocol() != Some(ALPN_PROTOCOL) {
        bail!("ANA peer TLS connection negotiated an unexpected ALPN protocol");
    }
    let certificates = connection.peer_certificates()
        .context("ANA peer TLS client did not present a certificate")?;
    validate_peer_certificate_chain(certificates)?;
    let peer = certificates.first().context("ANA peer TLS client certificate chain is empty")?;
    verify_peer_key_usage(peer.as_ref())
        .context("ANA peer TLS client Key Usage verification failed")?;
    let identity = verify_peer_identity(peer.as_ref(), network_name, None)
        .context("ANA peer TLS client identity verification failed")?;
    if !allowed_node_ids.contains(&identity.node_id) {
        bail!("ANA peer TLS client node ID is not in the inbound allowlist");
    }
    Ok(rustls::StreamOwned::new(connection, tcp))
}

/// Complete a client-side TLS handshake and authenticate the remote ANA node
/// before any application-protocol bytes are sent.
pub fn connect_authenticated(
    mut tcp: std::net::TcpStream,
    config: Arc<ClientConfig>,
    server_name: &str,
    network_name: &str,
    expected_node_id: &str,
) -> Result<rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>> {
    let name = rustls::pki_types::ServerName::try_from(server_name.to_owned())
        .context("invalid ANA peer TLS server name")?;
    let mut connection = rustls::ClientConnection::new(config, name)
        .context("could not create ANA TLS client connection")?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while connection.is_handshaking() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!("ANA peer TLS client handshake exceeded its 10-second deadline");
        }
        tcp.set_read_timeout(Some(remaining))
            .context("could not set ANA TLS client handshake read deadline")?;
        tcp.set_write_timeout(Some(remaining))
            .context("could not set ANA TLS client handshake write deadline")?;
        connection.complete_io(&mut tcp)
            .context("ANA peer TLS client handshake failed")?;
    }
    if connection.alpn_protocol() != Some(ALPN_PROTOCOL) {
        bail!("ANA peer TLS connection negotiated an unexpected ALPN protocol");
    }
    let certificates = connection.peer_certificates()
        .context("ANA peer TLS server did not present a certificate")?;
    validate_peer_certificate_chain(certificates)?;
    let peer = certificates.first().context("ANA peer TLS server certificate chain is empty")?;
    verify_peer_key_usage(peer.as_ref())
        .context("ANA peer TLS server Key Usage verification failed")?;
    verify_peer_identity(peer.as_ref(), network_name, Some(expected_node_id))
        .context("ANA peer TLS server identity verification failed")?;
    Ok(rustls::StreamOwned::new(connection, tcp))
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
    fn peer_pin_configuration_is_strict_and_covers_exact_endpoints() {
        let a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let peers = vec!["127.0.0.1:9001".to_owned(), "[::1]:9002".to_owned()];
        let config = PeerPinConfig::parse(
            &format!("127.0.0.1:9001={a},[::1]:9002={b}"), a, &peers
        ).unwrap();
        assert_eq!(config.outbound_pin("127.0.0.1:9001").unwrap(), a);
        assert!(config.permits_inbound(a));
        assert!(!config.permits_inbound(b));
    }

    #[test]
    fn peer_pin_configuration_rejects_missing_unknown_duplicate_and_malformed_entries() {
        let a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let peers = vec!["127.0.0.1:9001".to_owned()];
        assert!(PeerPinConfig::parse("", a, &peers).is_err());
        assert!(PeerPinConfig::parse(&format!("127.0.0.1:9002={a}"), a, &peers).is_err());
        assert!(PeerPinConfig::parse(&format!("127.0.0.1:9001={a},127.0.0.1:9001={b}"), a, &peers).is_err());
        assert!(PeerPinConfig::parse(&format!("127.0.0.1:9001={a}"), &format!("{a},{a}"), &peers).is_err());
        assert!(PeerPinConfig::parse("127.0.0.1:9001=ABC", a, &peers).is_err());
        assert!(PeerPinConfig::parse(&format!("127.0.0.1:9001={a},"), a, &peers).is_err());
        assert!(PeerPinConfig::parse(&format!("127.0.0.1:9001={a}"), "", &peers).is_err());
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
    fn peer_certificate_chain_limits_are_enforced() {
        use rustls::pki_types::CertificateDer;
        assert!(validate_peer_certificate_chain(&[]).is_err());
        let too_many: Vec<_> = (0..=MAX_PEER_CERTIFICATES)
            .map(|_| CertificateDer::from(vec![1u8; 1]))
            .collect();
        assert!(validate_peer_certificate_chain(&too_many).is_err());
        let oversized = vec![CertificateDer::from(vec![1u8; MAX_PEER_CERTIFICATE_DER_BYTES + 1])];
        assert!(validate_peer_certificate_chain(&oversized).is_err());
        let aggregate = vec![
            CertificateDer::from(vec![1u8; 64 * 1024]),
            CertificateDer::from(vec![2u8; 64 * 1024]),
            CertificateDer::from(vec![3u8; 64 * 1024]),
            CertificateDer::from(vec![4u8; 64 * 1024]),
            CertificateDer::from(vec![5u8; 1]),
        ];
        assert!(validate_peer_certificate_chain(&aggregate).is_err());
        let valid = vec![
            CertificateDer::from(vec![1u8; 1024]),
            CertificateDer::from(vec![2u8; 1024]),
        ];
        assert!(validate_peer_certificate_chain(&valid).is_ok());
    }

    #[test]
    fn oversized_peer_certificate_is_rejected_before_x509_parsing() {
        let oversized = vec![0u8; MAX_PEER_CERTIFICATE_DER_BYTES + 1];
        let error = verify_peer_identity(&oversized, "testnet", None).unwrap_err();
        assert!(error.to_string().contains("64 KiB DER size limit"));
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

    #[test]
    fn live_mtls_enforces_outbound_pin_and_inbound_allowlist() {
        use std::{
            collections::HashSet,
            net::{TcpListener, TcpStream},
            thread,
            time::Duration,
        };

        let ca = test_fixture("mtls-ca.pem");
        let crl = test_fixture("mtls-crl.pem");
        let server_cert = test_fixture("mtls-server.pem");
        let server_key = test_fixture("mtls-server.key");
        let client_cert = test_fixture("mtls-client.pem");
        let client_key = test_fixture("mtls-client.key");
        let server_identity = verify_peer_identity(
            read_certificates(&server_cert, "test server").unwrap()[0].as_ref(),
            "testnet",
            None,
        ).unwrap();
        let client_identity = verify_peer_identity(
            read_certificates(&client_cert, "test client").unwrap()[0].as_ref(),
            "testnet",
            None,
        ).unwrap();
        let server_config = load_server_config(&ca, &crl, &server_cert, &server_key).unwrap();
        let client_config = load_client_config(&ca, &crl, &client_cert, &client_key).unwrap();

        // The CA-valid server must still be rejected when its SPKI pin is wrong.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let allowed_client = HashSet::from([client_identity.node_id.clone()]);
        let server_config_for_thread = server_config.clone();
        let server_thread = thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let _ = tcp.set_read_timeout(Some(Duration::from_secs(5)));
            let _ = tcp.set_write_timeout(Some(Duration::from_secs(5)));
            accept_authenticated(tcp, server_config_for_thread, "testnet", &allowed_client).is_ok()
        });
        let tcp = TcpStream::connect(address).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        tcp.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        assert!(connect_authenticated(
            tcp,
            client_config.clone(),
            "ana-peer.invalid",
            "testnet",
            &"f".repeat(64),
        ).is_err());
        assert!(server_thread.join().unwrap());

        // A valid TLS client is rejected when its node ID is not allowlisted.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_config_for_thread = server_config.clone();
        let server_thread = thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let _ = tcp.set_read_timeout(Some(Duration::from_secs(5)));
            let _ = tcp.set_write_timeout(Some(Duration::from_secs(5)));
            accept_authenticated(tcp, server_config_for_thread, "testnet", &HashSet::new()).is_err()
        });
        let tcp = TcpStream::connect(address).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        tcp.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let client_result = connect_authenticated(
            tcp,
            client_config,
            "ana-peer.invalid",
            "testnet",
            &server_identity.node_id,
        );
        assert!(client_result.is_ok(), "server identity should be valid; inbound authorization is checked by server");
        drop(client_result);
        assert!(server_thread.join().unwrap(), "server accepted a client outside its inbound allowlist");
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
        assert_tls_handshake_rejected(Arc::new(config), "mtls-crl.pem");
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
    fn expired_client_certificate_is_rejected_by_webpki_verifier() {
        use rustls::pki_types::UnixTime;

        let roots = read_trust_roots(&test_fixture("mtls-ca.pem")).unwrap();
        let crls = read_required_crls(&test_fixture("mtls-crl.pem")).unwrap();
        let verifier = WebPkiClientVerifier::builder(roots)
            .with_crls(crls)
            .enforce_revocation_expiration()
            .build()
            .unwrap();
        let certs = read_certificates(&test_fixture("mtls-client.pem"), "test client").unwrap();
        let (_, parsed) = parse_x509_certificate(certs[0].as_ref()).unwrap();
        let after_expiry = parsed.validity().not_after.timestamp() + 1;
        let now = UnixTime::since_unix_epoch(
            Duration::from_secs(u64::try_from(after_expiry).unwrap())
        );

        assert!(
            rustls::server::danger::ClientCertVerifier::verify_client_cert(
                verifier.as_ref(), &certs[0], &[], now
            ).is_err(),
            "an otherwise trusted client certificate must be rejected after notAfter"
        );
    }

    #[test]
    fn server_auth_only_certificate_is_rejected_as_a_client_identity() {
        use rustls::pki_types::UnixTime;
        use std::time::{SystemTime, UNIX_EPOCH};

        // This dedicated test CA signs a leaf whose EKU is exactly serverAuth.
        // It intentionally has no clientAuth EKU and is not the dual-use mTLS
        // server fixture used by the transport integration tests.
        let roots = read_trust_roots(&test_fixture("peer-eku-test-ca.pem")).unwrap();
        let verifier = WebPkiClientVerifier::builder(roots).build().unwrap();
        let certs = read_certificates(
            &test_fixture("peer-server-auth-only.pem"),
            "serverAuth-only test certificate",
        )
        .unwrap();
        let (_, parsed) = parse_x509_certificate(certs[0].as_ref()).unwrap();
        let eku = parsed.extended_key_usage().unwrap().unwrap();
        assert!(eku.value.server_auth);
        assert!(!eku.value.client_auth);
        let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let now = UnixTime::since_unix_epoch(elapsed);

        assert!(
            rustls::server::danger::ClientCertVerifier::verify_client_cert(
                verifier.as_ref(), &certs[0], &[], now
            ).is_err(),
            "a serverAuth-only certificate must be rejected for client authentication"
        );
    }

    #[test]
    fn client_certificate_with_key_encipherment_only_is_rejected() {
        use rustls::pki_types::UnixTime;
        use std::time::{SystemTime, UNIX_EPOCH};

        // This leaf is signed by a dedicated test CA and has clientAuth EKU,
        // but its Key Usage is keyEncipherment only (no digitalSignature).
        // TLS client authentication must reject this incompatible key usage.
        let roots = read_trust_roots(&test_fixture("peer-ku-test-ca.pem")).unwrap();
        let verifier = WebPkiClientVerifier::builder(roots).build().unwrap();
        let certs = read_certificates(
            &test_fixture("peer-key-encipherment-only.pem"),
            "keyEncipherment-only test certificate",
        )
        .unwrap();
        let (_, parsed) = parse_x509_certificate(certs[0].as_ref()).unwrap();
        let key_usage = parsed.key_usage().unwrap().unwrap();
        assert!(key_usage.value.key_encipherment());
        assert!(!key_usage.value.digital_signature());
        let eku = parsed.extended_key_usage().unwrap().unwrap();
        assert!(eku.value.client_auth);

        let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let now = UnixTime::since_unix_epoch(elapsed);
        // The WebPKI verifier alone accepts this otherwise trusted leaf, so
        // ANA's explicit post-handshake peer policy must reject it.
        assert!(
            rustls::server::danger::ClientCertVerifier::verify_client_cert(
                verifier.as_ref(), &certs[0], &[], now
            ).is_ok(),
            "fixture must be otherwise valid under the CA and clientAuth EKU"
        );
        assert!(
            verify_peer_key_usage(certs[0].as_ref()).is_err(),
            "ANA peer policy must reject a client certificate without digitalSignature"
        );
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
    fn configured_tls_roles_advertise_the_ana_peer_alpn() {
        let ca = test_fixture("mtls-ca.pem");
        let crl = test_fixture("mtls-crl.pem");
        let server = load_server_config(
            &ca,
            &crl,
            &test_fixture("mtls-server.pem"),
            &test_fixture("mtls-server.key"),
        )
        .unwrap();
        let client = load_client_config(
            &ca,
            &crl,
            &test_fixture("mtls-client.pem"),
            &test_fixture("mtls-client.key"),
        )
        .unwrap();

        assert_eq!(server.alpn_protocols, vec![ALPN_PROTOCOL.to_vec()]);
        assert_eq!(client.alpn_protocols, vec![ALPN_PROTOCOL.to_vec()]);
    }

    #[test]
    fn mismatched_alpn_is_rejected_by_both_peer_transport_endpoints() {
        use std::{
            collections::HashSet,
            net::{TcpListener, TcpStream},
            thread,
            time::Duration,
        };

        let ca = test_fixture("mtls-ca.pem");
        let crl = test_fixture("mtls-crl.pem");
        let server_cert = test_fixture("mtls-server.pem");
        let server_key = test_fixture("mtls-server.key");
        let client_cert = test_fixture("mtls-client.pem");
        let client_key = test_fixture("mtls-client.key");

        let server_identity = verify_peer_identity(
            read_certificates(&server_cert, "test server").unwrap()[0].as_ref(),
            "testnet",
            None,
        )
        .unwrap();
        let client_identity = verify_peer_identity(
            read_certificates(&client_cert, "test client").unwrap()[0].as_ref(),
            "testnet",
            None,
        )
        .unwrap();

        let server_config = load_server_config(&ca, &crl, &server_cert, &server_key).unwrap();
        let mut client_config =
            (*load_client_config(&ca, &crl, &client_cert, &client_key).unwrap()).clone();
        client_config.alpn_protocols = vec![b"not-ana-peer".to_vec()];

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_thread = thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            tcp.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            let allowed = HashSet::from([client_identity.node_id]);
            accept_authenticated(tcp, server_config, "testnet", &allowed).is_err()
        });

        let tcp = TcpStream::connect(address).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        tcp.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        assert!(connect_authenticated(
            tcp,
            Arc::new(client_config),
            "ana-peer.invalid",
            "testnet",
            &server_identity.node_id,
        )
        .is_err());
        assert!(server_thread.join().unwrap());
    }

    #[test]
    fn tls_12_only_client_is_rejected_by_tls_13_only_peer_server() {
        let roots = read_trust_roots(&test_fixture("mtls-ca.pem")).unwrap();
        let certs = read_certificates(&test_fixture("mtls-client.pem"), "test client").unwrap();
        let key = read_private_key(&test_fixture("mtls-client.key")).unwrap();
        let config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
            .with_root_certificates((*roots).clone())
            .with_client_auth_cert(certs, key)
            .unwrap();

        // The shared handshake helper uses load_server_config(), which only
        // advertises TLS 1.3. A TLS 1.2-only client must fail at negotiation.
        assert_tls_handshake_rejected(Arc::new(config), "mtls-crl.pem");
    }

    #[test]
    fn alpn_identifier_is_the_peer_protocol() {
        assert_eq!(ALPN_PROTOCOL, b"ana-peer/1");
    }
}
