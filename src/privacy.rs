//! Versioned privacy-transaction wire model for ANA's future private ledger.
//!
//! IMPORTANT: this module performs structural checks only. It does not implement
//! stealth-address derivation, CLSAG, Pedersen commitments, range proofs, or
//! cryptographic verification. Do not accept these transactions in consensus.

use anyhow::{bail, Result};
use curve25519_dalek::{
    constants::{ED25519_BASEPOINT_POINT, RISTRETTO_BASEPOINT_POINT},
    edwards::{CompressedEdwardsY, EdwardsPoint},
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::IsIdentity,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::{
    collections::HashSet,
    fs,
    io::{Read, Write},
    path::Path,
};

pub const MAX_PRIVACY_KEY_IMAGES: usize = 500_000;
const PRIVACY_KEY_IMAGE_STORE_VERSION: u8 = 1;
const MAX_PRIVACY_KEY_IMAGE_STORE_BYTES: u64 = 32 * 1024 * 1024;

pub const PRIVACY_TX_VERSION: u8 = 1;
/// Initial ring size chosen for the experimental v1 wire format.
/// This is a format parameter, not a claim of Monero-equivalent privacy.
pub const PRIVACY_RING_SIZE: usize = 16;
pub const MAX_PRIVACY_INPUTS: usize = 64;
pub const MAX_PRIVACY_OUTPUTS: usize = 64;
pub const MAX_RANGE_PROOF_BYTES: usize = 1024 * 1024;
pub const MAX_CLSAG_BYTES: usize = 16 * 1024;

/// Identifies a previously created output by its global output index.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OutputReference {
    pub global_index: u64,
}

/// One input spends one real output hidden among a fixed-size ring.
///
/// The cryptographic fields are opaque placeholders until a reviewed
/// implementation is integrated and consensus verification is implemented.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyInputV1 {
    pub ring: Vec<OutputReference>,
    pub key_image: [u8; 32],
    pub pseudo_output_commitment: [u8; 32],
    pub clsag_signature: Vec<u8>,
}

/// A one-time destination key with a Pedersen commitment and encrypted amount.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyOutputV1 {
    pub stealth: StealthOutputV1,
    pub commitment: [u8; 32],
    /// Reserved for authenticated encrypted amount data (8-byte amount + 16-byte tag).
    pub encrypted_amount: [u8; 24],
}

/// Experimental private transaction envelope.
///
/// Fees remain explicit so miners and nodes can account for them. Amounts,
/// destinations, and spend proofs are intended to become private once the
/// cryptographic protocol is implemented.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyTransactionV1 {
    pub version: u8,
    pub network: String,
    pub inputs: Vec<PrivacyInputV1>,
    pub outputs: Vec<PrivacyOutputV1>,
    pub fee: u64,
    pub range_proof: Vec<u8>,
}

impl PrivacyTransactionV1 {
    /// Check wire-format bounds and basic structural invariants only.
    ///
    /// Passing this method MUST NOT be interpreted as a valid signature,
    /// valid range proof, balanced transaction, or consensus-valid spend.
    pub fn validate_structure(&self, expected_network: &str) -> Result<()> {
        if self.version != PRIVACY_TX_VERSION || self.network != expected_network {
            bail!("unsupported privacy transaction version or network");
        }
        if self.inputs.is_empty()
            || self.inputs.len() > MAX_PRIVACY_INPUTS
            || self.outputs.is_empty()
            || self.outputs.len() > MAX_PRIVACY_OUTPUTS
        {
            bail!("privacy transaction input/output count is out of bounds");
        }
        if self.range_proof.is_empty() || self.range_proof.len() > MAX_RANGE_PROOF_BYTES {
            bail!("privacy range proof is missing or exceeds the size limit");
        }

        let mut key_images = HashSet::with_capacity(self.inputs.len());
        for input in &self.inputs {
            if input.ring.len() != PRIVACY_RING_SIZE {
                bail!("privacy input has an invalid ring size");
            }
            validate_compressed_point(&input.key_image, "key image")?;
            if !key_images.insert(input.key_image) {
                bail!("privacy input has a duplicate key image");
            }
            validate_compressed_ristretto(
                &input.pseudo_output_commitment,
                "pseudo-output commitment",
            )?;
            if input.clsag_signature.is_empty()
                || input.clsag_signature.len() > MAX_CLSAG_BYTES
            {
                bail!("privacy input CLSAG data is missing or too large");
            }

            let mut previous_index = None;
            for member in &input.ring {
                if let Some(previous) = previous_index {
                    if member.global_index <= previous {
                        bail!("privacy input ring members must be strictly increasing");
                    }
                }
                previous_index = Some(member.global_index);
            }
        }

        for output in &self.outputs {
            validate_compressed_point(&output.stealth.one_time_key, "one-time output key")?;
            validate_compressed_point(&output.stealth.tx_public_key, "transaction public key")?;
            validate_compressed_ristretto(&output.commitment, "output commitment")?;
        }
        Ok(())
    }
}


/// Network identifiers are deliberately restricted so address encodings
/// cannot be made ambiguous by separators, whitespace, or Unicode lookalikes.
fn valid_network_id(network: &str) -> bool {
    !network.is_empty()
        && network.len() <= 64
        && network
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
}

#[derive(Serialize, Deserialize)]
struct PrivacyKeyImageStoreV1 {
    version: u8,
    network: String,
    key_images: Vec<[u8; 32]>,
}

/// Experimental local key-image registry for unit tests only.
///
/// This registry is NOT consensus state. Its snapshot persistence is local
/// test storage, not rollback-resistant or consensus-grade state. It must not
/// be used to authorize a spend or integrated into block validation. The
/// mutation helper is compiled only for unit tests because no audited
/// cryptographic verifier currently produces a verified-transaction type.
#[derive(Clone, Debug, Default)]
pub struct PrivacyKeyImageRegistryV1 {
    spent: HashSet<[u8; 32]>,
    network: Option<String>,
}

impl PrivacyKeyImageRegistryV1 {
    /// Check a transaction's key images without mutating the registry.
    pub fn check_unspent(
        &self,
        tx: &PrivacyTransactionV1,
        expected_network: &str,
    ) -> Result<()> {
        tx.validate_structure(expected_network)?;
        if self.network.as_deref().is_some_and(|network| network != expected_network) {
            bail!("privacy key-image registry belongs to another network");
        }
        for input in &tx.inputs {
            if self.spent.contains(&input.key_image) {
                bail!("privacy key image has already been spent");
            }
        }
        Ok(())
    }

    /// Test helper only: production code cannot record unverified transactions.
    ///
    /// This deliberately accepts the structural test fixture; it is not a
    /// cryptographic verification boundary and must remain test-only until a
    /// verifier-backed transaction type is implemented.
    #[cfg(test)]
    pub fn record_after_verification(
        &mut self,
        tx: &PrivacyTransactionV1,
        expected_network: &str,
    ) -> Result<()> {
        self.check_unspent(tx, expected_network)?;
        if self.spent.len().saturating_add(tx.inputs.len()) > MAX_PRIVACY_KEY_IMAGES {
            bail!("privacy key-image registry capacity exceeded");
        }
        self.spent.extend(tx.inputs.iter().map(|input| input.key_image));
        self.network = Some(expected_network.to_owned());
        Ok(())
    }

    /// Persist a network-scoped snapshot using an atomic temporary-file rename.
    /// This is experimental local storage, not consensus-grade database state:
    /// callers must serialize writers and protect the containing directory.
    pub fn save(&self, path: &Path, network: &str) -> Result<()> {
        if !valid_network_id(network) {
            bail!("invalid privacy key-image store network");
        }
        if self.network.as_deref().is_some_and(|bound| bound != network) {
            bail!("cannot save privacy key-image registry under another network");
        }
        if self.spent.len() > MAX_PRIVACY_KEY_IMAGES {
            bail!("privacy key-image registry capacity exceeded");
        }
        let mut key_images: Vec<[u8; 32]> = self.spent.iter().copied().collect();
        key_images.sort_unstable();
        let snapshot = PrivacyKeyImageStoreV1 {
            version: PRIVACY_KEY_IMAGE_STORE_VERSION,
            network: network.to_owned(),
            key_images,
        };
        let bytes = serde_json::to_vec(&snapshot)?;
        if bytes.len() as u64 > MAX_PRIVACY_KEY_IMAGE_STORE_BYTES {
            bail!("privacy key-image store exceeds the size limit");
        }
        let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        fs::create_dir_all(parent)?;
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        temporary.write_all(&bytes)?;
        temporary.as_file().sync_all()?;
        temporary.persist(path).map_err(|error| error.error)?;
        Ok(())
    }

    /// Load and strictly validate a network-scoped key-image snapshot.
    pub fn load(path: &Path, expected_network: &str) -> Result<Self> {
        if !valid_network_id(expected_network) {
            bail!("invalid expected privacy key-image store network");
        }
        let file = fs::File::open(path)?;
        let mut bytes = Vec::new();
        file.take(MAX_PRIVACY_KEY_IMAGE_STORE_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_PRIVACY_KEY_IMAGE_STORE_BYTES {
            bail!("privacy key-image store exceeds the size limit");
        }
        let snapshot: PrivacyKeyImageStoreV1 = serde_json::from_slice(&bytes)?;
        if snapshot.version != PRIVACY_KEY_IMAGE_STORE_VERSION
            || snapshot.network != expected_network
            || snapshot.key_images.len() > MAX_PRIVACY_KEY_IMAGES
        {
            bail!("unsupported, wrong-network, or oversized privacy key-image store");
        }
        let mut spent = HashSet::with_capacity(snapshot.key_images.len());
        let mut previous: Option<[u8; 32]> = None;
        for key_image in snapshot.key_images {
            validate_compressed_point(&key_image, "persisted key image")?;
            if previous.is_some_and(|value| key_image <= value) {
                bail!("privacy key-image store is not strictly sorted or has duplicates");
            }
            previous = Some(key_image);
            spent.insert(key_image);
        }
        Ok(Self {
            spent,
            network: Some(expected_network.to_owned()),
        })
    }

    pub fn contains(&self, key_image: &[u8; 32]) -> bool {
        self.spent.contains(key_image)
    }

    pub fn len(&self) -> usize {
        self.spent.len()
    }

    pub fn is_empty(&self) -> bool {
        self.spent.is_empty()
    }
}

/// Public two-key address. The spend key controls outputs; the view key scans them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyAddressV1 {
    pub network: String,
    pub spend_public: [u8; 32],
    pub view_public: [u8; 32],
}

impl PrivacyAddressV1 {
    pub fn validate(&self, expected_network: &str) -> Result<()> {
        if !valid_network_id(&self.network)
            || !valid_network_id(expected_network)
            || self.network != expected_network
        {
            bail!("privacy address belongs to another network or has invalid network text");
        }
        validate_compressed_point(&self.spend_public, "address spend public key")?;
        validate_compressed_point(&self.view_public, "address view public key")?;
        Ok(())
    }

    /// Human-readable experimental encoding; not a finalized payment URI.
    pub fn encode(&self) -> String {
        format!("ana_priv1:{}:{}:{}", self.network,
            hex::encode(self.spend_public), hex::encode(self.view_public))
    }

    pub fn decode(encoded: &str, expected_network: &str) -> Result<Self> {
        let parts: Vec<&str> = encoded.split(':').collect();
        if parts.len() != 4 || parts[0] != "ana_priv1" {
            bail!("invalid ANA privacy address encoding");
        }
        let address = Self {
            network: parts[1].to_owned(),
            spend_public: hex::decode(parts[2])?.try_into()
                .map_err(|_| anyhow::anyhow!("invalid spend public key length"))?,
            view_public: hex::decode(parts[3])?.try_into()
                .map_err(|_| anyhow::anyhow!("invalid view public key length"))?,
        };
        address.validate(expected_network)?;
        Ok(address)
    }
}

/// Per-output stealth metadata; the output's position is part of key derivation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StealthOutputV1 {
    pub one_time_key: [u8; 32],
    pub tx_public_key: [u8; 32],
    pub view_tag: u8,
}

/// Experimental wallet keys. Encrypt key material before persisting it.
pub struct PrivacyWalletKeysV1 {
    spend_secret: Scalar,
    view_secret: Scalar,
    address: PrivacyAddressV1,
}

impl PrivacyWalletKeysV1 {
    pub fn generate(network: &str) -> Result<Self> {
        Self::from_secrets(network, random_scalar(), random_scalar())
    }

    pub fn from_secrets(network: &str, spend_secret: Scalar, view_secret: Scalar) -> Result<Self> {
        if spend_secret == Scalar::ZERO || view_secret == Scalar::ZERO {
            bail!("privacy wallet secret scalars must be non-zero");
        }
        let address = PrivacyAddressV1 {
            network: network.to_owned(),
            spend_public: (ED25519_BASEPOINT_POINT * spend_secret).compress().to_bytes(),
            view_public: (ED25519_BASEPOINT_POINT * view_secret).compress().to_bytes(),
        };
        address.validate(network)?;
        Ok(Self { spend_secret, view_secret, address })
    }

    pub fn address(&self) -> &PrivacyAddressV1 { &self.address }

    /// Scan one candidate output and recover its one-time private key on a match.
    /// Amount recovery and consensus spend verification are not implemented.
    pub fn scan_output(&self, output_index: u64, output: &StealthOutputV1) -> Result<Option<DiscoveredOutputV1>> {
        let tx_public = decompress_point(&output.tx_public_key)?;
        let shared = tx_public * self.view_secret;
        if view_tag(&shared, output_index) != output.view_tag { return Ok(None); }
        let derivation = output_derivation(&shared, output_index);
        let expected = ED25519_BASEPOINT_POINT * derivation
            + decompress_point(&self.address.spend_public)?;
        if expected.compress().to_bytes() != output.one_time_key { return Ok(None); }
        Ok(Some(DiscoveredOutputV1 {
            output_index,
            one_time_secret: derivation + self.spend_secret,
        }))
    }
}

/// Wallet-discovered one-time spend key; secret has no Debug/Serialize interface.
pub struct DiscoveredOutputV1 {
    pub output_index: u64,
    one_time_secret: Scalar,
}

impl DiscoveredOutputV1 {
    pub fn public_key(&self) -> [u8; 32] {
        (ED25519_BASEPOINT_POINT * self.one_time_secret).compress().to_bytes()
    }
}

/// Create a one-time destination output for a recipient privacy address.
pub fn create_stealth_output(
    recipient: &PrivacyAddressV1,
    expected_network: &str,
    output_index: u64,
) -> Result<StealthOutputV1> {
    recipient.validate(expected_network)?;
    let ephemeral_secret = random_scalar();
    let tx_public_key = (ED25519_BASEPOINT_POINT * ephemeral_secret).compress().to_bytes();
    let shared = decompress_point(&recipient.view_public)? * ephemeral_secret;
    let derivation = output_derivation(&shared, output_index);
    let one_time_key = (ED25519_BASEPOINT_POINT * derivation
        + decompress_point(&recipient.spend_public)?).compress().to_bytes();
    Ok(StealthOutputV1 { one_time_key, tx_public_key, view_tag: view_tag(&shared, output_index) })
}

fn random_scalar() -> Scalar {
    loop {
        let mut wide = [0u8; 64];
        OsRng.fill_bytes(&mut wide);
        let scalar = Scalar::from_bytes_mod_order_wide(&wide);
        wide.fill(0);
        if scalar != Scalar::ZERO { return scalar; }
    }
}

/// Decode a canonical, non-identity point in the prime-order Edwards subgroup.
/// This is an encoding check only; it does not verify a signature or proof.
fn validate_compressed_point(encoded: &[u8; 32], field: &str) -> Result<EdwardsPoint> {
    let compressed = CompressedEdwardsY(*encoded);
    let point = compressed
        .decompress()
        .ok_or_else(|| anyhow::anyhow!("invalid Edwards point encoding for {field}"))?;
    if point.compress().to_bytes() != *encoded {
        bail!("non-canonical Edwards point encoding for {field}");
    }
    if point.is_identity() || !point.is_torsion_free() {
        bail!("identity or non-prime-subgroup Edwards point for {field}");
    }
    Ok(point)
}

fn decompress_point(encoded: &[u8; 32]) -> Result<EdwardsPoint> {
    validate_compressed_point(encoded, "wallet public point")
}

/// Decode a canonical, non-identity Ristretto point used for Pedersen commitments.
/// Ristretto encodings are not interchangeable with Edwards compressed points.
fn validate_compressed_ristretto(encoded: &[u8; 32], field: &str) -> Result<RistrettoPoint> {
    let compressed = CompressedRistretto(*encoded);
    let point = compressed
        .decompress()
        .ok_or_else(|| anyhow::anyhow!("invalid Ristretto point encoding for {field}"))?;
    if point.compress().to_bytes() != *encoded {
        bail!("non-canonical Ristretto point encoding for {field}");
    }
    if point.is_identity() {
        bail!("identity Ristretto point for {field}");
    }
    Ok(point)
}

fn output_derivation(shared: &EdwardsPoint, output_index: u64) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(b"ANA-PRIVACY-OUTPUT-DERIVATION-v1");
    hasher.update(shared.compress().as_bytes());
    hasher.update(output_index.to_le_bytes());
    let digest = hasher.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn view_tag(shared: &EdwardsPoint, output_index: u64) -> u8 {
    let mut hasher = Sha512::new();
    hasher.update(b"ANA-PRIVACY-VIEW-TAG-v1");
    hasher.update(shared.compress().as_bytes());
    hasher.update(output_index.to_le_bytes());
    hasher.finalize()[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::traits::Identity;

    #[test]
    fn stealth_output_is_discovered_only_by_matching_wallet() {
        let recipient = PrivacyWalletKeysV1::generate("ANA-TESTNET-1").unwrap();
        let unrelated = PrivacyWalletKeysV1::generate("ANA-TESTNET-1").unwrap();
        let output = create_stealth_output(recipient.address(), "ANA-TESTNET-1", 42).unwrap();
        let found = recipient.scan_output(42, &output).unwrap().unwrap();
        assert_eq!(found.output_index, 42);
        assert_eq!(found.public_key(), output.one_time_key);
        assert!(unrelated.scan_output(42, &output).unwrap().is_none());
    }

    #[test]
    fn stealth_output_is_bound_to_output_index() {
        let wallet = PrivacyWalletKeysV1::generate("ANA-TESTNET-1").unwrap();
        let output = create_stealth_output(wallet.address(), "ANA-TESTNET-1", 5).unwrap();
        assert!(wallet.scan_output(6, &output).unwrap().is_none());
        assert!(wallet.scan_output(5, &output).unwrap().is_some());
    }

    #[test]
    fn privacy_address_rejects_ambiguous_or_noncanonical_network_ids() {
        let wallet = PrivacyWalletKeysV1::generate("ANA-TESTNET-1").unwrap();
        let mut address = wallet.address().clone();
        for invalid in ["", "ana-testnet-1", "ANA:TESTNET", "ANA TESTNET", "ANA_1", "ＡＮＡ"] {
            address.network = invalid.to_owned();
            assert!(address.validate("ANA-TESTNET-1").is_err(), "accepted {invalid:?}");
        }
        address.network = "A".repeat(65);
        assert!(address.validate("ANA-TESTNET-1").is_err());
        assert!(wallet.address().validate("ana-testnet-1").is_err());
    }

    #[test]
    fn privacy_address_round_trips_and_rejects_other_network() {
        let wallet = PrivacyWalletKeysV1::generate("ANA-TESTNET-1").unwrap();
        let encoded = wallet.address().encode();
        let decoded = PrivacyAddressV1::decode(&encoded, "ANA-TESTNET-1").unwrap();
        assert_eq!(&decoded, wallet.address());
        assert!(PrivacyAddressV1::decode(&encoded, "ANA-MAINNET").is_err());
    }

    fn structurally_valid_transaction() -> PrivacyTransactionV1 {
        let valid_point = ED25519_BASEPOINT_POINT.compress().to_bytes();
        let valid_commitment = RISTRETTO_BASEPOINT_POINT.compress().to_bytes();
        PrivacyTransactionV1 {
            version: PRIVACY_TX_VERSION,
            network: "ANA-TESTNET-1".into(),
            inputs: vec![PrivacyInputV1 {
                ring: (0..PRIVACY_RING_SIZE as u64)
                    .map(|global_index| OutputReference { global_index })
                    .collect(),
                key_image: valid_point,
                pseudo_output_commitment: valid_commitment,
                clsag_signature: vec![3; 64],
            }],
            outputs: vec![PrivacyOutputV1 {
                stealth: StealthOutputV1 { one_time_key: valid_point, tx_public_key: valid_point, view_tag: 7 },
                commitment: valid_commitment,
                encrypted_amount: [6; 24],
            }],
            fee: 100,
            range_proof: vec![8; 64],
        }
    }

    #[test]
    fn privacy_v1_accepts_well_formed_envelope() {
        assert!(structurally_valid_transaction()
            .validate_structure("ANA-TESTNET-1")
            .is_ok());
    }

    #[test]
    fn privacy_v1_rejects_wrong_network_and_version() {
        let mut tx = structurally_valid_transaction();
        assert!(tx.validate_structure("ANA-MAINNET").is_err());
        tx.network = "ANA-TESTNET-1".into();
        tx.version = PRIVACY_TX_VERSION + 1;
        assert!(tx.validate_structure("ANA-TESTNET-1").is_err());
    }

    #[test]
    fn privacy_v1_rejects_wrong_ring_size_and_duplicate_members() {
        let mut tx = structurally_valid_transaction();
        tx.inputs[0].ring.pop();
        assert!(tx.validate_structure("ANA-TESTNET-1").is_err());

        let mut tx = structurally_valid_transaction();
        tx.inputs[0].ring[1].global_index = tx.inputs[0].ring[0].global_index;
        assert!(tx.validate_structure("ANA-TESTNET-1").is_err());
    }

    #[test]
    fn privacy_v1_rejects_unsorted_ring_members() {
        let mut tx = structurally_valid_transaction();
        tx.inputs[0].ring.swap(0, 1);
        assert!(tx.validate_structure("ANA-TESTNET-1").is_err());
    }

    #[test]
    fn privacy_v1_rejects_duplicate_ring_members_even_when_adjacent() {
        let mut tx = structurally_valid_transaction();
        tx.inputs[0].ring[1].global_index = tx.inputs[0].ring[0].global_index;
        assert!(tx.validate_structure("ANA-TESTNET-1").is_err());
    }

    #[test]
    fn key_image_registry_persists_and_is_network_scoped() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("privacy-key-images.json");
        let tx = structurally_valid_transaction();
        let key_image = tx.inputs[0].key_image;
        let mut registry = PrivacyKeyImageRegistryV1::default();
        registry.record_after_verification(&tx, "ANA-TESTNET-1").unwrap();
        registry.save(&path, "ANA-TESTNET-1").unwrap();

        let loaded = PrivacyKeyImageRegistryV1::load(&path, "ANA-TESTNET-1").unwrap();
        assert!(loaded.contains(&key_image));
        assert_eq!(loaded.len(), 1);
        assert!(PrivacyKeyImageRegistryV1::load(&path, "ANA-MAINNET").is_err());
    }

    #[test]
    fn key_image_registry_save_replaces_an_existing_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("replace-store.json");
        let first = structurally_valid_transaction();
        let mut registry = PrivacyKeyImageRegistryV1::default();
        registry.record_after_verification(&first, "ANA-TESTNET-1").unwrap();
        registry.save(&path, "ANA-TESTNET-1").unwrap();

        let mut second = structurally_valid_transaction();
        second.inputs[0].key_image =
            (ED25519_BASEPOINT_POINT * Scalar::from(9u64)).compress().to_bytes();
        registry.record_after_verification(&second, "ANA-TESTNET-1").unwrap();
        registry.save(&path, "ANA-TESTNET-1").unwrap();

        let loaded = PrivacyKeyImageRegistryV1::load(&path, "ANA-TESTNET-1").unwrap();
        assert_eq!(loaded.len(), 2);
        assert!(loaded.contains(&first.inputs[0].key_image));
        assert!(loaded.contains(&second.inputs[0].key_image));
    }

    #[test]
    fn key_image_registry_rejects_truncated_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("truncated-store.json");
        std::fs::write(&path, br#"{"version":1,"network":"ANA-TESTNET-1","key_images":["#)
            .unwrap();
        assert!(PrivacyKeyImageRegistryV1::load(&path, "ANA-TESTNET-1").is_err());
    }

    #[test]
    fn key_image_registry_cannot_be_relabelled_to_another_network() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("network-bound-store.json");
        let tx = structurally_valid_transaction();
        let mut registry = PrivacyKeyImageRegistryV1::default();
        registry.record_after_verification(&tx, "ANA-TESTNET-1").unwrap();
        assert!(registry.save(&path, "ANA-MAINNET").is_err());
        assert!(registry.save(&path, "ANA-TESTNET-1").is_ok());
        assert!(registry
            .check_unspent(&tx, "ANA-MAINNET")
            .is_err());
    }

    #[test]
    fn key_image_registry_rejects_noncanonical_persisted_data() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("bad-store.json");
        let snapshot = PrivacyKeyImageStoreV1 {
            version: PRIVACY_KEY_IMAGE_STORE_VERSION,
            network: "ANA-TESTNET-1".into(),
            key_images: vec![
                ED25519_BASEPOINT_POINT.compress().to_bytes(),
                ED25519_BASEPOINT_POINT.compress().to_bytes(),
            ],
        };
        std::fs::write(&path, serde_json::to_vec(&snapshot).unwrap()).unwrap();
        assert!(PrivacyKeyImageRegistryV1::load(&path, "ANA-TESTNET-1").is_err());
    }

    #[test]
    fn key_image_registry_rejects_replay_across_transactions() {
        let tx = structurally_valid_transaction();
        let key_image = tx.inputs[0].key_image;
        let mut registry = PrivacyKeyImageRegistryV1::default();

        assert!(registry.check_unspent(&tx, "ANA-TESTNET-1").is_ok());
        registry.record_after_verification(&tx, "ANA-TESTNET-1").unwrap();
        assert!(registry.contains(&key_image));
        assert_eq!(registry.len(), 1);
        assert!(registry.check_unspent(&tx, "ANA-TESTNET-1").is_err());
        assert!(registry
            .record_after_verification(&tx, "ANA-TESTNET-1")
            .is_err());
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn key_image_registry_recording_is_atomic_on_conflict() {
        let mut registry = PrivacyKeyImageRegistryV1::default();
        let existing = structurally_valid_transaction();
        registry
            .record_after_verification(&existing, "ANA-TESTNET-1")
            .unwrap();

        let mut candidate = structurally_valid_transaction();
        candidate.inputs[0].key_image =
            (ED25519_BASEPOINT_POINT * Scalar::from(2u64)).compress().to_bytes();
        let mut conflicting = candidate.inputs[0].clone();
        conflicting.key_image = existing.inputs[0].key_image;
        conflicting.ring.iter_mut().for_each(|member| member.global_index += 100);
        candidate.inputs.push(conflicting);

        let new_key_image = candidate.inputs[0].key_image;
        assert!(registry
            .record_after_verification(&candidate, "ANA-TESTNET-1")
            .is_err());
        assert!(!registry.contains(&new_key_image));
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn privacy_v1_rejects_duplicate_key_images() {
        let mut tx = structurally_valid_transaction();
        let mut second = tx.inputs[0].clone();
        second.ring.iter_mut().for_each(|member| member.global_index += 100);
        tx.inputs.push(second);
        assert!(tx.validate_structure("ANA-TESTNET-1").is_err());
    }

    #[test]
    fn point_encoding_rejects_identity_noncanonical_and_invalid_points() {
        let identity = EdwardsPoint::identity().compress().to_bytes();
        assert!(validate_compressed_point(&identity, "test").is_err());
        assert!(validate_compressed_point(&[0xff; 32], "test").is_err());
        let basepoint = ED25519_BASEPOINT_POINT.compress().to_bytes();
        assert!(validate_compressed_point(&basepoint, "test").is_ok());
    }

    #[test]
    fn privacy_v1_uses_ristretto_for_pedersen_commitments() {
        let mut tx = structurally_valid_transaction();
        assert!(tx.validate_structure("ANA-TESTNET-1").is_ok());

        // Edwards encodings must not be accepted in Ristretto commitment fields.
        let edwards = ED25519_BASEPOINT_POINT.compress().to_bytes();
        tx.inputs[0].pseudo_output_commitment = edwards;
        assert!(tx.validate_structure("ANA-TESTNET-1").is_err());

        let mut tx = structurally_valid_transaction();
        tx.outputs[0].commitment = edwards;
        assert!(tx.validate_structure("ANA-TESTNET-1").is_err());
    }

    #[test]
    fn privacy_v1_rejects_identity_ristretto_commitments() {
        let identity = RistrettoPoint::default().compress().to_bytes();

        let mut tx = structurally_valid_transaction();
        tx.inputs[0].pseudo_output_commitment = identity;
        assert!(tx.validate_structure("ANA-TESTNET-1").is_err());

        let mut tx = structurally_valid_transaction();
        tx.outputs[0].commitment = identity;
        assert!(tx.validate_structure("ANA-TESTNET-1").is_err());
    }

    #[test]
    fn privacy_v1_rejects_invalid_curve_point_fields() {
        let mut tx = structurally_valid_transaction();
        tx.inputs[0].key_image = [0xff; 32];
        assert!(tx.validate_structure("ANA-TESTNET-1").is_err());
        let mut tx = structurally_valid_transaction();
        tx.outputs[0].stealth.tx_public_key = EdwardsPoint::identity().compress().to_bytes();
        assert!(tx.validate_structure("ANA-TESTNET-1").is_err());
    }

    #[test]
    fn privacy_v1_rejects_small_order_points_in_every_point_field() {
        // The compressed Edwards encoding with y = 0 decompresses to a
        // non-identity point of small order. It must not pass prime-subgroup
        // validation even though it is a decodable curve point.
        let small_order = [0u8; 32];

        let mut tx = structurally_valid_transaction();
        tx.inputs[0].key_image = small_order;
        assert!(tx.validate_structure("ANA-TESTNET-1").is_err());

        let mut tx = structurally_valid_transaction();
        tx.inputs[0].pseudo_output_commitment = small_order;
        assert!(tx.validate_structure("ANA-TESTNET-1").is_err());

        let mut tx = structurally_valid_transaction();
        tx.outputs[0].stealth.one_time_key = small_order;
        assert!(tx.validate_structure("ANA-TESTNET-1").is_err());

        let mut tx = structurally_valid_transaction();
        tx.outputs[0].stealth.tx_public_key = small_order;
        assert!(tx.validate_structure("ANA-TESTNET-1").is_err());

        let mut tx = structurally_valid_transaction();
        tx.outputs[0].commitment = small_order;
        assert!(tx.validate_structure("ANA-TESTNET-1").is_err());
    }

    #[test]
    fn privacy_v1_rejects_missing_proof_material() {
        let mut tx = structurally_valid_transaction();
        tx.range_proof.clear();
        assert!(tx.validate_structure("ANA-TESTNET-1").is_err());

        let mut tx = structurally_valid_transaction();
        tx.inputs[0].clsag_signature.clear();
        assert!(tx.validate_structure("ANA-TESTNET-1").is_err());
    }
}
