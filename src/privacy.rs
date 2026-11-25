//! Versioned privacy-transaction wire model for ANA's future private ledger.
//!
//! IMPORTANT: this module performs structural checks only. It does not implement
//! stealth-address derivation, CLSAG, Pedersen commitments, range proofs, or
//! cryptographic verification. Do not accept these transactions in consensus.

use anyhow::{bail, Result};
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, edwards::{CompressedEdwardsY, EdwardsPoint}, scalar::Scalar};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::collections::HashSet;

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
    pub view_tag: u8,
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
            if input.key_image.iter().all(|byte| *byte == 0)
                || !key_images.insert(input.key_image)
            {
                bail!("privacy input has a zero or duplicate key image");
            }
            if input.pseudo_output_commitment.iter().all(|byte| *byte == 0) {
                bail!("privacy input has an empty pseudo-output commitment");
            }
            if input.clsag_signature.is_empty()
                || input.clsag_signature.len() > MAX_CLSAG_BYTES
            {
                bail!("privacy input CLSAG data is missing or too large");
            }

            let mut ring_members = HashSet::with_capacity(input.ring.len());
            for member in &input.ring {
                if !ring_members.insert(member.global_index) {
                    bail!("privacy input ring contains a duplicate output");
                }
            }
        }

        for output in &self.outputs {
            if output.stealth.one_time_key.iter().all(|byte| *byte == 0)
                || output.commitment.iter().all(|byte| *byte == 0)
            {
                bail!("privacy output has an empty key or commitment");
            }
        }
        Ok(())
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
        if self.network != expected_network || self.network.contains(':') {
            bail!("privacy address belongs to another network or has invalid network text");
        }
        for encoded in [&self.spend_public, &self.view_public] {
            let point = CompressedEdwardsY(*encoded).decompress()
                .ok_or_else(|| anyhow::anyhow!("privacy address contains an invalid public key"))?;
            if point.is_identity() { bail!("privacy address contains the identity point"); }
        }
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

fn decompress_point(encoded: &[u8; 32]) -> Result<EdwardsPoint> {
    let point = CompressedEdwardsY(*encoded).decompress()
        .ok_or_else(|| anyhow::anyhow!("invalid Edwards public point"))?;
    if point.is_identity() { bail!("identity Edwards point is not allowed"); }
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
    fn privacy_address_round_trips_and_rejects_other_network() {
        let wallet = PrivacyWalletKeysV1::generate("ANA-TESTNET-1").unwrap();
        let encoded = wallet.address().encode();
        let decoded = PrivacyAddressV1::decode(&encoded, "ANA-TESTNET-1").unwrap();
        assert_eq!(&decoded, wallet.address());
        assert!(PrivacyAddressV1::decode(&encoded, "ANA-MAINNET").is_err());
    }

    fn structurally_valid_transaction() -> PrivacyTransactionV1 {
        PrivacyTransactionV1 {
            version: PRIVACY_TX_VERSION,
            network: "ANA-TESTNET-1".into(),
            inputs: vec![PrivacyInputV1 {
                ring: (0..PRIVACY_RING_SIZE as u64)
                    .map(|global_index| OutputReference { global_index })
                    .collect(),
                key_image: [1; 32],
                pseudo_output_commitment: [2; 32],
                clsag_signature: vec![3; 64],
            }],
            outputs: vec![PrivacyOutputV1 {
                stealth: StealthOutputV1 { one_time_key: [4; 32], tx_public_key: [9; 32], view_tag: 7 },
                commitment: [5; 32],
                encrypted_amount: [6; 24],
                view_tag: 7,
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
    fn privacy_v1_rejects_duplicate_key_images() {
        let mut tx = structurally_valid_transaction();
        let mut second = tx.inputs[0].clone();
        second.ring.iter_mut().for_each(|member| member.global_index += 100);
        tx.inputs.push(second);
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
