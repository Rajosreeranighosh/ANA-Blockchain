//! Versioned privacy-transaction wire model for ANA's future private ledger.
//!
//! IMPORTANT: this module performs structural checks only. It does not implement
//! stealth-address derivation, CLSAG, Pedersen commitments, range proofs, or
//! cryptographic verification. Do not accept these transactions in consensus.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
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
    pub one_time_key: [u8; 32],
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
            if output.one_time_key.iter().all(|byte| *byte == 0)
                || output.commitment.iter().all(|byte| *byte == 0)
            {
                bail!("privacy output has an empty key or commitment");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                one_time_key: [4; 32],
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
