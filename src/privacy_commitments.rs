//! Experimental Pedersen commitments for future ANA confidential amounts.
//!
//! This module uses Ristretto points, deliberately separate from the Edwards
//! point encodings used by the current privacy transaction envelope.
//! It is a primitive prototype only: no range proofs, transaction balance
//! verification, CLSAG, amount encryption, or consensus integration is provided.
//! Do not use these functions to authorize or accept a transaction.

use anyhow::{bail, Result};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use sha2::Sha512;

/// Domain-separated secondary generator for ANA Pedersen commitments.
/// This value is deterministic and must never be replaced by a known discrete-log relation.
fn blinding_generator() -> RistrettoPoint {
    RistrettoPoint::hash_from_bytes::<Sha512>(
        b"ANA-PEDERSEN-BLINDING-GENERATOR-v1",
    )
}

/// Commitment C = amount*G + blinding*H, with amount represented in atomic units.
pub fn commit_amount(amount: u64, blinding: Scalar) -> [u8; 32] {
    let commitment = RISTRETTO_BASEPOINT_POINT * Scalar::from(amount)
        + blinding_generator() * blinding;
    commitment.compress().to_bytes()
}

/// Check an opening against a compressed Ristretto commitment.
pub fn verify_opening(
    encoded_commitment: &[u8; 32],
    amount: u64,
    blinding: Scalar,
) -> Result<()> {
    let compressed = CompressedRistretto(*encoded_commitment);
    let point = compressed
        .decompress()
        .ok_or_else(|| anyhow::anyhow!("invalid Ristretto commitment encoding"))?;
    if point.compress().to_bytes() != *encoded_commitment {
        bail!("non-canonical Ristretto commitment encoding");
    }
    let expected = RISTRETTO_BASEPOINT_POINT * Scalar::from(amount)
        + blinding_generator() * blinding;
    if point != expected {
        bail!("Pedersen commitment opening does not match");
    }
    Ok(())
}

/// Add two compressed commitments homomorphically.
/// The caller must separately account for fees and prove amount ranges.
pub fn add_commitments(
    left: &[u8; 32],
    right: &[u8; 32],
) -> Result<[u8; 32]> {
    let left = CompressedRistretto(*left)
        .decompress()
        .ok_or_else(|| anyhow::anyhow!("invalid left Ristretto commitment"))?;
    let right = CompressedRistretto(*right)
        .decompress()
        .ok_or_else(|| anyhow::anyhow!("invalid right Ristretto commitment"))?;
    Ok((left + right).compress().to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_accepts_correct_opening_and_rejects_wrong_opening() {
        let blinding = Scalar::from(123_456u64);
        let commitment = commit_amount(42 * 100_000_000, blinding);
        assert!(verify_opening(&commitment, 42 * 100_000_000, blinding).is_ok());
        assert!(verify_opening(&commitment, 43 * 100_000_000, blinding).is_err());
        assert!(verify_opening(&commitment, 42 * 100_000_000, Scalar::from(7u64)).is_err());
    }

    #[test]
    fn commitments_are_homomorphic_for_amount_and_blinding_sums() {
        let amount_a = 12_345u64;
        let amount_b = 67_890u64;
        let blind_a = Scalar::from(111u64);
        let blind_b = Scalar::from(222u64);
        let a = commit_amount(amount_a, blind_a);
        let b = commit_amount(amount_b, blind_b);
        let sum = add_commitments(&a, &b).unwrap();
        let expected = commit_amount(amount_a + amount_b, blind_a + blind_b);
        assert_eq!(sum, expected);
    }

    #[test]
    fn malformed_commitment_encoding_is_rejected() {
        assert!(verify_opening(&[0xff; 32], 1, Scalar::ZERO).is_err());
        assert!(add_commitments(&[0xff; 32], &[0u8; 32]).is_err());
    }
}
