//! Experimental Pedersen commitments for future ANA confidential amounts.
//!
//! This module uses Ristretto points, deliberately separate from the Edwards
//! point encodings used by the current privacy transaction envelope.
//! It is a primitive prototype only: no range proofs, CLSAG, authenticated
//! amount encryption, or consensus integration is provided. Do not use these
//! functions to authorize or accept a transaction.

use anyhow::{bail, Result};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
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

/// Verify the Pedersen amount-balance equation for a transaction.
///
/// Under ANA's C = amount*G + blinding*H convention, this checks:
/// sum(inputs) - sum(outputs) - fee*G == identity.
///
/// This is only an algebraic commitment check. It does not prove that input
/// commitments belong to ring members, that CLSAG signatures are valid, or
/// that any committed amount is in range. Those checks are mandatory elsewhere.
pub fn verify_commitment_balance(
    input_commitments: &[[u8; 32]],
    output_commitments: &[[u8; 32]],
    fee: u64,
) -> Result<()> {
    if input_commitments.is_empty() || output_commitments.is_empty() {
        bail!("commitment balance requires at least one input and output");
    }

    let mut balance = RistrettoPoint::identity();
    for encoded in input_commitments {
        let point = CompressedRistretto(*encoded)
            .decompress()
            .ok_or_else(|| anyhow::anyhow!("invalid input commitment encoding"))?;
        if point.compress().to_bytes() != *encoded {
            bail!("non-canonical input commitment encoding");
        }
        balance += point;
    }

    for encoded in output_commitments {
        let point = CompressedRistretto(*encoded)
            .decompress()
            .ok_or_else(|| anyhow::anyhow!("invalid output commitment encoding"))?;
        if point.compress().to_bytes() != *encoded {
            bail!("non-canonical output commitment encoding");
        }
        balance -= point;
    }

    balance -= RISTRETTO_BASEPOINT_POINT * Scalar::from(fee);
    if balance != RistrettoPoint::identity() {
        bail!("Pedersen input/output/fee commitments are not balanced");
    }
    Ok(())
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

    #[test]
    fn blinding_generator_is_non_identity_and_distinct_from_value_generator() {
        let h = blinding_generator();
        assert_ne!(h, RistrettoPoint::default());
        assert_ne!(h, RISTRETTO_BASEPOINT_POINT);
    }

    #[test]
    fn addition_rejects_malformed_encoding_in_either_operand() {
        let valid = commit_amount(1, Scalar::from(9u64));
        assert!(add_commitments(&[0xff; 32], &valid).is_err());
        assert!(add_commitments(&valid, &[0xff; 32]).is_err());
    }

    #[test]
    fn homomorphic_addition_returns_a_canonical_ristretto_encoding() {
        let a = commit_amount(5, Scalar::from(13u64));
        let b = commit_amount(8, Scalar::from(21u64));
        let sum = add_commitments(&a, &b).unwrap();
        let point = CompressedRistretto(sum).decompress().unwrap();
        assert_eq!(point.compress().to_bytes(), sum);
        assert!(verify_opening(&sum, 13, Scalar::from(34u64)).is_ok());
    }

    #[test]
    fn balanced_transaction_commitments_include_explicit_fee() {
        // 1,000 input units = 400 + 500 output units + 100 fee.
        // Input blinding is the sum of output blindings.
        let input = commit_amount(1_000, Scalar::from(30u64));
        let outputs = [
            commit_amount(400, Scalar::from(10u64)),
            commit_amount(500, Scalar::from(20u64)),
        ];
        assert!(verify_commitment_balance(&[input], &outputs, 100).is_ok());
    }

    #[test]
    fn commitment_balance_rejects_wrong_fee_or_unbalanced_amounts() {
        let input = commit_amount(1_000, Scalar::from(30u64));
        let outputs = [
            commit_amount(400, Scalar::from(10u64)),
            commit_amount(500, Scalar::from(20u64)),
        ];
        assert!(verify_commitment_balance(&[input], &outputs, 99).is_err());
        let bad_output = commit_amount(501, Scalar::from(20u64));
        assert!(verify_commitment_balance(&[input], &[outputs[0], bad_output], 100).is_err());
    }

    #[test]
    fn commitment_balance_rejects_empty_sets_and_malformed_points() {
        let valid = commit_amount(10, Scalar::from(4u64));
        assert!(verify_commitment_balance(&[], &[valid], 0).is_err());
        assert!(verify_commitment_balance(&[valid], &[], 0).is_err());
        assert!(verify_commitment_balance(&[[0xff; 32]], &[valid], 0).is_err());
        assert!(verify_commitment_balance(&[valid], &[[0xff; 32]], 0).is_err());
    }
}
