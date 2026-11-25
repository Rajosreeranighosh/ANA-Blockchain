//! Experimental 64-bit Bulletproof range proofs for ANA commitments.
//!
//! This module uses the Dalek Bulletproofs implementation over Ristretto.
//! It deliberately uses the same value and blinding generators as
//! privacy_commitments so the proof commitment matches commit_amount().
//!
//! This proves only that one committed value is in [0, 2^64). It does NOT prove
//! transaction balance, fee correctness, ownership, or compliance with the
//! global ANA supply cap. It is not wired into transaction consensus.

use anyhow::{bail, Context, Result};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use merlin::Transcript;
use rand::rngs::OsRng;
use sha2::Sha512;

use crate::privacy_commitments::commit_amount;

const RANGE_BITS: usize = 64;
const RANGE_PROOF_BYTES: usize = 672;
const TRANSCRIPT_DOMAIN: &[u8] = b"ANA-CONFIDENTIAL-AMOUNT-RANGE-v1";

fn blinding_generator() -> RistrettoPoint {
    RistrettoPoint::hash_from_bytes::<Sha512>(
        b"ANA-PEDERSEN-BLINDING-GENERATOR-v1",
    )
}

fn pedersen_generators() -> PedersenGens {
    PedersenGens {
        B: RISTRETTO_BASEPOINT_POINT,
        B_blinding: blinding_generator(),
    }
}

fn range_transcript() -> Transcript {
    let mut transcript = Transcript::new(TRANSCRIPT_DOMAIN);
    transcript.append_message(b"network", b"ANA-TESTNET-1");
    transcript.append_message(b"range-bits", &[RANGE_BITS as u8]);
    transcript
}

/// Prove that an amount is in [0, 2^64), returning proof bytes and its commitment.
///
/// Amount is in atomic units. Keep the blinding secret and never reuse it for
/// unrelated commitments. The returned commitment is byte-for-byte compatible
/// with privacy_commitments::commit_amount.
pub fn prove_amount_range(
    amount: u64,
    blinding: Scalar,
) -> Result<(Vec<u8>, [u8; 32])> {
    let bp_gens = BulletproofGens::new(RANGE_BITS, 1);
    let pc_gens = pedersen_generators();
    let mut transcript = range_transcript();
    let mut rng = OsRng;

    let (proof, commitment) = RangeProof::prove_single_with_rng(
        &bp_gens,
        &pc_gens,
        &mut transcript,
        amount,
        &blinding,
        RANGE_BITS,
        &mut rng,
    )
    .context("could not create ANA amount range proof")?;

    let encoded_commitment = commitment.to_bytes();
    if encoded_commitment != commit_amount(amount, blinding) {
        bail!("range proof commitment does not match ANA commitment encoding");
    }

    let proof_bytes = proof.to_bytes();
    if proof_bytes.len() != RANGE_PROOF_BYTES {
        bail!("unexpected 64-bit range proof length");
    }

    Ok((proof_bytes, encoded_commitment))
}

/// Verify a 64-bit range proof against an ANA Ristretto commitment.
///
/// The caller must also verify transaction balance, fees, and consensus supply
/// accounting separately. A valid range proof alone does not authorize a spend.
pub fn verify_amount_range(
    proof_bytes: &[u8],
    encoded_commitment: &[u8; 32],
) -> Result<()> {
    if proof_bytes.len() != RANGE_PROOF_BYTES {
        bail!("invalid 64-bit range proof length");
    }

    let compressed = CompressedRistretto(*encoded_commitment);
    let point = compressed
        .decompress()
        .ok_or_else(|| anyhow::anyhow!("invalid ANA Ristretto commitment"))?;
    if point.compress().to_bytes() != *encoded_commitment {
        bail!("non-canonical ANA commitment encoding");
    }

    let proof = RangeProof::from_bytes(proof_bytes)
        .context("invalid ANA Bulletproof encoding")?;
    let bp_gens = BulletproofGens::new(RANGE_BITS, 1);
    let pc_gens = pedersen_generators();
    let mut transcript = range_transcript();
    let mut rng = OsRng;

    proof
        .verify_single_with_rng(
            &bp_gens,
            &pc_gens,
            &mut transcript,
            &compressed,
            RANGE_BITS,
            &mut rng,
        )
        .context("ANA amount range proof verification failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_range_proof_matches_existing_ana_commitment() {
        let amount = 50 * 100_000_000u64;
        let blinding = Scalar::from(0xA11CEu64);
        let (proof, commitment) = prove_amount_range(amount, blinding).unwrap();

        assert_eq!(commitment, commit_amount(amount, blinding));
        assert_eq!(proof.len(), RANGE_PROOF_BYTES);
        verify_amount_range(&proof, &commitment).unwrap();
    }

    #[test]
    fn range_proof_rejects_a_different_valid_commitment() {
        let (proof, commitment) =
            prove_amount_range(123_456, Scalar::from(77u64)).unwrap();
        let wrong_commitment = commit_amount(123_457, Scalar::from(78u64));

        assert_ne!(commitment, wrong_commitment);
        assert!(verify_amount_range(&proof, &wrong_commitment).is_err());
    }

    #[test]
    fn malformed_or_wrong_length_proofs_are_rejected() {
        let commitment = commit_amount(1, Scalar::from(9u64));
        assert!(verify_amount_range(&[0u8; 16], &commitment).is_err());
        assert!(verify_amount_range(&[0xff; RANGE_PROOF_BYTES], &commitment).is_err());
    }

    #[test]
    fn malformed_commitment_is_rejected_before_proof_verification() {
        assert!(verify_amount_range(&[0u8; RANGE_PROOF_BYTES], &[0xff; 32]).is_err());
    }
}
