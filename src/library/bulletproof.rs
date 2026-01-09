use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

use crate::library::output::setup_generators;
use crate::library::constants::{TRANSCRIPT_TAG,BULLETPROOF_N_BITS};

pub fn create_bulletproof(
    commitment_c: RistrettoPoint,
    v: u64,
    r: Scalar,
) -> Result<RangeProof, String> {
    if v == 0 {
        return Err("cannot prove v>0 if v=0".into());
    }
    if !(BULLETPROOF_N_BITS == 8 || BULLETPROOF_N_BITS == 16 || BULLETPROOF_N_BITS == 32 || BULLETPROOF_N_BITS == 64) {
        return Err("n_bits must be one of {8,16,32,64}".into());
    }

    let (g1, g2, _g_pay, _g_vrf) = setup_generators();
    let pc_gens = PedersenGens { B: g1, B_blinding: g2 };
    let bp_gens = BulletproofGens::new(BULLETPROOF_N_BITS, 1);

    let v_minus_1 = v - 1;

    let c_prime = commitment_c - g1;
    let c_prime_comp = c_prime.compress();

    let mut prover_transcript = Transcript::new(TRANSCRIPT_TAG);
    let (proof, committed_value_from_api) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        v_minus_1,
        &r,
        BULLETPROOF_N_BITS,
    )
    .map_err(|e| format!("prove_single failed: {e:?}"))?;

    if committed_value_from_api != c_prime_comp {
        return Err("commitment mismatch: your C != v*G1 + r*G2 (or G1/G2 differ)".into());
    }

    Ok(proof)
}

pub fn bulletproof_to_hex(proof: &RangeProof) -> String {
    hex::encode(proof.to_bytes())
}

pub fn bulletproof_from_hex(proof_hex: &str) -> Result<RangeProof, String> {
    let s = proof_hex.trim().strip_prefix("0x").unwrap_or(proof_hex.trim());
    let bytes = hex::decode(s).map_err(|e| format!("hex decode failed: {e}"))?;
    RangeProof::from_bytes(&bytes).map_err(|e| format!("RangeProof::from_bytes failed: {e:?}"))
}

pub fn verify_bulletproof(
    range_proof_hex: &str,
    c_diff: &RistrettoPoint,
) -> Result<(), String> {
    let proof:RangeProof = bulletproof_from_hex(range_proof_hex)?;

    let (g1, g2, _g_pay, _g_vrf) = setup_generators();
    let pc_gens = PedersenGens { B: g1, B_blinding: g2 };
    let bp_gens = BulletproofGens::new(BULLETPROOF_N_BITS, 1);

    let c_prime = (c_diff - pc_gens.B).compress();

    let mut transcript = Transcript::new(TRANSCRIPT_TAG);
    proof
        .verify_single(&bp_gens, &pc_gens, &mut transcript, &c_prime, BULLETPROOF_N_BITS)
        .map_err(|e| format!("verify_single failed: {e:?}"))
}

