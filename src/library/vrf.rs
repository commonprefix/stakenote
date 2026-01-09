use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;
use vrf_r255::{PublicKey,SecretKey,Proof};

use crate::library::helpers::{ctoption_to_result};
use crate::library::output::setup_generators;
use crate::library::structs::{VRFKey};

fn sk_from_hex_32(hex_str: &str) -> Result<SecretKey, String> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);

    let raw = hex::decode(hex_str).map_err(|e| format!("hex decode failed: {e}"))?;
    if raw.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", raw.len()));
    }

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&raw);

    ctoption_to_result(SecretKey::from_bytes(bytes), "invalid secret key encoding")
}

pub fn create_vrf_keypair_from_hex(sk_hex: &str) -> Result<VRFKey, String> {
    let sk = sk_from_hex_32(&sk_hex)?;
    let pk = PublicKey::from(sk);
    Ok(VRFKey { sk: sk, vk: pk })
}

pub fn vk_point_from_scalar(sk: Scalar) -> RistrettoPoint {
    let (_, _, _, gvrf) = setup_generators();
    sk * gvrf
}

pub fn create_vrf_message(prefix: &str, n: u64) -> Vec<u8> {
    let mut msg = Vec::with_capacity(prefix.len() + 8);
    msg.extend_from_slice(prefix.as_bytes());
    msg.extend_from_slice(&n.to_be_bytes());
    msg
}

pub fn compute_vrf(sk: SecretKey, msg: &Vec<u8>) -> Result<(String, Proof), String> {
    let pk = PublicKey::from(sk);

    let proof = sk.prove(&msg);

    let beta_ct = pk.verify(&msg, &proof);
    let beta = ctoption_to_result(beta_ct, "VRF proof did not verify")?;

    let beta_hex = hex::encode(&beta);

    Ok((beta_hex, proof))
}
