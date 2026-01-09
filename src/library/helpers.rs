use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rug::Integer;
use subtle::CtOption;
use std::error::Error;

use crate::library::structs::{BlockMsg,ClsagSig,OutputPublic,BlockMsgJson,ClsagSigJson,OutputPubJson,BlockJson,Block};

/// Convert 32 big-endian bytes to Integer in [0, 2^256).
pub fn u256_from_be(bytes32: &[u8; 32]) -> Integer {
    Integer::from_digits(bytes32, rug::integer::Order::MsfBe)
}

pub fn ctoption_to_result<T: Copy>(x: CtOption<T>, err: &'static str) -> Result<T, String> {
    if bool::from(x.is_some()) {
        Ok(x.unwrap())
    } else {
        Err(err.to_string())
    }
}

// -------------------------
// Hex helpers
// -------------------------

pub fn ristretto_point_to_hex(p: &RistrettoPoint) -> String {
    hex::encode(p.compress().to_bytes()) // 32 bytes
}

pub fn scalar_to_hex(s: &Scalar) -> String {
    hex::encode(s.to_bytes()) // 32 bytes
}

pub fn bytes_to_hex(b: &[u8]) -> String {
    hex::encode(b)
}

pub fn hex_to_bytes(h: &str) -> Result<Vec<u8>, String> {
    let s = h.trim().strip_prefix("0x").unwrap_or(h.trim());
    hex::decode(s).map_err(|e| format!("hex decode failed: {e}"))
}

pub fn point_to_hex(p: &RistrettoPoint) -> String {
    hex::encode(p.compress().to_bytes()) // 32 bytes
}

pub fn hex_to_point(h: &str) -> Result<RistrettoPoint, String> {
    let bytes = hex_to_bytes(h)?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes for point, got {}", bytes.len()));
    }
    let mut b = [0u8; 32];
    b.copy_from_slice(&bytes);
    CompressedRistretto(b)
        .decompress()
        .ok_or("invalid Ristretto point encoding".to_string())
}

pub fn hex_to_scalar(h: &str) -> Result<Scalar, String> {
    let bytes = hex_to_bytes(h)?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes for scalar, got {}", bytes.len()));
    }
    let mut b = [0u8; 32];
    b.copy_from_slice(&bytes);
    ctoption_to_result(Scalar::from_canonical_bytes(b), "invalid scalar encoding")
}

// -------------------------
// Read/write JSON files
// -------------------------

pub fn write_block_json(path: &str, block: &Block) -> Result<(), Box<dyn std::error::Error>> {
    let j = BlockJson {
        msg: BlockMsgJson::from(&block.msg),
        ring: block.ring.iter().map(OutputPubJson::from).collect(),
        sig: ClsagSigJson::from(&block.sig),
    };
    std::fs::write(path, serde_json::to_string_pretty(&j)?)?;
    Ok(())
}

pub fn read_block_from_json_file(path: &str) -> Result<Block, Box<dyn Error>> {
    let txt = std::fs::read_to_string(path)?;

    let j:BlockJson = serde_json::from_str(&txt)?;

    let msg:BlockMsg = BlockMsg::try_from(j.msg)?;
    let sig:ClsagSig = ClsagSig::try_from(j.sig)?;

    let ring:Vec<OutputPublic> = j
        .ring
        .into_iter()
        .map(OutputPublic::try_from)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Block { msg, ring, sig })
}
