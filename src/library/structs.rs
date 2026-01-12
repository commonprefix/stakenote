use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use vrf_r255::{PublicKey,SecretKey};
use serde::{Deserialize, Serialize};

use crate::library::helpers::{hex_to_point,hex_to_bytes,bytes_to_hex,point_to_hex,hex_to_scalar,scalar_to_hex};

#[derive(Clone, Debug)]
pub struct VRFKey {
    pub sk: SecretKey,
    pub vk: PublicKey,
}

#[derive(Clone, Debug)]
pub struct ClsagSig {
    pub c_diff: RistrettoPoint,
    pub c0: Scalar,
    pub s_x: Vec<Scalar>,
    pub s_r: Vec<Scalar>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClsagSigJson {
    pub diff_commitment: String,
    pub c0: String,
    pub s_x: Vec<String>,
    pub s_r: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct OutputSecret {
    pub sk_pay: Scalar,
    pub amount: u64,
    pub r: Scalar,
}

#[derive(Clone, Debug)]
pub struct OutputPublic {
    pub vk_pay: RistrettoPoint,
    pub commitment: RistrettoPoint,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OutputPubJson {
    pub pubkey: String,
    pub stake_commitment: String,
}

#[derive(Clone, Debug)]
pub struct Output {
    pub secret: OutputSecret,
    pub public: OutputPublic,
}

#[derive(Clone, Debug)]
pub struct BlockMsg {
    pub payload_b: Vec<u8>,
    pub epoch: u64,
    pub slot: u64,
    pub vk_vrf_o: RistrettoPoint,
    pub y_o: String,
    pub pi_y: Vec<u8>,
    pub t: u64,
    pub key_image: RistrettoPoint,
    pub range_proof: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockMsgJson {
    pub payload: String,
    pub epoch: u64,
    pub slot: u64,
    pub vrf_pubkey: String,
    pub vrf_output: String,
    pub vrf_proof: String,
    pub t: u64,
    pub key_image: String,
    pub range_proof: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockJson {
    pub msg: BlockMsgJson,
    pub ring: Vec<OutputPubJson>,
    pub sig: ClsagSigJson,
}

pub struct Block {
    pub msg: BlockMsg,
    pub ring: Vec<OutputPublic>,
    pub sig: ClsagSig,
}

// -------------------------
// Conversions: in-memory <-> JSON
// -------------------------

impl From<&BlockMsg> for BlockMsgJson {
    fn from(m: &BlockMsg) -> Self {
        Self {
            payload: bytes_to_hex(&m.payload_b),
            epoch: m.epoch,
            slot: m.slot,
            vrf_pubkey: point_to_hex(&m.vk_vrf_o),
            vrf_output: m.y_o.clone(),
            vrf_proof: bytes_to_hex(&m.pi_y),
            t: m.t,
            key_image: point_to_hex(&m.key_image),
            range_proof: m.range_proof.clone(),
        }
    }
}

impl TryFrom<BlockMsgJson> for BlockMsg {
    type Error = String;

    fn try_from(j: BlockMsgJson) -> Result<Self, Self::Error> {
        Ok(Self {
            payload_b: hex_to_bytes(&j.payload)?,
            epoch: j.epoch,
            slot: j.slot,
            vk_vrf_o: hex_to_point(&j.vrf_pubkey)?,
            y_o: j.vrf_output,
            pi_y: hex_to_bytes(&j.vrf_proof)?,
            t: j.t,
            key_image: hex_to_point(&j.key_image)?,
            range_proof: j.range_proof,
        })
    }
}

impl From<&ClsagSig> for ClsagSigJson {
    fn from(s: &ClsagSig) -> Self {
        Self {
            diff_commitment: point_to_hex(&s.c_diff),
            c0: scalar_to_hex(&s.c0),
            s_x: s.s_x.iter().map(scalar_to_hex).collect(),
            s_r: s.s_r.iter().map(scalar_to_hex).collect(),
        }
    }
}

impl TryFrom<ClsagSigJson> for ClsagSig {
    type Error = String;

    fn try_from(j: ClsagSigJson) -> Result<Self, Self::Error> {
        let s_x = j.s_x.into_iter().map(|h| hex_to_scalar(&h)).collect::<Result<Vec<_>, _>>()?;
        let s_r = j.s_r.into_iter().map(|h| hex_to_scalar(&h)).collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            c_diff: hex_to_point(&j.diff_commitment)?,
            c0: hex_to_scalar(&j.c0)?,
            s_x,
            s_r,
        })
    }
}

impl From<&OutputPublic> for OutputPubJson {
    fn from(o: &OutputPublic) -> Self {
        Self {
            pubkey: point_to_hex(&o.vk_pay),
            stake_commitment: point_to_hex(&o.commitment),
        }
    }
}

impl TryFrom<OutputPubJson> for OutputPublic {
    type Error = String;

    fn try_from(j: OutputPubJson) -> Result<Self, Self::Error> {
        Ok(Self {
            vk_pay: hex_to_point(&j.pubkey)?,
            commitment: hex_to_point(&j.stake_commitment)?,
        })
    }
}
