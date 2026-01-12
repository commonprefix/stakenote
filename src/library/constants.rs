// GLOBAL
pub const G1_LABEL:&str = "StakeNote/G1";
pub const G2_LABEL:&str = "StakeNote/G2";
pub const GPAY_LABEL:&str = "StakeNote/GPAY";

// CONSENSUS
pub const EPOCH_NONCE:&str = "nonce";
pub const EPOCH_NUMBER:u64 = 7;
pub const BLOCK_PAYLOAD:&[u8; 18] = b"block-header-bytes";

// RANGE PROOF
pub const TRANSCRIPT_TAG:&[u8; 13] = b"StakeNote/v>0";
pub const BULLETPROOF_N_BITS:usize = 64;

// ELIGIBILITY
pub const L_VRF: u32 = 256;
pub const PREC: u32 = 600;  // precision for MPFR computations (>= L_VRF is good)
pub const F_PARAM:f64 = 0.05;

// CLSAG
pub const HASH_SALT:&[u8; 15] = b"StakeNote/H(vk)";
pub const MSG_SERIALIZE_NAME:&[u8; 11] = b"StakeNote/M";
pub const SIG_SERIALIZE_NAME:&[u8; 15] = b"StakeNote/CLSAG";
pub const RING_SIZE:usize = 16;
pub const DECOY_AMOUNT:u64 = 2_000_000_000;
pub const TOTAL_STAKE:u64 = 12_500_000_000;
