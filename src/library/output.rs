use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use curve25519_dalek::ristretto::RistrettoPoint;
use sha2::Sha512;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

use crate::library::structs::{Output,OutputSecret,OutputPublic};
use crate::library::constants::{G1_LABEL,G2_LABEL,GPAY_LABEL};

/// Compute output's amount as percentage of total stake.
pub fn amount_from_basis_points(v_total: u64, pct_bp: u32) -> u64 {
    // pct_bp in [0, 10_000] => [0%, 100%]
    assert!(pct_bp <= 10_000);
    // round to nearest (optional): add half denominator
    let num = (v_total as u128) * (pct_bp as u128) + 5_000;
    (num / 10_000) as u64
}

/// Deterministic generator from a label.
/// RistrettoPoint avoids cofactor/subgroup pitfalls for this kind of prototype.
fn gen_from_label(label: &str) -> RistrettoPoint {
    RistrettoPoint::hash_from_bytes::<Sha512>(label.as_bytes())
}

/// In the paper, Setup chooses generators G1, G2, GPAY, GVRF. :contentReference[oaicite:1]{index=1}
/// Here we derive them deterministically from fixed labels.
pub fn setup_generators() -> (RistrettoPoint, RistrettoPoint, RistrettoPoint, RistrettoPoint) {
    let g1:RistrettoPoint = gen_from_label(G1_LABEL);
    let g2:RistrettoPoint = gen_from_label(G2_LABEL);
    let g_pay:RistrettoPoint = gen_from_label(GPAY_LABEL);
    let g_vrf:RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
    (g1, g2, g_pay, g_vrf)
}

/// Create amount commitment
pub fn amount_commitment(amount: u64) -> (RistrettoPoint, Scalar) {
    let (g1, g2, _, _) = setup_generators();

    let mut rng = OsRng;
    let ro = Scalar::random(&mut rng);

    let vo_scalar = Scalar::from(amount);
    let co = vo_scalar * g1 + ro * g2;

    (co, ro)
}

/// Create a single output: (sko, vo, ro) and corresponding (vko, Co).
pub fn create_output(amount: u64) -> Output {
    let (_, _, g_pay, _) = setup_generators();

    let mut rng = OsRng;

    let sko = Scalar::random(&mut rng);
    let vko = sko * g_pay;
    let (co, ro) = amount_commitment(amount);

    Output {
        secret: OutputSecret {
            sk_pay: sko,
            amount,
            r: ro,
        },
        public: OutputPublic {
            vk_pay: vko,
            commitment: co,
        },
    }
}
