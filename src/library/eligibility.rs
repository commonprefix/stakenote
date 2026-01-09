use rug::{Float, Integer};
use rug::float::Round;
use std::cmp::Ordering;
use rug::ops::Pow;

use crate::library::helpers::u256_from_be;
use crate::library::constants::{L_VRF,PREC,F_PARAM};

pub fn sigma_from_amount(v_o: u64, v_total: u64) -> Float {
    let mut s = Float::with_val(PREC, v_o);
    s /= Float::with_val(PREC, v_total);
    s
}

pub fn amount_from_sigma(sigma_min: &Float, v_total: u64) -> u64 {
    assert!(v_total > 0);

    let mut prod = Float::with_val(PREC, sigma_min);
    prod *= Float::with_val(PREC, v_total);

    let (mut vo_int, _ord): (Integer, Ordering) = prod.to_integer_round(Round::Up).expect("rounding conversion failed");

    let zero = Integer::from(0);
    if vo_int < zero {
        vo_int = zero;
    }
    let v_total_i = Integer::from(v_total);
    if vo_int > v_total_i {
        vo_int = v_total_i;
    }

    vo_int
        .to_string()
        .parse::<u64>()
        .expect("v_o' does not fit u64")
}

/// Compute phi_f(sigma) = 1 - (1 - f)^sigma (leader election probability function)
fn phi_f(sigma: &Float) -> Float {
    let one = Float::with_val(PREC, 1);
    let f = Float::with_val(PREC, F_PARAM);
    let base = Float::with_val(PREC, &one - &f);
    let pow = base.pow(sigma);
    Float::with_val(PREC, one - pow)
}

/// Returns true if: y < 2^l * phi_f(sigma)
fn eligibility_test(y: &Integer, sigma: &Float) -> bool {
    let phi = phi_f(sigma);

    // threshold = floor( 2^ℓ * phi )
    let two_l = Integer::from(1) << L_VRF;
    let mut thr_f = Float::with_val(PREC, &two_l);
    thr_f *= phi;

    // floor (positive number, so truncation toward 0 == floor)
    let threshold:Integer = thr_f.to_integer().unwrap();

    y < &threshold
}

/// If eligible at `sigma`, binary-search the smallest sigma' in [0, sigma] s.t. eligible.
/// If not eligible at `sigma`, return `sigma` unchanged.
fn smallest_sigma_passing(y: &Integer, sigma: &Float) -> Float {
    // If it doesn't pass at sigma, per your requirement just return sigma itself.
    if !eligibility_test(y, sigma) {
        return Float::with_val(PREC, sigma);
    }

    // Binary search for minimal sigma' in [0, sigma]
    let mut lo = Float::with_val(PREC, 0);
    let mut hi = Float::with_val(PREC, sigma);

    // Precision target (tweak as you like). Since sigma is in [0,1], 1e-18 is already very tight.
    let eps = Float::with_val(PREC, 1e-18);

    // Invariant: eligible(hi) = true. eligible(lo) may be false.
    // If eligible at 0, minimal is 0.
    if eligibility_test(y, &lo) {
        return lo;
    }

    // Hard cap iterations to avoid any chance of infinite loops.
    for _ in 0..300 {
        let mut diff = Float::with_val(PREC, &hi);
        diff -= &lo;
        if diff <= eps {
            break;
        }

        // mid = (lo + hi)/2 (avoid "incomplete" arithmetic types)
        let mut mid = Float::with_val(PREC, &lo);
        mid += &hi;
        mid /= 2;

        if eligibility_test(y, &mid) {
            hi = mid;
        } else {
            lo = mid;
        }
    }

    hi
}

/// Now returns: (is_eligible_at_sigma, smallest_sigma'<=sigma that still passes)
pub fn is_eligible(beta_hex: &String, sigma: &Float) -> (bool, Float) {
    let beta = hex::decode(beta_hex).expect("bad hex");
    assert_eq!(beta.len(), 64);

    // y is interpreted as the first 32 bytes (256 bits) of beta
    let mut y_bytes = [0u8; 32];
    y_bytes.copy_from_slice(&beta[..32]);
    let y = u256_from_be(&y_bytes);

    let pass = eligibility_test(&y, sigma);
    if !pass {
        return (false, Float::with_val(PREC, sigma));
    }

    let sigma_min = smallest_sigma_passing(&y, sigma);
    (true, sigma_min)
}
