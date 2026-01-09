use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;
use sha2::{Digest, Sha512};

use crate::library::output::{setup_generators};
use crate::library::structs::{BlockMsg,ClsagSig,Output,OutputPublic};
use crate::library::constants::{HASH_SALT,MSG_SERIALIZE_NAME,SIG_SERIALIZE_NAME};
use crate::library::helpers::{ctoption_to_result};

/// H(vk) for key images and the I-column: map public key to a point.
fn hash_to_point(vk: &RistrettoPoint) -> RistrettoPoint {
    let mut h = Sha512::new();
    h.update(HASH_SALT);
    h.update(vk.compress().as_bytes());
    RistrettoPoint::from_hash(h)
}

/// Serialize M in a stable way for Fiat–Shamir hashes.
fn serialize_m(m: &BlockMsg) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MSG_SERIALIZE_NAME);
    out.extend_from_slice(&(m.payload_b.len() as u64).to_le_bytes());
    out.extend_from_slice(&m.payload_b);
    out.extend_from_slice(&m.epoch.to_le_bytes());
    out.extend_from_slice(&m.slot.to_le_bytes());
    out.extend_from_slice(m.vk_vrf_o.compress().as_bytes());
    out.extend_from_slice(&(m.y_o.len() as u64).to_le_bytes());
    out.extend_from_slice(&m.y_o);
    out.extend_from_slice(&(m.pi_y.len() as u64).to_le_bytes());
    out.extend_from_slice(&m.pi_y);
    out.extend_from_slice(&m.t.to_le_bytes());
    out.extend_from_slice(m.key_image.compress().as_bytes());
    out.extend_from_slice(&m.range_proof.clone().into_bytes());
    out
}

/// H_clsag(M || i || L_i || V_i || I_i || A_i) -> Scalar. 
fn h_clsag(m_bytes: &[u8], i: usize, l: &RistrettoPoint, v: &RistrettoPoint, ii: &RistrettoPoint, a: &RistrettoPoint) -> Scalar {
    let mut h = Sha512::new();
    h.update(SIG_SERIALIZE_NAME);
    h.update(m_bytes);
    h.update((i as u64).to_le_bytes());
    h.update(l.compress().as_bytes());
    h.update(v.compress().as_bytes());
    h.update(ii.compress().as_bytes());
    h.update(a.compress().as_bytes());
    Scalar::from_hash(h)
}

/// Compute the output key image I_o = sk_pay * H(vk_o). :contentReference[oaicite:9]{index=9}
pub fn key_image_from_sk(sk_pay: &Scalar, vk_o: &RistrettoPoint) -> RistrettoPoint {
    sk_pay * hash_to_point(vk_o)
}

/// Sign(M, Oblock, (sk_pay, amount, r)) -> σCLSAG. :contentReference[oaicite:10]{index=10}
pub fn clsag_sign(m: &BlockMsg, oblock: &[OutputPublic], correct_out: &Output, ro: Scalar) -> Result<ClsagSig, String> {
    let n = oblock.len();
    if n == 0 { return Err("empty ring".into()); }

    let (g1, g2, gpay, gvrf) = setup_generators();

    let vk_o = correct_out.public.vk_pay;
    let c_o = correct_out.public.commitment;

    // Find index k where (vk_k, C_k) matches our (vk_o, C_o). :contentReference[oaicite:12]{index=12}
    let mut k_opt = None;
    for (idx, row) in oblock.iter().enumerate() {
        if row.vk_pay.compress() == vk_o.compress() && row.commitment.compress() == c_o.compress() {
            k_opt = Some(idx);
            break;
        }
    }
    let k = k_opt.ok_or("signer output not found in ring")?;

    // Check amount >= T (paper requires vo ≥ T and range proof later proves (vo - T) >= 0). 
    if correct_out.secret.amount < m.t {
        return Err("amount < T".into());
    }

    // Pick r' and compute C = (amount - T)G1 + r'G2. :contentReference[oaicite:14]{index=14}
    let c_diff = Scalar::from(correct_out.secret.amount - m.t) * g1 + ro * g2;

    // Precompute D_i = C_i - T*G1 - C. 
    let t_g1 = Scalar::from(m.t) * g1;
    let mut d:Vec<RistrettoPoint> = Vec::with_capacity(n);
    for row in oblock {
        d.push(row.commitment - t_g1 - c_diff);
    }

    // Fiat–Shamir message bytes
    let m_bytes = serialize_m(m);

    // Allocate responses and challenges
    let mut s_x = vec![Scalar::ZERO; n];
    let mut s_r = vec![Scalar::ZERO; n];
    let mut c = vec![Scalar::ZERO; n]; // c[i] is challenge at index i

    // Sample (ax, ar) and compute Lk, Vk, Ik, Ak. :contentReference[oaicite:16]{index=16}
    let mut rng = OsRng;
    let alpha_x = Scalar::random(&mut rng);
    let alpha_r = Scalar::random(&mut rng);

    let l_k = alpha_x * gpay;
    let v_k = alpha_x * gvrf;
    let i_k = alpha_x * hash_to_point(&vk_o);
    let a_k = alpha_r * g2;

    // c_{k+1} = Hclsag(M || k || Lk || Vk || Ik || Ak). :contentReference[oaicite:17]{index=17}
    let k1 = (k + 1) % n;
    c[k1] = h_clsag(&m_bytes, k, &l_k, &v_k, &i_k, &a_k);

    // Walk i = k+1 .. wrap until k:
    let mut i = k1;
    while i != k {
        // pick s_i^(x), s_i^(r) random. :contentReference[oaicite:18]{index=18}
        s_x[i] = Scalar::random(&mut rng);
        s_r[i] = Scalar::random(&mut rng);

        // Li = sxi*GPAY + ci*vki
        let l_i = s_x[i] * gpay + c[i] * oblock[i].vk_pay;

        // Vi = sxi*GVRF + ci*vkVRF,o (vkVRF,o is in M) :contentReference[oaicite:19]{index=19}
        let v_i = s_x[i] * gvrf + c[i] * m.vk_vrf_o;

        // Ii = sxi*H(vki) + ci*I_o :contentReference[oaicite:20]{index=20}
        let h_vki = hash_to_point(&oblock[i].vk_pay);
        let i_i = s_x[i] * h_vki + c[i] * m.key_image;

        // Ai = sri*G2 + ci*D_i 
        let a_i = s_r[i] * g2 + c[i] * d[i];

        // c_{i+1} = Hclsag(M || i || Li || Vi || Ii || Ai) :contentReference[oaicite:22]{index=22}
        let next = (i + 1) % n;
        c[next] = h_clsag(&m_bytes, i, &l_i, &v_i, &i_i, &a_i);

        i = next;
    }

    // Close the ring: compute s_k^(x), s_k^(r). :contentReference[oaicite:23]{index=23}
    s_x[k] = alpha_x - c[k] * correct_out.secret.sk_pay;
    s_r[k] = alpha_r - c[k] * (correct_out.secret.r - ro);

    // Output σ = <C, c0, (s0x,s0r), ...>. :contentReference[oaicite:24]{index=24}
    Ok(ClsagSig {
        c_diff,
        c0: c[0],
        s_x,
        s_r,
    })
}

/// Verify(M, Oblock, σ) -> bool. :contentReference[oaicite:25]{index=25}
pub fn clsag_verify(m: &BlockMsg, oblock: &[OutputPublic], sig: &ClsagSig) -> bool {
    let n = oblock.len();
    if n == 0 || sig.s_x.len() != n || sig.s_r.len() != n {
        return false;
    }

    let (g1, g2, gpay, gvrf) = setup_generators();

    // D_i = C_i - T*G1 - C
    let t_g1 = Scalar::from(m.t) * g1;
    let mut d:Vec<RistrettoPoint> = Vec::with_capacity(n);
    for row in oblock {
        d.push(row.commitment - t_g1 - sig.c_diff);
    }

    let m_bytes = serialize_m(m);

    // c'[0] = c0
    let mut c_prime = vec![Scalar::ZERO; n + 1];
    c_prime[0] = sig.c0;

    // recompute challenges
    for i in 0..n {
        let l_i = sig.s_x[i] * gpay + c_prime[i] * oblock[i].vk_pay;
        let v_i = sig.s_x[i] * gvrf + c_prime[i] * m.vk_vrf_o;
        let h_vki = hash_to_point(&oblock[i].vk_pay);
        let i_i = sig.s_x[i] * h_vki + c_prime[i] * m.key_image;
        let a_i = sig.s_r[i] * g2 + c_prime[i] * d[i];

        c_prime[i + 1] = h_clsag(&m_bytes, i, &l_i, &v_i, &i_i, &a_i);
    }

    c_prime[n] == sig.c0
}

fn clsag_sig_to_bytes(sig: &ClsagSig) -> Vec<u8> {
    let n = sig.s_x.len();
    assert_eq!(n, sig.s_r.len(), "s_x and s_r must have same length");

    let mut out = Vec::with_capacity(32 + 32 + 4 + 32*n + 32*n);

    out.extend_from_slice(sig.c_diff.compress().as_bytes());
    out.extend_from_slice(sig.c0.as_bytes());
    out.extend_from_slice(&(n as u32).to_le_bytes());

    for s in &sig.s_x {
        out.extend_from_slice(s.as_bytes());
    }

    for s in &sig.s_r {
        out.extend_from_slice(s.as_bytes());
    }

    out
}

pub fn clsag_sig_to_hex(sig: &ClsagSig) -> String {
    hex::encode(clsag_sig_to_bytes(sig))
}

pub fn clsag_sig_from_hex(hex_str: &str) -> Result<ClsagSig, String> {
    let s = hex_str.trim().strip_prefix("0x").unwrap_or(hex_str.trim());
    let bytes = hex::decode(s).map_err(|e| format!("hex decode failed: {e}"))?;

    if bytes.len() < 32 + 32 + 4 {
        return Err("input too short".into());
    }

    let mut off = 0usize;

    let mut cd = [0u8; 32];
    cd.copy_from_slice(&bytes[off..off + 32]);
    off += 32;
    let c_diff = CompressedRistretto(cd)
        .decompress()
        .ok_or("invalid c_diff encoding")?;

    let mut c0b = [0u8; 32];
    c0b.copy_from_slice(&bytes[off..off + 32]);
    off += 32;
    let c0 = ctoption_to_result(Scalar::from_canonical_bytes(c0b), "invalid scalar c0")?;

    let mut nb = [0u8; 4];
    nb.copy_from_slice(&bytes[off..off + 4]);
    off += 4;
    let n = u32::from_le_bytes(nb) as usize;

    let expected_len = 32 + 32 + 4 + 32 * n + 32 * n;
    if bytes.len() != expected_len {
        return Err(format!(
            "wrong length: got {}, expected {} for n={}",
            bytes.len(),
            expected_len,
            n
        ));
    }

    let mut s_x = Vec::with_capacity(n);
    for _ in 0..n {
        let mut sb = [0u8; 32];
        sb.copy_from_slice(&bytes[off..off + 32]);
        off += 32;
        let si = ctoption_to_result(Scalar::from_canonical_bytes(sb), "invalid scalar in s_x")?;
        s_x.push(si);
    }

    let mut s_r = Vec::with_capacity(n);
    for _ in 0..n {
        let mut sb = [0u8; 32];
        sb.copy_from_slice(&bytes[off..off + 32]);
        off += 32;
        let si = ctoption_to_result(Scalar::from_canonical_bytes(sb), "invalid scalar in s_r")?;
        s_r.push(si);
    }

    Ok(ClsagSig { c_diff, c0, s_x, s_r })
}
