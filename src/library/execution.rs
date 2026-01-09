use std::time::{Duration, Instant};
use rand_core::{OsRng,RngCore};

use crate::library::output::{create_output,amount_commitment};
use crate::library::vrf::{create_vrf_message,compute_vrf,create_vrf_keypair_from_hex,vk_point_from_scalar};
use crate::library::eligibility::{sigma_from_amount,amount_from_sigma,is_eligible};
use crate::library::bulletproof::{create_bulletproof,bulletproof_to_hex,verify_bulletproof};
use crate::library::clsag::{clsag_sign,key_image_from_sk,clsag_verify};
use crate::library::structs::{OutputPublic,BlockMsg,ClsagSig,Block};
use crate::library::constants::{RING_SIZE,TOTAL_STAKE,DECOY_AMOUNT,EPOCH_NONCE,BLOCK_PAYLOAD,EPOCH_NUMBER,SLOT_NUMBER};

pub fn execute(v_o:u64) -> Result<(Block, Duration, Duration, Duration, Duration, Duration), Box<dyn std::error::Error>> {
    let out = create_output(v_o);
    let sk_bytes:[u8; 32] = out.secret.sk_pay.to_bytes();
    let key_image = key_image_from_sk(&out.secret.sk_pay, &out.public.vk_pay);

    let sk_hex = hex::encode(sk_bytes);
    let vrf_key = create_vrf_keypair_from_hex(&sk_hex)?;
    let sk = vrf_key.sk;

    let mut ring:Vec<OutputPublic> = Vec::with_capacity(RING_SIZE);
    for _ in 0..(RING_SIZE - 1) {
        let decoy = create_output(DECOY_AMOUNT);
        ring.push(decoy.public);
    }
    let k = (OsRng.next_u32() as usize) % RING_SIZE;
    ring.insert(k, out.public.clone());

    let epoch_nonce = EPOCH_NONCE;
    let block:Block;
    let duration_t_calculation:Duration;
    let duration_bulletproof:Duration;
    let duration_clsag:Duration;
    let duration_bulletproof_verify:Duration;
    let duration_clsag_verify:Duration;

    let mut idx = 0;
    loop {
        idx += 1;
        let msg = create_vrf_message(epoch_nonce, idx);
        let (hex_vrf_output, vrf_proof) = compute_vrf(sk, &msg)?;

        let sigma = sigma_from_amount(v_o, TOTAL_STAKE);
        let (eligible, sigma_min) = is_eligible(&hex_vrf_output, &sigma);
        if eligible {
            let mut now = Instant::now();

            let t_val:u64 = amount_from_sigma(&sigma_min, TOTAL_STAKE);

            duration_t_calculation = now.elapsed();

            now = Instant::now();

            let val_t_diff = v_o-t_val;
            let (t_val_commitment, ro) = amount_commitment(val_t_diff);

            let bulletproof = create_bulletproof(t_val_commitment, val_t_diff, ro)?;
            let hex_proof:String = bulletproof_to_hex(&bulletproof);

            duration_bulletproof = now.elapsed();

            now = Instant::now();

            let vk_vrf_o = vk_point_from_scalar(out.secret.sk_pay);

            let m = BlockMsg {
                payload_b: BLOCK_PAYLOAD.to_vec(),
                epoch: EPOCH_NUMBER,
                slot: SLOT_NUMBER,
                vk_vrf_o,
                y_o: hex_vrf_output.into_bytes(),
                pi_y: vrf_proof.to_bytes().to_vec(),
                t: t_val,
                key_image,
                range_proof: hex_proof.clone(),
            };

            let sig:ClsagSig = clsag_sign(&m, &ring, &out, ro)?;

            duration_clsag = now.elapsed();

            block = Block { msg: m, sig: sig, ring: ring };

            now = Instant::now();

            verify_bulletproof(&block.msg.range_proof,&block.sig.c_diff)?;
            println!("Range proof verified!");

            duration_bulletproof_verify = now.elapsed();

            now = Instant::now();

            let sig_verification = clsag_verify(&block.msg, &block.ring, &block.sig);
            println!("CLSAG verify = {sig_verification}");

            duration_clsag_verify = now.elapsed();

            break;
        }
    }

    Ok((block, duration_t_calculation, duration_bulletproof, duration_clsag, duration_bulletproof_verify, duration_clsag_verify))
}
