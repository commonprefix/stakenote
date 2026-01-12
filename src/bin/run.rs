use stakenote_implementation::library::output::amount_from_basis_points;
use stakenote_implementation::library::bulletproof::verify_bulletproof;
use stakenote_implementation::library::clsag::clsag_verify;
use stakenote_implementation::library::helpers::{write_block_json,read_block_from_json_file,ctoption_to_result};
use stakenote_implementation::library::execution::execute;
use stakenote_implementation::library::structs::Block;
use stakenote_implementation::library::constants::{EPOCH_NONCE,TOTAL_STAKE};
use stakenote_implementation::library::vrf::{create_vrf_message,vrf_pubkey_from_point,proof_from_slice};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pct_bp:u32 = 3000; // 30%
    let v_o = amount_from_basis_points(TOTAL_STAKE, pct_bp);
    let block:Block;
    (block, _) = execute(v_o).expect("Execution failed");
    write_block_json("block.json", &block)?;

    // --- VERIFY ---
    let block:Block = read_block_from_json_file("block.json")?;

    let vk_pubkey = vrf_pubkey_from_point(&block.msg.vk_vrf_o);
    let vrf_msg = create_vrf_message(EPOCH_NONCE, block.msg.slot);
    let vrf_proof = proof_from_slice(&block.msg.pi_y.clone()).expect("VRF proof reconstruction failed");
    let beta_ct = vk_pubkey.verify(&vrf_msg, &vrf_proof);
    let beta = ctoption_to_result(beta_ct, "VRF proof did not verify")?;
    let beta_hex = hex::encode(&beta);
    println!("VRF verification: {}", beta_hex==block.msg.y_o);

    let sig_verification = clsag_verify(&block.msg, &block.ring, &block.sig);
    println!("CLSAG verification: {sig_verification}");

    verify_bulletproof(&block.msg.range_proof,&block.sig.c_diff)?;
    println!("Range proof verified!");

    Ok(())
}
