use stakenote_implementation::library::output::amount_from_basis_points;
use stakenote_implementation::library::bulletproof::verify_bulletproof;
use stakenote_implementation::library::clsag::clsag_verify;
use stakenote_implementation::library::helpers::{write_block_json,read_block_from_json_file};
use stakenote_implementation::library::execution::execute;
use stakenote_implementation::library::structs::Block;
use stakenote_implementation::library::constants::TOTAL_STAKE;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pct_bp:u32 = 3000; // 30%
    let v_o = amount_from_basis_points(TOTAL_STAKE, pct_bp);

    let block:Block;
    (block, _, _, _, _, _) = execute(v_o).expect("Execution failed");

    let t_val:u64 = block.msg.t;
    let t_bp:u64 = ((t_val as u128) * 10_000u128 / (v_o as u128)) as u64;
    let t_pct:f64 = (t_bp as f64) / 100.0;

    // --- VERIFY ---
    write_block_json("block.json", &block)?;

    let block:Block = read_block_from_json_file("block.json")?;

    let sig_verification = clsag_verify(&block.msg, &block.ring, &block.sig);
    println!("CLSAG verify = {sig_verification}");

    verify_bulletproof(&block.msg.range_proof,&block.sig.c_diff)?;
    println!("Range proof verified!");

    Ok(())
}
