use std::time::Duration;
use stakenote_implementation::library::output::amount_from_basis_points;
use stakenote_implementation::library::execution::execute;
use stakenote_implementation::library::structs::Block;
use stakenote_implementation::library::constants::TOTAL_STAKE;

use std::collections::HashMap;
use std::fs::File;
use std::io::BufWriter;
use serde_json;

fn write_measurement_to_file(path:&str, data:&HashMap<u32, Vec<(u64, u64, u64, u128, u128, u128, u128, u128, u128)>>) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::create(path)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, data)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut t_accuracy:HashMap<u32, Vec<(u64, u64, u64, u128, u128, u128, u128, u128, u128)>> = HashMap::new();

    for pct_bp in (500u32..=4500u32).step_by(500) {
        t_accuracy.insert(pct_bp, vec![]);
        let v_o = amount_from_basis_points(TOTAL_STAKE, pct_bp);

        for _ in 0..10_000 {
            let block:Block;
            let duration_t_calculation:Duration;
            let duration_bulletproof:Duration;
            let duration_clsag:Duration;
            let duration_vrf_verify:Duration;
            let duration_bulletproof_verify:Duration;
            let duration_clsag_verify:Duration;
            (block, duration_t_calculation, duration_bulletproof, duration_clsag, duration_vrf_verify, duration_bulletproof_verify, duration_clsag_verify) = execute(v_o).expect("Execution failed");

            let t_val:u64 = block.msg.t;
            let t_bp:u64 = ((t_val as u128) * 10_000u128 / (v_o as u128)) as u64;
            let t_pct:f64 = (t_bp as f64) / 100.0;
            println!("t is {:.2}% of v_o ({} vs {}) ({:.2?}+{:.2?}+{:.2?} -- {:.2?}+{:.2?}+{:.2?})", t_pct, t_val, v_o, duration_t_calculation, duration_bulletproof, duration_clsag, duration_vrf_verify, duration_bulletproof_verify, duration_clsag_verify);

            t_accuracy.entry(pct_bp).or_insert_with(Vec::new).push((v_o, t_val, t_bp, duration_t_calculation.as_micros(), duration_bulletproof.as_micros(), duration_clsag.as_micros(), duration_bulletproof_verify.as_micros(), duration_bulletproof_verify.as_micros(), duration_clsag_verify.as_micros()));
        }
    }
    write_measurement_to_file("measurement.json", &t_accuracy)?;

    Ok(())
}
