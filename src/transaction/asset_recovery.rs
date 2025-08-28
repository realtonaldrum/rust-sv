use crate::util::{Error, Result};
use crate::messages::{Tx};
use crate::messages::tx_raw::{build_raw_tx, read_raw_tx};

// Step 6 - Do Digital Asset Recovery (Simulation) as a miner who receives the raw tx
pub fn asset_recovery(raw_tx_hex: &str, fee_rate: f64, redelegation_address: &str) -> Result<String> {
    let mut tx_from_raw_tx: Tx = read_raw_tx(raw_tx_hex)?;
    let total_output_amount_in_satoshi: u64 = tx_from_raw_tx.get_total_output_amount();
    
    if total_output_amount_in_satoshi == 0 {
        return Err(Error::BadData("No output value to recover".to_string()));
    }
    let tx_without_outputs: Tx = tx_from_raw_tx.remove_all_outputs();

    // Estimate transaction size with one output
    // Assume P2PKH output size: 8 bytes (satoshis) + 1 byte (varint) + 25 bytes (scriptPubKey) = 34 bytes
    // Base size: 10 bytes (version, input count, output count, locktime)
    // Input size: Use actual input sizes from tx
    let input_size: usize = tx_without_outputs.inputs.iter().map(|input| input.size()).sum();
    let estimated_tx_size = 10 + input_size + 34; // Overhead + inputs + 1 P2PKH output
    let estimated_fee: u64 = (estimated_tx_size as f64 * fee_rate).ceil() as u64;

    // Ensure the fee doesn't exceed the total output amount
    // To prevent spending 400 BSV in fees for a 1 Satoshi tx - TXID: 6a0d4e3e859ae693f49777fff82a9bb7286c1649dd2c3bc01cd163d6a3018676
    if estimated_fee >= total_output_amount_in_satoshi {
        return Err(Error::BadData("Fee exceeds total output amount".to_string()));
    }

    // Calculate the new output amount
    let new_output_amount: u64 = total_output_amount_in_satoshi - estimated_fee;
    if new_output_amount == 0 {
        return Err(Error::BadData("Output amount after fee is zero".to_string()));
    }

    // Debugging information
    let debugging_info: bool = true;
    if debugging_info {
        println!("DEBUG - Total Output Amount: {} satoshis", total_output_amount_in_satoshi);
        println!("DEBUG - Estimated Fee: {} satoshis for {} Bytes", estimated_fee, estimated_tx_size);
        println!("DEBUG - New Output Amount: {} satoshis", new_output_amount);
        println!();
    }

    // Add the new output with the redelegation address
    let mut final_tx = tx_without_outputs;

    final_tx.add_output(redelegation_address, new_output_amount)?;

    // Serialize the final transaction to hex
    let new_raw_tx_hex = build_raw_tx(&final_tx)?;

    Ok(new_raw_tx_hex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::tx_raw::{print_tx_info};

    #[test]
    fn test_asset_recovery(){
        let raw_tx_hex = "0200000001c7b275b1820d605c8e0d3b7ae8d08726bb9a6752b2e6410c3732afd0207d2741000000006b483045022100e514f4b3e3f5af910e34c3d70ea388472cd3fc1490482b9605c8c52d0e926ba302206af858669b70383ac3d45e6835529783ec7626e6c8457461abb7915dfb468223412103b4b0af90d28c3594d78d741b920462d3647ebce23a635c47343a3632b2f54cdbffffffff0296000000000000001976a91487bc1da7a2e6bc738e66af86064347099496a14e88ac1c000000000000001976a9148643e8590b36395bd8738c5d2ec96e5422739b0588ac00000000";
        let redelegation_address = "1MwQuAEFVHw7CShVcKJrxZ4LFmErEkQWKo";
        let fee_rate = 0.01;
        let new_tx = asset_recovery(raw_tx_hex, fee_rate, redelegation_address).unwrap();
        print_tx_info(&new_tx);
        println!("New Raw Tx Hex for Asset Recovery: {}", new_tx);
    }
}