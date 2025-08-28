use crate::util::{Result, Serializable};
use crate::messages::{Tx};
use crate::network::Network;
use crate::transaction::types::p2pkh::{to_hex, hex_to_bytes, to_asm};
use crate::wallet::adressing::{script_pubkey_to_p2pkh_address, scriptsig_to_p2pkh_address};
use std::io::Cursor;

// Step 4 - Builds a raw transaction hex string from a Tx struct
pub fn build_raw_tx(tx: &Tx) -> Result<String> {
    // Serialize the Tx struct to a byte buffer
    let mut buffer = Vec::new();
    tx.write(&mut buffer)?;
    
    // Convert to hex
    Ok(to_hex(&buffer))
}

// Step 5 - Control RAW TX
pub fn read_raw_tx(raw_tx_hex: &str) -> Result<Tx> {
    let bytes = hex_to_bytes(raw_tx_hex);
    let mut cursor = Cursor::new(bytes);
    Tx::read(&mut cursor)
}


pub fn print_tx_info(raw_tx_hex: &str) {
    let tx = read_raw_tx(raw_tx_hex).unwrap();
    // Decode raw transaction hex to bytes
    let raw_tx_bytes = hex::decode(raw_tx_hex).unwrap();
        
    // Calculate transaction size
    let tx_size = raw_tx_bytes.len();
    
    // Calculate TXID and fee
    let txid = tx.calculate_txid();
    let hash = tx.hash();

    // Print transaction details
    println!("Transaction ID: {:?}", to_hex(&txid));
    println!("Transaction Hash: {:?}", to_hex(&hash.0));
    println!("Version: {}", tx.version);
    println!("Transaction Size: {} bytes", tx_size);

    
    // Find out which network it is based on p2pkh adresse or maybe sooner?
    let network = if tx.outputs.iter().any(|o| o.lock_script.0.starts_with(&[0x76, 0xa9, 0x14])) {
        Network::Mainnet
    } else {
        Network::Testnet
    };

    // Process inputs
    println!("In-counter: {}", tx.inputs.len());
    for (i, input) in tx.inputs.iter().enumerate() {
        println!("Input {}:", i);
        println!("  Previous Output HashID: {}", to_hex(&input.prev_output.hash.0));
        println!("  Previous Output Index: {}", input.prev_output.index);
        println!("  Unlock Script (scriptSig) Hex: {}", to_hex(&input.unlock_script.0));
        println!("  Unlock Script (scriptSig) ASM: {}", to_asm(&input.unlock_script.0));
        if let Some(addr) = scriptsig_to_p2pkh_address(&input.unlock_script, network) {
            println!("  From P2PKH Address: {}", addr);
        } else {
            println!("  Non-P2PKH Input");
        }
        println!("  Sequence: {}", input.sequence);
    }

    // Process outputs
    println!("Out-counter: {}", tx.outputs.len());
    for (i, output) in tx.outputs.iter().enumerate() {
        println!("Output {}:", i);
        println!("  Satoshis: {}", output.satoshis);
        println!("  Lock Script (scriptPubKey) Hex: {}", to_hex(&output.lock_script.0));
        if let Some(addr) = script_pubkey_to_p2pkh_address(&output.lock_script, network) {
            println!("  To P2PKH Address: {}", addr);
        } else {
            println!("  Non-P2PKH Output");
        }
    }
    
    // Total amount needs to be known here
    let total_output = tx.get_total_output_amount();
    println!("Total Output Amount: {} satoshis", total_output);
    println!("Locktime: {}", tx.locktime);
    
    // Check for RBF signaling (BSV-specific)
    let is_rbf = tx.inputs.iter().any(|input| input.sequence < 0xffffffff);
    println!("RBF Signaled: {}", is_rbf);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_raw_tx() {
        let raw_tx_hex = "0200000001c7b275b1820d605c8e0d3b7ae8d08726bb9a6752b2e6410c3732afd0207d2741000000006b483045022100e514f4b3e3f5af910e34c3d70ea388472cd3fc1490482b9605c8c52d0e926ba302206af858669b70383ac3d45e6835529783ec7626e6c8457461abb7915dfb468223412103b4b0af90d28c3594d78d741b920462d3647ebce23a635c47343a3632b2f54cdbffffffff0296000000000000001976a91487bc1da7a2e6bc738e66af86064347099496a14e88ac1c000000000000001976a9148643e8590b36395bd8738c5d2ec96e5422739b0588ac00000000";
        print_tx_info(raw_tx_hex);
    }
}