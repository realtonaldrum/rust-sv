use crate::wallet::adressing::{encode_address, TransactionType};
use crate::script::{Script, op_codes};
use crate::network::Network;
use crate::util::{hash160, Error, Hash160, Result, sha256d};
use crate::transaction::{Tx};
use ripemd::{Ripemd160, Digest};
use base58::{FromBase58, ToBase58};

// Creates an unlocking script for a P2SH input.
/// Format: OP_0 <signature> <redeem_script>
/// The OP_0 is a dummy element required due to the OP_CHECKMULTISIG bug.
pub fn create_p2sh_unlock_script(signature: &[u8], redeem_script: &Script) -> Script {
    let mut script = Script::new();
    script.append(op_codes::OP_0); // Dummy element for OP_CHECKMULTISIG bug
    script.append_data(signature); // Signature
    script.append_data(&redeem_script.to_bytes()); // Redeem script
    script
}

// Function to generate a signature for a P2SH input
pub fn generate_signature(_private_key: &str, _tx: &Tx, _sighash_type: u32) {
    // TODO: Implement signature generation
}

/// Helper function to construct and validate redeem script for P2SH
/// OP_m [pubkey1] [pubkey2] ... [pubkeyN] OP_n OP_CHECKMULTISIG
/// OP_m: Number of signatures required (number_of_selected_utxo)
/// OP_n: Total number of public keys (number_of_all_utxo)
/// If you select 2 UTXOs, you get a 2-of-2 multisig: OP_2 [pubkey1] [pubkey2] OP_2 OP_CHECKMULTISIG (~71 bytes).
/// If you select 3 UTXOs, you get a 3-of-3 multisig: OP_3 [pubkey1] [pubkey2] [pubkey3] OP_3 OP_CHECKMULTISIG (~105 bytes).
pub fn construct_redeem_script(pubkeys: &[Vec<u8>], m: usize, n: usize) -> Result<Script> {

    // Why BSV has a multisig limit of 16?
    if m > n || n != pubkeys.len() || m == 0 || n > 16 {
        println!("DEBUG - m = number_of_signatures: {}, n = number_of_publickeys: {}, No. of PublicKey_vec: {}", m, n, pubkeys.len());
        return Err(Error::BadData("Invalid m or n for multisig".to_string()));
    }
    let mut script = Script::new();
    script.append((op_codes::OP_1 as u8 + m as u8 - 1).into()); // OP_m
    for pubkey in pubkeys {
        if pubkey.len() != 33 {
            return Err(Error::BadData("Invalid public key length".to_string()));
        }
        script.append_slice(&[pubkey.len() as u8]);
        script.append_slice(pubkey);
    }
    script.append((op_codes::OP_1 as u8 + n as u8 - 1).into()); // OP_n
    script.append(op_codes::OP_CHECKMULTISIG);
    Ok(script)
}

// Compute P2SH address from redeem script for validation
pub fn compute_p2sh_address(redeem_script: &Script, network: Network) -> Result<String> {
    // Compute HASH160(SHA256(redeem_script))
    let sha256_result = sha256d(&redeem_script.0).0;
    
    let mut ripemd160 = Ripemd160::new();
    ripemd160.update(sha256_result);
    let hash160 = ripemd160.finalize();

    let prefix = match network {
        Network::Mainnet => 0x05, // BSV Mainnet P2SH prefix
        Network::Testnet => 0x0c, // BSV Testnet P2SH prefix
        Network::STN => 0xc4,     // Assuming same as Testnet; adjust if needed
    };
    
    let mut address_bytes = vec![prefix];
    address_bytes.extend_from_slice(&hash160);
    
    // Compute checksum
    let checksum = &sha256d(&address_bytes).0[..4];
    
    address_bytes.extend_from_slice(&checksum[..4]);
    
    // Encode to base58
    let address = encode_address(Network::Mainnet, TransactionType::P2SH, &address_bytes)?;
    let base58_address = address.to_base58();
    Ok(base58_address)
}

// Function to check if a string is a valid P2SH scripthash
pub fn is_value_a_scripthash(scripthash: &str) -> bool {
    // A valid P2SH scripthash is a 40-character hexadecimal string (20 bytes)
    if scripthash.len() != 40 {
        return false;
    }
    
    // Check if the string is valid hexadecimal
    scripthash.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn address_to_scripthash(address: &str) -> Result<String> {
    // Decode Base58 address
    let payload = address.from_base58().map_err(|e| Error::BadData(format!("Failed to decode Base58 address: {:?}", e)))?;

    // Validate payload length (21 bytes for hash + network byte + 4-byte checksum)
    if payload.len() != 25 {
        return Err(Error::BadData("Invalid address length".to_string()));
    }

    // Verify network byte (0x00 or 0x05 for Mainnet, 0x6f or 0xc4 for Testnet/STN)
    let expected_version = match payload[0] {
        0x00 | 0x05 => [0x00, 0x05], // Mainnet P2PKH or P2SH
        0x6f | 0xc4 => [0x6f, 0xc4], // Testnet/STN P2PKH or P2SH
        _ => return Err(Error::BadData(format!("Invalid network byte {}", payload[0]))),
    };
    if !expected_version.contains(&payload[0]) {
        return Err(Error::BadData(format!("Invalid network byte {} for address", payload[0])));
    }

    // Verify checksum
    let data = &payload[0..21];
    let checksum = &payload[21..25];
    let computed_checksum = &sha256d(data).0[..4];

    if checksum != computed_checksum {
        return Err(Error::BadData("Invalid checksum".to_string()));
    }

    // Construct P2PKH script: OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
    let mut script_bytes = vec![
        0x76, // OP_DUP
        0xa9, // OP_HASH160
        0x14, // 20-byte length
    ];
    script_bytes.extend_from_slice(&payload[1..21]); // Append 20-byte hash
    script_bytes.extend_from_slice(&[0x88, 0xac]); // OP_EQUALVERIFY, OP_CHECKSIG

    // Compute script hash (HASH160 of scriptPubKey)
    let script_hash = hash160(&script_bytes);

    // Encode script to hex
    Ok(hex::encode(script_hash.0))
}

// Converts a P2PKH or P2SH script pubkey to a Bitcoin address
pub fn script_pubkey_to_address(script_pubkey: &str) -> Result<String> {
    // Parse the script pubkey hex string
    let script_bytes = hex::decode(script_pubkey).map_err(|e| Error::BadData(format!("Invalid hex: {}", e)))?;

    // Validate script structure and determine address type
    let (address_type, hash) = if script_bytes.len() == 25
        && script_bytes[0] == 0x76 // OP_DUP
        && script_bytes[1] == 0xa9 // OP_HASH160
        && script_bytes[2] == 0x14 // 20-byte length
        && script_bytes[23] == 0x88 // OP_EQUALVERIFY
        && script_bytes[24] == 0xac // OP_CHECKSIG
    {
        // P2PKH script: OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
        let mut pubkey_hash = [0u8; 20];
        pubkey_hash.copy_from_slice(&script_bytes[3..23]);
        (TransactionType::P2PKH, pubkey_hash)
    } else if script_bytes.len() == 23
        && script_bytes[0] == 0xa9 // OP_HASH160
        && script_bytes[1] == 0x14 // 20-byte length
        && script_bytes[22] == 0x87 // OP_EQUAL
    {
        // P2SH script: OP_HASH160 <20-byte hash> OP_EQUAL
        let mut script_hash = [0u8; 20];
        script_hash.copy_from_slice(&script_bytes[2..22]);
        (TransactionType::P2SH, script_hash)
    } else {
        return Err(Error::BadData("Invalid script pubkey".to_string()));
    };

    // Determine network prefix based on address type
    let prefix = match address_type {
        TransactionType::P2PKH => match Network::Mainnet {
            Network::Mainnet => 0x00,
            Network::Testnet | Network::STN => 0x6f,
        },
        TransactionType::P2SH => match Network::Mainnet {
            Network::Mainnet => 0x05,
            Network::Testnet | Network::STN => 0xc4,
        },
    };

    // Construct address bytes
    let mut address_bytes = vec![prefix];
    address_bytes.extend_from_slice(&hash);

    // Compute checksum
    let checksum = &sha256d(&address_bytes).0[..4];
    address_bytes.extend_from_slice(checksum);

    // Encode to Base58
    let address = encode_address(Network::Mainnet, address_type, &address_bytes)?;
    Ok(address.to_base58())
}

pub fn script_pubkey_to_pubkey_hash(script_pubkey: &str) -> Result<Vec<u8>> {
    // Parse the script pubkey hex string
    let script_bytes = hex::decode(script_pubkey).map_err(|e| Error::BadData(format!("Invalid hex: {}", e)))?;
    
    // Validate P2PKH script structure: OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
    if script_bytes.len() != 25
        || script_bytes[0] != 0x76 // OP_DUP
        || script_bytes[1] != 0xa9 // OP_HASH160
        || script_bytes[2] != 0x14 // 20-byte length
        || script_bytes[23] != 0x88 // OP_EQUALVERIFY
        || script_bytes[24] != 0xac // OP_CHECKSIG
    {
        return Err(Error::BadData("Invalid P2PKH script pubkey".to_string()));
    }

    // Extract and return the 20-byte public key hash (bytes 3 to 22)
    Ok(script_bytes[3..23].to_vec())
}

pub fn pubkey_hash_to_script_hash(pubkey_hash: &[u8]) -> Result<Hash160> {
    // Parse the public key hash hex string
    let pubkey_hash_bytes = hex::decode(pubkey_hash).map_err(|e| Error::BadData(format!("Invalid hex: {}", e)))?;

    // Validate public key hash length (20 bytes for hash160)
    if pubkey_hash_bytes.len() != 20 {
        return Err(Error::BadData("Invalid public key hash length, expected 20 bytes".to_string()));
    }

    // Construct P2PKH script: OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
    // Construct P2PKH script manually: OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
    let mut script = Script::new();
    script.append(op_codes::OP_DUP); // 0x76
    script.append(op_codes::OP_HASH160); // 0xa9
    script.append_data(&pubkey_hash_bytes); // OP_PUSH+20 followed by 20-byte hash
    script.append(op_codes::OP_EQUALVERIFY); // 0x88
    script.append(op_codes::OP_CHECKSIG); // 0xac

    let script_hash = hash160(&script.0); // Hash the script
    Ok(script_hash)
}

// Helper function to derive P2SH address from redeem script
pub fn derive_p2sh_address(redeem_script: &Script, network: Network) -> Result<Vec<u8>> {
    let script_hash = hash160(&redeem_script.to_bytes());
    let address = crate::wallet::adressing::encode_address(network, TransactionType::P2SH, &script_hash.0)?;
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::decode;
    
    #[test]
    fn test_script_pubkey_to_address() {
        let script = "76a91419f1f3b0c160762a70f5f1503d6a02b9157d7b1788ac";
        let expected_address = "13T1L3y7iM4vWErX2X51dK3yLNvhS1zb2F";
        let result = script_pubkey_to_address(script).expect("Failed to convert script to address");
        assert_eq!(result, expected_address);

        // Test invalid script
        let invalid_script = "76a91419f1f3b0c160762a70f5f1503d6a02b9157d7b17"; // Incomplete
        assert!(script_pubkey_to_address(invalid_script).is_err());
    }

    #[test]
    fn test_script_pubkey_to_pubkey_hash() {
        let script = "76a91419f1f3b0c160762a70f5f1503d6a02b9157d7b1788ac";
        let expected_hash = decode("19f1f3b0c160762a70f5f1503d6a02b9157d7b17").unwrap();
        let result = script_pubkey_to_pubkey_hash(script).expect("Failed to extract pubkey hash");
        assert_eq!(result, expected_hash);

        // Test invalid script
        let invalid_script = "76a91419f1f3b0c160762a70f5f1503d6a02b9157d7b17"; // Incomplete
        assert!(script_pubkey_to_pubkey_hash(invalid_script).is_err());
    }
}
