use std::fmt::Write;
use crate::script::op_codes::*;
use crate::script::{next_op, Script};
use crate::wallet::{
    adressing::{
        AddressForm, TransactionType
    },
    derivation::ExtendedKeypair,
};
use crate::network::Network;
use crate::util::{Error, Hash160, Result, sha256d};
use base58::{FromBase58};
use crate::transaction::{Tx};

// Simple hex encoding function
pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        write!(&mut s, "{:02x}", byte).unwrap();
    }
    s
}

// Simple hex decoding function (for examples)
pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut chars = hex.chars();
    while let (Some(h1), Some(h2)) = (chars.next(), chars.next()) {
        let byte = u8::from_str_radix(&format!("{}{}", h1, h2), 16).unwrap();
        bytes.push(byte);
    }
    bytes
}

// Function to disassemble Bitcoin script to ASM string
pub fn to_asm(script: &[u8]) -> String {
    let mut asm = String::new();
    let mut i = 0;
    while i < script.len() {
        let byte = script[i];
        if byte >= 0x01 && byte <= 0x4b { // OP_PUSHBYTES_1 to OP_PUSHBYTES_75
            let len = byte as usize;
            i += 1;
            if i + len > script.len() {
                asm.push_str("INVALID_PUSH ");
                break;
            }
            let data = &script[i..i + len];
            let data_hex = to_hex(data);
            if !asm.is_empty() {
                asm.push(' ');
            }
            write!(&mut asm, "OP_PUSHBYTES_{} {}", len, data_hex).unwrap();
            i += len;
        } else {
            if !asm.is_empty() {
                asm.push(' ');
            }
            let opcode = match byte {
                0x76 => "OP_DUP",
                0xa9 => "OP_HASH160",
                0x88 => "OP_EQUALVERIFY",
                0xac => "OP_CHECKSIG",
                _ => {
                    write!(&mut asm, "UNKNOWN_{:02x}", byte).unwrap();
                    ""
                }
            };
            if !opcode.is_empty() {
                asm.push_str(opcode);
            }
            i += 1;
        }
    }
    asm
}

////////////////////////////////////////////////////////////////////////
// Build P2PKH scriptPubKey
pub fn build_script_pubkey(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(25);
    script.push(0x76); // OP_DUP
    script.push(0xa9); // OP_HASH160
    script.push(0x14); // OP_PUSHBYTES_20
    script.extend_from_slice(pubkey_hash);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xac); // OP_CHECKSIG
    script
}

// Same approach but a bit different
/// Creates the pubkey script to send to an address
/// Same as Script::p2pkh();
pub fn create_lock_script(address: &Hash160) -> Script {
    let mut script = Script::new();
    script.append(OP_DUP);
    script.append(OP_HASH160);
    script.append_data(&address.0);
    script.append(OP_EQUALVERIFY);
    script.append(OP_CHECKSIG);
    script
}

////////////////////////////////////////////////////////////////////////
// Build P2PKH scriptSig
// This is the unlocking script in a transaction input that satisfies the scriptPubKey’s conditions
pub fn build_script_sig(sig: &[u8], pubkey: &[u8]) -> Vec<u8> {
    let mut script = Vec::new();
    // Push signature
    let sig_len = sig.len();
    assert!(sig_len <= 75, "Signature too long for simple push");
    script.push(sig_len as u8);
    script.extend_from_slice(sig);
    // Push pubkey
    let pubkey_len = pubkey.len();
    assert!(pubkey_len == 33 || pubkey_len == 65, "Pubkey must be 33 or 65 bytes");
    assert!(pubkey_len <= 75, "Pubkey too long for simple push");
    script.push(pubkey_len as u8);
    script.extend_from_slice(pubkey);
    // println!("ScriptSig Hex: {}", to_hex(&script));
    // println!("ScriptSig ASM: {}", to_asm(&script));
    script
}


// Same approach but a bit different
/// Creates a sigscript to sign a p2pkh transaction
pub fn create_unlock_script(sig: &[u8], public_key: &[u8; 33]) -> Script {
    let mut unlock_script = Script::new();
    unlock_script.append_data(sig);
    unlock_script.append_data(public_key);
    unlock_script
}

/// Returns whether the lock_script is p2pkh
pub fn check_lock_script(lock_script: &[u8]) -> bool {
    lock_script.len() == 25
        && lock_script[0] == OP_DUP
        && lock_script[1] == OP_HASH160
        && lock_script[2] == OP_PUSH + 20
        && lock_script[23] == OP_EQUALVERIFY
        && lock_script[24] == OP_CHECKSIG
}

/// Returns whether the unlock_script is p2pkh
pub fn check_unlock_script(unlock_script: &[u8]) -> bool {
    if unlock_script.len() == 0
        || unlock_script[0] < OP_PUSH + 71
        || unlock_script[0] > OP_PUSH + 73
    {
        return false;
    }
    let i = next_op(0, &unlock_script);
    if i >= unlock_script.len()
        || unlock_script[i] != OP_PUSH + 33 && unlock_script[i] != OP_PUSH + 65
    {
        return false;
    }
    next_op(i, &unlock_script) >= unlock_script.len()
}

/// Returns whether the lock_script is a P2PKH send to the provided address
pub fn check_lock_script_addr(hash160: &Hash160, lock_script: &[u8]) -> bool {
    check_lock_script(lock_script) && lock_script[3..23] == hash160.0
}

/// Returns whether the unlock_script contains our public key
pub fn check_unlock_script_addr(pubkey: &[u8], unlock_script: &[u8]) -> bool {
    if !check_unlock_script(unlock_script) {
        return false;
    }
    let i = next_op(0, &unlock_script);
    unlock_script[i + 1..] == *pubkey
}

/////////////////

/// Signs a transaction input and updates its unlock_script, returning the scriptSig bytes.
pub fn sign_input(
    keypair: &ExtendedKeypair,
    tx: &mut Tx,
    input_index: usize,
    lock_script: &Script,
    sighash_type: u8,
    input_satoshis: u64,
    pubkey_bytes: &[u8],
) -> Result<Vec<u8>> {
    let sighash = tx.sighash_for_input(input_index, lock_script, sighash_type, input_satoshis)?;
    let signature = keypair.sign(sighash)?;
    let mut sig = signature.to_vec();
    sig.push(sighash_type);
    let script_sig = build_script_sig(&sig, pubkey_bytes);
    tx.inputs[input_index].unlock_script = Script(script_sig.clone());
    Ok(script_sig)
}

////////////////////
/// Returns the public key this unlock_script was sent from
pub fn extract_pubkey(unlock_script: &[u8]) -> Result<Vec<u8>> {
    if !check_unlock_script(unlock_script) {
        let msg = "Script is not a sigscript for P2PKH".to_string();
        return Err(Error::BadData(msg));
    }
    let i = next_op(0, &unlock_script);
    Ok(unlock_script[i + 1..].to_vec())
}

/// Returns the address this lock_script sends to
pub fn extract_pubkeyhash(lock_script: &[u8]) -> Result<Hash160> {
    if check_lock_script(lock_script) {
        let mut hash160 = Hash160([0; 20]);
        hash160.0.clone_from_slice(&lock_script[3..23]);
        return Ok(hash160);
    } else {
        return Err(Error::BadData("Script is not a standard P2PKH".to_string()));
    }
}

/// Decodes a Base58Check-encoded address to extract the version byte and hash160
pub fn decode_address(address: AddressForm) -> Result<(Network, TransactionType, Hash160)> {
    // Decode the address based on its form
    let decoded = match address {
        AddressForm::Bytes(s) => {
            if s.len() != 25 {
                return Err(Error::BadData("Invalid address length".to_string()));
            }
            s
        }
        AddressForm::Base58(s) => {
            let decoded = s
                .from_base58()
                .map_err(|e| Error::BadData(format!("Failed to decode Base58 address: {:?}", e)))?;
            if decoded.len() != 25 {
                return Err(Error::BadData("Invalid address length".to_string()));
            }
            decoded
        }
    };

    let version = decoded[0];

    let mut hash160 = Hash160([0; 20]);
    hash160.0.copy_from_slice(&decoded[1..21]);
    let checksum = &decoded[21..25];

    // Validate checksum
    let hash = sha256d(&decoded[0..21]).0;
    if checksum != &hash[0..4] {
        return Err(Error::BadData("Invalid checksum".to_string()));
    }

    // Determine network and address type based on version byte
    let (network, address_type) = match version {
        0x00 => (Network::Mainnet, TransactionType::P2PKH),
        0x05 => (Network::Mainnet, TransactionType::P2SH),
        0x6f => (Network::Testnet, TransactionType::P2PKH),
        0xc4 => (Network::Testnet, TransactionType::P2SH),
        _ => return Err(Error::BadData(format!("Invalid version byte {}", version))),
    };

    Ok((network,address_type, hash160))
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

#[cfg(test)]
mod tests {
    use super::*;
    use hex::{self, decode};

        #[test]
    fn test_script_pubkey() {
        let user_data = get_userdata().unwrap();
        let basepath = exclude_brackets(&user_data.extended_derivationpath);
        let keypair = derive_seed_or_extended_key(&user_data.extended_key, &basepath, user_data.network)
            .expect("Failed to derive keypair");

        let path_2 = format!("path/{}/{}", user_data.type_index, 76);
        let keypair_2 = derive_seed_or_extended_key(&keypair.extended_private_key, &path_2, user_data.network)
            .expect("Failed to derive keypair 2");
        // Use get_public_key_bytes from ExtendedKeypair
        let pubkey_bytes = keypair_2.get_public_key_bytes().unwrap();
        
        // Generate pubkey hash
        let pubkey_hash = mahrustsv::util::hash160(&pubkey_bytes);
        let pubkey_hash_hex = hex::encode(&pubkey_hash.0[..]);
        println!("Pubkey Hash: {}", pubkey_hash_hex);
        println!("Length Bitails Scripthash: {:?}", pubkey_hash_hex.len());

        let expected_hash_hex = "9c19bac28bd509e98b112e669804375ce0de5bb4";
        let expected_hash = hex::decode(expected_hash_hex).expect("Failed to decode hex");
        assert_eq!(&pubkey_hash.0[..], expected_hash);

        let pubkey_hash_bytes = hex::decode(&pubkey_hash_hex).expect("Failed to decode hex");
        let pubkey_hash: [u8; 20] = pubkey_hash_bytes.try_into().expect("Pubkey hash must be 20 bytes");
        let script = build_script_pubkey(&pubkey_hash);
        
        let asm = to_asm(&script);
        let hex = to_hex(&script);
        
        println!("ScriptPubKey ASM: {}", asm);
        println!("ScriptPubKey Hex: {}", hex);

        // Expected
        assert_eq!(asm, "OP_DUP OP_HASH160 OP_PUSHBYTES_20 9c19bac28bd509e98b112e669804375ce0de5bb4 OP_EQUALVERIFY OP_CHECKSIG");
        assert_eq!(hex, "76a9149c19bac28bd509e98b112e669804375ce0de5bb488ac");
    }

    #[tokio::test]
    async fn test_script_sig() {
        let user_data = get_userdata().unwrap();
        let utxos: UTXOs = crate::service::bitails::get_balance::sync_utxo(&user_data.extended_key, &user_data.extended_derivationpath, &user_data.type_index, user_data.gap_limit, user_data.network)
            .await
            .expect("Failed to fetch UTXOs");        
        // let utxo = utxos.first().and_then(|header| header.unspent.first())
        //     .ok_or_else(|| "No UTXOs found")?;
        println!("UTXOs: {:?}", utxos);
        let (to_address_bytes , _i_unused) = get_unused_address(&user_data.extended_key, &user_data.extended_derivationpath, &user_data.type_index, user_data.gap_limit, user_data.network).unwrap();
        let (change_address_bytes, _i_change) = get_change_address(&user_data.extended_key, &user_data.extended_derivationpath, &user_data.type_index, user_data.gap_limit, user_data.network).unwrap();
        let to_address = to_address_bytes.to_base58();
        let change_address = change_address_bytes.to_base58();
        println!("From Address: {:?}", &utxos[0].address);
        println!("To Address: {:?}", to_address);
        println!("Change Address: {:?}", change_address);

        // Use the same derivation path as in other tests
        let basepath = exclude_brackets(&user_data.extended_derivationpath);
        let keypair = derive_seed_or_extended_key(&user_data.extended_key, &basepath, user_data.network)
            .expect("Failed to derive keypair");
        let path_2 = format!("path/{}/{}", user_data.type_index, utxos[0].index);
        let keypair_2 = derive_seed_or_extended_key(&keypair.extended_private_key, &path_2, user_data.network)
            .expect("Failed to derive keypair 2");

        // Generate scriptSig using the correct keypair
        let (script_sig, _tx) = main(
            &user_data.extended_key,
            &format!("{}/{}/{}", basepath, user_data.type_index, utxos[0].index), // Use the full derivation path
            user_data.network,
            &utxos[0].address,
            &utxos[0].unspent[0].txid,
            utxos[0].unspent[0].satoshis,
            utxos[0].unspent[0].vout,
            &to_address,
            &change_address,
            user_data.fee_rate,
            user_data.amount,
            user_data.locktime,
        ).unwrap();
        
        // Use get_public_key_bytes from ExtendedKeypair
        let pubkey_bytes = keypair_2.get_public_key_bytes().unwrap();
        let pubkey_hex = hex::encode(&pubkey_bytes); // Convert bytes to hex string
        println!("Pubkey Hex: {}", pubkey_hex);
        let asm = to_asm(&script_sig);
        let hex = to_hex(&script_sig);
        
        println!("ScriptSig ASM: {}", asm);
        println!("ScriptSig Hex: {}", hex);
        // println!("Length Bitails Scripthash: {:?}", "b7362d19fbf7031c4da2f33cdf431348f8c49c69".len());

        // Expected (note: the page has 48 for sig push which is 72 decimal, and 21 for 33)
        // assert_eq!(asm, "OP_PUSHBYTES_71 304402204376ecef00ffc30f12f6c68254688750c7785fbc3eb65c01efb0000dc0ccc25f02201817ffe2f870e0d9440fe740ec1753d878ba125f4d54a501bb920b499211d3a901 OP_PUSHBYTES_33 03b4b0af90d28c3594d78d741b920462d3647ebce23a635c47343a3632b2f54cdb");
        // assert_eq!(hex, "47304402204376ecef00ffc30f12f6c68254688750c7785fbc3eb65c01efb0000dc0ccc25f02201817ffe2f870e0d9440fe740ec1753d878ba125f4d54a501bb920b499211d3a9012103b4b0af90d28c3594d78d741b920462d3647ebce23a635c47343a3632b2f54cdb");
    }

    #[test]
    fn test_address_to_pubkey_hash() {
        let address = "13T1L3y7iM4vWErX2X51dK3yLNvhS1zb2F";
        let expected_hash = hex::decode("19f1f3b0c160762a70f5f1503d6a02b9157d7b17").unwrap();
        let result = decode(address).expect("Failed to decode address");
        assert_eq!(result, expected_hash);

        // Test invalid address
        let invalid_address = "1InvalidAddress123"; // Not a valid Base58 address
        assert!(decode(invalid_address).is_err());
    }

    use crate::script::op_codes;

    #[test]
    fn check_lock_script_test() {
        let mut s = Script::new();
        assert!(!check_lock_script(&s.0));
        s.append(op_codes::OP_DUP);
        s.append(op_codes::OP_HASH160);
        s.append_data(&Hash160([1; 20]).0);
        s.append(op_codes::OP_EQUALVERIFY);
        s.append(op_codes::OP_CHECKSIG);
        assert!(check_lock_script(&s.0));
        s.append(op_codes::OP_1);
        assert!(!check_lock_script(&s.0));
    }

    #[test]
    fn check_unlock_script_test() {
        assert!(!check_unlock_script(&Script::new().0));

        let mut sig71pkh33 = Script::new();
        sig71pkh33.append_data(&[0; 71]);
        assert!(!check_unlock_script(&sig71pkh33.0));
        sig71pkh33.append_data(&[0; 33]);
        assert!(check_unlock_script(&sig71pkh33.0));
        sig71pkh33.append(OP_1);
        assert!(!check_unlock_script(&sig71pkh33.0));

        let mut sig73pkh65 = Script::new();
        sig73pkh65.append_data(&[0; 73]);
        sig73pkh65.append_data(&[0; 65]);
        assert!(check_unlock_script(&sig73pkh65.0));

        let mut sig72pkh30 = Script::new();
        sig72pkh30.append_data(&[0; 72]);
        sig72pkh30.append_data(&[0; 30]);
        assert!(!check_unlock_script(&sig72pkh30.0));
    }

    #[test]
    fn check_lock_script_addr_test() {
        let s = create_lock_script(&Hash160([5; 20]));
        assert!(check_lock_script_addr(&Hash160([5; 20]), &s.0));
    }

    #[test]
    fn check_unlock_script_addr_test() {
        let mut s = Script::new();
        s.append_data(&[5; 71]);
        s.append_data(&[6; 65]);
        assert!(check_unlock_script_addr(&[6; 65], &s.0));
        assert!(!check_unlock_script_addr(&[7; 65], &s.0));
    }

    #[test]
    fn decode_address_test() {
        // Mainnet address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
        let result = decode_address(AddressForm::Base58("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string())).unwrap();
        assert_eq!(result.0, Network::Mainnet);
        assert_eq!(result.1, TransactionType::P2PKH);
        assert_eq!(
            result.1.0,
            [
                0x62, 0xe9, 0x07, 0xb1, 0x5c, 0xbf, 0x27, 0xd5, 0x42, 0x53,
                0x9c, 0xa7, 0xf5, 0x1c, 0x6a, 0xf5, 0x5b, 0x57, 0xa4, 0x89
            ]
        );

        // Testnet address: mipcBbFg9gMi1G7XgCA3h6nRKB4zK2yKz3
        let result = decode_address(AddressForm::Base58("mipcBbFg9gMi1G7XgCA3h6nRKB4zK2yKz3".to_string())).unwrap();
        assert_eq!(result.0, Network::Testnet);
        assert_eq!(result.1, TransactionType::P2PKH);
    }
}