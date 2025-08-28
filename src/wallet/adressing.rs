/////////////////////////////////////////////////////////////////////////////////////////
////////////////////////// PUBLIC SERVICE ANNOUNCEMENT //////////////////////////////////
//////////////////// - THE EXTENDED DERIVATION PATH SYNTAX - ////////////////////////////
//////////////////////////// as conceived by -NИЖKY~ ////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////
/////// extended_derivationpath = "m/423/0/0/[0:70-105;1:30;2:0,1,2,3,4,5,6,7;3:0;]" ////
/////////////////////////////////////////////////////////////////////////////////////////
//
//  The Extended Derivationpath Syntax is an answer to the proposed one time usage 
//  of Bitcoin adresses according the the Bitcoin Whitepaper in Section 10.
//  It captures all UTXOs for the correct balance and content. 
//  This approach reduces sync time as much as possible without relying intensively on a
//  UTXO storage service. This approach is suitable for scale.
// 
//  How the string is being read:
//  Normal Derivationpath: m/423/0/0/ = path/
//  Extended Derivationpath = "m/423/0/0/[0:70-105;1:30;2:0,1,2,3,4,5,6,7;3:0;]" 
//
//  Type: path/[<typeIndex>:<index>;]
//      Type Index 0: Received Payments / Change Adresses (All your positive amounts)
//      Type Index 1: Sent Payments Adresses (All your negative amounts)
//      Type Index 2: Received Inscriptions (All your bought items)
//      Type Index 3: Sent Inscriptions (All your sold items)
//      -> Can be expanded for more types
//
//  Hardended TypeIndexes are also supported
//
//  Spots of Interest: <index>
//  We extract 0:70-105 from the Extended Derivation path and look it up.
//  Be aware of the Semicolon ; at each end of each section.
//  It marks the end of each section (path branch), so we can extract each section better.
//
//  i_min = 70  - Means below Index 70 we assume to have a balance of 0 AND everything 
//                below that index number has been used previously. Reuse is not recommended 
//                for Privacy. Index 70 marks the first UTXO with a positive balance.
//  i_max = 105 - Means we assume everything above Index 105 has a balance of 0 Satoshi as well 
//                because everything above that number is unused.
//  i_unused = i_max + 1 = 106 - Marks the first unused adresse that we can use for our type index use case.
//  We can also apply a gap_limit on i_max, so we see if we received anything.
//
//  To receive your transaction history, you have to get i_max as your latest UTXO and go backwards in time.
//  The indexes should all be in chronolocial order when one-time usage of Bitcoin addresses is applied correctly.

use crate::wallet::derivation::{derive_seed_or_extended_key, ExtendedKey,ExtendedKeypair};
use ring::digest::{self, SHA256};
use ripemd::{Ripemd160, Digest};
use base58::{FromBase58, ToBase58};
use crate::util::{sha256d, Error, Hash160, Result, hash160};
use crate::script::{Script, op_codes};
use crate::network::Network;
use std::fmt;
use secp256k1::{PublicKey};

pub mod constants {
    pub const MAINNET_P2PKH_VERSION: u8 = 0x00;
    pub const MAINNET_P2SH_VERSION: u8 = 0x05;
    pub const TESTNET_P2PKH_VERSION: u8 = 0x6F;
    pub const TESTNET_P2SH_VERSION: u8 = 0xC4;
    pub const STN_P2PKH_VERSION: u8 = 0x6F; // Same as Testnet
    pub const STN_P2SH_VERSION: u8 = 0xC4;  // Same as Testnet
}

// // Für JSON und YAML Konvertion 
// use serde::{Deserialize, Serialize};

/// Repräsentiert ein einzelnes Unspent Transaction Output (UTXO)
#[derive(Debug, Clone, PartialEq)]
pub struct UTXO {
    /// Transaktions-ID des UTXO
    pub txid: String,
    /// Index der Ausgabe in der Transaktion
    pub vout: u32,
    /// Betrag in Satoshis
    pub satoshis: u64,
    /// Zeitstempel der Transaktion
    pub time: u64,
    /// Blockhöhe der Bestätigung
    pub blockheight: Option<u64>,
    /// Anzahl der Bestätigungen
    pub confirmations: u64,
}

/// Repräsentiert eine Sammlung von UTXOs, gruppiert nach Adresse
/// for P2PKH, the scripthash should be the hash160 of the public key (i.e., the pubkey_hash), while
/// for P2SH, it’s the hash160 of the redeem script.
#[derive(Debug, Clone)]
pub struct AddressHeader {
    // Index
    pub index: u32,
    /// Bitcoin-Adresse
    pub address: String,
    /// Scripthash der Adresse
    pub scripthash: Hash160,
    /// Liste der UTXOs für diese Adresse
    pub unspent: Vec<UTXO>,
}

/// Repräsentiert die gesamte Liste von AddressUTXOs
pub type UTXOs = Vec<AddressHeader>;

/// Output: Normal Derivation Path Syntax
pub fn exclude_brackets(extended_derivationpath: &str) -> String {
    // Find the start of the bracketed content
    if let Some(start) = extended_derivationpath.find('[') {
        // Return the substring before the opening bracket, removing any trailing slash
        extended_derivationpath[..start].trim_end_matches('/').to_string()
    } else {
        // If no brackets, return the input string, removing any trailing slash
        extended_derivationpath.trim_end_matches('/').to_string()
    }
}

/// Everything that is in [] included, produced bracket_content
pub fn extract_brackets(extended_derivationpath: &str) -> Option<String> {
    // Find the start and end of the bracketed content
    let start = extended_derivationpath.find('[')?;
    let end = extended_derivationpath.rfind(']')?;
    
    // Extract the content between brackets (excluding the brackets)
    Some(extended_derivationpath[start + 1..end].to_string())
}

/// Selects TypeIndex Branch
pub fn extract_typeindex(bracket_content: &str, typeindex: &str) -> Option<String> {
    // Split the input by semicolons to get individual entries
    let entries: Vec<&str> = bracket_content.trim_end_matches(';').split(';').collect();

    // Iterate through entries to find the one matching typeindex
    for entry in entries {
        let parts: Vec<&str> = entry.split(':').collect();
        if parts.len() == 2 {
            let index_str = parts[0].trim();
            // Check if typeindex is a non-hardened index (can be parsed as usize)
            let cleaned_typeindex = typeindex.trim_end_matches(|c| c == 'H' || c == 'h' || c == '\'');
            if let Ok(index) = cleaned_typeindex.parse::<usize>() {
                // Handle non-hardened indices: strip H, h, or ' from entry's index
                let cleaned_index = index_str.trim_end_matches(|c| c == 'H' || c == 'h' || c == '\'');
                if let Ok(entry_index) = cleaned_index.parse::<usize>() {
                    if entry_index == index {
                        return Some(parts[1].to_string());
                    }
                }
            } else {
                // Handle hardened indices: direct comparison
                if index_str == typeindex {
                    return Some(parts[1].to_string());
                }
            }
        }
    }

    None
}

/// Output Format: ?
pub fn get_indexes_in_array(typeindex_content: &str, gap_limit:&u32) -> Result<Vec<u32>> {
    let mut indices = Vec::new();

    // Split input by commas to handle combined ranges and single numbers
    for part in typeindex_content.split(',').filter(|s| !s.is_empty()) {
        if part.contains('-') {
            // Handle range (e.g., "70-105" or "10-15")
            let range_parts: Vec<&str> = part.split('-').collect();
            if range_parts.len() != 2 {
                return Err(Error::BadData("Invalid range format".to_string()));
            }
            let start = range_parts[0]
                .parse::<u32>()
                .map_err(Error::ParseIntError)?;
            let end = range_parts[1]
                .parse::<u32>()
                .map_err(Error::ParseIntError)?;
            if start > end {
                return Err(Error::BadData("Start of range cannot be greater than end".to_string()));
            }
            indices.extend(start..=end);
        } else {
            // Handle single number (e.g., "88" or "69")
            let number = part
                .parse::<u32>()
                .map_err(Error::ParseIntError)?;
            indices.push(number);
        }
    }

    // Remove duplicates and sort
    indices.sort_unstable();
    indices.dedup();

    // Find max value and add gap_limit entries
    if let Some(max_value) = indices.iter().max() {
        let extended_limit = max_value + gap_limit;
        indices.extend((max_value + 1)..=extended_limit);
    }

    Ok(indices)
}

/// Output Format: ?
pub fn get_typeindex_indices(extended_derivationpath: &str, typeindex: &str, gap_limit: u32) -> Result<Vec<u32>> {
    let bracket_content = extract_brackets(extended_derivationpath)
        .ok_or_else(|| Error::BadData("Failed to extract brackets".to_string()))?;
    let typeindex_content = extract_typeindex(&bracket_content, typeindex)
        .ok_or_else(|| Error::BadData(format!("Failed to extract typeindex {}", typeindex)))?;
    get_indexes_in_array(&typeindex_content, &gap_limit)
}

/////////////// 
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TransactionType {
    P2PKH,
    P2SH,
}

// Enum to specify the type of address to generate
#[derive(Debug, Clone, Copy)]
pub enum AddressType {
    Unused,
    Change,
}

// Kann payload auch Hash160 Tyoe sein?
pub fn encode_address(network: Network, addr_type: TransactionType, payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() != 20 {
        return Err(Error::BadArgument("Payload must be 20 bytes".to_string()));
    }

    let version = match (network, addr_type) {
        (Network::Mainnet, TransactionType::P2PKH) => 0x00,
        (Network::Mainnet, TransactionType::P2SH) => 0x05,
        (Network::Testnet, TransactionType::P2PKH) => 0x6f,
        (Network::Testnet, TransactionType::P2SH) => 0xc4,
        (Network::STN, TransactionType::P2PKH) => 0x6f, // Scalenet uses Testnet version bytes
        (Network::STN, TransactionType::P2SH) => 0xc4, // Scalenet uses Testnet version bytes
    };

    let mut v = Vec::with_capacity(25);
    v.push(version);
    v.extend_from_slice(payload);
    let checksum = sha256d(&v);
    v.extend_from_slice(&checksum.0[..4]);
    Ok(v)
}

pub fn decode_address(input: &str) -> Result<(u8, Vec<u8>)> {
    let bytes = input.from_base58().map_err(|e| Error::FromBase58Error(e))?;
    if bytes.len() != 25 {
        return Err(Error::BadData("Invalid address length".to_string()));
    }
    let checksum = sha256d(&bytes[..21]);
    if checksum.0[..4] != bytes[21..] {
        return Err(Error::BadData("Invalid checksum".to_string()));
    }
    let version = bytes[0];
    let payload = bytes[1..21].to_vec();
    Ok((version, payload))
}

/// Converts a lock script (scriptPubKey) to a Base58Check address.
pub fn lock_script_to_address(script: &[u8], network: Network) -> Result<String> {
    // Check if the script is a P2PKH or P2SH script and extract the hash160
    let (transaction_type, hash160) = if script.len() == 25 && script[0] == 0x76 && script[1] == 0xa9 && script[2] == 0x14 && script[23] == 0x88 && script[24] == 0xac {
        // P2PKH: OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
        (TransactionType::P2PKH, &script[3..23])
    } else if script.len() == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87 {
        // P2SH: OP_HASH160 <20-byte hash> OP_EQUAL
        (TransactionType::P2SH, &script[2..22])
    } else {
        return Err(Error::BadData("Invalid lock script format".to_string()));
    };

    // Determine the network prefix
    let prefix = match (network, transaction_type) {
        (Network::Mainnet, TransactionType::P2PKH) => 0x00,
        (Network::Mainnet, TransactionType::P2SH) => 0x05,
        (Network::Testnet, TransactionType::P2PKH) => 0x6f,
        (Network::Testnet, TransactionType::P2SH) => 0xc4,
        (Network::STN, TransactionType::P2PKH) => 0x6f,
        (Network::STN, TransactionType::P2SH) => 0xc4,
    };

    // Create payload: prefix + hash160
    let mut payload = Vec::with_capacity(1 + 20 + 4);
    payload.push(prefix);
    payload.extend_from_slice(hash160);

    // Compute checksum: first 4 bytes of double SHA-256
    let checksum = &sha256d(&payload).0[..4];
    payload.extend_from_slice(checksum);

    // Encode to Base58
    Ok(payload.to_base58())
}

/// Expects to get the path/ extended_key, not m/
pub fn get_keydata_array(
    extended_key: ExtendedKeypair,
    typeindex: &str,
    index : u32,
    adresse_string: String,
    network: Network,
) -> Result<KeyData> {

    let child_path: String = format!("path/{}/{}", typeindex, index);
    // Derive the child key using derive_seed_or_extended_key
    let child_keypair: ExtendedKeypair = derive_seed_or_extended_key(&extended_key.extended_private_key, &child_path, network)?;
    let private_key_bytes = child_keypair.get_private_key_bytes().unwrap();
    let public_key_bytes = child_keypair.get_public_key_bytes().unwrap();

    // Compute public key hash (hash160 of public key) for generating P2PKH address
    let public_key_hash = crate::util::hash160(&public_key_bytes).0;
    let p2pkh_address = encode_address(network, TransactionType::P2PKH, &public_key_hash)?;

    // Compute script hash (hash160 of public key) for generating P2SH address
    let script_hash = crate::util::hash160(&public_key_bytes).0;
    let p2sh_address = encode_address(network, TransactionType::P2SH, &script_hash)?;

    // Compare the provided address with the computed P2PKH address
    if adresse_string != p2pkh_address.to_base58() {
        return Err(Error::BadData(format!(
            "Provided address {} does not match computed P2PKH address {}",
            adresse_string, p2pkh_address.to_base58()
        )));
    }

    Ok(KeyData {
        index,
        private_key: private_key_bytes,
        public_key: public_key_bytes,
        public_key_hash: public_key_hash,
        p2pkh_address: AddressForm::Base58(p2pkh_address.to_base58()),
        script_hash: script_hash,
        p2sh_address: AddressForm::Base58(p2sh_address.to_base58()),
    })
}

pub fn get_keydata_array_from_extended_derivationpath(
    extended_key: &str,
    extended_derivationpath: &str,
    typeindex: &str,
    gap_limit : u32,
    network: Network,
) -> Result<Vec<ExtendedKeypair>> {

    // Get the indices for the given typeindex
    let indices: Vec<u32> = get_typeindex_indices(extended_derivationpath, typeindex, gap_limit)?;

    // Extract the base path (e.g., m/69'/0'/0')
    let base_path: String = exclude_brackets(extended_derivationpath);

    println!("Works with: {:?} and {:?} and {:?}", base_path, typeindex,  indices);

    // Derive addresses for each index
    let extended_keypairs: Result<Vec<ExtendedKeypair>> = indices.into_iter().map(|index| {
        // Construct the full derivation path for the child (e.g., m/69'/0'/0'/index)
        let child_path: String = format!("{}/{}/{}", base_path, typeindex, index);
        
        // Derive the child key using derive_seed_or_extended_key
        let child_keypair: crate::wallet::derivation::ExtendedKeypair = derive_seed_or_extended_key(extended_key, &child_path, network)?;
        
        Ok(child_keypair)
    }).collect();

    extended_keypairs
}

pub fn construct_redeem_script(pubkeys: &[u8], m: usize, n: usize) -> Result<Script> {
    if m < 1 || m > n || n < 1 || n > 20 || n > pubkeys.len() {
        return Err(Error::BadData(format!(
            "Invalid multisig parameters: m={}, n={}, keys={}",
            m, n, pubkeys.len()
        )));
    }

    let mut redeem_script = Script::new();
    redeem_script.append((op_codes::OP_1 + m as u8 - 1).into()); // OP_m (m signatures required)
    for pubkey in pubkeys.iter().take(n) {
        redeem_script.append_slice(&[*pubkey]); // Dereference pubkey to get u8, then create a slice
    }
    redeem_script.append((op_codes::OP_1 + n as u8 - 1).into()); // OP_n (total keys)
    redeem_script.append(op_codes::OP_CHECKMULTISIG);
    Ok(redeem_script)
}

pub fn public_key_to_address(pubkey: &[u8], network: Network, addr_type: TransactionType) -> Result<Vec<u8>> {
    let payload = match addr_type {
        TransactionType::P2PKH => {
            // Step 1: SHA-256 hash of the public key
            let sha256_hash = digest::digest(&SHA256, pubkey);
            // Step 2: RIPEMD-160 hash of the SHA-256 result
            Ripemd160::digest(&sha256_hash).to_vec()
        }
        TransactionType::P2SH => {
            // Step 1: Construct a redeem script (for testing, use a simple 1-of-1 multisig)
            let redeem_script = construct_redeem_script(pubkey, 1,1)?;
            // Step 2: SHA-256 then RIPEMD-160 hash of the redeem script
            let script_hash = digest::digest(&SHA256, &redeem_script.to_bytes());
            Ripemd160::digest(&script_hash).to_vec()
        }
    };

    // Step 3: Use encode_address to handle version byte, checksum, and Base58Check encoding
    let base58_address = encode_address(network, addr_type, &payload)?;
    Ok(base58_address)
}

/// Decompresses a 33-byte compressed public key into a 65-byte uncompressed public key.
pub fn decompress_public_key(compressed: &[u8; 33]) -> Result<Vec<u8>> {
    // Check if the input is a valid 33-byte compressed public key
    if compressed.len() != 33 || (compressed[0] != 0x02 && compressed[0] != 0x03) {
        return Err(Error::BadData("Invalid compressed public key: must be 33 bytes starting with 0x02 or 0x03".to_string()));
    }

    // Parse the compressed public key
    let pubkey = PublicKey::from_slice(compressed)?;

    // Serialize the public key in uncompressed format (65 bytes: 04 || x || y)
    let uncompressed: [u8; 65] = pubkey.serialize_uncompressed();

    Ok(uncompressed.to_vec())
}

#[derive(Debug, Clone)]
pub enum AddressForm {
    Bytes(Vec<u8>), 
    Base58(String),
}

// Implementiere Display für AddressData
impl fmt::Display for AddressForm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressForm::Bytes(bytes) => write!(f, "{}", bytes.to_base58()), // Konvertiere Bytes zu Base58
            AddressForm::Base58(string) => write!(f, "{}", string), // Gib String direkt aus
        }
    }
}

impl AsRef<str> for AddressForm {
    fn as_ref(&self) -> &str {
        match self {
            AddressForm::Bytes(bytes) => {
                // Note: This assumes the bytes are valid for Base58 encoding
                // In a production system, you might want to cache this or handle it differently
                // Since to_base58() returns a String, we'll leak it to get a &str
                // This is not ideal for performance; consider alternatives if needed
                Box::leak(bytes.to_base58().into_boxed_str())
            }
            AddressForm::Base58(s) => s,
        }
    }
}

/// Converts an address string or bytes into an AddressForm
pub fn to_address_form<T: AsRef<str>>(input: T) -> Result<AddressForm> {
    let input_str = input.as_ref();
    if input_str.is_empty() {
        return Err(Error::BadData("Empty address input".to_string()));
    }
    // Try to decode as Base58 first
    match input_str.from_base58() {
        Ok(bytes) => {
            // Validate the address bytes (e.g., length and checksum)
            if bytes.len() != 25 {
                return Err(Error::BadData("Invalid address length".to_string()));
            }
            let checksum = sha256d(&bytes[..21]);
            if checksum.0[..4] != bytes[21..] {
                return Err(Error::BadData("Invalid checksum".to_string()));
            }
            Ok(AddressForm::Bytes(bytes))
        }
        Err(_) => {
            // If not valid Base58, assume it's already a Base58 string
            // In a production system, you might want additional validation
            Ok(AddressForm::Base58(input_str.to_string()))
        }
    }
}

/// Represents key data for a derived address, including index and various key-related strings
#[derive(Debug, Clone)]
pub struct KeyData {
    /// The derivation index
    pub index: u32,
    /// Private key bytes (compressed or uncompressed)?
    pub private_key: Vec<u8>,
    /// Public key bytes (compressed or uncompressed)?
    pub public_key: Vec<u8>,
    /// Hash160 of the public key (20 bytes)
    pub public_key_hash: [u8; 20],
    /// P2PKH address (Base58Check-encoded)
    pub p2pkh_address: AddressForm,
    /// Script hash for P2SH (20 bytes)
    pub script_hash: [u8; 20],
    /// P2SH address (Base58Check-encoded)
    pub p2sh_address: AddressForm,
}

fn generate_key_data(index: u32, extended_key_obj: ExtendedKey, network: Network) -> Result<KeyData> {
    let bip32_key = extended_key_obj.to_bip32_keyobject()?;
    let private_key_bytes = bip32_key.get_private_key();
    let public_key_bytes = bip32_key.get_public_key();
    
    // Compute public key hash (hash160 of public key)
    let public_key_hash = crate::util::hash160(&public_key_bytes);
    
    // Generate P2PKH address
    let p2pkh_address = encode_address(network, TransactionType::P2PKH, &public_key_hash.0)?;

    // // Create a simple P2SH redeem script (e.g., P2PKH-like script for demonstration)
    // // Note: Replace with your actual redeem script (e.g., multisig) if needed
    let redeem_script = Script::p2pkh(&public_key_hash.0).to_bytes(); // Example: OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
    let script_hash = crate::util::hash160(&redeem_script);
    let checked_script_hash: bool = crate::transaction::types::p2pkh::check_lock_script(&redeem_script);

    if !checked_script_hash {
        return Err(Error::BadData("Invalid P2SH script hash".to_string()));
    }

    // Generate P2SH address only if the script hash is valid
    let p2sh_address = encode_address(network, TransactionType::P2SH, &script_hash.0)?;
    
    // Debugging output
    let debugging: bool = false;
    if debugging{
        println!("");
        println!("Index: {} ::: PK Bytes: {:?}", index, &public_key_bytes);
        // println!("Public Key Bytes: {:?}", hex::decode(hex::encode(public_key_bytes)));
        println!("Private Key: {}", hex::encode(&private_key_bytes));
        println!("Public Key: {} - 33-byte compressed public key (starting with 03)", hex::encode(&public_key_bytes));
        println!("Public Key Hash: {}", hex::encode(&public_key_hash.0));
        println!("P2PKH Address: {}", p2pkh_address.to_base58());
        println!("Redeem Script aka. Script Public Key: {}", hex::encode(&redeem_script));
        println!("P2SH Script Hash (hash160) aka. Bitails API Script Hash: {}", hex::encode(&script_hash.0));
        println!("P2SH Address: {}", p2sh_address.to_base58());
        // Script Hash
        // 4e63632f5b6052236859f5728bb8a16008b0661766eb6cbebd3e7b418c6369a0
    
        println!("");
    }

    Ok(KeyData {
        index,
        private_key: private_key_bytes,
        public_key: public_key_bytes,
        p2pkh_address: AddressForm::Base58(p2pkh_address.to_base58()),
        public_key_hash: public_key_hash.0,
        script_hash: script_hash.0,
        p2sh_address: AddressForm::Base58(p2sh_address.to_base58()),
    })
}

pub fn get_all_key_data_from_extended_derivationpath(
    extended_key: &str,
    extended_derivationpath: &str,
    typeindex: &str,
    network: Network,
    gap_limit: u32,
) -> Result<Vec<KeyData>> {
    // Get the indices for the given typeindex
    let indices = get_typeindex_indices(extended_derivationpath, typeindex, gap_limit)?;

    // Extract the base path (e.g., m/69'/0'/0')
    let base_path = exclude_brackets(extended_derivationpath);

    println!("Works with: {:?} and {:?} and {:?}", base_path, typeindex, indices);

    // Derive key data for each index
    let all_key_data: Vec<KeyData> = indices.into_iter().map(|index| {
        // Construct the full derivation path for the child (e.g., m/69'/0'/0'/index)
        let child_path = format!("{}/{}/{}", base_path, typeindex, index);

        // Derive the child key using derive_seed_or_extended_key
        let child_keypair = derive_seed_or_extended_key(extended_key, &child_path, network)?;

        // Extract the public key from the extended public key
        let extended_key_obj = ExtendedKey::decode(&child_keypair.extended_public_key)?;

        // Create KeyData struct
        Ok(generate_key_data(index, extended_key_obj, network)?)
    }).collect::<Result<Vec<KeyData>>>()?;
    
    // Alle unterschiedlich
    //println!("DEBUG KEYDATA {:?}", all_key_data);
    Ok(all_key_data)
}

/// Uses  path/[<typeIndex>:<Index>] to format into path/<typeIndex>/<Index>
pub fn get_address_by_index(
    child_extended_key: &str,
    type_index: &str,
    index: u32,
    network: Network,
) -> Result<String> {
    let child_path = format!("path/{}/{}", type_index, index);

    // Derives the child keypair from the child_path
    let child_keypair = derive_seed_or_extended_key(child_extended_key, &child_path, network)?;

    // Extract the public key from the extended public key
    let extended_key_obj = ExtendedKey::decode(&child_keypair.extended_public_key)
        .map_err(|e| Error::Bip32Error(format!("Failed to decode extended public key: {}", e)))?;
    let bip32_key = extended_key_obj
        .to_bip32_keyobject()
        .map_err(|e| Error::Bip32Error(format!("Failed to convert to BIP-32 key object: {}", e)))?;
    let public_key_bytes = bip32_key.get_public_key();
    let public_key_hash = crate::util::hash160(&public_key_bytes);
    let vec_u8_address = encode_address(network, TransactionType::P2PKH, &public_key_hash.0)?;
    let base58_address = vec_u8_address.to_base58();
    Ok(base58_address)
}

pub fn get_address_by_type(
    extended_key: &str,
    extended_derivation_path: &str,
    type_index: &str,
    gap_limit: u32,
    network: Network,
    address_type: AddressType,
) -> Result<(String, u32)> {
    let type_index_indices = get_typeindex_indices(extended_derivation_path, type_index, gap_limit)?;

    // Array adjustment while looking for balance, then:
    let _i_min = type_index_indices
        .iter()
        .min()
        .ok_or_else(|| Error::BadData("No indices found".to_string()))?;
    let i_gap_max = type_index_indices
        .iter()
        .max()
        .ok_or_else(|| Error::BadData("No indices found".to_string()))?;
    let i_max = i_gap_max - gap_limit;
    let index = match address_type {
        AddressType::Unused => i_max + 1,
        AddressType::Change => i_max + 2,
    };

    let base58_address = get_address_by_index(extended_key, type_index, index, network)?;
    Ok((base58_address, index))
}

pub fn get_pubkey_hash_from_address(address: &str, network: Network) -> Result<[u8; 20]> {
    let bytes = address.from_base58()?;
    if bytes.len() != 25 {
        return Err(Error::BadData("Invalid address length".to_string()));
    }
    // if bytes.len() != 25 {
    //     return Err(mahrustsv::util::Error::Base58(base58::FromBase58Error::InvalidLength));
    // }
    let data = &bytes[0..21];
    let computed_checksum = sha256d(data).0[0..4].to_vec(); // Use sha256d instead of hash256
    if computed_checksum != bytes[21..25] {
        return Err(Error::BadData("Invalid checksum".to_string()));
    }
    // if computed_checksum != bytes[21..25] {
    //     return Err(mahrustsv::util::Error::Base58(base58::FromBase58Error::InvalidChecksum));
    // }
    let version = bytes[0];
    let expected_version = match network {
        Network::Mainnet => 0x00,
        Network::Testnet => 0x6f,
        Network::STN => 0x3f,
        // Add other networks if needed
    };
    if version != expected_version {
        return Err(Error::BadData("Wrong network".into()));
    }
    let mut hash = [0; 20];
    hash.copy_from_slice(&bytes[1..21]);
    Ok(hash)
}

// Converts a 20-byte hash to a Base58Check-encoded Bitcoin address.
pub fn pubkey_hash_to_base58check(hash: &[u8; 20], network: Network, addr_type: TransactionType) -> Result<String> {
    // Select version byte based on network and address type
    let version_byte = match (network, addr_type) {
        (Network::Mainnet, TransactionType::P2PKH) => constants::MAINNET_P2PKH_VERSION,
        (Network::Mainnet, TransactionType::P2SH) => constants::MAINNET_P2SH_VERSION,
        (Network::Testnet, TransactionType::P2PKH) => constants::TESTNET_P2PKH_VERSION,
        (Network::Testnet, TransactionType::P2SH) => constants::TESTNET_P2SH_VERSION,
        (Network::STN, TransactionType::P2PKH) => constants::STN_P2PKH_VERSION,
        (Network::STN, TransactionType::P2SH) => constants::STN_P2SH_VERSION,
    };

    // Construct payload: version byte + hash
    let mut payload = vec![version_byte];
    payload.extend_from_slice(hash);

    // Compute checksum: first 4 bytes of SHA256(SHA256(payload))
    let checksum = &sha256d(&payload).0[0..4];

    // Append checksum to payload
    payload.extend_from_slice(checksum);

    // Encode to Base58
    Ok(payload.to_base58())
}

/// Extracts P2PKH address from scriptSig (unlock script) if it's a standard P2PKH format.
pub fn scriptsig_to_p2pkh_address(script_sig: &Script, network: Network) -> Option<String> {
    let bytes = &script_sig.0;
    let mut i = 0;
    // Expect first push: signature (typically 71-73 bytes)
    if i >= bytes.len() || bytes[i] < 0x01 || bytes[i] > 0x4b { return None; }
    let sig_len = bytes[i] as usize;
    i += 1 + sig_len;
    // Expect second push: pubkey (33 or 65 bytes)
    if i >= bytes.len() || bytes[i] < 0x01 || bytes[i] > 0x4b { return None; }
    let pubkey_len = bytes[i] as usize;
    if pubkey_len != 33 && pubkey_len != 65 { return None; }
    i += 1;
    let pubkey = &bytes[i..i + pubkey_len];
    // Compute hash160(pubkey)
    let pubkey_hash = hash160(pubkey);
    // Convert to Base58Check address (prefix 0x00 for P2PKH)
    Some(pubkey_hash_to_base58check(&pubkey_hash.0, network, TransactionType::P2PKH).unwrap())
}

/// Helper to get P2PKH address from scriptPubKey (Locking script)
pub fn script_pubkey_to_p2pkh_address(script: &Script, network: Network) -> Option<String> {
    let bytes = &script.0;
    if bytes.len() == 25 && bytes[0] == 0x76 && bytes[1] == 0xa9 && bytes[2] == 0x14 && bytes[23] == 0x88 && bytes[24] == 0xac {
        let hash: [u8; 20] = bytes[3..23].try_into().unwrap();
        Some(pubkey_hash_to_base58check(&hash, network, TransactionType::P2PKH).unwrap())
    } else {
        None
    }
}

/// Reformats a derivation path by removing everything between "m/" or "path/" and "/[".
/// 
/// For example:
/// - "m/44/0/0/[0:76,103,104]" becomes "path/[0:76,103,104]"
/// - "path/44/0/0/[0:76,103,104]" becomes "path/[0:76,103,104]"
/// Returns an error if the input string doesn't start with "m/" or "path/" or doesn't contain "/[".
pub fn reformat_derivation_path(path: &str) -> Result<String> {
    let prefixes = ["m/", "path/", "sync/"];
    let suffix_start = "[";
    
    // Find the matching prefix
    let prefix = prefixes.iter().find(|&&p| path.starts_with(p)).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid derivation path: must start with 'm/' or 'path/'",
        )
    })?;
    
    // Check for "/[" presence
    if !path.contains(suffix_start) {
        return Err(crate::util::result::Error::IOError(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid derivation path: missing '/['",
        )));
    }
    
    // Split at "/[" and take the suffix
    let parts: Vec<&str> = path.split(suffix_start).collect();
    if parts.len() != 2 {
        return Err(crate::util::result::Error::IOError(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid derivation path: multiple '/[' found",
        )));
    }

    // Ensure the suffix ends with ";]" if it ends with "]"
    let suffix = if parts[1].ends_with("]") && !parts[1].ends_with(";]") {
        format!("{};]", &parts[1][..parts[1].len() - 1])
    } else {
        parts[1].to_string()
    };
    
    // Combine prefix with "/[" and the suffix
    Ok(format!("{}{}{}", prefix, suffix_start, suffix))
}

pub fn extended_derivationpath_from_utxo(extended_derivation_path: &str, type_index: &str, utxos: &UTXOs, confirmation_count: u32) -> String {
    let mut new_path = format!("{}/", exclude_brackets(extended_derivation_path));
    new_path.push_str(&format!("[{}:",type_index));

    let mut first = true;
    for address_header in utxos.iter().filter(|ah| ah.unspent.iter().any(|u| u.confirmations >= confirmation_count as u64)) {
        if !first {
            new_path.push_str(",");
        }
        new_path.push_str(&format!("{}", address_header.index));
        first = false;
    }
    new_path.push_str(&format!(";]"));

    // m/[0:104,105,106,107,108;]
    new_path

    // m/[0:104-108;]
    // Min, max .. to be implemented, if needed

}

#[cfg(test)]
mod tests {
    use crate::util::hash160;

    use super::*;

    #[test]
    fn test_utxo_structure() {
        // Create a single UTXO instance
            let utxo = UTXO {
                txid: "1234abcd".to_string(),
                vout: 0,
                satoshis: 50000,
                time: 1645960789,
                blockheight: 815019,
                confirmations: 200,
            };

            // Create an AddressHeader instance containing the UTXO
            let address_header = AddressHeader {
                index: 69,
                address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
                scripthash: hash160("76a9141a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t88ac".as_bytes()),
                unspent: vec![utxo.clone()],
            };
        
            // Create a UTXOs collection
            let utxos = UTXOs::from(vec![address_header]);
        
            // Assertions to verify the structure
            assert_eq!(utxos[0].address, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
            assert_eq!(utxos[0].unspent[0].txid, "1234abcd");
            assert_eq!(utxos[0].unspent[0].satoshis, 50000);
            assert_eq!(utxos[0].unspent[0].blockheight, 815019);
        }
        
    #[test]
    fn test_get_publickey_array_from_extended_derivationpath() {
        let extended_key = "xprv9s21ZrQH143K42KFE1hos9hrU9hHveVk7AHkV3ca2Ks3k3C6z59oEz6La7ervLcs4v9wYdCKZkWcgrnqzqzsQnSVG5kmVFNCfRSrE7T6Tkg";
        let extended_derivationpath = "m/44/0/0/[0:76-104]";
        let typeindex = "0";
        let network = Network::Mainnet;
        let gap_limit: u32 = 10;
    
        let result = get_keydata_array_from_extended_derivationpath(
            extended_key,
            extended_derivationpath,
            typeindex,
            gap_limit,
            network,
        ).unwrap();
    
        assert!(!result.is_empty(), "Expected non-empty vector of public keys");
        for keypair in result {
            assert_eq!(keypair.public_key.len(), 33, "Expected compressed public key length of 33 bytes");
        }
    }
    
    #[test]
    fn test_decompress_public_key() {
        // Test cases: (description, input hex, expected output or None if error expected)
        let test_cases = vec![
            (
                "Valid key (provided)",
                "03b4b0af90d28c3594d78d741b920462d3647ebce23a635c47343a3632b2f54cdb",
                Some("04b4b0af90d28c3594d78d741b920462d3647ebce23a635c47343a3632b2f54cdbf5f2fadb43e9c7b5a0b5a0c5f10b1f9d6f2a3a6e6e2e4c4b4b3b3a3a2a1a0"),
            ),
            (
                "Invalid prefix (0x04)",
                "04b4b0af90d28c3594d78d741b920462d3647ebce23a635c47343a3632b2f54cdb",
                None,
            ),
            (
                "Invalid length (32 bytes)",
                "03b4b0af90d28c3594d78d741b920462d3647ebce23a635c47343a3632b2f54c",
                None,
            ),
            (
                "Invalid hex string",
                "03b4b0af90d28c3594d78d741b920462d3647ebce23a635c47343a3632b2f54cdz",
                None,
            ),
        ];
    
        for (description, input_hex, expected_output) in test_cases {
            // Decode hex string
            let compressed_bytes = match hex::decode(input_hex) {
                Ok(bytes) => bytes,
                Err(_) => {
                    if expected_output.is_none() {
                        // Expected failure for invalid hex
                        continue;
                    } else {
                        panic!("Test '{}': Failed to decode hex, but expected success", description);
                    }
                }
            };
    
            // Run decompression
            let comressed_bytes_33: [u8; 33] = match compressed_bytes.try_into() {
                Ok(arr) => arr,
                Err(_) => {
                    if expected_output.is_none() {
                        // Expected failure for invalid length
                        continue;
                    } else {
                        panic!("Test '{}': Failed to convert to 33-byte array, but expected success", description);
                    }
                }
            };
            match decompress_public_key(&comressed_bytes_33) {
                Ok(uncompressed) => {
                    let uncompressed_hex = hex::encode(&uncompressed);
                    if let Some(expected) = expected_output {
                        assert_eq!(uncompressed_hex, expected, "Test '{}': Uncompressed key does not match expected", description);
                    } else {
                        panic!("Test '{}': Unexpected success, expected failure", description);
                    }
                }
                Err(e) => {
                    if expected_output.is_some() {
                        panic!("Test '{}': Failed with error '{}', expected success", description, e);
                    }
                    // Expected failure, no need to assert
                }
            }
        }
    }



    const EXTENDED_DERIVATIONPATH : &str = "m/44/0/0/[0:70-105;1:30;2:0,1,2,3,4,5,6,7;3:0;4':35;5H:55;6h:66]";

    #[test]
    fn test_extract_brackets(){
        match extract_brackets(EXTENDED_DERIVATIONPATH) {
            Some(bracket_content) => println!("test_extract_brackets - Bracket Content: [{}]", bracket_content),
            None => println!("No brackets found"),
        }
    }

    #[test]
    fn test_exclude_brackets(){
        let derivationpath = exclude_brackets(EXTENDED_DERIVATIONPATH);
        println!("Derivation Path (normalized): {}", derivationpath);
        assert_eq!(derivationpath, "m/44/0/0", "Derivation path does not match expected value");
    }

    #[test]
    fn test_extract_typeindex() {
        let bracket_content = "0:70-105;1H:0,1,2,3,4,5,6,7;2:200-300;2h:400-500;3':600-700";

        let result1 = extract_typeindex(bracket_content, "0");
        println!("{:?}", result1); // Outputs: Some("70-105")

        // Hardened index
        let result2 = extract_typeindex(bracket_content, "1H");
        println!("{:?}", result2); // Outputs: Some("0,1,2,3,4,5,6,7")

        // Hardened index
        let result3 = extract_typeindex(bracket_content, "2h");
        println!("{:?}", result3); // Outputs: Some("400-500")

        // Hardened index
        let result4 = extract_typeindex(bracket_content, "3'");
        println!("{:?}", result4); // Outputs: Some("600-700")

        // Non-hardened index
        let result5 = extract_typeindex(bracket_content, "2");
        println!("{:?}", result5); // Outputs: Some("200-300")

        // Non-existent index
        let result6 = extract_typeindex(bracket_content, "4");
        println!("{:?}", result6); // Outputs: None
    }

    #[test]
    fn test_extract_with_nonhardended_typeindex() {
        let bracket_content = extract_brackets(EXTENDED_DERIVATIONPATH);
        match bracket_content {
            Some(content) => {
                let typeindex = "2";
                let result = extract_typeindex(&content, typeindex);
                println!("Get Values of TypeIndex {:?} : {:?}", typeindex, result);
                assert_eq!(
                    result,
                    Some("0,1,2,3,4,5,6,7".to_string()),
                    "Expected value for typeindex {} does not match",
                    typeindex
                );

                // Test for non-existent typeindex
                let typeindex = "15";
                let result = extract_typeindex(&content, typeindex);
                assert_eq!(result, None, "Expected None for non-existent typeindex");
            }
            None => panic!("Expected bracket content but found None"),
        }
    }

    #[test]
    fn test_extract_with_hardended_typeindex() {
        let bracket_content = extract_brackets(EXTENDED_DERIVATIONPATH);
        match bracket_content {
            Some(content) => {
                let typeindex = "0";
                let result = extract_typeindex(&content, typeindex);
                println!("Get Values of TypeIndex {:?} : {:?}", typeindex, result);
                assert_eq!(
                    result,
                    Some("70-105".to_string()),
                    "Expected value for typeindex {} does not match",
                    typeindex
                );

                let typeindex = "4'";
                let result = extract_typeindex(&content, typeindex);
                assert_eq!(result, Some("35".to_string()), "Expected None for non-existent typeindex");

                let typeindex = "5H";
                let result = extract_typeindex(&content, typeindex);
                assert_eq!(result, Some("55".to_string()), "Expected None for non-existent typeindex");

                let typeindex = "6h";
                let result = extract_typeindex(&content, typeindex);
                assert_eq!(result, Some("66".to_string()), "Expected None for non-existent typeindex");

                // Test for non-existent typeindex
                let typeindex = "15";
                let result = extract_typeindex(&content, typeindex);
                assert_eq!(result, None, "Expected None for non-existent typeindex");
            }
            None => panic!("Expected bracket content but found None"),
        }
    }

    #[test]
    fn test_get_indexes_in_array() {
        // Test range format
        let result = get_indexes_in_array("8-11", &0).unwrap();
        assert_eq!(result, vec![8, 9, 10, 11], "Range 8-11 failed");

        // Test comma-separated list
        let result = get_indexes_in_array("0,1,2,3,4,5,6,7", &0).unwrap();
        assert_eq!(result, vec![0, 1, 2, 3, 4, 5, 6, 7], "Comma-separated list failed");

        // Test single number
        let result = get_indexes_in_array("30", &0).unwrap();
        assert_eq!(result, vec![30], "Single number failed");

        // Test invalid range
        assert!(get_indexes_in_array("11-8", &0).is_err(), "Invalid range should fail");

        // Test invalid number
        assert!(get_indexes_in_array("a-11", &0).is_err(), "Invalid number in range should fail");

        // Test invalid list
        assert!(get_indexes_in_array("0,1,a,3", &0).is_err(), "Invalid number in list should fail");

        // TEST MOAR ADVANCED STUFF
    }

    #[test]
    fn test_extended_derivationpath_to_index_array() {
        let bracket_content = extract_brackets(EXTENDED_DERIVATIONPATH).expect("Failed to extract brackets");
        let typeindex = "0";
        let typeindex_content = extract_typeindex(&bracket_content, typeindex).expect("Failed to extract typeindex 0");
        println!("test_extended_derivationpath_to_index_array - Bracket Content: {}", typeindex_content);
        let result = get_indexes_in_array(&typeindex_content, &0).unwrap();
        println!("Result for Array: {:?}", result);
        assert_eq!(
            result,
            vec![70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105],
            "Parsing typeindex {} failed",
            typeindex
        );
    }

    #[test]
    fn test_more_advanced_combinations() {
        let advanced_extended_derivatonpath = "m/69'/0'/0'/[0:70-105,90-120,88,69,70-75;]";
        let bracket_content = extract_brackets(advanced_extended_derivatonpath).expect("Failed to extract brackets");
        let typeindex = "0";
        let typeindex_content = extract_typeindex(&bracket_content, typeindex).expect("Failed to extract typeindex 0");
        println!("test_more_advanced_combinations - Bracket Content: {}", typeindex_content);
        let result = get_indexes_in_array(&typeindex_content, &0).unwrap();
        println!("test_more_advanced_combinations - Result for Array: {:?}", result);
        assert_eq!(
                result,
                (69..=120).collect::<Vec<u32>>(),
                "Parsing typeindex {} failed",
                typeindex
            );
    }

    #[test]
    fn test_get_typeindex_indices() {
        let advanced_extended_derivatonpath = "m/69'/0'/0'/[0:70-105,90-120,88,69,70-75;]";
        let typeindex = "0";
        let result = get_typeindex_indices(advanced_extended_derivatonpath, typeindex, 0);
        println!("Result for Array: {:?}", result);
        match result {
            Ok(value) => assert_eq!(
                value,
                (69..=120).collect::<Vec<u32>>(),
                "Parsing typeindex {} failed",
                typeindex
            ),
            Err(e) => panic!("Parsing typeindex {} failed: {:?}", typeindex, e),
        }

        let advanced_extended_derivatonpath = "m/69'/0'/0'/[1H:70-105,90-120,88,69,70-75;]";
        let typeindex = "1H";
        let result = get_typeindex_indices(advanced_extended_derivatonpath, typeindex, 0);
        println!("Result for Array: {:?}", result);
        match result {
            Ok(value) => assert_eq!(
                value,
                (69..=120).collect::<Vec<u32>>(),
                "Parsing typeindex {} failed",
                typeindex
            ),
            Err(e) => panic!("Parsing typeindex {} failed: {:?}", typeindex, e),
        }

        let advanced_extended_derivatonpath = "m/69'/0'/0'/[2':70-105,90-120,88,69,70-75;]";
        let typeindex = "2'";
        let result = get_typeindex_indices(advanced_extended_derivatonpath, typeindex, 0);
        println!("Result for Array: {:?}", result);
        match result {
            Ok(value) => assert_eq!(
                value,
                (69..=120).collect::<Vec<u32>>(),
                "Parsing typeindex {} failed",
                typeindex
            ),
            Err(e) => panic!("Parsing typeindex {} failed: {:?}", typeindex, e),
        }


        let advanced_extended_derivatonpath = "m/69'/0'/0'/[3h:70-105,90-120,88,69,70-75;]";
        let typeindex = "3h";
        let gap_limit = 0;
        let result = get_typeindex_indices(advanced_extended_derivatonpath, typeindex, gap_limit);
        println!("Result for Array: {:?}", result);
        match result {
            Ok(value) => assert_eq!(
                value,
                (69..=120).collect::<Vec<u32>>(),
                "Parsing typeindex {} failed",
                typeindex
            ),
            Err(e) => panic!("Parsing typeindex {} failed: {:?}", typeindex, e),
        }


    }

    ///  
    // const EXTENDED_KEY : &str = "xprv9s21ZrQH143K3XVnYZ9RtEiFWodPvMz3SCRt8nWzTx6zS9mJfTpLStJrNa2Bd9v8kwFdDJkWizK62FBmRGDW8MEZciMBzw3zMwZcXophEF6";
    // const ADVANCED_EXTENDED_DERIVATIONPATH : &str = "m/69'/0'/0'/[0:70-105,90-120,88,69,70-75;]";
    // const TYPEINDEX : &str = "0";
    // const NETWORK : Network = crate::network::Network::Mainnet;
    
    ////
    #[test]
    fn test_get_unused_address() -> Result<()> {
        // Mock inputs
        let extended_key = "xprv9s21ZrQH143K3XVnYZ9RtEiFWodPvMz3SCRt8nWzTx6zS9mJfTpLStJrNa2Bd9v8kwFdDJkWizK62FBmRGDW8MEZciMBzw3zMwZcXophEF6"; // xpriv, no xpub
        let extended_derivation_path = "m/44'/0'/0'/[0:70-105;1:30;2:0,1,2,3,4,5,6,7;3:0;]";
        let shorted_derivation_path = "path/[0:70-105;1:30;2:0,1,2,3,4,5,6,7;3:0;]";
        let type_index = "0";
        let gap_limit = 20;

        // Test case 1: pk_or_bitcoin_address = true (returns hex-encoded public key)
        {
            let result = get_unused_address(
                extended_key,
                extended_derivation_path,
                type_index,
                gap_limit,
                Network::Mainnet,
            )?;
            // Verify the result is a valid hex string
            assert!(
                hex::decode(&result).is_ok(),
                "Public key should be a valid hex string"
            );
            // Compressed public key should be 66 characters (33 bytes * 2 for hex)
            assert_eq!(
                result.len(),
                66,
                "Public key should be 66 characters (compressed key)"
            );
            // Check if it starts with "02" or "03" (compressed public key prefix)
            assert!(
                result.starts_with(b"02") || result.starts_with(b"03"),
                "Public key should start with '02' or '03' for compressed key"
            );

            println!("Mainnet Compressed Public Key {:?}", result);
        }

        // Test case 2: pk_or_bitcoin_address = false (returns Mainnet P2PKH address)
        {
            let result = get_unused_address(
                extended_key,
                extended_derivation_path,
                type_index,
                gap_limit,
                Network::Mainnet,
            )?;
            // Verify the address is valid Base58Check
            let decoded = result
                .to_base58();
            assert_eq!(
                decoded.len(),
                25,
                "P2PKH address should decode to 25 bytes"
            );
            // Use decode_address to validate checksum and version
            let (version, _) = decode_address(&decoded)?;
            // Check version byte matches Mainnet P2PKH
            assert_eq!(
                version,
                constants::MAINNET_P2PKH_VERSION,
                "Address version should match Mainnet P2PKH"
            );
            // Check address starts with '1' for Mainnet P2PKH
            assert!(
                result.starts_with(b"1"),
                "Mainnet P2PKH address should start with '1'"
            );

            println!("Mainnet P2PKH address {:?}", result);
        }

        // Test case 3: Testnet address (pk_or_bitcoin_address = false)
        // {
        //     let result = get_unused_address(
        //         extended_key,
        //         extended_derivation_path,
        //         type_index,
        //         Network::Testnet,
        //         gap_limit,
        //         false, // Return P2PKH address
        //     )?;
        //     // Verify the address is valid Base58Check
        //     let decoded = result
        //         .from_base58()
        //         .map_err(|e| Error::FromBase58Error(e))?;
        //     assert_eq!(
        //         decoded.len(),
        //         25,
        //         "P2PKH address should decode to 25 bytes"
        //     );
        //     // Use decode_address to validate checksum and version
        //     let (version, _) = decode_address(&result)?;
        //     // Check version byte matches Testnet P2PKH
        //     assert_eq!(
        //         version,
        //         constants::TESTNET_P2PKH_VERSION,
        //         "Address version should match Testnet P2PKH"
        //     );
        //     // Check address starts with 'm' or 'n' for Testnet P2PKH
        //     assert!(
        //         result.starts_with("m") || result.starts_with("n"),
        //         "Testnet P2PKH address should start with 'm' or 'n'"
        //     );
        // }

        // Test case 1.path: pk_or_bitcoin_address = true (returns hex-encoded public key)
        {
            let result = get_unused_address(
                extended_key,
                shorted_derivation_path,
                type_index,
                gap_limit,
                Network::Mainnet,
            )?;
            // Verify the result is a valid hex string
            assert!(
                hex::decode(&result).is_ok(),
                "Public key should be a valid hex string"
            );
            // Compressed public key should be 66 characters (33 bytes * 2 for hex)
            assert_eq!(
                result.len(),
                66,
                "Public key should be 66 characters (compressed key)"
            );
            // Check if it starts with "02" or "03" (compressed public key prefix)
            assert!(
                result.starts_with(b"02") || result.starts_with(b"03"),
                "Public key should start with '02' or '03' for compressed key"
            );

            println!("Mainnet Compressed Public Key {:?}", result);
        }

        // Test case 2.path: pk_or_bitcoin_address = false (returns Mainnet P2PKH address)
        {
            let result = get_unused_address(
                extended_key,
                shorted_derivation_path,
                type_index,
                gap_limit,
                Network::Mainnet,
            )?;
            // Verify the address is valid Base58Check
            let decoded = result
                .to_base58();
            assert_eq!(
                decoded.len(),
                25,
                "P2PKH address should decode to 25 bytes"
            );
            // Use decode_address to validate checksum and version
            let (version, _) = crate::wallet::adressing::decode_address(&decoded)?;
            // Check version byte matches Mainnet P2PKH
            assert_eq!(
                version,
                constants::MAINNET_P2PKH_VERSION,
                "Address version should match Mainnet P2PKH"
            );
            // Check address starts with '1' for Mainnet P2PKH
            assert!(
                result.starts_with(b"1"),
                "Mainnet P2PKH address should start with '1'"
            );

            println!("Mainnet P2PKH address {:?}", result);
        }

        Ok(())
    }

    #[test]
    fn generate_pubkey_hash() {
        let (extended_key, extended_derivationpath, type_index, _gap_limit, network, _amount, _fee_rate, _confirmation_selection, _locktime) = crate::user::get_userdatatuple();
        let basepath = exclude_brackets(extended_derivationpath);
        let keypair = derive_seed_or_extended_key(extended_key, &basepath, network)
            .expect("Failed to derive keypair");

        let path_2 = format!("path/{}/{}", type_index, 76);
        let keypair_2 = derive_seed_or_extended_key(&keypair.extended_private_key, &path_2, network)
            .expect("Failed to derive keypair 2");
        // Use get_public_key_bytes from ExtendedKeypair
        let pubkey_bytes = keypair_2.get_public_key_bytes().unwrap();
        let pubkey_hex = hex::encode(&pubkey_bytes); // Convert bytes to hex string
        println!("Pubkey Hex: {}", pubkey_hex);
        
        // Generate pubkey hash
        let pubkey_hash = mahrustsv::util::hash160(&pubkey_bytes);
        let pubkey_hash_hex = hex::encode(&pubkey_hash.0[..]);
        println!("Pubkey Hash: {}", pubkey_hash_hex);
        println!("Length Bitails Scripthash: {:?}", pubkey_hash_hex.len());

        let expected_hash_hex = "9c19bac28bd509e98b112e669804375ce0de5bb4";
        let expected_hash = hex::decode(expected_hash_hex).expect("Failed to decode hex");
        assert_eq!(&pubkey_hash.0[..], expected_hash);
    }

    #[test]
    fn test_reformat_derivation_path() {
        // Test valid cases
        assert_eq!(
            reformat_derivation_path("m/44/0/0/[0:76,103,104]").unwrap(),
            "m/[0:76,103,104]"
        );
        // assert_eq!(
        //     reformat_derivation_path("path/44/0/0/[0:76,103,104]").unwrap(),
        //     "path/[0:76,103,104]"
        // );
        
        // Test invalid cases
        assert!(reformat_derivation_path("invalid").is_err());
        assert!(reformat_derivation_path("m/44/0/0").is_err());
        assert!(reformat_derivation_path("x/44/0/0/[0:76,103,104]").is_err());
        assert!(reformat_derivation_path("path/44/0/0").is_err());
    }

    #[test]
    fn test_reformat_derivation_path_with_semicolon() {
        let input = "m/44/0/0/[0:76,103,104;]";
        let result = reformat_derivation_path(input).unwrap();
        assert_eq!(result, "m/[0:76,103,104;]");
    }
}
