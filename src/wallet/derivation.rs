// Implements BIP32

use ring::hmac::{self as ring_hmac};
use ring::digest;
use secp256k1::{Secp256k1, SecretKey, PublicKey, Message};
use base58::{FromBase58,ToBase58};
use ripemd::{Ripemd160, Digest};
use crate::network::Network;
use crate::util::{sha256d, Error, Hash256, Result};

pub mod constants {
    pub const HARDENED_KEY_OFFSET: u32 = 0x80000000;
}

#[derive(Debug, PartialEq)]
pub enum ExtendedKeyType {
    Private,
    Public,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ExtendedKeypair {
    pub extended_private_key: String,
    pub extended_public_key: String,
    pub private_key: Option<Vec<u8>>, // Optional, as public-only keypairs won't have this
    pub public_key: Vec<u8>,          // Compressed public key (33 bytes)
}

#[derive(Debug, Clone, PartialEq)]
pub enum KeyForm {
    Bytes,
    Hex,
}
impl ExtendedKeypair {
    // Constructor for creating an ExtendedKeypair
    pub fn new(extended_private_key: String, extended_public_key: String) -> Result<Self> {
        let (private_key, public_key) = if !extended_private_key.is_empty() {
            // Decode the extended private key to get the private key bytes
            let extended_key_obj = ExtendedKey::decode(&extended_private_key)?;
            let bip32_key = extended_key_obj.to_bip32_keyobject()?;
            let priv_key = bip32_key.get_private_key();
            let pub_key = bip32_key.get_public_key();
            (Some(priv_key), pub_key)
        } else if !extended_public_key.is_empty() {
            // Decode the extended public key to get the public key bytes
            let extended_key_obj = ExtendedKey::decode(&extended_public_key)?;
            let bip32_key = extended_key_obj.to_bip32_keyobject()?;
            (None, bip32_key.get_public_key())
        } else {
            return Err(Error::Bip32Error("Both extended keys cannot be empty".to_string()));
        };

        Ok(ExtendedKeypair {
            extended_private_key,
            extended_public_key,
            private_key,
            public_key,
        })
    }

    // Encode the keypair (e.g., return xprv/tprv or xpub/tpub based on network and type)
    pub fn encode(&self, is_private: bool) -> &str {
        if is_private {
            &self.extended_private_key
        } else {
            &self.extended_public_key
        }
    }

    // Decode from a string (xprv/tprv or xpub/tpub)
    pub fn decode(s: &str, network: Network) -> Result<Self> {
        let (private_key, public_key, extended_private_key, extended_public_key) = if s.starts_with("xprv") && network == Network::Mainnet {
            let extended_key_obj = ExtendedKey::decode(s)?;
            let bip32_key = extended_key_obj.to_bip32_keyobject()?;
            let priv_key = bip32_key.get_private_key();
            let pub_key = bip32_key.get_public_key();
            (Some(priv_key), pub_key, s.to_string(), String::new())
        } else if s.starts_with("tprv") && network == Network::Testnet {
            let extended_key_obj = ExtendedKey::decode(s)?;
            let bip32_key = extended_key_obj.to_bip32_keyobject()?;
            let priv_key = bip32_key.get_private_key();
            let pub_key = bip32_key.get_public_key();
            (Some(priv_key), pub_key, s.to_string(), String::new())
        } else if s.starts_with("xpub") && network == Network::Mainnet {
            let extended_key_obj = ExtendedKey::decode(s)?;
            let bip32_key = extended_key_obj.to_bip32_keyobject()?;
            (None, bip32_key.get_public_key(), String::new(), s.to_string())
        } else if s.starts_with("tpub") && network == Network::Testnet {
            let extended_key_obj = ExtendedKey::decode(s)?;
            let bip32_key = extended_key_obj.to_bip32_keyobject()?;
            (None, bip32_key.get_public_key(), String::new(), s.to_string())
        } else {
            return Err(Error::Bip32Error("Invalid extended key or network mismatch".to_string()));
        };

        Ok(ExtendedKeypair {
            extended_private_key,
            extended_public_key,
            private_key,
            public_key,
        })
    }

    // Get version bytes for serialization based on the extended key string
    pub fn get_version_bytes(extended_key: &str) -> Result<[u8; 4]> {
        match extended_key {
            s if s.starts_with("xprv") => Ok([0x04, 0x88, 0xad, 0xe4]), // xprv (Mainnet, private)
            s if s.starts_with("xpub") => Ok([0x04, 0x88, 0xb2, 0x1e]), // xpub (Mainnet, public)
            s if s.starts_with("tprv") => Ok([0x04, 0x35, 0x83, 0x94]), // tprv (Testnet, private)
            s if s.starts_with("tpub") => Ok([0x04, 0x35, 0x87, 0xcf]), // tpub (Testnet, public)
            _ => Err(Error::Bip32Error("Invalid extended key prefix".to_string())),
        }
    }

    // Set version bytes for serialization
    pub fn set_version_bytes(network: Network, is_private: bool) -> [u8; 4] {
        match (network, is_private) {
            (Network::Mainnet, true) => [0x04, 0x88, 0xad, 0xe4], // xprv
            (Network::Mainnet, false) => [0x04, 0x88, 0xb2, 0x1e], // xpub
            (Network::Testnet, true) => [0x04, 0x35, 0x83, 0x94], // tprv
            (Network::Testnet, false) => [0x04, 0x35, 0x87, 0xcf], // tpub
            (Network::STN, true) => [0x04, 0x35, 0x83, 0x94], // tprv
            (Network::STN, false) => [0x04, 0x35, 0x87, 0xcf], // tpub
        }
    }
    
    // Get key as bytes
    pub fn get_key_bytes(&self, is_private: bool) -> Result<Vec<u8>> {
        let (key_str, key_type) = if is_private {
            (&self.extended_private_key, "private")
        } else {
            (&self.extended_public_key, "public")
        };

        if is_private && key_str.is_empty() {
            return Ok(vec![]);
        }

        let extended_key_obj = ExtendedKey::decode(key_str).map_err(|e| {
            Error::Bip32Error(format!("Failed to decode extended {} key: {}", key_type, e))
        })?;
        let bip32_key = extended_key_obj.to_bip32_keyobject().map_err(|e| {
            Error::Bip32Error(format!("Failed to convert to BIP-32 key object for {} key: {}", key_type, e))
        })?;

        Ok(if is_private {
            bip32_key.get_private_key()
        } else {
            bip32_key.get_public_key()
        })
    }

    // Get key as hex string
    pub fn get_key_hex(&self, is_private: bool) -> Result<String> {
        let key_bytes = self.get_key_bytes(is_private)?;
        Ok(hex::encode(key_bytes))
    }
    pub fn get_private_key(&self) -> Result<String> {
        let key = self.get_key_hex(true)?;
        Ok(key)
    }

    pub fn get_public_key(&self) -> Result<String> {
        let key = self.get_key_hex(false)?;
        Ok(key)
    }
    pub fn get_private_key_bytes(&self) -> Result<Vec<u8>> {
        self.get_key_bytes(true)
    }

    pub fn get_public_key_bytes(&self) -> Result<Vec<u8>> {
        self.get_key_bytes(false)
    }

    pub fn sign(&self, message: Hash256) -> Result<Vec<u8>> {
        let secp = Secp256k1::signing_only();
        let private_key = self.private_key.as_ref()
            .ok_or_else(|| Error::Bip32Error("No private key available for signing".to_string()))?;
        let mut private_key_array = [0u8; 32];
        private_key_array.copy_from_slice(private_key);
        let secret_key = SecretKey::from_byte_array(private_key_array)
            .map_err(|e| Error::Bip32Error(format!("Invalid private key: {}", e)))?;
        let msg = Message::from_digest(message.0); // Use message.0 to get [u8; 32]
        let signature = secp.sign_ecdsa(msg, &secret_key);
        Ok(signature.serialize_der().to_vec())
    }
}

/// Represents a BIP-32 extended key (private or public) as a simple 78 character long string
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtendedKey(pub [u8; 78]);

impl ExtendedKey {
    /// Converts an ExtendedKey String to a Bip32Key Object
    pub fn to_bip32_keyobject(&self) -> Result<Bip32Key> {
        let secp = Secp256k1::new();

        // Extract components from the 78-byte array
        let version: [u8; 4] = self.0[0..4].try_into().map_err(|_| {
            Error::Bip32Error("Invalid version bytes length".to_string())
        })?;
        let depth = self.0[4];
        let parent_fingerprint: [u8; 4] = self.0[5..9].try_into().map_err(|_| {
            Error::Bip32Error("Invalid parent fingerprint length".to_string())
        })?;
        let index: [u8; 4] = self.0[9..13].try_into().map_err(|_| {
            Error::Bip32Error("Invalid index length".to_string())
        })?;
        let chain_code: [u8; 32] = self.0[13..45].try_into().map_err(|_| {
            Error::Bip32Error("Invalid chain code length".to_string())
        })?;
        let key_data: [u8; 33] = self.0[45..78].try_into().map_err(|_| {
            Error::Bip32Error("Invalid key data length".to_string())
        })?;

        // Determine network and key type from version bytes
        let (network, is_private) = match version {
            [0x04, 0x88, 0xAD, 0xE4] => (Network::Mainnet, true),  // xprv
            [0x04, 0x88, 0xB2, 0x1E] => (Network::Mainnet, false), // xpub
            [0x04, 0x35, 0x83, 0x94] => (Network::Testnet, true),  // tprv
            [0x04, 0x35, 0x87, 0xCF] => (Network::Testnet, false), // tpub
            _ => return Err(Error::Bip32Error("Invalid version bytes".to_string())),
        };

        // Parse key data
        let (private_key, public_key) = if is_private {
            // For private keys, expect 0x00 followed by 32-byte private key
            if key_data[0] != 0 {
                return Err(Error::Bip32Error("Invalid private key prefix".to_string()));
            }
            let secret_key_bytes: [u8; 32] = key_data[1..33].try_into().map_err(|_| {
                Error::Bip32Error("Invalid private key length: expected 32 bytes".to_string())
            })?;
            let secret_key = SecretKey::from_byte_array(secret_key_bytes).map_err(|e| {
                Error::Bip32Error(format!("Invalid private key: {}", e))
            })?;
            let public_key = PublicKey::from_secret_key(&secp, &secret_key);
            (Some(secret_key), public_key)
        } else {
            // For public keys, expect 33-byte compressed public key
            let public_key = PublicKey::from_slice(&key_data).map_err(|e| {
                Error::Bip32Error(format!("Invalid public key: {}", e))
            })?;
            (None, public_key)
        };

        Ok(Bip32Key {
            private_key,
            public_key,
            network,
            version,
            chain_code,
            parent_fingerprint,
            depth,
            index,
        })
    }

    /// Returns the key data (private key or public key)
    pub fn key(&self) -> [u8; 33] {
        let mut key = [0u8; 33];
        key.copy_from_slice(&self.0[45..78]);
        key
    }

    /// Returns boolean if the key is private or not
    pub fn is_private(&self) -> Result<bool> {
        let version: [u8; 4] = self.0[0..4].try_into().map_err(|_| {
            Error::Bip32Error("Invalid version bytes length".to_string())
        })?;
        
        match version {
            [0x04, 0x88, 0xAD, 0xE4] => Ok(true),  // xprv
            [0x04, 0x35, 0x83, 0x94] => Ok(true),  // tprv
            [0x04, 0x88, 0xB2, 0x1E] => Ok(false), // xpub
            [0x04, 0x35, 0x87, 0xCF] => Ok(false), // tpub
            _ => Err(Error::Bip32Error("Invalid version bytes".to_string())),
        }
    }

    /// Returns network type and Extended Key Type
    pub fn check_keytype(&self) -> Result<(Network, ExtendedKeyType)> {
        let version: [u8; 4] = self.0[0..4].try_into().map_err(|_| {
            Error::Bip32Error("Invalid version bytes length".to_string())
        })?;
        
        match version {
            [0x04, 0x88, 0xAD, 0xE4] => Ok((Network::Mainnet, ExtendedKeyType::Private)),  // xprv
            [0x04, 0x88, 0xB2, 0x1E] => Ok((Network::Mainnet, ExtendedKeyType::Public)),   // xpub
            [0x04, 0x35, 0x83, 0x94] => Ok((Network::Testnet, ExtendedKeyType::Private)),  // tprv
            [0x04, 0x35, 0x87, 0xCF] => Ok((Network::Testnet, ExtendedKeyType::Public)),   // tpub
            _ => Err(Error::Bip32Error("Invalid version bytes".to_string())),
        }
    }

    /// Encodes an extended key into a base58 string
    pub fn encode(&self) -> Result<String> {
        base58_check_encode(&self.0)
    }


    /// Decodes an extended key from a base58 string
    pub fn decode(s: &str) -> Result<ExtendedKey> {
        let data = s.from_base58().map_err(|e| Error::Bip32Error(format!("Base58 decode error: {:?}", e)))?;
        if data.len() != 82 {
            return Err(Error::Bip32Error(format!("Invalid extended key length: {}", data.len())));
        }
        let payload = &data[..78];
        let checksum = &data[78..82];
        let computed_checksum = sha256d(payload);
        if checksum != &computed_checksum.0[..4] {
            return Err(Error::Bip32Error("Invalid checksum".to_string()));
        }
        let mut extended_key = ExtendedKey([0; 78]);
        extended_key.0.copy_from_slice(payload);
        Ok(extended_key)
    }

    
    pub fn get_private_key(xprv: &str) -> Result<[u8; 32]> {
        let decoded = xprv.from_base58()
            .map_err(|e| Error::Bip32Error(format!("Base58 decode error: {:?}", e)))?;

        if decoded.len() != 82 {
            return Err(Error::Bip32Error(format!("Invalid extended key length: {}", decoded.len())));
        }
        
        let payload = &decoded[..78];
        let checksum = &decoded[78..82];
        let computed_checksum = sha256d(payload);
        if checksum != &computed_checksum.0[..4] {
            return Err(Error::Bip32Error("Invalid checksum".to_string()));
        }

        if payload[45] != 0 {
            return Err(Error::Bip32Error("Invalid private key prefix".to_string()));
        }
        // The private key is in bytes 46..78 (last 32 bytes of the payload)
        let key_bytes: [u8; 32] = decoded[46..78]
            .try_into()
            .map_err(|_| Error::Bip32Error("Failed to extract 32-byte private key".to_string()))?;

        Ok(key_bytes)
    }

    // Convert an xpriv or xpub to a secp256k1::PublicKey
    pub fn get_public_key(extended_key: &str) -> Result<[u8; 33]> {
        let decoded = extended_key
        .from_base58()
        .map_err(|e| Error::Bip32Error(format!("Base58 decode error: {:?}", e)))?;
    
    if decoded.len() != 82 {
        return Err(Error::Bip32Error(format!("Invalid extended key length: {}", decoded.len())));
    }
    
    let payload = &decoded[..78];
    let checksum = &decoded[78..82];
    let computed_checksum = sha256d(payload);
    if checksum != &computed_checksum.0[..4] {
        return Err(Error::Bip32Error("Invalid checksum".to_string()));
    }
    
    if extended_key.starts_with("xprv") {
        // For xpriv, check private key prefix and derive public key from private key
        if decoded[45] != 0 {
            return Err(Error::Bip32Error("Invalid private key prefix".to_string()));
        }
        let key_bytes: [u8; 32] = decoded[46..78]
        .try_into()
        .map_err(|_| Error::Bip32Error("Failed to extract 32-byte private key".to_string()))?;
        let secret_key = SecretKey::from_byte_array(key_bytes)
        .map_err(|e| Error::Bip32Error(format!("Invalid private key: {}", e)))?;
            let secp = Secp256k1::signing_only();
            let public_key = PublicKey::from_secret_key(&secp, &secret_key);
            Ok(public_key.serialize())
        } else if extended_key.starts_with("xpub") {
            // For xpub, extract 33-byte compressed public key from bytes 45..78
            let pubkey_bytes: [u8; 33] = decoded[45..78]
                .try_into()
                .map_err(|_| Error::Bip32Error("Failed to extract 33-byte public key".to_string()))?;
            // Validate the public key
            PublicKey::from_slice(&pubkey_bytes)
                .map_err(|e| Error::Bip32Error(format!("Invalid public key: {}", e)))?;
            Ok(pubkey_bytes)
        } else {
            Err(Error::Bip32Error("Extended key must be xpriv or xpub".to_string()))
        }
    }
}

#[derive(Debug)]
pub struct Bip32Key {
    private_key: Option<SecretKey>,
    public_key: PublicKey,
    network: Network,
    version: [u8;4],
    chain_code: [u8; 32],
    parent_fingerprint: [u8; 4],
    depth: u8,
    index: [u8; 4],
}

impl Bip32Key {
    pub fn get_private_key(&self) -> Vec<u8> {
        self.private_key.as_ref().map(|pk| pk[..].to_vec()).unwrap_or_default()
    }

    pub fn get_public_key(&self) -> Vec<u8> {
        self.public_key.serialize().to_vec()
    }

    pub fn get_network(&self) -> Network {
        self.network
    }

    pub fn get_version(&self) -> [u8; 4] {
        self.version
    }

    pub fn get_chain_code(&self) -> [u8; 32] {
        self.chain_code
    }

    pub fn get_parent_fingerprint(&self) -> [u8; 4] {
        self.parent_fingerprint
    }

    pub fn get_depth(&self) -> u8 {
        self.depth
    }

    pub fn get_index(&self) -> [u8; 4] {
        self.index
    }
}

// Computes the fingerprint from a public key
fn compute_fingerprint(pubkey_bytes: &[u8]) -> [u8; 4] {
    let hash = digest::digest(&digest::SHA256, pubkey_bytes);
    let ripemd = Ripemd160::digest(&hash);
    let mut fingerprint = [0u8; 4];
    fingerprint.copy_from_slice(&ripemd[0..4]);
    fingerprint
}

fn base58_check_encode(data: &[u8]) -> Result<String> {
    // Example validation: xprv and xpub are typically 78 bytes before checksum
    if data.len() != 78 {
        return Err(Error::Bip32Error(format!("Invalid data length for base58check encoding: {}", data.len())));
    }
    let mut payload = Vec::new();
    payload.extend_from_slice(data);
    
    // Calculate checksum
    let hash = sha256d(&payload);
    payload.extend_from_slice(&hash.0[..4]);

    Ok(payload.to_base58())
}

// Validates and decodes a Base58Check-encoded extended key
fn decode_extended_key(input: &str) -> Result<(Vec<u8>, [u8; 4])> {
    let data = input
        .from_base58()
        .map_err(|e| Error::Bip32Error(format!("Invalid base58: {:?}", e)))?;
    if data.len() != 82 {
        return Err(Error::Bip32Error("Invalid extended key length".to_string()));
    }
    let payload = &data[..78];
    let checksum = &data[78..82];
    let hash = sha256d(payload);
    if checksum != &hash.0[..4] {
        return Err(Error::Bip32Error("Invalid checksum".to_string()));
    }
    let mut version = [0u8; 4];
    version.copy_from_slice(&data[0..4]);
    Ok((payload.to_vec(), version))
}

// Helper function for derive_seed_or_extended_key() that derives a child key from the current key
fn derive_child_key(
    private_key: &mut Option<SecretKey>,
    public_key: &mut Option<PublicKey>,
    chain_code: &mut [u8; 32],
    parent_fingerprint: &mut [u8; 4],
    depth: &mut u8,
    index: u32,
    hardened: bool,
) -> Result<()> {
    let secp = Secp256k1::new();
    if hardened && private_key.is_none() {
        return Err(Error::Bip32Error("Cannot derive hardened keys from public key".to_string()));
    }
    *depth = depth.checked_add(1).ok_or_else(|| Error::Bip32Error("Depth overflow".to_string()))?;

    let mut data = [0u8; 37];
    let pubkey = public_key.unwrap_or_else(|| PublicKey::from_secret_key(&secp, private_key.as_ref().unwrap()));
    let pubkey_bytes = pubkey.serialize();
    if hardened {
        data[0] = 0;
        data[1..33].copy_from_slice(&private_key.as_ref().unwrap()[..]);
    } else {
        data[0..33].copy_from_slice(&pubkey_bytes);
    }
    data[33..37].copy_from_slice(&index.to_be_bytes());

    let key = ring_hmac::Key::new(ring_hmac::HMAC_SHA512, chain_code);
    let i = ring_hmac::sign(&key, &data).as_ref().to_vec();
    let (il, ir) = i.split_at(32);

    if private_key.is_some() {
        let tweak = SecretKey::from_byte_array(il.try_into().map_err(|_| Error::Bip32Error("Invalid child private key length".to_string()))?)
            .map_err(|e| Error::Bip32Error(format!("Invalid child private key: {}", e)))?;
        let new_private_key = private_key.unwrap()
            .add_tweak(&tweak.into())
            .map_err(|_| Error::Bip32Error("Private key tweak overflow".to_string()))?;
        *private_key = Some(new_private_key);
        *public_key = Some(PublicKey::from_secret_key(&secp, private_key.as_ref().unwrap()));
    } else {
        let tweak = SecretKey::from_byte_array(il.try_into().map_err(|_| Error::Bip32Error("Invalid tweak length".to_string()))?)
            .map_err(|e| Error::Bip32Error(format!("Invalid tweak: {}", e)))?;
        *public_key = Some(public_key.unwrap()
            .add_exp_tweak(&secp, &tweak.into())
            .map_err(|_| Error::Bip32Error("Public key tweak overflow".to_string()))?);
    }

    chain_code.copy_from_slice(ir);
    *parent_fingerprint = compute_fingerprint(&pubkey_bytes);

    Ok(())
}

// Normalize path: convert "m" or Empty String into "m/" else add / at the end if not
fn normalize_path(derivation_path: &str) -> Result<String> {

    let normalized_path_2 = if derivation_path.is_empty() {
        "m/".to_string()
    } else if derivation_path.ends_with("]") {
        "m/".to_string()
    } else if !derivation_path.ends_with('/') {
    format!("{}/", derivation_path)
    } else {
        derivation_path.to_string()
    };
    
    // println!("DEBUG - normalized_path_2: {}", normalized_path_2);

    // Convert path starting with "path/" to start with "m/"
    let normalized_path = if normalized_path_2.starts_with("path/") {
        format!("m/{}", &normalized_path_2[5..])
    } else {
        normalized_path_2.clone()
    };

    // Validate path
    if !normalized_path.is_empty() && !normalized_path.starts_with("m/") {
        return Err(Error::Bip32Error("Path must start with 'm/'".to_string()));
    }
    let re = regex::Regex::new(r"^m(/(\d+[']?))*/?$").map_err(|e| Error::Bip32Error(format!("Regex error: {}", e)))?;
    if !normalized_path.is_empty() && !re.is_match(&normalized_path) {
        return Err(Error::Bip32Error("Invalid derivation path format".to_string()));
    }

    // println!("DEBUG - normalized_path: {}", normalized_path);
    Ok(normalized_path)
}

/// Powerful function that handles bascially everything you need
/// Converts Extended Derivation Path into Normal Derivationpath
pub fn derive_seed_or_extended_key(
    input: &str,
    derivation_path: &str,
    network: Network,
) -> Result<ExtendedKeypair> {
    
    // INIT
    let secp = Secp256k1::new();
    let mut depth: u8 = 0;
    let mut parent_index: [u8; 4] = [0; 4];
    let mut child_number: [u8; 4] = [0; 4];
    let mut private_key: Option<SecretKey> = None;
    let mut public_key: Option<PublicKey> = None;
    let mut chain_code: [u8; 32] = [0; 32]; // Initialize chain_code to zeros
    let mut parent_fingerprint: [u8; 4] = [0; 4];

    // Normalize derivation path
    let normalized_path = normalize_path(derivation_path)?;

    // Determine if input is a seed (hex) or extended key (xprv/xpub/tprv/tpub)

    let is_extended_key = input.starts_with("xprv") || input.starts_with("xpub") || input.starts_with("tprv") || input.starts_with("tpub");
    if is_extended_key {
    // Decode and validate extended key
    let (data, version) = decode_extended_key(input)?;
    depth = data[4];
    parent_fingerprint.copy_from_slice(&data[5..9]);
    parent_index.copy_from_slice(&data[9..13]);
    chain_code.copy_from_slice(&data[13..45]);

    // Check if it's a private or public key
    let is_private = version == ExtendedKeypair::set_version_bytes(network, true);
    if is_private {
        // Private key: data[45] is 0x00, followed by 32-byte private key
        if data[45] != 0 {
            return Err(Error::Bip32Error("Invalid private key prefix".to_string()));
        }       
        private_key = Some(SecretKey::from_byte_array(
            data[46..78]
                .try_into()
                .map_err(|e| Error::Bip32Error(format!("Invalid private key length: {}", e)))?,
        )
        .map_err(|e| Error::Bip32Error(format!("Invalid private key: {}", e)))?);
        public_key = Some(PublicKey::from_secret_key(&secp, private_key.as_ref().unwrap()));
    } else {
        public_key = Some(PublicKey::from_byte_array_compressed(
            data[45..78]
                .try_into()
                .map_err(|e| Error::Bip32Error(format!("Invalid public key length: {}", e)))?,
        )
        .map_err(|e| Error::Bip32Error(format!("Invalid public key: {}", e)))?);
    }
    // Return input key if path is "m" or empty
    if normalized_path == "m/" || normalized_path == "path/" || normalized_path.is_empty() {
        let extended_public_key = if !is_private {
            input.to_string()
        } else {
            let mut xpub_data = Vec::new();
            xpub_data.extend_from_slice(&ExtendedKeypair::set_version_bytes(network, false));
            xpub_data.push(depth);
            xpub_data.extend_from_slice(&parent_fingerprint);
            xpub_data.extend_from_slice(&parent_index);
            xpub_data.extend_from_slice(&chain_code);
            xpub_data.extend_from_slice(&public_key.unwrap().serialize());
            base58_check_encode(&xpub_data)?
        };
        return Ok(ExtendedKeypair {
            extended_private_key: if is_private { input.to_string() } else { String::new() },
            extended_public_key,
            private_key: private_key.map(|pk| pk[..].to_vec()),
            public_key: public_key.unwrap().serialize().to_vec(),
        });
    }
} else {
    // Assume input is a hex seed
    let seed = hex::decode(input)
        .map_err(|e| Error::Bip32Error(format!("Invalid hex seed: {}", e)))?;
    // Validate seed length (BIP-32 recommends 128-512 bits, i.e., 16-64 bytes)
    if seed.len() < 16 || seed.len() > 64 {
        println!("{:?}", &seed);
        return Err(Error::Bip32Error("Invalid seed length".to_string()));
    } 

    // Derive master key using HMAC-SHA512 with key "Bitcoin seed"
    let key = ring_hmac::Key::new(ring_hmac::HMAC_SHA512, b"Bitcoin seed");
    let i = ring_hmac::sign(&key, &seed).as_ref().to_vec();

    // Split into IL (private key) and IR (chain code)
    let (il, ir) = i.split_at(32);

    private_key = Some(SecretKey::from_byte_array(
        il.try_into()
            .map_err(|e| Error::Bip32Error(format!("Invalid private key length: {}", e)))?,
    )
    .map_err(|e| Error::Bip32Error(format!("Invalid private key: {}", e)))?);
    chain_code.copy_from_slice(ir);
    parent_fingerprint = [0; 4]; // Master key has no parent
}

// Process derivation path
let path_parts: Vec<&str> = normalized_path.trim_start_matches("m/").trim_end_matches('/').split('/').filter(|s| !s.is_empty()).collect();
for part in path_parts {
    if part.is_empty() {
        return Err(Error::Bip32Error("Empty path segment".to_string()));
    }
    let hardened = part.ends_with("'");
    let index_str = part.trim_end_matches("'");
    if index_str.is_empty() || index_str.chars().any(|c| !c.is_digit(10)) {
        return Err(Error::Bip32Error(format!("Invalid path index: {}", part)));
    }
    let index: u32 = index_str.parse().map_err(|_| Error::Bip32Error(format!("Invalid path index: {}", part)))?;
    if index > 0x7FFFFFFF && !hardened {
        return Err(Error::Bip32Error(format!("Non-hardened index {} exceeds maximum (2^31-1)", index)));
    }
    child_number = index.to_be_bytes();

    derive_child_key(
        &mut private_key,
        &mut public_key,
        &mut chain_code,
        &mut parent_fingerprint,
        &mut depth,
        index,
        hardened,
    )?;
        
    }
    
    // Serialize extended public key (xpub/tpub)
    let xpub_version = ExtendedKeypair::set_version_bytes(network, false);
    let mut xpub_data = Vec::new();
    xpub_data.extend_from_slice(&xpub_version);
    xpub_data.push(depth);
    xpub_data.extend_from_slice(&parent_fingerprint);
    xpub_data.extend_from_slice(&child_number);
    xpub_data.extend_from_slice(&chain_code);
    let pubkey = public_key.unwrap_or_else(|| PublicKey::from_secret_key(&secp, private_key.as_ref().unwrap()));
    xpub_data.extend_from_slice(&pubkey.serialize());
    let extended_public_key = base58_check_encode(&xpub_data)?;

    // Serialize extended private key (xprv) if available
    let extended_private_key = if let Some(pk) = private_key {
        let xprv_version = ExtendedKeypair::set_version_bytes(network, true);
        let mut xprv_data = Vec::new();
        xprv_data.extend_from_slice(&xprv_version);
        xprv_data.push(depth);
        xprv_data.extend_from_slice(&parent_fingerprint);
        xprv_data.extend_from_slice(&child_number);
        xprv_data.extend_from_slice(&chain_code);
        xprv_data.push(0);
        xprv_data.extend_from_slice(&pk[..]);
        base58_check_encode(&xprv_data)?
    } else {
        String::new()
    };
            
    Ok(ExtendedKeypair {
        extended_private_key,
        extended_public_key,
        private_key: private_key.map(|pk| pk[..].to_vec()),
        public_key: pubkey.serialize().to_vec(),
    })
}


#[cfg(test)]
mod tests {
    use crate::wallet::derivation::*;

    const SEED: &str = "697fce933855df6dc5f0490c8370157af5af4af1b5f20d5c6ec7f5c1d04b859e2389bdf68fd956fd9dede46d9aa9af114b23cec6a69c8905e84c2e6376e19eb7";
    const EXPECTED_MASTER_PRIV: &str = "xprv9s21ZrQH143K4aC15QhGLbgXYMdLskEFQ3rJ8ucq8uPE5zqoih5rSUWALU2CrgbGAQxiApmw6tE3DUgm7G2Ns2CPusPkfNKLJE7LX9TVoTs";
    // const EXPECTED_MASTER_PUB: &str = "xpub661MyMwAqRbcG1aFeagSFNez4qTtKphtoRMUwAvc2HdyJx6TD18azgdLDqNQNxxb9So1MEfG8oRn2ryuzCB4GFt87Lhh5wWy9r5g6xEVdrD";

    /// You need to know the derivation path from the master xpriv for this
    const EXPECTED_CHILD_PRIV : &str = "xprv9zPYpnKVEEdo5PJuiPNM3LjjZuJqnUd5CQ14MHr7aa26GWHDQpua1HMyJsnWg3unmmsBEQwDQPMfkDB3TtaNM6Ao4G5dGJzZzDYMWFe33LW";

    #[test]
    fn test_master_xpriv_from_seed()  -> Result<()> {
        let master_keypair_1 = derive_seed_or_extended_key(SEED, "", Network::Mainnet);
        assert_eq!(
            master_keypair_1.unwrap().extended_private_key,
            EXPECTED_MASTER_PRIV
        );

        let master_keypair_2 = derive_seed_or_extended_key(SEED, "m", Network::Mainnet);
        assert_eq!(
            master_keypair_2.unwrap().extended_private_key,
            EXPECTED_MASTER_PRIV
        );

        let master_keypair_3 = derive_seed_or_extended_key(SEED, "m/", Network::Mainnet);
        assert_eq!(
            master_keypair_3.unwrap().extended_private_key,
            EXPECTED_MASTER_PRIV
        );

        let master_keypair_4 = derive_seed_or_extended_key(EXPECTED_MASTER_PRIV, "", Network::Mainnet);
        assert_eq!(
            master_keypair_4.unwrap().extended_private_key,
            EXPECTED_MASTER_PRIV
        );

        let master_keypair_5 = derive_seed_or_extended_key(EXPECTED_MASTER_PRIV, "m", Network::Mainnet);
        assert_eq!(
            master_keypair_5.unwrap().extended_private_key,
            EXPECTED_MASTER_PRIV
        );

        let master_keypair_6 = derive_seed_or_extended_key(EXPECTED_MASTER_PRIV, "m/", Network::Mainnet);
        assert_eq!(
            master_keypair_6.unwrap().extended_private_key,
            EXPECTED_MASTER_PRIV
        );
        Ok(())
    }

    #[test]
    fn test_encode_decode() -> Result<()> {
        let network = Network::Testnet;
        let keypair = derive_seed_or_extended_key(SEED, "m/", network)?;

        for (is_private, label) in [(true, ExtendedKeyType::Private), (false, ExtendedKeyType::Public)] {
            let encoded = keypair.encode(is_private);
            println!("Encoded {:?} key: {:?}", label, encoded);

            let decoded = ExtendedKeypair::decode(&encoded, network)?;
            match is_private {
                true => {
                    println!("Decoded private key: {:?}", decoded.extended_private_key);
                    assert_eq!(keypair.extended_private_key, decoded.extended_private_key);
                }
                false => {
                    println!("Decoded public key:  {:?}", decoded.extended_public_key);
                    assert_eq!(keypair.extended_public_key, decoded.extended_public_key);
                }
            }
        }

        Ok(())
    }

    #[test]
    fn test_pubkey_from_xprv() -> Result<()> {
        let secp = Secp256k1::new();

        let private_key_arr = ExtendedKey::get_private_key(EXPECTED_MASTER_PRIV)?;
        println!("Private key: {:?}", private_key_arr);
        let secret_key = SecretKey::from_byte_array(private_key_arr)?;
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        println!("Public key: {}", hex::encode(public_key.serialize()));
        Ok(())
    }

    #[test]
    fn test_normal_private_derivation()  -> Result<()> {
        let child = derive_seed_or_extended_key(SEED,"m/0", Network::Mainnet)?;
        assert!(
            child.extended_private_key.starts_with("xprv"),
            "Expected private key version (xprv)"
        );
        Ok(())
    }

    #[test]
    fn test_unusual_but_valid_path_writings()  -> Result<()> {
        let master_keypair = derive_seed_or_extended_key(SEED, "", Network::Mainnet)?;
        let derived_keypair = derive_seed_or_extended_key(EXPECTED_MASTER_PRIV, "m/44/0/0/", Network::Mainnet)?;

        println!("Master  Keypair: {:?}", master_keypair);
        println!("Child   Keypair: {:?}", derived_keypair);

        assert_eq!(
            master_keypair.extended_private_key,
            EXPECTED_MASTER_PRIV,
            "Master key does not match expected value"
        );
        assert_eq!(
            derived_keypair.extended_private_key,
            EXPECTED_CHILD_PRIV,
            "Derived key does not match expected value"
        );
        assert!(
            derived_keypair.extended_private_key.starts_with("xprv"),
            "Expected private key version (xprv)"
        );

        Ok(())
    }

    #[test]
    fn test_derive_nonhardended_on_mainnet() -> Result<()> {
        let master_keypair = derive_seed_or_extended_key(SEED, "m/", Network::Mainnet)?;
        if master_keypair.extended_private_key != EXPECTED_MASTER_PRIV {
            println!("Master xprv dont match: {}", master_keypair.extended_private_key);
        }
        let derived_0 = derive_seed_or_extended_key(&master_keypair.extended_private_key, "m/", Network::Mainnet)?;
        if derived_0.extended_private_key != EXPECTED_MASTER_PRIV {
            println!("Derived xprv dont match: {}", derived_0.extended_private_key);
        }

        let derived_1 = derive_seed_or_extended_key(&master_keypair.extended_private_key, "m/44", Network::Mainnet)?;
        let expected_derived_1 = "xprv9vJrExfEY674BDfrZQHQwRJjGbm6ctqVq6jZfvNw4PKTjpPSvhrATjEkxUBkD7SNYV3r9hpjXDLW5NxirMDFSRXv546brK1zpaF8kBZb9bn"; // Replace with actual derived xprv
        if derived_1.extended_private_key != expected_derived_1 {
            println!("Derived xprv dont match: {}", expected_derived_1);
        }

        let derived_3 = derive_seed_or_extended_key(&master_keypair.extended_private_key, "m/44/0/0", Network::Mainnet)?;
        let expected_derived_3 = "xprv9zQBrJrMTvL2moMyWteT2YcUr5cad7RUUkXtgWyMpGStCCQq1EDXDU8YmnRUrxxx59TKKx4wEuSmS1Fm7QPBHxoAM7SFRG5H1A5xTeEi4Yw"; // Replace with actual derived xprv
        if derived_3.extended_private_key != expected_derived_3 {
            println!("Derived xprv dont match: {}", derived_3.extended_private_key);
        }

        assert_eq!(
            master_keypair.extended_private_key,
            EXPECTED_MASTER_PRIV,
            "Master key does not match expected value"
        );
        assert_eq!(
            derived_0.extended_private_key,
            EXPECTED_MASTER_PRIV,
            "Derived key does not match expected value"
        );

        Ok(())
    }

    #[test]
    fn test_derivation_step_by_step_mainnet() -> Result<()> {
        let master_keypair = derive_seed_or_extended_key(SEED, "m/", Network::Mainnet)?;
        assert_eq!(master_keypair.extended_private_key, EXPECTED_MASTER_PRIV, "Master key mismatch");

        let m = derive_seed_or_extended_key(&master_keypair.extended_private_key, "m/", Network::Mainnet)?;
        assert_eq!(m.extended_private_key, EXPECTED_MASTER_PRIV, "Master key mismatch");

        let m_44 = derive_seed_or_extended_key(&master_keypair.extended_private_key, "m/44", Network::Mainnet)?;
        println!("m/44 xprv: {}", m_44.extended_private_key);
        let m_44_0 = derive_seed_or_extended_key(&m_44.extended_private_key, "m/0", Network::Mainnet)?;
        println!("m/44/0 xprv: {}", m_44_0.extended_private_key);
        let derived = derive_seed_or_extended_key(&m_44_0.extended_private_key, "m/0", Network::Mainnet)?;
        println!("m/44/0/0 xprv: {}", derived.extended_private_key);

        // let correct_expected_derived = "xprv9zPYpnKVEEdo5PJuiPNM3LjjZuJqnUd5CQ14MHr7aa26GWHDQpua1HMyJsnWg3unmmsBEQwDQPMfkDB3TtaNM6Ao4G5dGJzZzDYMWFe33LW";
        // let uncorrect_expected_derived = "xprv9zKZ4Ycu1DUYWyJqPZLh9ZYiZs3K5kpvRHXoJCUSwNFwwKVbUVH5WNUg1SJdKJxFWo9X2KGBBhJXdNecQANJAidRXrN8Mju8LzQf4KmbebU";
        assert_eq!(derived.extended_private_key, EXPECTED_CHILD_PRIV, "Derived key mismatch");
        Ok(())
    }

    #[test]
    fn test_nonhardened_derivation_on_testnet() -> Result<()> {
        let master_keypair = derive_seed_or_extended_key(SEED, "m", Network::Testnet)?;
        let derived_keypair = derive_seed_or_extended_key(&master_keypair.extended_private_key, "m/44/0/0/", Network::Testnet)?;
        assert!(master_keypair.extended_private_key.starts_with("tprv"), "Expected testnet private key version (tprv)");
        assert!(derived_keypair.extended_private_key.starts_with("tprv"), "Expected testnet private key version (tprv)");
        Ok(())
    }



    // #[test]
    // fn test_hmac_manual()  -> Result<()> {
    //     let private_key = [
    //         232, 243, 46, 114, 61, 236, 244, 5, 26, 239, 172, 142, 44, 147, 201, 197, 178, 20, 49,
    //         56, 23, 205, 176, 26, 20, 148, 185, 23, 200, 67, 107, 53,
    //     ];
    //     let index = 0x80000000u32;
    //     let mut data = vec![0u8; 37]; // Pre-allocate 37 bytes
    //     data[0] = 0;
    //     data[1..33].copy_from_slice(&private_key[..32]);
    //     data[33..37].copy_from_slice(&index.to_be_bytes());
    //     assert_eq!(data.len(), 37, "HMAC data length should be 37 bytes");

    //     // Compute input checksum
    //     let input_checksum = Sha256::digest(&data);
    //     eprintln!(
    //         "HMAC input checksum: {}",
    //         hex::encode(input_checksum.to_vec())
    //     );

    //     // Compute HMAC with ring
    //     let hmac_key = ring_hmac::Key::new(ring_hmac::HMAC_SHA512, SEED.as_bytes());
    //     let result = ring_hmac::sign(&hmac_key, &data[..37]);
    //     let result_bytes = result.as_ref();
    //     eprintln!(
    //         "HMAC result: {} (len: {})",
    //         hex::encode(result_bytes),
    //         result_bytes.len()
    //     );

    //     assert_eq!(
    //         hex::encode(result_bytes),
    //         "04bfb2dd60fa8921c2a4085ec15507a921f49cdc839f27f0f280e9c1495d44b547fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"
    //     );
    //     Ok(())
    // }

    // #[test]
    // fn test_hmac()  -> Result<()> {
    //     let private_key = [
    //         232, 243, 46, 114, 61, 236, 244, 5, 26, 239, 172, 142, 44, 147, 201, 197, 178, 20, 49,
    //         56, 23, 205, 176, 26, 20, 148, 185, 23, 200, 67, 107, 53,
    //     ];
    //     let index = 0x80000000u32; // Hardened index
    //     let mut data = vec![0u8; 37]; // Pre-allocate 37 bytes
    //     data[0] = 0;
    //     data[1..33].copy_from_slice(&private_key[..32]);
    //     data[33..37].copy_from_slice(&index.to_be_bytes());
    //     assert_eq!(data.len(), 37, "HMAC data length should be 37 bytes");

    //     // Compute input checksum
    //     let input_checksum = Sha256::digest(&data);
    //     eprintln!(
    //         "HMAC input checksum: {}",
    //         hex::encode(input_checksum.to_vec())
    //     );

    //     // Compute HMAC with ring
    //     let hmac_key = ring_hmac::Key::new(ring_hmac::HMAC_SHA512, SEED.as_bytes());
    //     let result = ring_hmac::sign(&hmac_key, &data[..37]);
    //     let result_bytes = result.as_ref();
    //     eprintln!(
    //         "HMAC result: {} (len: {})",
    //         hex::encode(result_bytes),
    //         result_bytes.len()
    //     );

    //     assert_eq!(
    //         hex::encode(result_bytes),
    //         "04bfb2dd60fa8921c2a4085ec15507a921f49cdc839f27f0f280e9c1495d44b547fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"
    //     );
    //     Ok(())
    // }

    #[test]
    fn test_transform_path() -> Result<(), Error> {
        let input = "m/[0:103,104,105,106,107;]";
        let expected = "path/[0:103,104,105,106,107;]";
        let result = transform_path(input)?;
        assert_eq!(result, expected);

        let input = "m";
        let expected = "m";
        let result = transform_path(input)?;
        assert_eq!(result, expected);

        Ok(())
    }
}
