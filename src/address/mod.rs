//! Address encoding and decoding
//!
//! # Examples
//!
//! Extract the public key hash and address type from a base-58 address:
//!
//! ```rust
//! use sv::address::addr_decode;
//! use sv::network::Network;
//!
//! let addr = "15wpV72HRpAFPMmosR3jvGq7axU7t6ghX5";
//! let (pubkeyhash, addr_type) = addr_decode(&addr, Network::Mainnet).unwrap();
//! ```
//!
//! Encode a public key hash into a base-58 address:
//!
//! ```rust
//! use sv::address::{addr_encode, AddressType};
//! use sv::network::Network;
//! use sv::util::hash160;
//!
//! let pubkeyhash = hash160(&[0; 33]);
//! let addr = addr_encode(&pubkeyhash, AddressType::P2PKH, Network::Mainnet);
//! ```
//!
use crate::network::Network;
use crate::util::{sha256d, Error, Hash160, Result};
use bs58;

/// Address type which is either P2PKH or P2SH
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    /// Pay-to-public-key-hash address
    P2PKH,
    /// Pay-to-script-hash address
    P2SH,
}

/// Address structure holding bytes, type, and network
pub struct Address {
    bytes: Vec<u8>,
    addr_type: AddressType,
    network: Network,
}

impl Address {
    /// Encodes address bytes to base-58
    pub fn encode(&self) -> String {
        bs58::encode(&self.bytes).into_string()
    }

    /// Decodes a base-58 string to address bytes
    pub fn decode(input: &str) -> Result<Vec<u8>, bs58::decode::Error> {
        bs58::decode(input).into_vec()
    }
}

/// Converts a public key hash to its base-58 address
pub fn addr_encode(hash160: &Hash160, addr_type: AddressType, network: Network) -> String {
    let mut v = Vec::with_capacity(1 + hash160.0.len() + 4);
    v.push(match addr_type {
        AddressType::P2PKH => network.addr_pubkeyhash_flag(),
        AddressType::P2SH => network.addr_script_flag(),
    });
    v.extend_from_slice(&hash160.0);
    let checksum = sha256d(&v).0;
    v.extend_from_slice(&checksum[0..4]);
    bs58::encode(&v).into_string()
}

/// Decodes a base-58 address to a public key hash
pub fn addr_decode(input: &str, network: Network) -> Result<(Hash160, AddressType)> {
    let v = bs58::decode(input).into_vec()?;
    if v.len() < 6 {
        let msg = format!("Base58 address not long enough: {}", v.len());
        return Err(Error::BadData(msg));
    }

    // Verify checksum
    let v0 = &v[0..v.len() - 4];
    let v1 = &v[v.len() - 4..];
    let cs = sha256d(v0).0;
    if v1 != &cs[0..4] {
        let msg = format!("Bad checksum: {:?} != {:?}", &cs[..4], v1);
        return Err(Error::BadData(msg));
    }

    // Extract address type
    let addr_type_byte = v0[0];
    let addr_type = if addr_type_byte == network.addr_pubkeyhash_flag() {
        AddressType::P2PKH
    } else if addr_type_byte == network.addr_script_flag() {
        AddressType::P2SH
    } else {
        let msg = format!("Unknown address type {}", addr_type_byte);
        return Err(Error::BadData(msg));
    };

    // Extract hash160 address
    if v0.len() != 21 {
        let msg = format!("Hash160 address not long enough: {}", v0.len() - 1);
        return Err(Error::BadData(msg));
    }
    let mut hash160addr = [0; 20];
    hash160addr.copy_from_slice(&v0[1..]);
    Ok((Hash160(hash160addr), addr_type))
}

#[
