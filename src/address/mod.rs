//! Address encoding and decoding for Bitcoin SV
//!
//! This module provides functionality to encode and decode Bitcoin SV addresses
//! in base58 format, supporting P2PKH and P2SH address types.
//!
//! # Examples
//!
//! Extract the public key hash and address type from a base58 address:
//!
//! ```rust
//! use sv::address::addr_decode;
//! use sv::network::NetworkConfig;
//!
//! let addr = "15wpV72HRpAFPMmosR3jvGq7axU7t6ghX5";
//! let network = NetworkConfig::new(0).unwrap(); // Mainnet
//! let (pubkeyhash, addr_type) = addr_decode(&addr, network).unwrap();
//! ```
//!
//! Encode a public key hash into a base58 address:
//!
//! ```rust
//! use sv::address::{addr_encode, AddressType};
//! use sv::network::NetworkConfig;
//! use sv::util::hash160;
//!
//! let pubkeyhash = hash160(&[0; 33]);
//! let network = NetworkConfig::new(0).unwrap(); // Mainnet
//! let addr = addr_encode(&pubkeyhash, AddressType::P2PKH, network);
//! ```

use crate::network::NetworkConfig;
use crate::util::{sha256d, Error, Hash160, Result};
use base58;

/// Address type, either P2PKH or P2SH.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    /// Pay-to-public-key-hash address.
    P2PKH,
    /// Pay-to-script-hash address.
    P2SH,
}

/// Address structure holding bytes, type, and network.
#[derive(Debug, Clone, PartialEq)]
pub struct Address {
    bytes: Vec<u8>,
    addr_type: AddressType,
    network: NetworkConfig,
}

impl Address {
    /// Creates a new `Address` with the given bytes, type, and network.
    pub fn new(bytes: Vec<u8>, addr_type: AddressType, network: NetworkConfig) -> Self {
        Address { bytes, addr_type, network }
    }

    /// Encodes the address to a base58 string.
    pub fn encode(&self) -> String {
        let mut payload = vec![match self.addr_type {
            AddressType::P2PKH => self.network.addr_pubkeyhash_flag(),
            AddressType::P2SH => self.network.addr_script_flag(),
        }];
        payload.extend_from_slice(&self.bytes);
        let checksum = sha256d(&payload).0[..4].to_vec();
        payload.extend_from_slice(&checksum);
        bs58::encode(&payload).into_string()
    }

    /// Decodes a base58 string into an `Address`, validating network and checksum.
    pub fn decode(input: &str, network: NetworkConfig) -> Result<Self> {
        let bytes = bs58::decode(input)
            .into_vec()
            .map_err(|e| Error::BadData(format!("Base58 decode error: {}", e)))?;
        if bytes.len() < 6 {
            return Err(Error::BadData(format!("Address too short: {} bytes", bytes.len())));
        }

        let payload = &bytes[..bytes.len() - 4];
        let checksum_provided = &bytes[bytes.len() - 4..];
        let checksum_computed = &sha256d(payload).0[..4];
        if *checksum_provided != *checksum_computed {
            return Err(Error::BadData(format!(
                "Checksum mismatch: expected {:?}, got {:?}",
                checksum_computed, checksum_provided
            )));
        }

        let addr_type = match payload[0] {
            flag if flag == network.addr_pubkeyhash_flag() => AddressType::P2PKH,
            flag if flag == network.addr_script_flag() => AddressType::P2SH,
            flag => return Err(Error::BadData(format!("Unknown address type: {}", flag))),
        };

        if payload.len() != 21 {
            return Err(Error::BadData(format!(
                "Invalid payload length: {} bytes",
                payload.len()
            )));
        }

        Ok(Address {
            bytes: payload[1..].to_vec(),
            addr_type,
            network,
        })
    }
}

/// Converts a public key hash to a base58 address.
pub fn addr_encode(hash160: &Hash160, addr_type: AddressType, network: NetworkConfig) -> String {
    let mut payload = vec![match addr_type {
        AddressType::P2PKH => network.addr_pubkeyhash_flag(),
        AddressType::P2SH => network.addr_script_flag(),
    }];
    payload.extend_from_slice(&hash160.0);
    let checksum = sha256d(&payload).0[..4].to_vec();
    payload.extend_from_slice(&checksum);
    bs58::encode(&payload).into_string()
}

/// Decodes a base58 address to a public key hash and address type.
pub fn addr_decode(input: &str, network: NetworkConfig) -> Result<(Hash160, AddressType)> {
    let address = Address::decode(input, network)?;
    let mut hash160_bytes = [0; 20];
    hash160_bytes.copy_from_slice(&address.bytes);
    Ok((Hash160(hash160_bytes), address.addr_type))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hash160;

    #[test]
    fn test_encode_decode_p2pkh() {
        let network = NetworkConfig::new(0).unwrap(); // Mainnet
        let pubkeyhash = hash160(&[0; 33]);
        let addr = addr_encode(&pubkeyhash, AddressType::P2PKH, network);
        let network = NetworkConfig::new(0).unwrap(); // Mainnet
        let (decoded_hash, addr_type) = addr_decode(&addr, network).unwrap();
        assert_eq!(decoded_hash, pubkeyhash);
        assert_eq!(addr_type, AddressType::P2PKH);
    }

    #[test]
    fn test_encode_decode_p2sh() {
        let network = NetworkConfig::new(0).unwrap(); // Mainnet
        let scripthash = hash160(&[1; 33]);
        let addr = addr_encode(&scripthash, AddressType::P2SH, network);
        let network = NetworkConfig::new(0).unwrap(); // Mainnet
        let (decoded_hash, addr_type) = addr_decode(&addr, network).unwrap();
        assert_eq!(decoded_hash, scripthash);
        assert_eq!(addr_type, AddressType::P2SH);
    }

    #[test]
    fn test_invalid_checksum() {
        let network = NetworkConfig::new(0).unwrap(); // Mainnet
        let invalid_addr = "15wpV72HRpAFPMmosR3jvGq7axU7t6ghX6"; // Altered last char
        let result = addr_decode(&invalid_addr, network);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::BadData(_))));
    }

    #[test]
    fn test_invalid_length() {
        let network = NetworkConfig::new(0).unwrap(); // Mainnet
        let short_addr = "1"; // Too short
        let result = addr_decode(&short_addr, network);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::BadData(_))));
    }

    #[test]
    fn test_invalid_addr_type() {
        let network = NetworkConfig::new(1).unwrap(); // Testnet
        let invalid_addr = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"; // P2SH on Testnet
        let result = addr_decode(&invalid_addr, network);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::BadData(_))));
    }
}
