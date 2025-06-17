use base58::{ToBase58, FromBase58};
use crate::util::{Error, hash160, sha256d};
use crate::network::Network;
use std::io;

// Version bytes for different address types and networks
const MAINNET_P2PKH_VERSION: u8 = 0x00; // Bitcoin P2PKH addresses
const MAINNET_P2SH_VERSION: u8 = 0x05;  // Bitcoin P2SH addresses
const TESTNET_P2PKH_VERSION: u8 = 0x6F; // Testnet P2PKH addresses
const TESTNET_P2SH_VERSION: u8 = 0xC4;  // Testnet P2SH addresses

/// Encodes a payload into a Bitcoin address (P2PKH or P2SH)
pub fn encode_address(network: Network, version: u8, payload: &[u8]) -> Result<String, Error> {
    if payload.len() != 20 {
        return Err(Error::BadArgument("Payload must be 20 bytes".to_string()));
    }
    let mut v = Vec::with_capacity(25);
    v.push(version);
    v.extend_from_slice(payload);
    let checksum = sha256d(&v);
    v.extend_from_slice(&checksum.0[..4]);
    Ok(v.to_base58()) // Line 68: Replaced bs58::encode(&payload).into_string()
}

/// Decodes a Bitcoin address into its version byte and payload
pub fn decode_address(input: &str) -> Result<(u8, Vec<u8>), Error> {
    let bytes = input.from_base58().map_err(|e| Error::FromBase58(e))?; // Line 73: Replaced bs58::decode(input)
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

/// Encodes a public key hash into a P2PKH address
pub fn encode_p2pkh_address(network: Network, pubkey_hash: &[u8]) -> Result<String, Error> {
    let version = match network {
        Network::Mainnet => MAINNET_P2PKH_VERSION,
        Network::Testnet | Network::STN => TESTNET_P2PKH_VERSION,
    };
    encode_address(network, version, pubkey_hash) // Line 120: Replaced bs58::encode(&payload).into_string()
}

/// Encodes a script hash into a P2SH address
pub fn encode_p2sh_address(network: Network, script_hash: &[u8]) -> Result<String, Error> {
    let version = match network {
        Network::Mainnet => MAINNET_P2SH_VERSION,
        Network::Testnet | Network::STN => TESTNET_P2SH_VERSION,
    };
    encode_address(network, version, script_hash)
}

/// Validates an address for a given network
pub fn validate_address(network: Network, address: &str) -> Result<(), Error> {
    let (version, _) = decode_address(address)?;
    let expected_version = match network {
        Network::Mainnet => [MAINNET_P2PKH_VERSION, MAINNET_P2SH_VERSION],
        Network::Testnet | Network::STN => [TESTNET_P2PKH_VERSION, TESTNET_P2SH_VERSION],
    };
    if !expected_version.contains(&version) {
        return Err(Error::BadData("Invalid address version for network".to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_encode_decode_p2pkh() -> Result<(), Error> {
        let pubkey_hash = hex::decode("1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b")?.try_into().unwrap();
        let address = encode_p2pkh_address(Network::Mainnet, &pubkey_hash)?;
        assert_eq!(address, "13G2fZ3kE5YgqWAv1Gxf3qY7a7e4k6XzV");
        let (version, decoded) = decode_address(&address)?;
        assert_eq!(version, MAINNET_P2PKH_VERSION);
        assert_eq!(decoded, pubkey_hash);
        Ok(())
    }

    #[test]
    fn test_encode_decode_p2sh() -> Result<(), Error> {
        let script_hash = hex::decode("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0")?.try_into().unwrap();
        let address = encode_p2sh_address(Network::Testnet, &script_hash)?;
        let (version, decoded) = decode_address(&address)?;
        assert_eq!(version, TESTNET_P2SH_VERSION);
        assert_eq!(decoded, script_hash);
        Ok(())
    }

    #[test]
    fn test_validate_address() -> Result<(), Error> {
        let valid_mainnet = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let valid_testnet = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn";
        validate_address(Network::Mainnet, valid_mainnet)?;
        validate_address(Network::Testnet, valid_testnet)?;
        assert!(validate_address(Network::Mainnet, valid_testnet).is_err());
        Ok(())
    }
}
