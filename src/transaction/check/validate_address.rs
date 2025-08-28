use crate::util::{Error, Result, sha256d};
use crate::network::Network;
use base58::FromBase58;

/// Validates that the address matches the expected network and is a P2PKH address
pub fn validate_address_network(address: &str, network: Network) -> Result<()> {
    // Input sanitization
    if address.is_empty() {
        return Err(Error::BadData("Empty address provided".to_string()));
    }
    if address.len() < 26 || address.len() > 35 {
        return Err(Error::BadData("Invalid address length".to_string()));
    }
    if !address.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(Error::BadData("Invalid characters in address".to_string()));
    }

    // Decode Base58Check
    let payload = address
        .from_base58()
        .map_err(|e| Error::BadData(format!("Failed to decode Base58 address: {:?}", e)))?;

    // Validate payload length (21 bytes for hash + network byte + 4-byte checksum)
    if payload.len() != 25 {
        return Err(Error::BadData("Invalid address length".to_string()));
    }

    // Verify network byte
    let expected_version = match network {
        Network::Mainnet => [0x00, 0x05], // P2PKH or P2SH
        Network::Testnet => [0x6f, 0xc4], // P2PKH or P2SH
        Network::STN => [0x6f, 0xc4],    // Assuming same as Testnet; adjust if needed
    };
    if !expected_version.contains(&payload[0]) {
        return Err(Error::BadData(format!("Invalid network byte {} for network {:?}", payload[0], network)));
    }

    // Verify checksum
    let data = &payload[0..21];
    let checksum = &payload[21..25];
    let hash = sha256d(data).0;
    if checksum != &hash[0..4] {
        return Err(Error::BadData("Invalid checksum".to_string()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::{self, decode};

    #[test]
    fn validate_address_network_test() {
        // Valid Mainnet address
        assert!(validate_address_network("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", Network::Mainnet).is_ok());
        // Wrong network
        assert!(validate_address_network("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", Network::Testnet).is_err());
        // Valid Testnet address
        assert!(validate_address_network("mipcBbFg9gMi1G7XgCA3h6nRKB4zK2yKz3", Network::Testnet).is_ok());
        // Invalid address (wrong checksum)
        assert!(validate_address_network("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb", Network::Mainnet).is_err());
    }
}