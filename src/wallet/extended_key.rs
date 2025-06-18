use crate::network::Network;
use crate::util::{sha256d, Error, Result, Serializable};
use base58::{ToBase58, FromBase58};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use std::io::{self, Read, Write};
use std::fmt;

// Version bytes for extended keys
pub const MAINNET_PRIVATE_EXTENDED_KEY: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4]; // xprv
pub const MAINNET_PUBLIC_EXTENDED_KEY: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E]; // xpub
pub const TESTNET_PRIVATE_EXTENDED_KEY: [u8; 4] = [0x04, 0x35, 0x83, 0x94]; // tprv
pub const TESTNET_PUBLIC_EXTENDED_KEY: [u8; 4] = [0x04, 0x35, 0x87, 0xCF]; // tpub
pub const HARDENED_KEY: u32 = 0x80000000;

/// Type of extended key
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtendedKeyType {
    Private,
    Public,
}

/// Represents a BIP-32 extended key (private or public)
#[derive(Clone, PartialEq, Eq)]
pub struct ExtendedKey(pub [u8; 78]);

impl ExtendedKey {
    /// Returns the version bytes
    pub fn version(&self) -> [u8; 4] {
        let mut version = [0u8; 4];
        version.copy_from_slice(&self.0[0..4]);
        version
    }

    /// Returns the depth of the key
    pub fn depth(&self) -> u8 {
        self.0[4]
    }

    /// Returns the parent fingerprint
    pub fn parent_fingerprint(&self) -> [u8; 4] {
        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&self.0[5..9]);
        fingerprint
    }

    /// Returns the child number
    pub fn child_number(&self) -> u32 {
        u32::from_be_bytes(self.0[9..13].try_into().unwrap())
    }

    /// Returns the chain code
    pub fn chain_code(&self) -> [u8; 32] {
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&self.0[13..45]);
        chain_code
    }

    /// Returns the key data (private key or public key)
    pub fn key(&self) -> [u8; 33] {
        let mut key = [0u8; 33];
        key.copy_from_slice(&self.0[45..78]);
        key
    }

    /// Checks if the key is private
    pub fn is_private(&self) -> bool {
        let version = self.version();
        version == MAINNET_PRIVATE_EXTENDED_KEY || version == TESTNET_PRIVATE_EXTENDED_KEY
    }

    /// Encodes an extended key into a base58 string
    pub fn encode(&self) -> String {
        let checksum = sha256d(&self.0);
        let mut v = Vec::with_capacity(82);
        v.extend_from_slice(&self.0);
        v.extend_from_slice(&checksum.0[..4]);
        v.to_base58()
    }

    /// Decodes an extended key from a base58 string
    pub fn decode(s: &str) -> Result<ExtendedKey> {
        let v = s.from_base58().map_err(|e| Error::FromBase58Error(e))?;
        if v.len() != 82 {
            return Err(Error::BadData("Invalid extended key length".to_string()));
        }
        let checksum = sha256d(&v[..78]);
        if checksum.0[..4] != v[78..] {
            return Err(Error::BadData("Invalid checksum".to_string()));
        }
        let mut extended_key = ExtendedKey([0; 78]);
        extended_key.0.copy_from_slice(&v[..78]);
        Ok(extended_key)
    }

    /// Derives a child key (hardened or normal)
    pub fn derive_child(&self, index: u32, secp: &Secp256k1<secp256k1::All>) -> Result<ExtendedKey> {
        let is_private = self.is_private();
        let is_hardened = index >= HARDENED_KEY;

        // Prepare HMAC input
        let mut hmac_input = Vec::new();
        if is_private && is_hardened {
            hmac_input.push(0);
            let private_key = &self.key()[1..33]; // Private key without prefix
            eprintln!("Using private key for HMAC: {} (len: {})", hex::encode(private_key), private_key.len());
            hmac_input.extend_from_slice(private_key);
        } else if is_private {
            let pubkey = PublicKey::from_secret_key(secp, &SecretKey::from_slice(&self.key()[1..33])?);
            eprintln!("Using public key for HMAC: {} (len: {})", hex::encode(pubkey.serialize()), pubkey.serialize().len());
            hmac_input.extend_from_slice(&pubkey.serialize());
        } else {
            if is_hardened {
                return Err(Error::InvalidOperation("Hardened derivation not supported for public keys".to_string()));
            }
            eprintln!("Using public key for HMAC: {} (len: {})", hex::encode(&self.key()), self.key().len());
            hmac_input.extend_from_slice(&self.key()); // Public key
        }
        hmac_input.extend_from_slice(&index.to_be_bytes());
        eprintln!("Derive HMAC key: {} (len: {})", hex::encode(self.chain_code()), self.chain_code().len());
        eprintln!("Derive HMAC input: {} (len: {})", hex::encode(&hmac_input), hmac_input.len());

        // Compute HMAC
        let chain_code = self.chain_code();
        let mut hmac = Hmac::<Sha512>::new_from_slice(&chain_code)
            .map_err(|e| Error::BadData(format!("Invalid HMAC key: {}", e)))?;
        hmac.update(&hmac_input);
        let result = hmac.finalize().into_bytes();
        eprintln!("Raw HMAC result: {} (len: {})", hex::encode(&result), result.len());
        if result.len() != 64 {
            return Err(Error::BadData(format!("Invalid HMAC output length: {}", result.len())));
        }
        let il: [u8; 32] = result[0..32].try_into().unwrap();
        let new_chain_code: [u8; 32] = result[32..64].try_into().unwrap();
        eprintln!("HMAC output il: {}", hex::encode(&il));
        eprintln!("HMAC output chain_code: {}", hex::encode(&new_chain_code));

        let mut child_key = ExtendedKey([0; 78]);
        // Set version bytes (same as parent for private keys)
        child_key.0[0..4].copy_from_slice(&self.version());
        // Increment depth
        child_key.0[4] = self.depth().wrapping_add(1);
        // Compute parent fingerprint
        let parent_pubkey = if is_private {
            PublicKey::from_secret_key(secp, &SecretKey::from_slice(&self.key()[1..33])?)
        } else {
            PublicKey::from_slice(&self.key())?
        };
        let parent_fingerprint: [u8; 4] = sha256d(&parent_pubkey.serialize()).0[..4].try_into().unwrap();
        child_key.0[5..9].copy_from_slice(&parent_fingerprint);
        // Set child index
        child_key.0[9..13].copy_from_slice(&index.to_be_bytes());
        // Set chain code
        child_key.0[13..45].copy_from_slice(&new_chain_code);

        // Compute child key
        if is_private {
            let parent_secret = SecretKey::from_slice(&self.key()[1..33])?;
            let tweak = SecretKey::from_slice(&il).map_err(|e| Error::BadData(format!("Invalid tweak: {}", e)))?;
            let child_secret = parent_secret.add_tweak(&tweak.into()).map_err(|e| Error::BadData(format!("Tweak failed: {}", e)))?;
            child_key.0[45] = 0; // Private key prefix
            child_key.0[46..78].copy_from_slice(&child_secret[..]);
            eprintln!("Parent private key: {}", hex::encode(&self.key()[1..33]));
            eprintln!("Tweak: {}", hex::encode(&il));
            eprintln!("Child private key: {}", hex::encode(&child_secret[..]));
        } else {
            let pubkey = PublicKey::from_slice(&self.key())?;
            let tweak = SecretKey::from_slice(&il).map_err(|e| Error::BadData(format!("Invalid tweak: {}", e)))?;
            let child_pubkey = pubkey.add_exp_tweak(secp, &tweak.into()).map_err(|e| Error::BadData(format!("Tweak failed: {}", e)))?;
            child_key.0[45..78].copy_from_slice(&child_pubkey.serialize());
        }

        eprintln!("Child key bytes: {:?}", child_key.0);
        Ok(child_key)
    }
}

impl Serializable<ExtendedKey> for ExtendedKey {
    fn read(reader: &mut dyn Read) -> Result<ExtendedKey> {
        let mut data = [0u8; 78];
        reader.read_exact(&mut data).map_err(Error::Io)?;
        Ok(ExtendedKey(data))
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_all(&self.0)?;
        Ok(())
    }
}

impl fmt::Debug for ExtendedKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ExtendedKey({})", self.encode())
    }
}

/// Derives an extended key from a seed or parent key
pub fn derive_extended_key(
    input: &str,
    path: &str,
    network: Network,
    secp: &Secp256k1<secp256k1::All>,
) -> Result<ExtendedKey> {
    if path.is_empty() || path == "m" {
        let seed = hex::decode(input).map_err(|_| Error::BadData("Invalid hex seed".to_string()))?;
        return extended_key_from_seed(&seed, network);
    }

    let mut key = ExtendedKey::decode(input)?;
    let path_parts: Vec<&str> = path.trim_start_matches("m/").split('/').collect();
    for part in path_parts {
        let is_hardened = part.ends_with('H') || part.ends_with('\'');
        let index_str = part.trim_end_matches(|c| c == 'H' || c == '\'');
        let index: u32 = index_str
            .parse()
            .map_err(|_| Error::BadData("Invalid derivation index".to_string()))?;
        let index = if is_hardened { index + HARDENED_KEY } else { index };
        key = key.derive_child(index, secp)?;
    }
    Ok(key)
}

/// Creates an extended private key from a seed
pub fn extended_key_from_seed(seed: &[u8], network: Network) -> Result<ExtendedKey> {
    let mut hmac = Hmac::<Sha512>::new_from_slice(b"Bitcoin seed")
        .map_err(|e| Error::BadData(format!("Invalid HMAC key: {}", e)))?;
    hmac.update(seed);
    let result = hmac.finalize().into_bytes();
    if result.len() != 64 {
        return Err(Error::BadData(format!("Invalid HMAC output length: {}", result.len())));
    }

    let secret_key = SecretKey::from_slice(&result[0..32])?;
    let chain_code = &result[32..64];

    let mut key = ExtendedKey([0; 78]);
    let version = match network {
        Network::Mainnet => MAINNET_PRIVATE_EXTENDED_KEY,
        Network::Testnet | Network::STN => TESTNET_PRIVATE_EXTENDED_KEY,
    };
    key.0[0..4].copy_from_slice(&version);
    key.0[4] = 0;
    key.0[5..9].copy_from_slice(&[0; 4]);
    key.0[9..13].copy_from_slice(&[0; 4]);
    key.0[13..45].copy_from_slice(chain_code);
    key.0[45] = 0;
    key.0[46..78].copy_from_slice(&secret_key[..]);

    eprintln!("Master private key: {}", hex::encode(&secret_key[..]));
    eprintln!("Master chain code: {}", hex::encode(chain_code));
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_hmac() -> Result<()> {
        let key = hex::decode("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508")?;
        let private_key = hex::decode("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")?;
        let index = 0x80000000u32; // Hardened index
        let mut data = vec![0u8];
        data.extend_from_slice(&private_key);
        data.extend_from_slice(&index.to_be_bytes());
        eprintln!("HMAC key: {} (len: {})", hex::encode(&key), key.len());
        eprintln!("HMAC data: {} (len: {})", hex::encode(&data), data.len());
        let mut hmac = Hmac::<Sha512>::new_from_slice(&key)
            .map_err(|e| Error::BadData(format!("Invalid HMAC key: {}", e)))?;
        hmac.update(&data);
        let result = hmac.finalize().into_bytes();
        eprintln!("HMAC result: {} (len: {})", hex::encode(&result), result.len());
        assert_eq!(
            hex::encode(&result),
            "2c7a9b4f0f048d2bdda9e7c5d92b10b2ef0b329a3db5aead3e351e0c7d8f421747fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"
        );
        Ok(())
    }

    #[test]
    fn test_encode_decode() -> Result<()> {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f")?;
        let key = extended_key_from_seed(&seed, Network::Testnet)?;
        let encoded = key.encode();
        let decoded = ExtendedKey::decode(&encoded)?;
        assert_eq!(key, decoded);
        Ok(())
    }

    #[test]
    fn test_path() -> Result<()> {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f")?;
        let master = extended_key_from_seed(&seed, Network::Testnet)?;
        let secp = Secp256k1::new();

        let child = master.derive_child(HARDENED_KEY, &secp)?; // m/0H
        let encoded = child.encode();
        assert_eq!(
            encoded,
            "tprv8gRrNu65W2Msef2BdBSUptoeAD4G86h89uBYhZdb4ePkW4rJdc83fuBcfPwzEm2mnT2dB47GsbvHa1YJ9B7sa9B2FCND3c4ZfofvW7q7G8k"
        );
        Ok(())
    }
    }
