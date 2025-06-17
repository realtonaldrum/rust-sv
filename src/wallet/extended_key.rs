use crate::network::Network;
use crate::util::{sha256d, Error, Result, Serializable};
use base58::{ToBase58, FromBase58};
use ring::hmac;
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use std::io::{Read, Write};
use std::fmt;

// Version bytes for extended keys
pub const MAINNET_PRIVATE_EXTENDED_KEY: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4]; // xprv
pub const MAINNET_PUBLIC_EXTENDED_KEY: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];  // xpub
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
        let mut version = [u8; 4];
        version.copy_from_slice(&self.0[0..4]);
        version
    }

    /// Returns the depth of the key
    pub fn depth(&self) -> u8 {
        self.0[4]
    }

    /// Returns the parent fingerprint
    pub fn parent_fingerprint(&self) -> [u8; 4] {
        let mut fingerprint = [u8; 4];
        fingerprint.copy_from_slice(&self.0[5..9]);
        fingerprint
    }

    /// Returns the child number
    pub fn child_number(&self) -> u32 {
        u32::from_be_bytes(self.0[9..13].try_into().unwrap())
    }

    /// Returns the chain code
    pub fn chain_code(&self) -> [u8; 32] {
        let mut chain_code = [u8; 32];
        chain_code.copy_from_slice(&self.0[13..45]);
        chain_code
    }

    /// Returns the key data (private key or public key)
    pub fn key(&self) -> [u8; 33] {
        let mut key = [u8; 33];
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
        let version = self.version();
        eprintln!("Version bytes: {:?}", version);
        let checksum = sha256d(&self.0);
        eprintln!("Checksum: {:?}", &checksum.0[..4]);
        let mut v = Vec::with_capacity(82);
        v.extend_from_slice(&self.0);
        v.extend_from_slice(&checksum.0[..4]);
        eprintln!("Bytes to encode: {:?}", v);
        let result = v.to_base58();
        eprintln!("Encoded key: {}", result);
        result
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
        let mut hmac = hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA512, &self.chain_code()));

        if is_private && is_hardened {
            hmac.update(&[0]);
            hmac.update(&self.key()[1..33]);
        } else if is_private {
            let pubkey = PublicKey::from_secret_key(secp, &SecretKey::from_slice(&self.key()[1..33])?);
            hmac.update(&pubkey.serialize());
        } else {
            if is_hardened {
                return Err(Error::InvalidOperation("Hardened derivation not supported for public keys".to_string()));
            }
            hmac.update(&self.key());
        }

        let index_bytes = index.to_be_bytes();
        hmac.update(&index_bytes);
        let result = hmac.sign();

        let mut child_key = ExtendedKey([0; 78]);
        child_key.0[0..4].copy_from_slice(&self.version());
        child_key.0[4] = self.depth().wrapping_add(1);
        // Fix: Compute parent fingerprint from compressed public key
        let parent_pubkey = if is_private {
            PublicKey::from_secret_key(secp, &SecretKey::from_slice(&self.key()[1..33])?)
        } else {
            PublicKey::from_slice(&self.key())?
        };
        let parent_fingerprint = sha256d(&parent_pubkey.serialize()).0[..4].to_vec();
        child_key.0[5..9].copy_from_slice(&parent_fingerprint);
        child_key.0[9..13].copy_from_slice(&index_bytes);
        child_key.0[13..45].copy_from_slice(&result.as_ref()[32..64]);

        if is_private {
            let mut child_secret = SecretKey::from_slice(&result.as_ref()[0..32])?;
            child_secret = child_secret.add_tweak(&SecretKey::from_slice(&self.key()[1..33])?.into())?;
            child_key.0[45] = 0;
            child_key.0[46..78].copy_from_slice(&child_secret[..]);
        } else {
            let pubkey = PublicKey::from_slice(&self.key())?;
            let tweak = SecretKey::from_slice(&result.as_ref()[0..32])?;
            let child_pubkey = pubkey.add_exp_tweak(secp, &tweak.into())?;
            child_key.0[45..78].copy_from_slice(&child_pubkey.serialize());
        }

        Ok(child_key)
    }
}

impl Serializable for ExtendedKey {
    fn read(reader: &mut dyn Read) -> Result<ExtendedKey> {
        let mut data = [0u8; 78];
        reader.read_exact(&mut data)?;
        Ok(ExtendedKey(data))
    }

    fn write(&self, writer: &mut dyn Write) -> std::io::Result<()> {
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
        let seed = hex::decode(input).map_err(|e| Error::FromHexError(e))?;
        return extended_key_from_seed(&seed, network);
    }

    let mut key = ExtendedKey::decode(input)?;
    let path_parts: Vec<&str> = path.trim_start_matches("m/").split('/').collect();
    for part in path_parts {
        let is_hardened = part.ends_with('H') || part.ends_with('\'');
        let index_str = part.trim_end_matches(|c| c == 'H' || c == '\'');
        let index: u32 = index_str
            .parse()
            .map_err(|e| Error::ParseIntError(e))?;
        let index = if is_hardened { index + HARDENED_KEY } else { index };
        key = key.derive_child(index, secp)?;
    }
    Ok(key)
}

/// Creates an extended private key from a seed
pub fn extended_key_from_seed(seed: &[u8], network: Network) -> Result<ExtendedKey> {
    let _secp = Secp256k1::new();
    let mut hmac = hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA512, b"Bitcoin seed"));
    hmac.update(seed);
    let result = hmac.sign();

    let secret_key = SecretKey::from_slice(&result.as_ref()[0..32])?;
    let chain_code = &result.as_ref()[32..64];

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

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

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
        eprintln!("Child key bytes: {:?}", child.0);
        eprintln!("Actual tprv for m/0H: {}", encoded);
        assert_eq!(
            encoded,
            "tprv8gRrNu65W2Msef2BdBSUptoeAD4G86h89uBYhZdb4ePkW4rJdc83fuBcfPwzEm2mnT2dB47GsbvHa1YJ9B7sa9B2FCND3c4ZfofvW7q7G8k"
        );
        Ok(())
    }
}
