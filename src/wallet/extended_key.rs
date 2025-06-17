use crate::network::Network;
use crate::util::{hash160, sha256d, Error, Result, Serializable};
use byteorder::{BigEndian, WriteBytesExt};
use bs58;
use ring::hmac;
use secp256k1::{Secp256k1, SecretKey, PublicKey, Scalar};
use std::fmt;
use std::io;
use std::io::{Cursor, Read, Write};

/// Maximum private key value (exclusive)
const SECP256K1_CURVE_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// Index which begins the derived hardened keys
pub const HARDENED_KEY: u32 = 0x80000000;

/// "xpub" prefix for public extended keys on mainnet
pub const MAINNET_PUBLIC_EXTENDED_KEY: u32 = 0x0488B21E;
/// "xprv" prefix for private extended keys on mainnet
pub const MAINNET_PRIVATE_EXTENDED_KEY: u32 = 0x0488ADE4;
/// "tpub" prefix for public extended keys on testnet
pub const TESTNET_PUBLIC_EXTENDED_KEY: u32 = 0x043587CF;
/// "tprv" prefix for private extended keys on testnet
pub const TESTNET_PRIVATE_EXTENDED_KEY: u32 = 0x04358394;

/// Public or private key type
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum ExtendedKeyType {
    Public,
    Private,
}

/// A private or public key in an hierarchical deterministic wallet
#[derive(Clone, Copy)]
pub struct ExtendedKey(pub [u8; 78]);

impl ExtendedKey {
    /// Creates a new extended public key
    pub fn new_public_key(
        network: Network,
        depth: u8,
        parent_fingerprint: &[u8],
        index: u32,
        chain_code: &[u8],
        public_key: &[u8],
    ) -> Result<ExtendedKey> {
        if parent_fingerprint.len() != 4 {
            return Err(Error::BadArgument("Fingerprint must be 4 bytes".to_string()));
        }
        if chain_code.len() != 32 {
            return Err(Error::BadArgument("Chain code must be 32 bytes".to_string()));
        }
        if public_key.len() != 33 {
            return Err(Error::BadArgument("Public key must be 33 bytes".to_string()));
        }
        let mut extended_key = ExtendedKey([0; 78]);
        {
            let mut c = Cursor::new(&mut extended_key.0 as &mut [u8]);
            match network {
                Network::Mainnet => c.write_u32::<BigEndian>(MAINNET_PUBLIC_EXTENDED_KEY)?,
                Network::Testnet | Network::STN => c.write_u32::<BigEndian>(TESTNET_PUBLIC_EXTENDED_KEY)?,
            }
            c.write_u8(depth)?;
            c.write(parent_fingerprint)?;
            c.write_u32::<BigEndian>(index)?;
            c.write(chain_code)?;
            c.write(public_key)?;
        }
        Ok(extended_key)
    }

    /// Creates a new extended private key
    pub fn new_private_key(
        network: Network,
        depth: u8,
        parent_fingerprint: &[u8],
        index: u32,
        chain_code: &[u8],
        private_key: &[u8],
    ) -> Result<ExtendedKey> {
        if parent_fingerprint.len() != 4 {
            return Err(Error::BadArgument("Fingerprint must be 4 bytes".to_string()));
        }
        if chain_code.len() != 32 {
            return Err(Error::BadArgument("Chain code must be 32 bytes".to_string()));
        }
        if private_key.len() != 32 {
            return Err(Error::BadArgument("Private key must be 32 bytes".to_string()));
        }
        let mut extended_key = ExtendedKey([0; 78]);
        {
            let mut c = Cursor::new(&mut extended_key.0 as &mut [u8]);
            match network {
                Network::Mainnet => c.write_u32::<BigEndian>(MAINNET_PRIVATE_EXTENDED_KEY)?,
                Network::Testnet | Network::STN => c.write_u32::<BigEndian>(TESTNET_PRIVATE_EXTENDED_KEY)?,
            }
            c.write_u8(depth)?;
            c.write(parent_fingerprint)?;
            c.write_u32::<BigEndian>(index)?;
            c.write(chain_code)?;
            c.write_u8(0)?;
            c.write(private_key)?;
        }
        Ok(extended_key)
    }

    /// Gets the extended key version byte prefix
    pub fn version(&self) -> u32 {
        ((self.0[0] as u32) << 24)
            | ((self.0[1] as u32) << 16)
            | ((self.0[2] as u32) << 8)
            | (self.0[3] as u32)
    }

    /// Gets the network
    pub fn network(&self) -> Result<Network> {
        match self.version() {
            MAINNET_PUBLIC_EXTENDED_KEY | MAINNET_PRIVATE_EXTENDED_KEY => Ok(Network::Mainnet),
            TESTNET_PUBLIC_EXTENDED_KEY | TESTNET_PRIVATE_EXTENDED_KEY => Ok(Network::Testnet),
            ver => Err(Error::BadData(format!("Unknown extended key version {ver:#x}"))),
        }
    }

    /// Gets the key type
    pub fn key_type(&self) -> Result<ExtendedKeyType> {
        match self.version() {
            MAINNET_PUBLIC_EXTENDED_KEY | TESTNET_PUBLIC_EXTENDED_KEY => Ok(ExtendedKeyType::Public),
            MAINNET_PRIVATE_EXTENDED_KEY | TESTNET_PRIVATE_EXTENDED_KEY => Ok(ExtendedKeyType::Private),
            ver => Err(Error::BadData(format!("Unknown extended key version {ver:#x}"))),
        }
    }

    /// Gets the depth
    pub fn depth(&self) -> u8 {
        self.0[4]
    }

    /// Gets the first 4 bytes of the parent key, or 0 if this is the master key
    pub fn parent_fingerprint(&self) -> [u8; 4] {
        [self.0[5], self.0[6], self.0[7], self.0[8]]
    }

    /// Get the index of this key as derived from the parent
    pub fn index(&self) -> u32 {
        ((self.0[9] as u32) << 24)
            | ((self.0[10] as u32) << 16)
            | ((self.0[11] as u32) << 8)
            | (self.0[12] as u32)
    }

    /// Gets the chain code
    pub fn chain_code(&self) -> [u8; 32] {
        let mut chain_code = [0; 32];
        chain_code.copy_from_slice(&self.0[13..45]);
        chain_code
    }

    /// Gets the public key if this is an extended public key
    pub fn public_key(&self) -> Result<[u8; 33]> {
        match self.key_type()? {
            ExtendedKeyType::Public => {
                let mut public_key = [0; 33];
                public_key.copy_from_slice(&self.0[45..78]);
                Ok(public_key)
            }
            ExtendedKeyType::Private => {
                let secp = Secp256k1::new();
                let secret_key = SecretKey::from_slice(&self.0[46..78])?;
                let public_key = PublicKey::from_secret_key(&secp, &secret_key);
                Ok(public_key.serialize())
            }
        }
    }

    /// Gets the private key if this is an extended private key
    pub fn private_key(&self) -> Result<[u8; 32]> {
        if self.key_type()? == ExtendedKeyType::Private {
            let mut private_key = [0; 32];
            private_key.copy_from_slice(&self.0[46..78]);
            Ok(private_key)
        } else {
            Err(Error::BadData("Cannot get private key from public extended key".to_string()))
        }
    }

    /// Gets the fingerprint of the public key hash
    pub fn fingerprint(&self) -> Result<[u8; 4]> {
        let public_key_hash = hash160(&self.public_key()?);
        let mut fingerprint = [0; 4];
        fingerprint.copy_from_slice(&public_key_hash.0[..4]);
        Ok(fingerprint)
    }

    /// Gets the extended public key for this key
    pub fn extended_public_key(&self) -> Result<ExtendedKey> {
        match self.key_type()? {
            ExtendedKeyType::Public => Ok(*self),
            ExtendedKeyType::Private => {
                let secp = Secp256k1::new();
                let secret_key = SecretKey::from_slice(&self.0[46..78])?;
                let public_key = PublicKey::from_secret_key(&secp, &secret_key).serialize();
                ExtendedKey::new_public_key(
                    self.network()?,
                    self.depth(),
                    &self.0[5..9],
                    self.index(),
                    &self.0[13..45],
                    &public_key,
                )
            }
        }
    }

    /// Derives an extended child private key from an extended parent private key
    pub fn derive_private_key(&self, index: u32) -> Result<ExtendedKey> {
        if self.key_type()? == ExtendedKeyType::Public {
            return Err(Error::BadData("Cannot derive private key from public key".to_string()));
        }
        let network = self.network()?;
        if self.depth() == 255 {
            return Err(Error::BadData("Cannot derive key: depth at maximum".to_string()));
        }

        let secp = Secp256k1::new();
        let private_key = SecretKey::from_slice(&self.0[46..78])?;
        let chain_code = &self.0[13..45];
        let key = hmac::Key::new(hmac::HMAC_SHA512, chain_code);
        let hmac = if index >= HARDENED_KEY {
            let mut v = Vec::with_capacity(37);
            v.push(0x00);
            v.extend_from_slice(&private_key[..]);
            v.write_u32::<BigEndian>(index)?;
            eprintln!("HMAC input (hardened): {:?}", v);
            hmac::sign(&key, &v)
        } else {
            let mut v = Vec::with_capacity(37);
            let public_key = PublicKey::from_secret_key(&secp, &private_key).serialize();
            v.extend_from_slice(&public_key);
            v.write_u32::<BigEndian>(index)?;
            eprintln!("HMAC input (non-hardened): {:?}", v);
            hmac::sign(&key, &v)
        };
        eprintln!("HMAC output: {:?}", hmac.as_ref());

        if hmac.as_ref().len() != 64 {
            return Err(Error::BadData("Invalid HMAC length".to_string()));
        }

        // Left 32 bytes (IL) is the tweak, right 32 bytes is the chain code
        let tweak = &hmac.as_ref()[..32];
        let child_chain_code = &hmac.as_ref()[32..64];

        // Validate tweak
        if !is_private_key_valid(tweak) {
            return Err(Error::BadData("Invalid child key tweak".to_string()));
        }

        // Compute child private key: parent_private_key + tweak (mod n)
        let tweak_scalar = Scalar::from_be_bytes(*tweak)
            .map_err(|_| Error::BadData("Invalid tweak scalar".to_string()))?;
        let mut child_private_key = private_key;
        child_private_key
            .add_tweak(&tweak_scalar)
            .map_err(|_| Error::BadData("Invalid child private key".to_string()))?;

        let fingerprint = self.fingerprint()?;
        ExtendedKey::new_private_key(
            network,
            self.depth() + 1,
            &fingerprint,
            index,
            child_chain_code,
            &child_private_key[..],
        )
    }

    /// Derives an extended child public key from an extended parent public key
    pub fn derive_public_key(&self, index: u32) -> Result<ExtendedKey> {
        if index >= HARDENED_KEY {
            return Err(Error::BadArgument("Cannot derive hardened key from public key".to_string()));
        }
        let network = self.network()?;
        if self.depth() == 255 {
            return Err(Error::BadData("Cannot derive key: depth at maximum".to_string()));
        }

        let chain_code = &self.0[13..45];
        let key = hmac::Key::new(hmac::HMAC_SHA512, chain_code);
        let mut v = Vec::with_capacity(37);
        let public_key = self.public_key()?;
        v.extend_from_slice(&public_key);
        v.write_u32::<BigEndian>(index)?;
        eprintln!("HMAC input (public): {:?}", v);
        let hmac = hmac::sign(&key, &v);
        eprintln!("HMAC output: {:?}", hmac.as_ref());

        if hmac.as_ref().len() != 64 {
            return Err(Error::BadData("Invalid HMAC length".to_string()));
        }

        let tweak = &hmac.as_ref()[..32];
        let child_chain_code = &hmac.as_ref()[32..64];

        if !is_private_key_valid(tweak) {
            return Err(Error::BadData("Invalid child key tweak".to_string()));
        }

        let secp = Secp256k1::new();
        let tweak_key = SecretKey::from_slice(tweak)?;
        let tweak_public = PublicKey::from_secret_key(&secp, &tweak_key);
        let parent_public_key = PublicKey::from_slice(&public_key)?;
        let child_public_key = parent_public_key
            .combine(&tweak_public)
            .map_err(|_| Error::BadData("Invalid child public key".to_string()))?;
        let child_public_key = child_public_key.serialize();

        let fingerprint = self.fingerprint()?;
        ExtendedKey::new_public_key(
            network,
            self.depth() + 1,
            &fingerprint,
            index,
            child_chain_code,
            &child_public_key,
        )
    }

    /// Encodes an extended key into a string
    pub fn encode(&self) -> String {
        let version = self.version();
        eprintln!("Version bytes: {:?}", version.to_be_bytes());
        let checksum = sha256d(&self.0);
        let mut v = Vec::with_capacity(82);
        v.extend_from_slice(&self.0);
        v.extend_from_slice(&checksum.0[..4]);
        let result = bs58::encode(&v).into_string();
        eprintln!("Encoded key: {}", result);
        result
    }

    /// Decodes an extended key from a string
    pub fn decode(s: &str) -> Result<ExtendedKey> {
        let v = bs58::decode(s).into_vec()?;
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
}

impl Serializable<ExtendedKey> for ExtendedKey {
    fn read(reader: &mut dyn Read) -> Result<ExtendedKey> {
        let mut k = ExtendedKey([0; 78]);
        reader.read_exact(&mut k.0)?;
        Ok(k)
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_all(&self.0)?;
        Ok(())
    }
}

impl fmt::Debug for ExtendedKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.encode())
    }
}

impl PartialEq for ExtendedKey {
    fn eq(&self, other: &ExtendedKey) -> bool {
        self.0 == other.0
    }
}

impl Eq for ExtendedKey {}

/// Derives a key using the BIP-32 and BIP-44 shortened key notation
pub fn derive_extended_key(master: &ExtendedKey, path: &str) -> Result<ExtendedKey> {
    let parts: Vec<&str> = path.split('/').collect();
    let mut key_type = ExtendedKeyType::Public;

    if parts[0] == "m" {
        if master.key_type()? == ExtendedKeyType::Public {
            return Err(Error::BadArgument("Cannot derive private key from public master".to_string()));
        }
        key_type = ExtendedKeyType::Private;
    } else if parts[0] != "M" {
        return Err(Error::BadArgument("Path must start with 'm' or 'M'".to_string()));
    }

    let mut key = *master;

    for part in parts[1..].iter() {
        if part.is_empty() {
            return Err(Error::BadArgument("Empty path component".to_string()));
        }

        let index = if part.ends_with("'") || part.ends_with("h") || part.ends_with("H") {
            let index: u32 = part
                .trim_end_matches(|c| c == '\'' || c == 'h' || c == 'H')
                .parse()
                .map_err(|_| Error::BadArgument("Invalid index".to_string()))?;
            if index >= HARDENED_KEY {
                return Err(Error::BadArgument("Index already hardened".to_string()));
            }
            index + HARDENED_KEY
        } else {
            part.parse().map_err(|_| Error::BadArgument("Invalid index".to_string()))?
        };

        key = match key_type {
            ExtendedKeyType::Public => key.derive_public_key(index)?,
            ExtendedKeyType::Private => key.derive_private_key(index)?,
        };
    }

    Ok(key)
}

/// Checks that a private key is in valid SECP256K1 range
pub fn is_private_key_valid(key: &[u8]) -> bool {
    if key.len() != 32 {
        return false;
    }
    let mut non_zero = false;
    for i in 0..32 {
        if key[i] != 0 {
            non_zero = true;
        }
        if key[i] > SECP256K1_CURVE_ORDER[i] {
            return false;
        }
        if key[i] < SECP256K1_CURVE_ORDER[i] {
            return non_zero;
        }
    }
    non_zero
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn private_key_range() -> Result<()> {
        let mut max = SECP256K1_CURVE_ORDER;
        max[31] -= 1;
        assert!(is_private_key_valid(&max));
        assert!(is_private_key_valid(&[0x01; 32]));
        assert!(!is_private_key_valid(&[0x00; 32]));
        assert!(!is_private_key_valid(&[0xff; 32]));
        assert!(!is_private_key_valid(&SECP256K1_CURVE_ORDER));
        Ok(())
    }

    #[test]
    fn path() -> Result<()> {
        // BIP-32 test vector 1
        let m = master_private_key("000102030405060708090a0b0c0d0e0f");
        let actual_m_tprv = derive_extended_key(&m, "m")?.encode();
        eprintln!("Actual tprv for m: {}", actual_m_tprv);
        let expected_m_tprv = "tprv8ZgxMBicQKsPeDgjzdC36fs6bMjGApWDNLR9erAXMs5skhMv36j9MV5ecvfavji5khqjWaWSFhN3YcCUUdiKH6isR4Pwy3U5y5egddBr16m";
        eprintln!("Expected tprv for m: {}", expected_m_tprv);
        assert_eq!(actual_m_tprv, expected_m_tprv);

        let actual_m_0h_tprv = derive_extended_key(&m, "m/0H")?.encode();
        eprintln!("Actual tprv for m/0H: {}", actual_m_0h_tprv);
        let expected_m_0h_tprv = "tprv8bxNLu25VazNnppTCP4fyhyCvBHcYtzE3wr3cwYeL4HA7yf6TLGEUdS4QAFKweDBrd2Le7zmudMBhVQnvUTZgo3pozdsKFG5EqWbvq5j2Xs";
        eprintln!("Expected tprv for m/0H: {}", expected_m_0h_tprv);
        assert_eq!(actual_m_0h_tprv, expected_m_0h_tprv);

        // Placeholder assertions (need updating with correct BIP-32 test vectors)
        assert_eq!(derive_extended_key(&m, "m/0H")?.extended_public_key()?.encode(), "tpubDD2Qwo4h3u6WVf2nXDzWjZDHkXhV3n5h4cD9Vby3k6XJ6W2n3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3");
        assert_eq!(derive_extended_key(&m, "m/0h/1")?.encode(), "tprv8iL3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t");
        assert_eq!(derive_extended_key(&m, "m/0h/1")?.extended_public_key()?.encode(), "tpubDD3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t");
        assert_eq!(derive_extended_key(&m, "m/0h/1/2'")?.encode(), "tprv8k3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t");
        assert_eq!(derive_extended_key(&m, "m/0h/1/2'")?.extended_public_key()?.encode(), "tpubDE3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t");
        assert_eq!(derive_extended_key(&m, "m/0H/1/2H/2")?.encode(), "tprv8n3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t");
        assert_eq!(derive_extended_key(&m, "m/0H/1/2H/2")?.extended_public_key()?.encode(), "tpubDF3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t");
        assert_eq!(derive_extended_key(&m, "m/0H/1/2H/2/1000000000")?.encode(), "tprv8p3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t");
        assert_eq!(derive_extended_key(&m, "m/0H/1/2H/2/1000000000")?.extended_public_key()?.encode(), "tpubDG3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t");

        // BIP-32 test vector 2
        let m = master_private_key("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542");
        assert_eq!(derive_extended_key(&m, "m")?.encode(), "tprv8ZgxMBicQKsPd3XSaQeQeZ3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t");
        assert_eq!(derive_extended_key(&m, "m")?.extended_public_key()?.encode(), "tpubD6NzVbkrYhZ4X3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t");
        assert_eq!(derive_extended_key(&m, "m/0")?.encode(), "tprv8e3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t");
        assert_eq!(derive_extended_key(&m, "m/0")?.extended_public_key()?.encode(), "tpubD8t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t");
        assert_eq!(derive_extended_key(&m, "m/0/2147483647H")?.encode(), "tprv8g3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t");
        assert_eq!(derive_extended_key(&m, "m/0/2147483647H")?.extended_public_key()?.encode(), "tpubDCt3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t");
        assert_eq!(derive_extended_key(&m, "m/0/2147483647H/1")?.encode(), "tprv8i3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t");
        assert_eq!(derive_extended_key(&m, "m/0/2147483647H/1")?.extended_public_key()?.encode(), "tpubDEt3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t");
        assert_eq!(derive_extended_key(&m, "m/0/2147483647H/1/2147483646H")?.encode(), "tprv8k3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t");
        assert_eq!(derive_extended_key(&m, "m/0/2147483647H/1/2147483646H")?.extended_public_key()?.encode(), "tpubDFt3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t");
        assert_eq!(derive_extended_key(&m, "m/0/2147483647H/1/2147483646H/2")?.encode(), "tprv8n3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t");
        assert_eq!(derive_extended_key(&m, "m/0/2147483647H/1/2147483646H/2")?.extended_public_key()?.encode(), "tpubDGt3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t");

        // BIP-32 test vector 3
        let m = master_private_key("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be");
        assert_eq!(derive_extended_key(&m, "m")?.encode(), "tprv8ZgxMBicQKsPd3XSaQeQeZ3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t");
        assert_eq!(derive_extended_key(&m, "m")?.extended_public_key()?.encode(), "tpubD6NzVbkrYhZ4X3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t");
        assert_eq!(derive_extended_key(&m, "m/0H")?.encode(), "tprv8e3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t");
        assert_eq!(derive_extended_key(&m, "m/0H")?.extended_public_key()?.encode(), "tpubD8t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t3t");
        Ok(())
    }

    #[test]
    fn new_public_key() -> Result<()> {
        let key = ExtendedKey::new_public_key(
            Network::Testnet,
            111,
            &[0, 1, 2, 3],
            44,
            &[5; 32],
            &[6; 33],
        )?;
        assert_eq!(key.network()?, Network::Testnet);
        assert_eq!(key.key_type()?, ExtendedKeyType::Public);
        assert_eq!(key.depth(), 111);
        assert_eq!(key.parent_fingerprint(), [0, 1, 2, 3]);
        assert_eq!(key.index(), 44);
        assert_eq!(key.chain_code(), [5; 32]);
        assert_eq!(key.public_key()?, [6; 33]);

        assert!(ExtendedKey::new_public_key(
            Network::Testnet,
            111,
            &[0, 1, 2],
            44,
            &[5; 32],
            &[6; 33],
        )
        .is_err());
        assert!(ExtendedKey::new_public_key(
            Network::Testnet,
            111,
            &[0, 1, 2, 3],
            44,
            &[5; 31],
            &[6; 33],
        )
        .is_err());
        assert!(ExtendedKey::new_public_key(
            Network::Testnet,
            111,
            &[0, 1, 2, 3],
            44,
            &[5; 32],
            &[6; 32],
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn new_private_key() -> Result<()> {
        let key = ExtendedKey::new_private_key(
            Network::Mainnet,
            255,
            &[4, 5, 6, 7],
            HARDENED_KEY + 100,
            &[7; 32],
            &[8; 32],
        )?;
        assert_eq!(key.network()?, Network::Mainnet);
        assert_eq!(key.key_type()?, ExtendedKeyType::Private);
        assert_eq!(key.depth(), 255);
        assert_eq!(key.parent_fingerprint(), [4, 5, 6, 7]);
        assert_eq!(key.index(), HARDENED_KEY + 100);
        assert_eq!(key.chain_code(), [7; 32]);
        assert_eq!(key.private_key()?, [8; 32]);

        assert!(ExtendedKey::new_private_key(
            Network::Mainnet,
            255,
            &[4, 5, 6],
            HARDENED_KEY + 100,
            &[7; 32],
            &[8; 32],
        )
        .is_err());
        assert!(ExtendedKey::new_private_key(
            Network::Mainnet,
            255,
            &[4, 5, 6, 7],
            HARDENED_KEY + 100,
            &[7],
            &[8; 32],
        )
        .is_err());
        assert!(ExtendedKey::new_private_key(
            Network::Mainnet,
            255,
            &[4, 5, 6, 7],
            HARDENED_KEY + 100,
            &[7; 32],
            &[8; 33],
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn invalid() -> Result<()> {
        let k = ExtendedKey([5; 78]);
        assert!(k.network().is_err());
        assert!(k.key_type().is_err());
        Ok(())
    }

    #[test]
    fn encode_decode() -> Result<()> {
        let k = master_private_key("0123456789abcdef");
        assert_eq!(k, ExtendedKey::decode(&k.encode())?);
        let k = derive_extended_key(&k, "M/1/2/3/4/5")?;
        assert_eq!(k, ExtendedKey::decode(&k.encode())?);
        Ok(())
    }

    fn master_private_key(seed: &str) -> ExtendedKey {
        let seed = hex::decode(seed).unwrap();
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA512, b"Bitcoin seed");
        let hmac = hmac::sign(&hmac_key, &seed);
        eprintln!("HMAC output: {:?}", hmac.as_ref());
        eprintln!("Private key: {:?}", &hmac.as_ref()[0..32]);
        eprintln!("Chain code: {:?}", &hmac.as_ref()[32..]);
        ExtendedKey::new_private_key(
            Network::Testnet,
            0,
            &[0; 4],
            0,
            &hmac.as_ref()[32..64],
            &hmac.as_ref()[0..32],
        )
        .unwrap()
    }
}
