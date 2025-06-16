use crate::network::Network;
use crate::util::{hash160, sha256d, Error, Result, Serializable};
use byteorder::{BigEndian, WriteBytesExt};
use bs58;
use ring::hmac;
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use secp256k1_sys::CPtr;
use std::fmt;
use std::io;
use std::io::{Cursor, Read, Write};
use std::slice;

/// Maximum private key value (exclusive)
const SECP256K1_CURVE_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// Index which begins the derived hardened keys
pub const HARDENED_KEY: u32 = 2147483648;

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
            return Err(Error::BadArgument("Fingerprint must be len 4".to_string()));
        }
        if chain_code.len() != 32 {
            return Err(Error::BadArgument("Chain code must be len 32".to_string()));
        }
        if public_key.len() != 33 {
            return Err(Error::BadArgument("Public key must be len 33".to_string()));
        }
        let mut extended_key = ExtendedKey([0; 78]);
        {
            let mut c = Cursor::new(&mut extended_key.0 as &mut [u8]);
            match network {
                Network::Mainnet => c
                    .write_u32::<BigEndian>(MAINNET_PUBLIC_EXTENDED_KEY)
                    .unwrap(),
                Network::Testnet | Network::STN => c
                    .write_u32::<BigEndian>(TESTNET_PUBLIC_EXTENDED_KEY)
                    .unwrap(),
            }
            c.write_u8(depth).unwrap();
            c.write(parent_fingerprint).unwrap();
            c.write_u32::<BigEndian>(index).unwrap();
            c.write(chain_code).unwrap();
            c.write(public_key).unwrap();
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
            return Err(Error::BadArgument("Fingerprint must be len 4".to_string()));
        }
        if chain_code.len() != 32 {
            return Err(Error::BadArgument("Chain code must be len 32".to_string()));
        }
        if private_key.len() != 32 {
            return Err(Error::BadArgument("Private key must be len 32".to_string()));
        }
        let mut extended_key = ExtendedKey([0; 78]);
        {
            let mut c = Cursor::new(&mut extended_key.0 as &mut [u8]);
            match network {
                Network::Mainnet => c
                    .write_u32::<BigEndian>(MAINNET_PRIVATE_EXTENDED_KEY)
                    .unwrap(),
                Network::Testnet | Network::STN => c
                    .write_u32::<BigEndian>(TESTNET_PRIVATE_EXTENDED_KEY)
                    .unwrap(),
            }
            c.write_u8(depth).unwrap();
            c.write(parent_fingerprint).unwrap();
            c.write_u32::<BigEndian>(index).unwrap();
            c.write(chain_code).unwrap();
            c.write_u8(0).unwrap();
            c.write(private_key).unwrap();
        }
        Ok(extended_key)
    }

    /// Gets the extended key version byte prefix
    pub fn version(&self) -> u32 {
        ((self.0[0] as u32) << 24)
            | ((self.0[1] as u32) << 16)
            | ((self.0[2] as u32) << 8)
            | ((self.0[3] as u32) << 0)
    }

    /// Gets the network
    pub fn network(&self) -> Result<Network> {
        let ver = self.version();
        if ver == MAINNET_PUBLIC_EXTENDED_KEY || ver == MAINNET_PRIVATE_EXTENDED_KEY {
            return Ok(Network::Mainnet);
        } else if ver == TESTNET_PUBLIC_EXTENDED_KEY || ver == TESTNET_PRIVATE_EXTENDED_KEY {
            return Ok(Network::Testnet);
        } else {
            let msg = format!("Unknown extended key version {:?}", ver);
            return Err(Error::BadData(msg));
        }
    }

    /// Gets the key type
    pub fn key_type(&self) -> Result<ExtendedKeyType> {
        let ver = self.version();
        if ver == MAINNET_PUBLIC_EXTENDED_KEY || ver == TESTNET_PUBLIC_EXTENDED_KEY {
            return Ok(ExtendedKeyType::Public);
        } else if ver == MAINNET_PRIVATE_EXTENDED_KEY || ver == TESTNET_PRIVATE_EXTENDED_KEY {
            return Ok(ExtendedKeyType::Private);
        } else {
            let msg = format!("Unknown extended key version {:?}", ver);
            return Err(Error::BadData(msg));
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
            | ((self.0[12] as u32) << 0)
    }

    /// Gets the chain code
    pub fn chain_code(&self) -> [u8; 32] {
        let mut chain_code = [0; 32];
        chain_code.clone_from_slice(&self.0[13..45]);
        chain_code
    }

    /// Gets the public key if this is an extended public key
    pub fn public_key(&self) -> Result<[u8; 33]> {
        match self.key_type()? {
            ExtendedKeyType::Public => {
                let mut public_key = [0; 33];
                public_key.clone_from_slice(&self.0[45..]);
                Ok(public_key)
            }
            ExtendedKeyType::Private => {
                let secp = Secp256k1::signing_only();
                let secp_secret_key = SecretKey::from_slice(&self.0[46..])?;
                let secp_public_key = PublicKey::from_secret_key(&secp, &secp_secret_key);
                Ok(secp_public_key.serialize())
            }
        }
    }

    /// Gets the private key if this is an extended private key
    pub fn private_key(&self) -> Result<[u8; 32]> {
        if self.key_type()? == ExtendedKeyType::Private {
            let mut private_key = [0; 32];
            private_key.clone_from_slice(&self.0[46..]);
            Ok(private_key)
        } else {
            let msg = "Cannot get private key of public extended key";
            Err(Error::BadData(msg.to_string()))
        }
    }

    /// Gets the fingerprint of the public key hash
    pub fn fingerprint(&self) -> Result<[u8; 4]> {
        let mut fingerprint = [0; 4];
        let public_key_hash = hash160(&self.public_key()?);
        fingerprint.clone_from_slice(&public_key_hash.0[..4]);
        Ok(fingerprint)
    }

    /// Gets the extended public key for this key
    pub fn extended_public_key(&self) -> Result<ExtendedKey> {
        match self.key_type()? {
            ExtendedKeyType::Public => Ok(self.clone()),
            Extended
