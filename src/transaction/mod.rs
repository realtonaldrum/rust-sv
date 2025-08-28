//! Build and sign transactions
//!
//! # Examples
//!
//! Sign a transaction:
//!
//! ```rust
//! use sv::messages::{Tx, TxIn};
//! use sv::transaction::generate_signature;
//! use sv::transaction::p2pkh::{create_lock_script, create_unlock_script};
//! use sv::transaction::sighash::{sighash, SigHashCache, SIGHASH_FORKID, SIGHASH_NONE};
//! use sv::util::{hash160};
//!
//! // Use real values here
//! let mut tx = Tx {
//!     inputs: vec![TxIn {
//!         ..Default::default()
//!     }],
//!     ..Default::default()
//! };
//! let private_key = [1; 32];
//! let public_key = [1; 33];
//!
//! let lock_script = create_lock_script(&hash160(&public_key));
//! let mut cache = SigHashCache::new();
//! let sighash_type = SIGHASH_NONE | SIGHASH_FORKID;
//! let sighash = sighash(&tx, 0, &lock_script.0, 0, sighash_type, &mut cache).unwrap();
//! let signature = generate_signature(&private_key, &sighash, sighash_type).unwrap();
//! tx.inputs[0].unlock_script = create_unlock_script(&signature, &public_key);
//! ```
use crate::messages::{Tx, TxIn, TxOut, OutPoint};
use crate::util::{Hash256, Result};
use secp256k1::{Secp256k1, Message, SecretKey, ecdsa::{Signature, SerializedSignature}};
use crate::script::Script;

pub mod types {
    pub mod p2sh;
    pub mod p2pkh;
}

pub mod sighash;

pub mod check {
    pub mod op_equalverify;
    pub mod check_endianness;
    pub mod validate_address;
}

pub mod asset_recovery;
pub mod calculate_fee;

/// Trait defining transaction operations
pub trait Transaction {
    fn version(&self) -> u32;
    fn inputs(&self) -> &Vec<TxIn>;
    fn outputs(&self) -> &Vec<TxOut>;
    fn locktime(&self) -> u32;
    fn txid(&self) -> Hash256;
}

impl Transaction for Tx {
    fn version(&self) -> u32 {self.version}
    fn inputs(&self) -> &Vec<TxIn> {&self.inputs}
    fn outputs(&self) -> &Vec<TxOut> {&self.outputs}
    fn locktime(&self) -> u32 {self.locktime}
    fn txid(&self) -> Hash256 {
        // Placeholder: Implement actual txid calculation (double SHA256 of serialized tx)
        Hash256([0; 32])
    }
}

/// Generates a signature for a transaction sighash
pub fn generate_signature(
    private_key: [u8; 32],
    sighash: &Hash256,
    sighash_type: u8,
) -> Result<Vec<u8>> {
    let secp = Secp256k1::signing_only();
    let message = Message::from_digest(sighash.0);
    let secret_key = SecretKey::from_byte_array(private_key)?;
    let mut signature: Signature = secp.sign_ecdsa(message, &secret_key); // Fixed: removed & from message
    signature.normalize_s();
    let sig: SerializedSignature = signature.serialize_der();
    let mut v = sig.to_vec();
    v.push(sighash_type);
    Ok(v)
}

use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Cursor, Read};

/// Decodes a raw transaction hex string into bytes
pub fn decode(raw_tx: &str) -> Result<Vec<u8>> {
    hex::decode(raw_tx).map_err(|e| crate::util::Error::BadData(format!("Invalid hex: {}", e)))
}

/// Deserializes transaction bytes into a Tx struct
pub fn deserialize(raw_bytes: &[u8]) -> Result<Tx> {
    let mut cursor = Cursor::new(raw_bytes);

    // Read version (4 bytes, little-endian)
    let version = cursor.read_u32::<LittleEndian>()?;

    // Read number of inputs (VarInt)
    let input_count = read_varint(&mut cursor)?;

    // Read inputs
    let mut inputs = Vec::new();
    for _ in 0..input_count {
        let hash = {
            let mut txid_bytes = [0u8; 32];
            cursor.read_exact(&mut txid_bytes)?;
            txid_bytes.reverse(); // Bitcoin txids are reversed in serialization
            Hash256(txid_bytes)
        };
        let index = cursor.read_u32::<LittleEndian>()?;
        let script_len = read_varint(&mut cursor)?;
        let mut unlock_script_bytes = vec![0u8; script_len as usize];
        cursor.read_exact(&mut unlock_script_bytes)?;
        let unlock_script = Script(unlock_script_bytes);
        let sequence = cursor.read_u32::<LittleEndian>()?;
        inputs.push(TxIn {
            prev_output: OutPoint { hash, index },
            unlock_script,
            sequence,
            ..Default::default()
        });
    }

    // Read number of outputs (VarInt)
    let output_count = read_varint(&mut cursor)?;
    
    // Read outputs
    let mut outputs = Vec::new();
    for _ in 0..output_count {
        let satoshis = cursor.read_u64::<LittleEndian>()?;
        let script_len = read_varint(&mut cursor)?;
        let mut lock_script_bytes = vec![0u8; script_len as usize];
        cursor.read_exact(&mut lock_script_bytes)?;
        let lock_script = Script(lock_script_bytes);
        outputs.push(TxOut { satoshis, lock_script });
    }

    // Read locktime (4 bytes, little-endian)
    let locktime = cursor.read_u32::<LittleEndian>()?;

    Ok(Tx {
        version,
        inputs,
        outputs,
        locktime,
        ..Default::default()
    })
}

/// Helper function to read VarInt
fn read_varint<R: Read>(reader: &mut R) -> Result<u64> {
    let first_byte = reader.read_u8()?;
    match first_byte {
        0xFD => Ok(reader.read_u16::<LittleEndian>()? as u64),
        0xFE => Ok(reader.read_u32::<LittleEndian>()? as u64),
        0xFF => Ok(reader.read_u64::<LittleEndian>()?),
        _ => Ok(first_byte as u64),
    }
}

// Simple hex decoding function (for examples)
pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut chars = hex.chars();
    while let (Some(h1), Some(h2)) = (chars.next(), chars.next()) {
        let byte = u8::from_str_radix(&format!("{}{}", h1, h2), 16).unwrap();
        bytes.push(byte);
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::{decode, deserialize, Transaction};
    use crate::util::Hash256;

    #[test]
    fn test_decode_and_deserialize() {
        let raw_tx = "0100000002c7b275b1820d605c8e0d3b7ae8d08726bb9a6752b2e6410c3732afd0207d2741000000006a47304402202dc10c1891ab0cd464400aef7a6e2518407be91a8b571039e6d0a89b5af6be560220472a866dfbc1d6c57d74e8a88b48fc63a9af1440527bece61ca23e3922ea6570412103b4b0af90d28c3594d78d741b920462d3647ebce23a635c47343a3632b2f54cdbffffffff4cbad2270169656046356889d7ffeac67800ded8fdb6310ac34af59bd5589966000000006a4730440220119039a562bc39fbf43c4c61b37e44a3cda85c68ff477e38534dcd769ba1e50f0220340d7e4ab67644a42ddad9ee65010b7421846f9e7c518e992ef2d00faa263eea41210346368f01e90334cb244a1027911a61ba736412331fc84fd7c11bec5ca3b91754ffffffff02f41a0000000000001976a914fe651e45ae44f6642e45ab9b181b1c80c42ff20288ac00ae2f00000000001976a91487bc1da7a2e6bc738e66af86064347099496a14e88ac00000000";

        let tx_bytes = decode(raw_tx).expect("Failed to decode hex");
        let tx = deserialize(&tx_bytes).expect("Failed to deserialize");

        assert_eq!(tx.version(), 1, "Transaction version should be 1");
        assert_eq!(tx.inputs().len(), 2, "Transaction should have 2 inputs");
        assert_eq!(tx.outputs().len(), 2, "Transaction should have 2 outputs");
        assert_eq!(tx.locktime(), 0, "Locktime should be 0");
        assert_eq!(tx.outputs()[0].satoshis, 6900, "First output value should be 6900 satoshis");
        assert_eq!(tx.outputs()[1].satoshis, 3153408, "Second output value should be 3153408 satoshis");

        let expected_txid_0 = Hash256(hex::decode("41742d0720fd2a370c41e6b252679abb2687d0e87a3b0d8e5c600d82b175b2c7").unwrap().try_into().unwrap());
        let expected_txid_1 = Hash256(hex::decode("669958d59bf54ac30a31b6fdfbd8de0078c6eaffd7896835466065690127d2ba").unwrap().try_into().unwrap());
        assert_eq!(tx.inputs()[0].prev_output.hash, expected_txid_0, "First input's previous txid is incorrect");
        assert_eq!(tx.inputs()[1].prev_output.hash, expected_txid_1, "Second input's previous txid is incorrect");
    }

    #[test]
    fn test_invalid_raw_tx() {
        // Test with invalid hex string
        let invalid_raw_tx = "invalid_hex";
        assert!(decode(invalid_raw_tx).is_err(), "Should fail on invalid hex");

        // Test with truncated valid hex (incomplete transaction)
        let truncated_raw_tx = "0100000002c7b275b1820d605c8e0d3b7ae8d08726bb9a6752b2e6410c3732afd0207d27410";
        let truncated_bytes = decode(truncated_raw_tx).expect("Failed to decode truncated hex");
        assert!(deserialize(&truncated_bytes).is_err(), "Should fail on incomplete transaction");
    }
}