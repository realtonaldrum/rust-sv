//! The check_op_equalverify function verifies that the hash of a public key (for P2PKH) 
//! matches the expected pubkey_hash from the UTXO's scriptPubKey.

use crate::util::{hash160, Error as CrateError, Hash160};
use crate::script::Script;
use crate::wallet::adressing::{TransactionType};
use crate::network::Network;
use crate::wallet::adressing::get_pubkey_hash_from_address;

/// Verifies the OP_EQUALVERIFY operation for P2PKH or P2SH scripts.
/// For P2PKH: Checks if hash160(public_key) matches the expected pubkey_hash.
/// For P2SH: Checks if hash160(redeem_script) matches the expected scripthash.
/// ScriptPubKey:  (standard P2PKH)
/// Scripthash (that Bitails API shows): Used for Electrum-style queries
pub fn check_op_equalverify(
    public_key: Vec<&[u8]>, // For P2PKH
    redeem_script: Option<&Script>, // For P2SH
    expected_hash: Hash160, // pubkey_hash (P2PKH) or scripthash (P2SH)
    transaction_type: TransactionType,
) -> Result<(), CrateError> {

    let expected_hash_bytes = expected_hash.0;

    if expected_hash_bytes.len() != 20 {
        return Err(CrateError::BadData(format!(
            "Expected hash length must be 20 bytes, got {} bytes",
            expected_hash_bytes.len()
        )));
    }

    match transaction_type {
        TransactionType::P2PKH => {
            // Ensure exactly one public key is provided
            let single_key = public_key
                .get(0)
                .ok_or_else(|| CrateError::BadData("No public key provided for P2PKH".to_string()))?;
            if public_key.len() > 1 {
                return Err(CrateError::BadData("Multiple public keys provided for P2PKH".to_string()));
            }
            let computed_hash = hash160(single_key);
            if computed_hash.0 != expected_hash_bytes.as_slice() {
                return Err(CrateError::BadData(format!(
                    "OP_EQUALVERIFY failed: public key hash {} does not match expected pubkey_hash {:?}",
                    hex::encode(computed_hash.0),
                    expected_hash
                )));
            }
            println!(
                "DEBUG - P2PKH OP_EQUALVERIFY passed: public key hash {} matches expected pubkey_hash {:?}",
                hex::encode(computed_hash.0),
                expected_hash
            );
        }
        TransactionType::P2SH => {
            let redeem_script = redeem_script.ok_or_else(|| CrateError::BadData("Redeem script required for P2SH".to_string()))?;
            let redeem_script_bytes = redeem_script.to_bytes();
            let computed_hash = hash160(&redeem_script_bytes);
            if computed_hash.0 != expected_hash_bytes.as_slice() {
                return Err(CrateError::BadData(format!(
                    "OP_EQUALVERIFY failed: redeem script hash {} does not match expected scripthash {:?} for redeem script {}",
                    hex::encode(computed_hash.0),
                    expected_hash,
                    hex::encode(&redeem_script_bytes)
                )));
            }
            println!(
                "DEBUG - P2SH OP_EQUALVERIFY passed: redeem script hash {} matches expected scripthash {:?} for redeem script {}",
                hex::encode(computed_hash.0),
                expected_hash,
                hex::encode(&redeem_script_bytes)
            );
        }
    }
    
    Ok(())
}

pub fn validate_input(
    pubkey: &[u8],
    utxo_address: &str,
    network: Network,
) -> Result<(), CrateError> {
    let pubkey_hash = get_pubkey_hash_from_address(utxo_address, network)?;
    check_op_equalverify(
        vec![pubkey],
        None,
        Hash160(pubkey_hash),
        TransactionType::P2PKH,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::Hash160;
    use crate::transaction::hex_to_bytes;
    
    // Neuer Test für check_op_equalverify
    #[test]
    fn test_check_op_equalverify() {
        // Testfall 1: Gültiger öffentlicher Schlüssel und Adresse (P2PKH)
        let network = Network::Mainnet; // Oder Network::Testnet für BSV-Testnet
        let address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"; // Beispiel-BSV-Adresse (Satoshi's Adresse, Mainnet)
        let pubkey_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"; // Öffentlicher Schlüssel, der zu dieser Adresse passt
        let pubkey = hex_to_bytes(pubkey_hex);

        // Extrahiere pubkey_hash aus der Adresse
        let expected_hash = get_pubkey_hash_from_address(&address, network).expect("Failed to decode address");
        let expected_hash = Hash160(expected_hash);

        // Teste OP_EQUALVERIFY
        let result = check_op_equalverify(vec![&pubkey], None, expected_hash, TransactionType::P2PKH);
        assert!(result.is_ok(), "OP_EQUALVERIFY failed for valid pubkey: {:?}", result.err());

        // Testfall 2: Ungültiger öffentlicher Schlüssel
        let wrong_pubkey_hex = "02d0c7d9ed53f986d7e593f0c8a18a35454a89d4f8b1c8536e58e9f2e094f90e64"; // Zufälliger Schlüssel
        let wrong_pubkey = hex_to_bytes(wrong_pubkey_hex);
        let result = check_op_equalverify(vec![&wrong_pubkey], None, expected_hash, TransactionType::P2PKH);
        assert!(result.is_err(), "OP_EQUALVERIFY should fail for wrong pubkey");

        // Testfall 3: Falsche Adressart (P2SH statt P2PKH)
        let result = check_op_equalverify(vec![&pubkey], None, expected_hash, TransactionType::P2SH);
        assert!(result.is_err(), "OP_EQUALVERIFY should fail for wrong address type");

        // Testfall 4: Kein öffentlicher Schlüssel
        let result = check_op_equalverify(vec![], None, expected_hash, TransactionType::P2PKH);
        assert!(result.is_err(), "OP_EQUALVERIFY should fail with no pubkey");

        // Testfall 5: Mehrere öffentliche Schlüssel (nicht erlaubt für P2PKH)
        let result = check_op_equalverify(vec![&pubkey, &wrong_pubkey], None, expected_hash, TransactionType::P2PKH);
        assert!(result.is_err(), "OP_EQUALVERIFY should fail with multiple pubkeys");
    }

}