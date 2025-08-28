use crate::messages::message::Payload;
use crate::messages::{OutPoint, TxIn, TxOut, COINBASE_OUTPOINT_HASH, COINBASE_OUTPOINT_INDEX};
use crate::script::{op_codes, Script, TransactionChecker, NO_FLAGS, PREGENESIS_RULES};
use crate::transaction::sighash::{sighash, SigHashCache};
use crate::util::{sha256d, var_int, Error, Hash256, Result, Serializable};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use linked_hash_map::LinkedHashMap;
use op_codes::{OP_EQUAL, OP_HASH160};
use std::collections::HashSet;
use std::fmt;
use std::io;
use std::io::{Read, Write};
use crate::wallet::adressing::{AddressForm, TransactionType};
use crate::transaction::types::p2pkh::{create_lock_script, decode_address};

/// Maximum number of satoshis possible
pub const MAX_SATOSHIS: u64 = 21_000_000 * 100_000_000;

/// Bitcoin transaction
#[derive(Default, PartialEq, Eq, Hash, Clone)]
pub struct Tx {
    /// Transaction version
    pub version: u32,
    /// Transaction inputs
    pub inputs: Vec<TxIn>,
    /// Transaction outputs
    pub outputs: Vec<TxOut>,
    /// The block number or timestamp at which this transaction is unlocked
    pub locktime: u32,
}

impl Tx {
   
    /// Creates a new transaction with default values.
    pub fn new(version: u32, locktime: u32) -> Self {
        Tx {
            version: version,
            inputs: Vec::new(),
            outputs: Vec::new(),
            locktime: locktime,
        }
    }

    /// Creates a new transaction with specified values.
    pub fn new_with_params(version: u32, inputs: Vec<TxIn>, outputs: Vec<TxOut>, locktime: u32) -> Self {
        Tx {
            version,
            inputs,
            outputs,
            locktime,
        }
    }

    // Calculate TXID (double SHA-256 hash of serialized transaction)
    pub fn calculate_txid(&self) -> [u8; 32] {
        let serialized = self.serialize();
        sha256d(&serialized).0
    }

    // Basic serialization (simplified, real implementation would need proper varint encoding)
    fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();
        
        // Version (4 bytes)
        result.extend_from_slice(&self.version.to_le_bytes());
        
        // Input count (simplified varint)
        result.push(self.inputs.len() as u8);
        
        // Serialize inputs
        for input in &self.inputs {
            result.extend_from_slice(&input.prev_output.hash.0);
            result.extend_from_slice(&input.prev_output.index.to_le_bytes());
            result.push(input.unlock_script.0.len() as u8); // Simplified varint
            result.extend_from_slice(&input.unlock_script.0);
            result.extend_from_slice(&input.sequence.to_le_bytes());
        }
        
        // Output count (simplified varint)
        result.push(self.outputs.len() as u8);
        
        // Serialize outputs
        for output in &self.outputs {
            result.extend_from_slice(&output.satoshis.to_le_bytes());
            result.push(output.lock_script.0.len() as u8); // Simplified varint
            result.extend_from_slice(&output.lock_script.0);
        }
        
        // Locktime (4 bytes)
        result.extend_from_slice(&self.locktime.to_le_bytes());
        
        result
    }

    // Helper function to serialize a Tx for comparison (from previous code)
    pub fn serialize_transaction(tx: &Tx) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        tx.write(&mut bytes)?;
        Ok(bytes)
    }

    /// Adds an input to the transaction.
    /// - `txid`: The transaction ID as a hex string.
    /// - `vout`: The output index.
    /// - `script_sig`: Optional unlock script (defaults to empty).
    pub fn add_input(&mut self, txid: &str, vout: u32, script_sig: Option<Script>) -> Result<()> {
        let hash = Hash256::decode(txid)
            .map_err(|_| Error::BadArgument("Invalid txid format (expected hex)".to_string()))?;
        let prev_output = OutPoint {
            hash,
            index: vout,
        };
        let unlock_script = script_sig.unwrap_or(Script::default());
        let input = TxIn {
            prev_output,
            unlock_script,
            sequence: 0xFFFFFFFF, // Default sequence for finality
        };
        self.inputs.push(input);
        Ok(())
    }

    /// Removes all inputs from the transaction. keeps original inputs
    pub fn remove_all_inputs(&mut self) -> Self {
        self.inputs.clear();
        self.clone()
    }
    
    /// Adds an output to the transaction.
    /// - `address`: The recipient address as a string (Base58 encoded, P2PKH or P2SH).
    /// - `satoshis`: The amount in satoshis.
    /// - `network`: The network (Mainnet or Testnet) for address validation.
    /// Note: This implementation supports legacy Base58 addresses (P2PKH/P2SH). For Bech32 (e.g., tb1q...), additional decoding would be required.
    pub fn add_output(&mut self, address: &str, satoshis: u64) -> Result<()> {
        let (_network, addr_type, hash160) = decode_address(AddressForm::Base58(address.to_string()))?;
        let lock_script = match addr_type {
            TransactionType::P2PKH => create_lock_script(&hash160),
            TransactionType::P2SH => {
                // Implement P2SH lock script: OP_HASH160 <hash160> OP_EQUAL
                let mut script = Script::new();
                script.append(op_codes::OP_HASH160);
                script.append_data(&hash160.0);
                script.append(op_codes::OP_EQUAL);
                script
            }
        };
        let output = TxOut {
            satoshis,
            lock_script,
        };
        self.outputs.push(output);
        Ok(())
    }

    /// Removes all outputs from the transaction, keeps original outputs
    pub fn remove_all_outputs(&mut self) -> Self {
        self.outputs.clear();
        self.clone()
    }

    /// Sets the locktime for the transaction.
    pub fn set_locktime(&mut self, locktime: u32) {
        self.locktime = locktime;
    }

    /// Calculates the total value of all outputs in satoshis.
    pub fn get_total_output_amount(&self) -> u64 {
        self.outputs.iter().map(|output| output.satoshis).sum()
    }

    /// Calculates the hash of the transaction also known as the txid
    pub fn hash(&self) -> Hash256 {
        let mut b = Vec::with_capacity(self.size());
        self.write(&mut b).unwrap();
        sha256d(&b)
    }

    /// Validates a non-coinbase transaction
    pub fn validate(
        &self,
        require_sighash_forkid: bool,
        use_genesis_rules: bool,
        utxos: &LinkedHashMap<OutPoint, TxOut>,
        pregenesis_outputs: &HashSet<OutPoint>,
    ) -> Result<()> {
        // Make sure neither in or out lists are empty
        if self.inputs.len() == 0 {
            return Err(Error::BadData("inputs empty".to_string()));
        }
        if self.outputs.len() == 0 {
            return Err(Error::BadData("outputs empty".to_string()));
        }

        // Each output value, as well as the total, must be in legal money range
        let mut total_out = 0;
        for tx_out in self.outputs.iter() {
            total_out += tx_out.satoshis;
        }
        if total_out > MAX_SATOSHIS {
            return Err(Error::BadData("Total out exceeds max satoshis".to_string()));
        }

        // Make sure none of the inputs are coinbase transactions
        for tx_in in self.inputs.iter() {
            if tx_in.prev_output.hash == COINBASE_OUTPOINT_HASH
                && tx_in.prev_output.index == COINBASE_OUTPOINT_INDEX
            {
                return Err(Error::BadData("Unexpected coinbase".to_string()));
            }
        }

        // Check that locktime <= INT_MAX because some clients interpret this differently
        if self.locktime > 2_147_483_647 {
            return Err(Error::BadData("Lock time too large".to_string()));
        }

        // Check that all inputs are in the utxo set and are in legal money range
        let mut total_in = 0;
        for tx_in in self.inputs.iter() {
            let utxo = utxos.get(&tx_in.prev_output);
            if let Some(tx_out) = utxo {
                total_in += tx_out.satoshis;
            } else {
                return Err(Error::BadData("utxo not found".to_string()));
            }
        }
        if total_in > MAX_SATOSHIS {
            return Err(Error::BadData("Total in exceeds max satoshis".to_string()));
        }

        // Check inputs spent > outputs received
        if total_in < total_out {
            return Err(Error::BadData("Output total exceeds input".to_string()));
        }

        // Verify each script
        let mut sighash_cache = SigHashCache::new();
        for input in 0..self.inputs.len() {
            let tx_in = &self.inputs[input];
            let tx_out = utxos.get(&tx_in.prev_output).unwrap();

            let mut script = Script::new();
            script.append_slice(&tx_in.unlock_script.0);
            script.append(op_codes::OP_CODESEPARATOR);
            script.append_slice(&tx_out.lock_script.0);

            let mut tx_checker = TransactionChecker {
                tx: self,
                sig_hash_cache: &mut sighash_cache,
                input: input,
                satoshis: tx_out.satoshis,
                require_sighash_forkid,
            };

            let is_pregenesis_input = pregenesis_outputs.contains(&tx_in.prev_output);
            let flags = if !use_genesis_rules || is_pregenesis_input {
                PREGENESIS_RULES
            } else {
                NO_FLAGS
            };

            script.eval(&mut tx_checker, flags)?;
        }

        if use_genesis_rules {
            for tx_out in self.outputs.iter() {
                if tx_out.lock_script.0.len() == 22
                    && tx_out.lock_script.0[0] == OP_HASH160
                    && tx_out.lock_script.0[21] == OP_EQUAL
                {
                    return Err(Error::BadData("P2SH sunsetted".to_string()));
                }
            }
        }

        Ok(())
    }

    /// Returns whether the transaction is the block reward
    pub fn coinbase(&self) -> bool {
        return self.inputs.len() == 1
            && self.inputs[0].prev_output.hash == COINBASE_OUTPOINT_HASH
            && self.inputs[0].prev_output.index == COINBASE_OUTPOINT_INDEX;
    }

    /// Computes the sighash for a specific input
    pub fn sighash_for_input(
        &self,
        input_index: usize,
        script_code: &Script,
        sighash_type: u8,
        satoshis: u64,
    ) -> Result<Hash256> {
        let mut cache = SigHashCache::new();
        sighash(self, input_index, &script_code.0, satoshis, sighash_type, &mut cache)
    }
}

impl Serializable<Tx> for Tx {
    fn read(reader: &mut dyn Read) -> Result<Tx> {
        let version = reader.read_i32::<LittleEndian>()?;
        let version = version as u32;
        let n_inputs = var_int::read(reader)?;
        let mut inputs = Vec::with_capacity(n_inputs as usize);
        for _i in 0..n_inputs {
            inputs.push(TxIn::read(reader)?);
        }
        let n_outputs = var_int::read(reader)?;
        let mut outputs = Vec::with_capacity(n_outputs as usize);
        for _i in 0..n_outputs {
            outputs.push(TxOut::read(reader)?);
        }
        let locktime = reader.read_u32::<LittleEndian>()?;
        Ok(Tx {
            version,
            inputs,
            outputs,
            locktime,
        })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_u32::<LittleEndian>(self.version)?;
        var_int::write(self.inputs.len() as u64, writer)?;
        for tx_in in self.inputs.iter() {
            tx_in.write(writer)?;
        }
        var_int::write(self.outputs.len() as u64, writer)?;
        for tx_out in self.outputs.iter() {
            tx_out.write(writer)?;
        }
        writer.write_u32::<LittleEndian>(self.locktime)?;
        Ok(())
    }
}

impl Payload<Tx> for Tx {
    fn size(&self) -> usize {
        let mut size = 8;
        size += var_int::size(self.inputs.len() as u64);
        for tx_in in self.inputs.iter() {
            size += tx_in.size();
        }
        size += var_int::size(self.outputs.len() as u64);
        for tx_out in self.outputs.iter() {
            size += tx_out.size();
        }
        size
    }
}

impl fmt::Debug for Tx {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let inputs_str = format!("[<{} inputs>]", self.inputs.len());
        let outputs_str = format!("[<{} outputs>]", self.outputs.len());

        f.debug_struct("Tx")
            .field("version", &self.version)
            .field(
                "inputs",
                if self.inputs.len() <= 3 {
                    &self.inputs
                } else {
                    &inputs_str
                },
            )
            .field(
                "outputs",
                if self.outputs.len() <= 3 {
                    &self.outputs
                } else {
                    &outputs_str
                },
            )
            .field("locktime", &self.locktime)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::OutPoint;
    use crate::util::Hash256;
    use std::io::Cursor;

    #[test]
    fn write_read() {
        let mut v = Vec::new();
        let t = Tx {
            version: 1,
            inputs: vec![
                TxIn {
                    prev_output: OutPoint {
                        hash: Hash256([9; 32]),
                        index: 9,
                    },
                    unlock_script: Script(vec![1, 3, 5, 7, 9]),
                    sequence: 100,
                },
                TxIn {
                    prev_output: OutPoint {
                        hash: Hash256([0; 32]),
                        index: 8,
                    },
                    unlock_script: Script(vec![3; 333]),
                    sequence: 22,
                },
            ],
            outputs: vec![
                TxOut {
                    satoshis: 99,
                    lock_script: Script(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 100, 99, 98, 97, 96]),
                },
                TxOut {
                    satoshis: 199,
                    lock_script: Script(vec![56, 78, 90, 90, 78, 56]),
                },
            ],
            locktime: 1000,
        };
        t.write(&mut v).unwrap();
        assert!(v.len() == t.size());
        assert!(Tx::read(&mut Cursor::new(&v)).unwrap() == t);
    }

    #[test]
    fn hash() {
        // The coinbase from block 2
        let tx = Tx {
            version: 1,
            inputs: vec![TxIn {
                prev_output: OutPoint {
                    hash: Hash256([0; 32]),
                    index: 4294967295,
                },
                unlock_script: Script(vec![4, 255, 255, 0, 29, 1, 11]),
                sequence: 4294967295,
            }],
            outputs: vec![TxOut {
                satoshis: 5000000000,
                lock_script: Script(vec![
                    65, 4, 114, 17, 168, 36, 245, 91, 80, 82, 40, 228, 195, 213, 25, 76, 31, 207,
                    170, 21, 164, 86, 171, 223, 55, 249, 185, 217, 122, 64, 64, 175, 192, 115, 222,
                    230, 200, 144, 100, 152, 79, 3, 56, 82, 55, 217, 33, 103, 193, 62, 35, 100, 70,
                    180, 23, 171, 121, 160, 252, 174, 65, 42, 227, 49, 107, 119, 172,
                ]),
            }],
            locktime: 0,
        };
        let h = "9b0fc92260312ce44e74ef369f5c66bbb85848f2eddd5a7a1cde251e54ccfdd5";
        assert!(tx.hash() == Hash256::decode(h).unwrap());
        assert!(tx.coinbase());
    }

    #[test]
    fn validate() {
        let utxo = (
            OutPoint {
                hash: Hash256([5; 32]),
                index: 3,
            },
            TxOut {
                satoshis: 100,
                lock_script: Script(vec![]),
            },
        );
        let mut utxos = LinkedHashMap::new();
        utxos.insert(utxo.0.clone(), utxo.1.clone());

        let tx = Tx {
            version: 2,
            inputs: vec![TxIn {
                prev_output: utxo.0.clone(),
                unlock_script: Script(vec![op_codes::OP_1]),
                sequence: 0,
            }],
            outputs: vec![
                TxOut {
                    satoshis: 10,
                    lock_script: Script(vec![]),
                },
                TxOut {
                    satoshis: 20,
                    lock_script: Script(vec![]),
                },
            ],
            locktime: 0,
        };
        assert!(tx.validate(true, true, &utxos, &HashSet::new()).is_ok());

        let mut tx_test = tx.clone();
        tx_test.inputs = vec![];
        assert!(tx_test
            .validate(true, true, &utxos, &HashSet::new())
            .is_err());

        let mut tx_test = tx.clone();
        tx_test.outputs = vec![];
        assert!(tx_test
            .validate(true, true, &utxos, &HashSet::new())
            .is_err());

        let mut tx_test = tx.clone();
        tx_test.outputs[0].satoshis = 0;
        tx_test.outputs[0].satoshis = 0;
        assert!(tx_test
            .validate(true, true, &utxos, &HashSet::new())
            .is_ok());

        let mut tx_test = tx.clone();
        tx_test.outputs[0].satoshis = MAX_SATOSHIS;
        tx_test.outputs[1].satoshis = MAX_SATOSHIS;
        assert!(tx_test
            .validate(true, true, &utxos, &HashSet::new())
            .is_err());

        let mut tx_test = tx.clone();
        tx_test.outputs[1].satoshis = MAX_SATOSHIS + 1;
        assert!(tx_test
            .validate(true, true, &utxos, &HashSet::new())
            .is_err());

        let mut tx_test = tx.clone();
        tx_test.inputs[0].prev_output.hash = COINBASE_OUTPOINT_HASH;
        tx_test.inputs[0].prev_output.index = COINBASE_OUTPOINT_INDEX;
        assert!(tx_test
            .validate(true, true, &utxos, &HashSet::new())
            .is_err());

        let mut tx_test = tx.clone();
        tx_test.locktime = 4294967295;
        assert!(tx_test
            .validate(true, true, &utxos, &HashSet::new())
            .is_err());

        let mut tx_test = tx.clone();
        tx_test.inputs[0].prev_output.hash = Hash256([8; 32]);
        assert!(tx_test
            .validate(true, true, &utxos, &HashSet::new())
            .is_err());

        let mut utxos_clone = utxos.clone();
        let prev_output = &tx.inputs[0].prev_output;
        utxos_clone.get_mut(prev_output).unwrap().satoshis = u64::MAX;
        assert!(tx
            .validate(true, true, &utxos_clone, &HashSet::new())
            .is_err());

        let mut utxos_clone = utxos.clone();
        let prev_output = &tx.inputs[0].prev_output;
        utxos_clone.get_mut(prev_output).unwrap().satoshis = MAX_SATOSHIS + 1;
        assert!(tx
            .validate(true, true, &utxos_clone, &HashSet::new())
            .is_err());

        let mut tx_test = tx.clone();
        tx_test.outputs[0].satoshis = 100;
        assert!(tx_test
            .validate(true, true, &utxos, &HashSet::new())
            .is_err());

        let mut utxos_clone = utxos.clone();
        let prev_output = &tx.inputs[0].prev_output;
        utxos_clone.get_mut(prev_output).unwrap().lock_script = Script(vec![op_codes::OP_0]);
        assert!(tx
            .validate(true, true, &utxos_clone, &HashSet::new())
            .is_err());

        let mut tx_test = tx.clone();
        tx_test.outputs[0].lock_script = Script(vec![
            OP_HASH160, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, OP_EQUAL,
        ]);
        assert!(tx_test
            .validate(true, false, &utxos, &HashSet::new())
            .is_ok());
        assert!(tx_test
            .validate(true, true, &utxos, &HashSet::new())
            .is_err());
    }

    #[test]
    fn test_txid_and_hash_equivalence() {
        // Create a sample transaction (using the coinbase from block 2 as in the existing test)
        let tx = Tx {
            version: 1,
            inputs: vec![TxIn {
                prev_output: OutPoint {
                    hash: Hash256([0; 32]),
                    index: 4294967295,
                },
                unlock_script: Script(vec![4, 255, 255, 0, 29, 1, 11]),
                sequence: 4294967295,
            }],
            outputs: vec![TxOut {
                satoshis: 5000000000,
                lock_script: Script(vec![
                    65, 4, 114, 17, 168, 36, 245, 91, 80, 82, 40, 228, 195, 213, 25, 76, 31, 207,
                    170, 21, 164, 86, 171, 223, 55, 249, 185, 217, 122, 64, 64, 175, 192, 115, 222,
                    230, 200, 144, 100, 152, 79, 3, 56, 82, 55, 217, 33, 103, 193, 62, 35, 100, 70,
                    180, 23, 171, 121, 160, 252, 174, 65, 42, 227, 49, 107, 119, 172,
                ]),
            }],
            locktime: 0,
        };

        // Calculate both and compare
        let txid_array = tx.calculate_txid();
        let hash_struct = tx.hash();

        // Assert they are equivalent
        assert_eq!(txid_array, hash_struct.0, "calculate_txid and hash() should produce the same output");

        // Also verify against the known hash from the existing test
        let expected_hash = "9b0fc92260312ce44e74ef369f5c66bbb85848f2eddd5a7a1cde251e54ccfdd5";
        assert_eq!(hash_struct, Hash256::decode(expected_hash).unwrap());
        assert_eq!(txid_array, Hash256::decode(expected_hash).unwrap().0);
    }
}
