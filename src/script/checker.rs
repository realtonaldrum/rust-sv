use crate::messages::Tx;
use crate::transaction::sighash::{sighash, SigHashCache, SIGHASH_FORKID};
use crate::util::{Error, Result};
use secp256k1::{Message, PublicKey, Secp256k1};
use secp256k1::ecdsa::Signature;

const LOCKTIME_THRESHOLD: i32 = 500000000;
const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;
const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;

pub trait Checker {
    fn check_sig(&mut self, sig: &[u8], pubkey: &[u8], script: &[u8]) -> Result<bool>;
    fn check_locktime(&self, locktime: i32) -> Result<bool>;
    fn check_sequence(&self, sequence: i32) -> Result<bool>;
}

pub struct TransactionlessChecker {}

impl Checker for TransactionlessChecker {
    fn check_sig(&mut self, _sig: &[u8], _pubkey: &[u8], _script: &[u8]) -> Result<bool> {
        Err(Error::IllegalState("Illegal transaction check".to_string()))
    }

    fn check_locktime(&self, _locktime: i32) -> Result<bool> {
        Err(Error::IllegalState("Illegal transaction check".to_string()))
    }

    fn check_sequence(&self, _sequence: i32) -> Result<bool> {
        Err(Error::IllegalState("Illegal transaction check".to_string()))
    }
}

pub struct TransactionChecker<'a> {
    pub tx: &'a Tx,
    pub sig_hash_cache: &'a mut SigHashCache,
    pub input: usize,
    pub satoshis: u64,
    pub require_sighash_forkid: bool,
}

impl<'a> Checker for TransactionChecker<'a> {
    fn check_sig(&mut self, sig: &[u8], pubkey: &[u8], script: &[u8]) -> Result<bool> {
        if sig.len() < 1 {
            return Err(Error::ScriptError("Signature too short".to_string()));
        }
        let sighash_type = sig[sig.len() - 1];
        if self.require_sighash_forkid && sighash_type & SIGHASH_FORKID == 0 {
            return Err(Error::ScriptError("SIGHASH_FORKID not present".to_string()));
        }
        let sig_hash = sighash(
            self.tx,
            self.input,
            script,
            self.satoshis,
            sighash_type,
            self.sig_hash_cache,
        )?;
        let der_sig = &sig[0..sig.len() - 1];
        let secp = Secp256k1::verification_only();
        let mut signature = Signature::from_der(der_sig)?;
        signature.normalize_s();
        let message = Message::from_digest(sig_hash.0);
        let public_key = PublicKey::from_slice(&pubkey)?;
        Ok(secp.verify_ecdsa(message, &signature, &public_key).is_ok())
    }

    fn check_locktime(&self, locktime: i32) -> Result<bool> {
        if locktime < 0 {
            return Err(Error::ScriptError("locktime negative".to_string()));
        }
        if (locktime >= LOCKTIME_THRESHOLD && (self.tx.locktime as i32) < LOCKTIME_THRESHOLD)
            || (locktime < LOCKTIME_THRESHOLD && (self.tx.locktime as i32) >= LOCKTIME_THRESHOLD)
        {
            return Err(Error::ScriptError("locktime types different".to_string()));
        }
        if locktime > self.tx.locktime as i32 {
            return Err(Error::ScriptError("locktime greater than tx".to_string()));
        }
        if self.tx.inputs[self.input].sequence == 0xffffffff {
            return Err(Error::ScriptError("sequence is 0xffffffff".to_string()));
        }
        Ok(true)
    }

    fn check_sequence(&self, sequence: i32) -> Result<bool> {
        if sequence < 0 {
            return Err(Error::ScriptError("sequence negative".to_string()));
        }
        let sequence = sequence as u32;
        if sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
            return Ok(true);
        }
        if self.tx.version < 2 {
            return Err(Error::ScriptError("tx version less than 2".to_string()));
        }
        if self.tx.inputs[self.input].sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
            let msg = "tx sequence disable flag set".to_string();
            return Err(Error::ScriptError(msg));
        }
        let sequence_masked = sequence & 0x0000ffff;
        let tx_sequence_masked = self.tx.inputs[self.input].sequence & 0x0000ffff;
        if (sequence_masked < SEQUENCE_LOCKTIME_TYPE_FLAG
            && tx_sequence_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG)
            || (sequence_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG
                && sequence_masked < SEQUENCE_LOCKTIME_TYPE_FLAG)
        {
            let msg = "sequence types different".to_string();
            return Err(Error::ScriptError(msg));
        }
        if sequence_masked > tx_sequence_masked {
            let msg = "sequence greater than tx".to_string();
            return Err(Error::ScriptError(msg));
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{OutPoint, TxIn, TxOut};
    use crate::script::op_codes::*;
    use crate::script::{Script, NO_FLAGS, PREGENESIS_RULES};
    use crate::transaction::generate_signature;
    use crate::transaction::sighash::{
        SIGHASH_ALL, SIGHASH_ANYONECANPAY, SIGHASH_FORKID, SIGHASH_NONE, SIGHASH_SINGLE,
    };
    use crate::util::{hash160, Hash256};
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    #[test]
    fn standard_p2pkh() {
        standard_p2pkh_test(SIGHASH_ALL);
        standard_p2pkh_test(SIGHASH_ALL | SIGHASH_FORKID);
    }

    fn standard_p2pkh_test(sighash_type: u8) {
        let secp = Secp256k1::new();
        let private_key = [1; 32];
        let secret_key = SecretKey::from_byte_array(private_key).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &secret_key).serialize();
        let pkh = hash160(&pk);

        let mut lock_script = Script::new();
        lock_script.append(OP_DUP);
        lock_script.append(OP_HASH160);
        lock_script.append_data(&pkh.0);
        lock_script.append(OP_EQUALVERIFY);
        lock_script.append(OP_CHECKSIG);

        let tx_1 = Tx {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOut {
                satoshis: 10,
                lock_script,
            }],
            locktime: 0,
        };

        let mut tx_2 = Tx {
            version: 1,
            inputs: vec![TxIn {
                prev_output: OutPoint {
                    hash: tx_1.hash(),
                    index: 0,
                },
                unlock_script: Script(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![],
            locktime: 0,
        };

        let mut cache = SigHashCache::new();
        let lock_script = &tx_1.outputs[0].lock_script.0;
        let sig_hash = sighash(&tx_2, 0, lock_script, 10, sighash_type, &mut cache).unwrap();
        let sig = generate_signature(private_key, &sig_hash, sighash_type).unwrap();

        let mut unlock_script = Script::new();
        unlock_script.append_data(&sig);
        unlock_script.append_data(&pk);
        tx_2.inputs[0].unlock_script = unlock_script;

        let mut cache = SigHashCache::new();
        let mut c = TransactionChecker {
            tx: &tx_2,
            sig_hash_cache: &mut cache,
            input: 0,
            satoshis: 10,
            require_sighash_forkid: false,
        };

        let mut script = Script::new();
        script.append_slice(&tx_2.inputs[0].unlock_script.0);
        script.append(OP_CODESEPARATOR);
        script.append_slice(&tx_1.outputs[0].lock_script.0);
        assert!(script.eval(&mut c, NO_FLAGS).is_ok());
    }

    #[test]
    fn multisig() {
        multisig_test(SIGHASH_ALL);
        multisig_test(SIGHASH_ALL | SIGHASH_FORKID);
    }

    fn multisig_test(sighash_type: u8) {
        let secp = Secp256k1::new();
        let private_key1 = [1; 32];
        let private_key2 = [2; 32];
        let private_key3 = [3; 32];
        let secret_key1 = SecretKey::from_byte_array(private_key1).unwrap();
        let secret_key2 = SecretKey::from_byte_array(private_key2).unwrap();
        let secret_key3 = SecretKey::from_byte_array(private_key3).unwrap();
        let pk1 = PublicKey::from_secret_key(&secp, &secret_key1).serialize();
        let pk2 = PublicKey::from_secret_key(&secp, &secret_key2).serialize();
        let pk3 = PublicKey::from_secret_key(&secp, &secret_key3).serialize();

        let mut lock_script = Script::new();
        lock_script.append(OP_2);
        lock_script.append_data(&pk1);
        lock_script.append_data(&pk2);
        lock_script.append_data(&pk3);
        lock_script.append(OP_3);
        lock_script.append(OP_CHECKMULTISIG);

        let tx_1 = Tx {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOut {
                satoshis: 10,
                lock_script,
            }],
            locktime: 0,
        };

        let mut tx_2 = Tx {
            version: 1,
            inputs: vec![TxIn {
                prev_output: OutPoint {
                    hash: tx_1.hash(),
                    index: 0,
                },
                unlock_script: Script(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![],
            locktime: 0,
        };

        let mut cache = SigHashCache::new();
        let lock_script = &tx_1.outputs[0].lock_script.0;
        let sig_hash = sighash(&tx_2, 0, lock_script, 10, sighash_type, &mut cache).unwrap();
        let sig1 = generate_signature(private_key1, &sig_hash, sighash_type).unwrap();
        let sig3 = generate_signature(private_key3, &sig_hash, sighash_type).unwrap();

        let mut unlock_script = Script::new();
        unlock_script.append(OP_0);
        unlock_script.append_data(&sig1);
        unlock_script.append_data(&sig3);
        tx_2.inputs[0].unlock_script = unlock_script;

        let mut cache = SigHashCache::new();
        let mut c = TransactionChecker {
            tx: &tx_2,
            sig_hash_cache: &mut cache,
            input: 0,
            satoshis: 10,
            require_sighash_forkid: false,
        };

        let mut script = Script::new();
        script.append_slice(&tx_2.inputs[0].unlock_script.0);
        script.append(OP_CODESEPARATOR);
        script.append_slice(&tx_1.outputs[0].lock_script.0);
        assert!(script.eval(&mut c, NO_FLAGS).is_ok());
    }

    #[test]
    fn blank_check() {
        blank_check_test(SIGHASH_NONE | SIGHASH_ANYONECANPAY);
        blank_check_test(SIGHASH_NONE | SIGHASH_ANYONECANPAY | SIGHASH_FORKID);
    }

    fn blank_check_test(sighash_type: u8) {
        let secp = Secp256k1::new();

        let private_key1 = [1; 32];
        let secret_key1 = SecretKey::from_byte_array(private_key1).unwrap();
        let pk1 = PublicKey::from_secret_key(&secp, &secret_key1).serialize();
        let pkh1 = hash160(&pk1);

        let private_key2 = [2; 32];
        let secret_key2 = SecretKey::from_byte_array(private_key2).unwrap();
        let pk2 = PublicKey::from_secret_key(&secp, &secret_key2).serialize();
        let pkh2 = hash160(&pk2);

        let mut lock_script1 = Script::new();
        lock_script1.append(OP_DUP);
        lock_script1.append(OP_HASH160);
        lock_script1.append_data(&pkh1.0);
        lock_script1.append(OP_EQUALVERIFY);
        lock_script1.append(OP_CHECKSIG);

        let mut lock_script2 = Script::new();
        lock_script2.append(OP_DUP);
        lock_script2.append(OP_HASH160);
        lock_script2.append_data(&pkh2.0);
        lock_script2.append(OP_EQUALVERIFY);
        lock_script2.append(OP_CHECKSIG);

        let tx_1 = Tx {
            version: 1,
            inputs: vec![],
            outputs: vec![
                TxOut {
                    satoshis: 10,
                    lock_script: lock_script1,
                },
                TxOut {
                    satoshis: 20,
                    lock_script: lock_script2,
                },
            ],
            locktime: 0,
        };

        let mut tx_2 = Tx {
            version: 1,
            inputs: vec![TxIn {
                prev_output: OutPoint {
                    hash: tx_1.hash(),
                    index: 0,
                },
                unlock_script: Script(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![],
            locktime: 0,
        };

        // Sign the first input

        let mut cache = SigHashCache::new();
        let lock_script = &tx_1.outputs[0].lock_script.0;
        let sig_hash1 = sighash(&tx_2, 0, lock_script, 10, sighash_type, &mut cache).unwrap();
        let sig1 = generate_signature(private_key1, &sig_hash1, sighash_type).unwrap();

        let mut unlock_script1 = Script::new();
        unlock_script1.append_data(&sig1);
        unlock_script1.append_data(&pk1);
        tx_2.inputs[0].unlock_script = unlock_script1;

        // Add another input and sign that separately

        tx_2.inputs.push(TxIn {
            prev_output: OutPoint {
                hash: tx_1.hash(),
                index: 1,
            },
            unlock_script: Script(vec![]),
            sequence: 0xffffffff,
        });

        let mut cache = SigHashCache::new();
        let lock_script = &tx_1.outputs[1].lock_script.0;

        let sig_hash2 = sighash(&tx_2, 1, lock_script, 20, sighash_type, &mut cache).unwrap();
        let sig2 = generate_signature(private_key2, &sig_hash2, sighash_type).unwrap();

        let mut unlock_script2 = Script::new();
        unlock_script2.append_data(&sig2);
        unlock_script2.append_data(&pk2);
        tx_2.inputs[1].unlock_script = unlock_script2;

        let mut cache = SigHashCache::new();
        let mut c1 = TransactionChecker {
            tx: &tx_2,
            sig_hash_cache: &mut cache,
            input: 0,
            satoshis: 10,
            require_sighash_forkid: false,
        };

        let mut script1 = Script::new();
        script1.append_slice(&tx_2.inputs[0].unlock_script.0);
        script1.append(OP_CODESEPARATOR);
        script1.append_slice(&tx_1.outputs[0].lock_script.0);
        assert!(script1.eval(&mut c1, NO_FLAGS).is_ok());

        let mut cache = SigHashCache::new();
        let mut c2 = TransactionChecker {
            tx: &tx_2,
            sig_hash_cache: &mut cache,
            input: 1,
            satoshis: 20,
            require_sighash_forkid: false,
        };

        let mut script2 = Script::new();
        script2.append_slice(&tx_2.inputs[1].unlock_script.0);
        script2.append(OP_CODESEPARATOR);
        script2.append_slice(&tx_1.outputs[1].lock_script.0);
        assert!(script2.eval(&mut c2, NO_FLAGS).is_ok());
    }

    #[test]
    fn batch() {
        batch_test(SIGHASH_SINGLE | SIGHASH_ANYONECANPAY);
        batch_test(SIGHASH_SINGLE | SIGHASH_ANYONECANPAY | SIGHASH_FORKID);
    }

    fn batch_test(sighash_type: u8) {
        let secp = Secp256k1::new();

        let private_key1 = [1; 32];
        let secret_key1 = SecretKey::from_byte_array(private_key1).unwrap();
        let pk1 = PublicKey::from_secret_key(&secp, &secret_key1).serialize();
        let pkh1 = hash160(&pk1);

        let private_key2 = [2; 32];
        let secret_key2 = SecretKey::from_byte_array(private_key2).unwrap();
        let pk2 = PublicKey::from_secret_key(&secp, &secret_key2).serialize();
        let pkh2 = hash160(&pk2);

        let mut lock_script1 = Script::new();
        lock_script1.append(OP_DUP);
        lock_script1.append(OP_HASH160);
        lock_script1.append_data(&pkh1.0);
        lock_script1.append(OP_EQUALVERIFY);
        lock_script1.append(OP_CHECKSIG);

        let mut lock_script2 = Script::new();
        lock_script2.append(OP_DUP);
        lock_script2.append(OP_HASH160);
        lock_script2.append_data(&pkh2.0);
        lock_script2.append(OP_EQUALVERIFY);
        lock_script2.append(OP_CHECKSIG);

        let tx_1 = Tx {
            version: 1,
            inputs: vec![],
            outputs: vec![
                TxOut {
                    satoshis: 10,
                    lock_script: lock_script1.clone(),
                },
                TxOut {
                    satoshis: 20,
                    lock_script: lock_script2.clone(),
                },
            ],
            locktime: 0,
        };

        let mut tx_2 = Tx {
            version: 1,
            inputs: vec![TxIn {
                prev_output: OutPoint {
                    hash: tx_1.hash(),
                    index: 0,
                },
                unlock_script: Script(vec![]),
                sequence: 0xffffffff,
            }],
            outputs: vec![TxOut {
                satoshis: 10,
                lock_script: lock_script1.clone(),
            }],
            locktime: 0,
        };

        // Sign the first input and output

        let mut cache = SigHashCache::new();
        let lock_script = &tx_1.outputs[0].lock_script.0;
        let sig_hash1 = sighash(&tx_2, 0, lock_script, 10, sighash_type, &mut cache).unwrap();
        let sig1 = generate_signature(private_key1, &sig_hash1, sighash_type).unwrap();

        let mut unlock_script1 = Script::new();
        unlock_script1.append_data(&sig1);
        unlock_script1.append_data(&pk1);
        tx_2.inputs[0].unlock_script = unlock_script1;

        // Add another input and output and sign that separately

        tx_2.inputs.push(TxIn {
            prev_output: OutPoint {
                hash: tx_1.hash(),
                index: 1,
            },
            unlock_script: Script(vec![]),
            sequence: 0xffffffff,
        });
        tx_2.outputs.push(TxOut {
            satoshis: 20,
            lock_script: lock_script2.clone(),
        });

        let mut cache = SigHashCache::new();
        let sig_hash2 = sighash(
            &tx_2,
            1,
            &tx_1.outputs[1].lock_script.0,
            20,
            sighash_type,
            &mut cache,
        )
        .unwrap();
        let sig2 = generate_signature(private_key2, &sig_hash2, sighash_type).unwrap();

        let mut unlock_script2 = Script::new();
        unlock_script2.append_data(&sig2);
        unlock_script2.append_data(&pk2);
        tx_2.inputs[1].unlock_script = unlock_script2;

        let mut cache = SigHashCache::new();
        let mut c1 = TransactionChecker {
            tx: &tx_2,
            sig_hash_cache: &mut cache,
            input: 0,
            satoshis: 10,
            require_sighash_forkid: false,
        };

        let mut script1 = Script::new();
        script1.append_slice(&tx_2.inputs[0].unlock_script.0);
        script1.append(OP_CODESEPARATOR);
        script1.append_slice(&tx_1.outputs[0].lock_script.0);
        assert!(script1.eval(&mut c1, NO_FLAGS).is_ok());

        let mut cache = SigHashCache::new();
        let mut c2 = TransactionChecker {
            tx: &tx_2,
            sig_hash_cache: &mut cache,
            input: 1,
            satoshis: 20,
            require_sighash_forkid: false,
        };

        let mut script2 = Script::new();
        script2.append_slice(&tx_2.inputs[1].unlock_script.0);
        script2.append(OP_CODESEPARATOR);
        script2.append_slice(&tx_1.outputs[1].lock_script.0);
        assert!(script2.eval(&mut c2, NO_FLAGS).is_ok());
    }

    #[test]
    fn check_locktime() {
        let mut lock_script = Script::new();
        lock_script.append_num(500).unwrap();
        lock_script.append(OP_CHECKLOCKTIMEVERIFY);
        lock_script.append(OP_1);
        let mut tx = Tx {
            version: 1,
            inputs: vec![TxIn {
                prev_output: OutPoint {
                    hash: Hash256([0; 32]),
                    index: 0,
                },
                unlock_script: Script(vec![]),
                sequence: 0,
            }],
            outputs: vec![],
            locktime: 499,
        };
        {
            let mut cache = SigHashCache::new();
            let mut c = TransactionChecker {
                tx: &tx,
                sig_hash_cache: &mut cache,
                input: 0,
                satoshis: 0,
                require_sighash_forkid: false,
            };
            assert!(lock_script.eval(&mut c, PREGENESIS_RULES).is_err());
        }
        {
            tx.locktime = 500;
            let mut cache = SigHashCache::new();
            let mut c = TransactionChecker {
                tx: &tx,
                sig_hash_cache: &mut cache,
                input: 0,
                satoshis: 0,
                require_sighash_forkid: false,
            };
            assert!(lock_script.eval(&mut c, PREGENESIS_RULES).is_ok());
        }
    }

    #[test]
    fn check_sequence() {
        let mut lock_script = Script::new();
        lock_script
            .append_num(500 | SEQUENCE_LOCKTIME_TYPE_FLAG as i32)
            .unwrap();
        lock_script.append(OP_CHECKSEQUENCEVERIFY);
        lock_script.append(OP_1);
        let mut tx = Tx {
            version: 2,
            inputs: vec![TxIn {
                prev_output: OutPoint {
                    hash: Hash256([0; 32]),
                    index: 0,
                },
                unlock_script: Script(vec![]),
                sequence: 499 | SEQUENCE_LOCKTIME_TYPE_FLAG,
            }],
            outputs: vec![],
            locktime: 0,
        };
        {
            let mut cache = SigHashCache::new();
            let mut c = TransactionChecker {
                tx: &tx,
                sig_hash_cache: &mut cache,
                input: 0,
                satoshis: 0,
                require_sighash_forkid: false,
            };
            assert!(lock_script.eval(&mut c, PREGENESIS_RULES).is_err());
        }
        {
            tx.inputs[0].sequence = 500 | SEQUENCE_LOCKTIME_TYPE_FLAG;
            let mut cache = SigHashCache::new();
            let mut c = TransactionChecker {
                tx: &tx,
                sig_hash_cache: &mut cache,
                input: 0,
                satoshis: 0,
                require_sighash_forkid: false,
            };
            assert!(lock_script.eval(&mut c, PREGENESIS_RULES).is_ok());
        }
    }
}
