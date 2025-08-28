//! Script opcodes and interpreter
//!
//! # Examples
//!
//! Evaluate a script that divides two numbers:
//!
//! ```rust
//! use rustsv::script::op_codes::*;
//! use rustsv::script::{Script, TransactionlessChecker, NO_FLAGS};
//!
//! let mut script = Script::new();
//! script.append(OP_10);
//! script.append(OP_5);
//! script.append(OP_DIV);
//!
//! script.eval(&mut TransactionlessChecker {}, NO_FLAGS).unwrap();
//! ```

use crate::script::op_codes::*;
use crate::util::{Result, Error, hash160, sha256d};
use crate::wallet::adressing::{AddressForm, constants, encode_address, decode_address, TransactionType};
use crate::network::Network;
use base58::ToBase58;
use hex;
use std::fmt;

mod checker;
mod interpreter;
#[allow(dead_code)]
pub mod op_codes;
pub mod stack;

pub use self::checker::{Checker, TransactionChecker, TransactionlessChecker};
pub(crate) use self::interpreter::next_op;
pub use self::interpreter::{NO_FLAGS, PREGENESIS_RULES};

/// Transaction script
#[derive(Default, Clone, PartialEq, Eq, Hash)]
pub struct Script(pub Vec<u8>);

impl Script {
    /// Creates a new empty script
    pub fn new() -> Script {
        Script(vec![])
    }

    /// Appends a single opcode or data byte
    pub fn append(&mut self, byte: u8) {
        self.0.push(byte);
    }

    /// Appends a slice of data
    pub fn append_slice(&mut self, slice: &[u8]) {
        self.0.extend_from_slice(slice);
    }

    /// Appends the opcodes and provided data that push it onto the stack
    pub fn append_data(&mut self, data: &[u8]) {
        let len = data.len();
        match len {
            0 => self.0.push(op_codes::OP_0),
            1..=75 => {
                self.0.push(op_codes::OP_PUSH + len as u8);
                self.0.extend_from_slice(data);
            }
            76..=255 => {
                self.0.push(op_codes::OP_PUSHDATA1);
                self.0.push(len as u8);
                self.0.extend_from_slice(data);
            }
            256..=65535 => {
                self.0.push(op_codes::OP_PUSHDATA2);
                self.0.push((len >> 0) as u8);
                self.0.push((len >> 8) as u8);
                self.0.extend_from_slice(data);
            }
            _ => {
                self.0.push(op_codes::OP_PUSHDATA4);
                self.0.push((len >> 0) as u8);
                self.0.push((len >> 8) as u8);
                self.0.push((len >> 16) as u8);
                self.0.push((len >> 24) as u8);
                self.0.extend_from_slice(data);
            }
        }
    }

    /// Appends the opcodes to push a number to the stack
    ///
    /// The number must be in the range [2^-31+1,2^31-1].
    pub fn append_num(&mut self, n: i32) -> Result<()> {
        self.append_data(&stack::encode_num(n as i64)?);
        Ok(())
    }

    /// Evaluates a script using the provided checker
    pub fn eval<T: Checker>(&self, checker: &mut T, flags: u32) -> Result<()> {
        interpreter::eval(&self.0, checker, flags)
    }

    /// Returns the underlying script bytes as a Vec<u8>
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    /// Creates a P2PKH locking script:
    pub fn p2pkh(pubkey_hash: &[u8]) -> Self {
        let mut script = Script::new();
        script.append(OP_DUP);
        script.append(OP_HASH160);
        script.append_data(pubkey_hash);
        script.append(OP_EQUALVERIFY);
        script.append(OP_CHECKSIG);
        script
    }

    /// Creates a P2SH locking script: OP_HASH160 <script_hash> OP_EQUAL
    pub fn p2sh(script_hash: &[u8; 20]) -> Self {
        let mut script = Script::new();
        script.append(op_codes::OP_HASH160);
        script.append_slice(&script_hash[..]);
        script.append(op_codes::OP_EQUAL);
        script
    }

    /// Creates a Script from a hash160, assuming the redeem script is known or retrievable
    pub fn from_hash160(hash: &[u8]) -> Self {
        // Placeholder: In a real implementation, retrieve the actual redeem script
        // For now, create a P2SH script using the hash
        let mut script = Script::new();
        script.append(op_codes::OP_HASH160);
        script.append_data(hash);
        script.append(op_codes::OP_EQUAL);
        script
    }
}

impl fmt::Debug for Script {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let script = &self.0;
        let mut ret = String::new();
        let mut i = 0;
        ret.push_str("[");
        while i < script.len() {
            if i != 0 {
                ret.push_str(" ")
            }
            match script[i] {
                OP_0 => ret.push_str("OP_0"),
                OP_1NEGATE => ret.push_str("OP_1NEGATE"),
                OP_1 => ret.push_str("OP_1"),
                OP_2 => ret.push_str("OP_2"),
                OP_3 => ret.push_str("OP_3"),
                OP_4 => ret.push_str("OP_4"),
                OP_5 => ret.push_str("OP_5"),
                OP_6 => ret.push_str("OP_6"),
                OP_7 => ret.push_str("OP_7"),
                OP_8 => ret.push_str("OP_8"),
                OP_9 => ret.push_str("OP_9"),
                OP_10 => ret.push_str("OP_10"),
                OP_11 => ret.push_str("OP_11"),
                OP_12 => ret.push_str("OP_12"),
                OP_13 => ret.push_str("OP_13"),
                OP_14 => ret.push_str("OP_14"),
                OP_15 => ret.push_str("OP_15"),
                OP_16 => ret.push_str("OP_16"),
                len @ 1..=75 => {
                    ret.push_str(&format!("OP_PUSH+{} ", len));
                    if i + 1 + len as usize <= script.len() {
                        ret.push_str(&hex::encode(&script[i + 1..i + 1 + len as usize]));
                    } else {
                        break;
                    }
                }
                OP_PUSHDATA1 => {
                    ret.push_str("OP_PUSHDATA1 ");
                    if i + 2 <= script.len() {
                        let len = script[i + 1] as usize;
                        ret.push_str(&format!("{} ", len));
                        if i + 2 + len <= script.len() {
                            ret.push_str(&hex::encode(&script[i + 2..i + 2 + len]));
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                OP_PUSHDATA2 => {
                    ret.push_str("OP_PUSHDATA2 ");
                    if i + 3 <= script.len() {
                        let len = ((script[i + 1] as usize) << 0) + ((script[i + 2] as usize) << 8);
                        ret.push_str(&format!("{} ", len));
                        if i + 3 + len <= script.len() {
                            ret.push_str(&hex::encode(&script[i + 3..i + 3 + len]));
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                OP_PUSHDATA4 => {
                    ret.push_str("OP_PUSHDATA4 ");
                    if i + 5 <= script.len() {
                        let len = ((script[i + 1] as usize) << 0)
                            + ((script[i + 2] as usize) << 8)
                            + ((script[i + 3] as usize) << 16)
                            + ((script[i + 4] as usize) << 24);
                        ret.push_str(&format!("{} ", len));
                        if i + 5 + len <= script.len() {
                            ret.push_str(&hex::encode(&script[i..i + len]));
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                OP_NOP => ret.push_str("OP_NOP"),
                OP_IF => ret.push_str("OP_IF"),
                OP_NOTIF => ret.push_str("OP_NOTIF"),
                OP_ELSE => ret.push_str("OP_ELSE"),
                OP_ENDIF => ret.push_str("OP_ENDIF"),
                OP_VERIFY => ret.push_str("OP_VERIFY"),
                OP_RETURN => ret.push_str("OP_RETURN"),
                OP_TOALTSTACK => ret.push_str("OP_TOALTSTACK"),
                OP_FROMALTSTACK => ret.push_str("OP_FROMALTSTACK"),
                OP_IFDUP => ret.push_str("OP_IFDUP"),
                OP_DEPTH => ret.push_str("OP_DEPTH"),
                OP_DROP => ret.push_str("OP_DROP"),
                OP_DUP => ret.push_str("OP_DUP"),
                OP_NIP => ret.push_str("OP_NIP"),
                OP_OVER => ret.push_str("OP_OVER"),
                OP_PICK => ret.push_str("OP_PICK"),
                OP_ROLL => ret.push_str("OP_ROLL"),
                OP_ROT => ret.push_str("OP_ROT"),
                OP_SWAP => ret.push_str("OP_SWAP"),
                OP_TUCK => ret.push_str("OP_TUCK"),
                OP_2DROP => ret.push_str("OP_2DROP"),
                OP_2DUP => ret.push_str("OP_2DUP"),
                OP_3DUP => ret.push_str("OP_3DUP"),
                OP_2OVER => ret.push_str("OP_2OVER"),
                OP_2ROT => ret.push_str("OP_2ROT"),
                OP_2SWAP => ret.push_str("OP_2SWAP"),
                OP_CAT => ret.push_str("OP_CAT"),
                OP_SPLIT => ret.push_str("OP_SPLIT"),
                OP_SIZE => ret.push_str("OP_SIZE"),
                OP_AND => ret.push_str("OP_AND"),
                OP_OR => ret.push_str("OP_OR"),
                OP_XOR => ret.push_str("OP_XOR"),
                OP_EQUAL => ret.push_str("OP_EQUAL"),
                OP_EQUALVERIFY => ret.push_str("OP_EQUALVERIFY"),
                OP_1ADD => ret.push_str("OP_1ADD"),
                OP_1SUB => ret.push_str("OP_1SUB"),
                OP_NEGATE => ret.push_str("OP_NEGATE"),
                OP_ABS => ret.push_str("OP_ABS"),
                OP_NOT => ret.push_str("OP_NOT"),
                OP_0NOTEQUAL => ret.push_str("OP_0NOTEQUAL"),
                OP_ADD => ret.push_str("OP_ADD"),
                OP_SUB => ret.push_str("OP_SUB"),
                OP_DIV => ret.push_str("OP_DIV"),
                OP_MOD => ret.push_str("OP_MOD"),
                OP_BOOLAND => ret.push_str("OP_BOOLAND"),
                OP_BOOLOR => ret.push_str("OP_BOOLOR"),
                OP_NUMEQUAL => ret.push_str("OP_NUMEQUAL"),
                OP_NUMEQUALVERIFY => ret.push_str("OP_NUMEQUALVERIFY"),
                OP_NUMNOTEQUAL => ret.push_str("OP_NUMNOTEQUAL"),
                OP_LESSTHAN => ret.push_str("OP_LESSTHAN"),
                OP_GREATERTHAN => ret.push_str("OP_GREATERTHAN"),
                OP_LESSTHANOREQUAL => ret.push_str("OP_LESSTHANOREQUAL"),
                OP_GREATERTHANOREQUAL => ret.push_str("OP_GREATERTHANOREQUAL"),
                OP_MIN => ret.push_str("OP_MIN"),
                OP_MAX => ret.push_str("OP_MAX"),
                OP_WITHIN => ret.push_str("OP_WITHIN"),
                OP_NUM2BIN => ret.push_str("OP_NUM2BIN"),
                OP_BIN2NUM => ret.push_str("OP_BIN2NUM"),
                OP_RIPEMD160 => ret.push_str("OP_RIPEMD160"),
                OP_SHA1 => ret.push_str("OP_SHA1"),
                OP_SHA256 => ret.push_str("OP_SHA256"),
                OP_HASH160 => ret.push_str("OP_HASH160"),
                OP_HASH256 => ret.push_str("OP_HASH256"),
                OP_CODESEPARATOR => ret.push_str("OP_CODESEPARATOR"),
                OP_CHECKSIG => ret.push_str("OP_CHECKSIG"),
                OP_CHECKSIGVERIFY => ret.push_str("OP_CHECKSIGVERIFY"),
                OP_CHECKMULTISIG => ret.push_str("OP_CHECKMULTISIG"),
                OP_CHECKMULTISIGVERIFY => ret.push_str("OP_CHECKMULTISIGVERIFY"),
                OP_CHECKLOCKTIMEVERIFY => ret.push_str("OP_CHECKLOCKTIMEVERIFY"),
                OP_CHECKSEQUENCEVERIFY => ret.push_str("OP_CHECKSEQUENCEVERIFY"),
                _ => ret.push_str(&format!("{}", script[i])),
            }
            i = next_op(i, script);
        }

        // Add whatever is remaining if we exited early
        if i < script.len() {
            for j in i..script.len() {
                ret.push_str(&format!(" {}", script[j]));
            }
        }
        ret.push_str("]");
        f.write_str(&ret)
    }
}

/// Enum zur Darstellung des analysierten Skripttyps
#[derive(Debug, Clone, PartialEq)]
pub enum ScriptType {
    P2PKH([u8; 20]), // Enthält den public key hash
    Multisig {
        m: usize,           // Anzahl erforderlicher Signaturen
        n: usize,           // Gesamtzahl der Schlüssel
        pubkeys: Vec<Vec<u8>>, // Öffentliche Schlüssel
    },
    Unknown,
}

/// Analysiert einen P2SH-Redeem-Skript und bestimmt dessen Typ
pub fn analyze_p2sh_redeem_script(script: &Script) -> Result<ScriptType> {
    let bytes = script.to_bytes();
    let len = bytes.len();

    // Prüfen, ob es ein Standard-P2PKH-Skript ist (OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG)
    if len == 25 && bytes[0] == op_codes::OP_DUP && bytes[1] == op_codes::OP_HASH160 && bytes[2] == 20 && bytes[23] == op_codes::OP_EQUALVERIFY && bytes[24] == op_codes::OP_CHECKSIG {
        let pubkey_hash: [u8; 20] = bytes[3..23].try_into().map_err(|_| Error::BadData("Invalid pubkey hash length".to_string()))?;
        return Ok(ScriptType::P2PKH(pubkey_hash));
    }

    // Prüfen, ob es ein Multisig-Skript ist (OP_m <pubkey1> ... <pubkeyN> OP_n OP_CHECKMULTISIG)
    if len >= 4 && bytes[len - 1] == op_codes::OP_CHECKMULTISIG {
        let m = (bytes[0] - op_codes::OP_1 + 1) as usize;
        let n = (bytes[len - 2] - op_codes::OP_1 + 1) as usize;
        if m > 0 && n >= m && n <= 20 {
            let mut pubkeys = Vec::new();
            let mut offset = 1; // Start nach OP_m
            for _ in 0..n {
                if offset >= len - 2 {
                    return Err(Error::BadData("Invalid multisig script: insufficient data".to_string()));
                }
                let key_len = bytes[offset] as usize;
                offset += 1;
                if offset + key_len > len - 2 {
                    return Err(Error::BadData("Invalid multisig script: key length exceeds script".to_string()));
                }
                let pubkey = bytes[offset..offset + key_len].to_vec();
                if key_len != 33 && key_len != 65 {
                    return Err(Error::BadData("Invalid public key length in multisig".to_string()));
                }
                pubkeys.push(pubkey);
                offset += key_len;
            }
            if offset == len - 2 && bytes[offset] == (op_codes::OP_1 + n as u8 - 1) {
                return Ok(ScriptType::Multisig { m, n, pubkeys });
            }
        }
    }

    Ok(ScriptType::Unknown)
}

/// Konvertiert eine P2SH-Adresse in ein transparentes Format (Bare Multisig oder P2PKH)
pub fn convert_p2sh_to_transparent(
    p2sh_address: &AddressForm,
    network: Network,
    redeem_script: &Script,
) -> Result<(ScriptType, AddressForm)> {
    // Schritt 1: Dekodiere die P2SH-Adresse, um den Script-Hash zu erhalten
    let (version, script_hash) = match p2sh_address {
        AddressForm::Bytes(bytes) => {
            if bytes.len() != 25 {
                return Err(Error::BadData("Invalid address length".to_string()));
            }
            let version = bytes[0];
            let payload = bytes[1..21].to_vec();
            let checksum = sha256d(&bytes[..21]);
            if checksum.0[..4] != bytes[21..] {
                return Err(Error::BadData("Invalid checksum".to_string()));
            }
            (version, payload)
        }
        AddressForm::Base58(s) => decode_address(s)?,
    };

    // Schritt 2: Überprüfe, ob die Adresse eine P2SH-Adresse ist
    let expected_version = match network {
        Network::Mainnet => constants::MAINNET_P2SH_VERSION,
        Network::Testnet | Network::STN => constants::TESTNET_P2SH_VERSION,
    };
    if version != expected_version {
        return Err(Error::BadData("Address is not a P2SH address".to_string()));
    }

    // Step 3: Verify the script hash matches the redeem script
    let computed_hash = hash160(&redeem_script.to_bytes());
    if computed_hash.0[..] != script_hash[..] {
        return Err(Error::BadData("Redeem script hash does not match address".to_string()));
    }

    // Step 4: Analyze the provided redeem script
    let script_type = analyze_p2sh_redeem_script(redeem_script)?;

    // Schritt 4: Konvertiere in ein transparentes Format
    match script_type {
        ScriptType::P2PKH(pubkey_hash) => {
            // Für P2PKH: Generiere die P2PKH-Adresse direkt aus dem public key hash
            let p2pkh_address = encode_address(network, TransactionType::P2PKH, &pubkey_hash)?;
            Ok((script_type, AddressForm::Base58(p2pkh_address.to_base58())))
        }
        ScriptType::Multisig { m, n, pubkeys } => {
            // Für Multisig: Erstelle ein Bare-Multisig-Skript
            let mut bare_script = Script::new();
            bare_script.append((op_codes::OP_1 + m as u8 - 1).into()); // OP_m
            for pubkey in pubkeys.iter().take(n) {
                bare_script.append_slice(pubkey);
            }
            bare_script.append((op_codes::OP_1 + n as u8 - 1).into()); // OP_n
            bare_script.append(op_codes::OP_CHECKMULTISIG);

            // Konvertiere das Bare-Multisig-Skript in einen Script-Hash für eine neue Adresse
            let bare_script_hash = hash160(&bare_script.to_bytes());
            let bare_address = encode_address(network, TransactionType::P2SH, &bare_script_hash.0)?;
            Ok((ScriptType::Multisig { m, n, pubkeys }, AddressForm::Base58(bare_address.to_base58())))
        }
        ScriptType::Unknown => Err(Error::BadData("Unsupported redeem script type".to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::op_codes::*;
    use super::*;

    #[test]
    fn append_data() {
        let mut s = Script::new();
        s.append_data(&vec![]);
        assert!(s.0.len() == 1);

        let mut s = Script::new();
        s.append_data(&vec![0; 1]);
        assert!(s.0[0] == OP_PUSH + 1 && s.0.len() == 2);

        let mut s = Script::new();
        s.append_data(&vec![0; 75]);
        assert!(s.0[0] == OP_PUSH + 75 && s.0.len() == 76);

        let mut s = Script::new();
        s.append_data(&vec![0; 76]);
        assert!(s.0[0] == OP_PUSHDATA1 && s.0[1] == 76 && s.0.len() == 78);

        let mut s = Script::new();
        s.append_data(&vec![0; 255]);
        assert!(s.0[0] == OP_PUSHDATA1 && s.0[1] == 255 && s.0.len() == 257);

        let mut s = Script::new();
        s.append_data(&vec![0; 256]);
        assert!(s.0[0] == OP_PUSHDATA2 && s.0[1] == 0 && s.0[2] == 1 && s.0.len() == 259);

        let mut s = Script::new();
        s.append_data(&vec![0; 65535]);
        assert!(s.0[0] == OP_PUSHDATA2 && s.0[1] == 255 && s.0[2] == 255 && s.0.len() == 65538);

        let mut s = Script::new();
        s.append_data(&vec![0; 65536]);
        assert!(s.0[0] == OP_PUSHDATA4 && s.0[1] == 0 && s.0[2] == 0 && s.0[3] == 1);
        assert!(s.0.len() == 65541);
    }

    // use crate::util::Hash160;
    // #[test]
    // fn test_from_address() {
    //     let address = "mfmKD4cP6Na7T8D87XRSiR7shA1HNGSaec"; // Testnet address
    //     let script = Script::from_address(address).unwrap(); // or create_script_from_address
    //     let expected_hash160 = Hash160([0x02, 0xb7, 0x48, 0x13, 0xb0, 0x47, 0x60, 0x6b, 0x4b, 0x3f,
    //                                 0xbd, 0xfb, 0x1a, 0x6e, 0x8e, 0x05, 0x3f, 0xdb, 0x8d, 0xab]);
    //     let expected_script = create_lock_script(&expected_hash160);
    //     assert_eq!(script, expected_script);
    // }
    
    #[test]
    fn test_analyze_p2sh_redeem_script() {
        // Testfall 1: P2PKH Redeem-Skript
        let mut p2pkh_script = Script::new();
        p2pkh_script.append(op_codes::OP_DUP);
        p2pkh_script.append(op_codes::OP_HASH160);
        let pubkey_hash = [0u8; 20]; // Dummy public key hash
        p2pkh_script.append_slice(&pubkey_hash);
        p2pkh_script.append(op_codes::OP_EQUALVERIFY);
        p2pkh_script.append(op_codes::OP_CHECKSIG);

        let result = analyze_p2sh_redeem_script(&p2pkh_script).unwrap();
        assert_eq!(result, ScriptType::P2PKH(pubkey_hash));

        // Testfall 2: Multisig Redeem-Skript (2-of-3)
        let mut multisig_script = Script::new();
        multisig_script.append(op_codes::OP_2);
        let pubkey1 = vec![0x02; 33]; // Dummy compressed public key
        let pubkey2 = vec![0x03; 33];
        let pubkey3 = vec![0x04; 33];
        multisig_script.append_slice(&pubkey1);
        multisig_script.append_slice(&pubkey2);
        multisig_script.append_slice(&pubkey3);
        multisig_script.append(op_codes::OP_3);
        multisig_script.append(op_codes::OP_CHECKMULTISIG);

        let result = analyze_p2sh_redeem_script(&multisig_script).unwrap();
        assert_eq!(
            result,
            ScriptType::Multisig {
                m: 2,
                n: 3,
                pubkeys: vec![pubkey1, pubkey2, pubkey3],
            }
        );

        // Testfall 3: Ungültiges Skript
        let invalid_script = Script::new();
        let result = analyze_p2sh_redeem_script(&invalid_script).unwrap();
        assert_eq!(result, ScriptType::Unknown);
    }

    #[test]
    fn test_convert_p2sh_to_transparent() {
    let network = Network::Mainnet;

    // Testfall 1: P2SH mit P2PKH-Redeem-Skript
    let pubkey_hash = [0u8; 20];
    let mut redeem_script = Script::new();
    redeem_script.append(op_codes::OP_DUP);
    redeem_script.append(op_codes::OP_HASH160);
    redeem_script.append_slice(&pubkey_hash);
    redeem_script.append(op_codes::OP_EQUALVERIFY);
    redeem_script.append(op_codes::OP_CHECKSIG);
    let script_hash = hash160(&redeem_script.to_bytes());
    let p2sh_address = encode_address(network, TransactionType::P2SH, &script_hash.0).unwrap();
    let address_form = AddressForm::Base58(p2sh_address.to_base58());

    let (script_type, new_address) = convert_p2sh_to_transparent(&address_form, network, &redeem_script).unwrap();
    assert_eq!(script_type, ScriptType::P2PKH(pubkey_hash));
    let expected_p2pkh = encode_address(network, TransactionType::P2PKH, &pubkey_hash).unwrap();
    assert_eq!(new_address.to_string(), expected_p2pkh.to_base58());

    // Testfall 2: P2SH mit Multisig-Redeem-Skript
    let mut multisig_script = Script::new();
    multisig_script.append(op_codes::OP_2);
    let pubkey1 = vec![0x02; 33];
    let pubkey2 = vec![0x03; 33];
    multisig_script.append_slice(&pubkey1);
    multisig_script.append_slice(&pubkey2);
    multisig_script.append(op_codes::OP_2);
    multisig_script.append(op_codes::OP_CHECKMULTISIG);
    let script_hash = hash160(&multisig_script.to_bytes());
    let p2sh_address = encode_address(network, TransactionType::P2SH, &script_hash.0).unwrap();
    let address_form = AddressForm::Base58(p2sh_address.to_base58());

    let (script_type, _new_address) = convert_p2sh_to_transparent(&address_form, network, &multisig_script).unwrap();
    assert_eq!(
        script_type,
        ScriptType::Multisig {
            m: 2,
            n: 2,
            pubkeys: vec![pubkey1, pubkey2],
        }
    );
}
}