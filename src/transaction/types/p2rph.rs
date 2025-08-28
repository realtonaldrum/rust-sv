/// Pay to R-Puzzle Hash (P2RPH)

use sv::script::{Script, NO_FLAGS, TransactionlessChecker};
use sv::script::op_codes::*;
use rand::rngs::OsRng;
use rand::RngCore;
// Note: This is a demonstration file for P2RPH (Pay to R-Puzzle Hash) using rust-sv.
// We use dummy data for public key, signatures, and rHash as generating real keys, valid signatures,
// and computing rHash requires additional setup (e.g., valid private keys, transaction context for signing,
// and extracting R from a signature).
// In practice:
// - pubKey: Valid ECDSA public key (33 or 65 bytes).
// - sig and sig': Valid signatures (~70-72 bytes each), generated with the same k but different SIGHASH flags.
// - rHash: HASH160 (RIPEMD160(SHA256(R))) where R is the public nonce from the signature.
// Note: To mitigate malleation, use two signatures with different SIGHASH types and different k values as advised.

fn main() {
    // Dummy rHash (20 bytes)
    let r_hash: Vec<u8> = vec![0x00; 20]; // Dummy HASH160 value

    // Build scriptPubKey: OP_OVER OP_3 OP_SPLIT OP_NIP OP_1 OP_SPLIT OP_SWAP OP_SPLIT OP_DROP OP_HASH160 <rHash> OP_EQUALVERIFY OP_TUCK OP_CHECKSIGVERIFY OP_CHECKSIG
    let mut script_pubkey = Script::new();
    script_pubkey.append(OP_OVER);
    script_pubkey.append(OP_3);
    script_pubkey.append(OP_SPLIT);
    script_pubkey.append(OP_NIP);
    script_pubkey.append(OP_1);
    script_pubkey.append(OP_SPLIT);
    script_pubkey.append(OP_SWAP);
    script_pubkey.append(OP_SPLIT);
    script_pubkey.append(OP_DROP);
    script_pubkey.append(OP_HASH160);
    script_pubkey.append_data(&r_hash);
    script_pubkey.append(OP_EQUALVERIFY);
    script_pubkey.append(OP_TUCK);
    script_pubkey.append(OP_CHECKSIGVERIFY);
    script_pubkey.append(OP_CHECKSIG);

    // Print scriptPubKey as hex (assuming Script exposes bytes; adjust if needed)
    println!("scriptPubKey (hex): {}", hex::encode(script_pubkey.0)); // Assuming pub struct Script(pub Vec<u8>);

    // Dummy public key (33 bytes, compressed format)
    let pubkey: Vec<u8> = vec![0x02; 33]; // Dummy compressed pubkey

    // Dummy signatures (~72 bytes each)
    let sig_prime: Vec<u8> = vec![0x30; 72]; // Dummy sig' (with different SIGHASH or k)
    let sig: Vec<u8> = vec![0x30; 72]; // Dummy sig

    // Build scriptSig: <sig'> <sig> <pubKey>
    let mut script_sig = Script::new();
    script_sig.append_data(&sig_prime);
    script_sig.append_data(&sig);
    script_sig.append_data(&pubkey);

    // Print scriptSig as hex
    println!("scriptSig (hex): {}", hex::encode(script_sig.0));

    // To evaluate, combine scriptSig + scriptPubKey and evaluate with a checker.
    // Note: This will fail with dummy data as signatures won't verify and rHash won't match.
    // For real evaluation, use TransactionChecker with a valid transaction context.
    // Example (commented out):
    // let mut combined = Script::new();
    // combined.append_slice(&script_sig.0);
    // combined.append_slice(&script_pubkey.0);
    // let result = combined.eval(&mut TransactionlessChecker {}, NO_FLAGS);
    // println!("Evaluation result: {:?}", result);

    // The evaluation process would follow the stack operations as described:
    // Stack starts empty.
    // Push from scriptSig: <sig'> <sig> <pubKey>
    // Then execute scriptPubKey opcodes:
    // OP_OVER: Duplicate second from top -> <sig'> <sig> <pubKey> <sig>
    // OP_3 OP_SPLIT: Split first 3 bytes from top -> <sig'> <sig> <pubKey> <3 bytes> <sig'>
    // OP_NIP: Remove second from top (3 bytes) -> <sig'> <sig> <pubKey> <sig'>
    // OP_1 OP_SPLIT: Split 1 byte (R length) from top -> <sig'> <sig> <pubKey> <R Length> <sig">
    // OP_SWAP: Swap top two -> <sig'> <sig> <pubKey> <sig"> <R Length>
    // OP_SPLIT: Split R using length -> <sig'> <sig> <pubKey> <R> <sig'">
    // OP_DROP: Drop top (sig'") -> <sig'> <sig> <pubKey> <R>
    // OP_HASH160: Hash top (R) to rHashA -> <sig'> <sig> <pubKey> <rHashA>
    // Push <rHash>: <sig'> <sig> <pubKey> <rHashA> <rHash>
    // OP_EQUALVERIFY: Check equal and consume, fail if not
    // OP_TUCK: Tuck pubKey behind sig -> <sig'> <pubKey> <sig> <pubKey>
    // OP_CHECKSIGVERIFY: Check sig against pubKey, consume, verify
    // OP_CHECKSIG: Check sig' against pubKey, leave true/false
}