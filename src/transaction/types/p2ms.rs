/// Pay to Multi Signature (P2MS)
/// 
/// use sv::script::{Script, NO_FLAGS, TransactionlessChecker};
use sv::script::op_codes::*;

// Note: This is a demonstration file for P2MS (Pay to Multi Signature) using rust-sv.
// We use dummy data for public keys and signatures as generating real keys and valid signatures
// requires additional setup (e.g., valid private keys and transaction context for signing).
// In practice, use valid ECDSA public keys (33 or 65 bytes) and signatures (~70-72 bytes).

fn main() {
    // Dummy public keys (33 bytes each, compressed format)
    let pubkey1: Vec<u8> = vec![0x02; 33]; // Dummy compressed pubkey
    let pubkey2: Vec<u8> = vec![0x02; 33];
    let pubkey3: Vec<u8> = vec![0x02; 33];
    let pubkey4: Vec<u8> = vec![0x02; 33];
    let pubkey5: Vec<u8> = vec![0x02; 33];

    // Build scriptPubKey: OP_3 <pubKey1> <pubKey2> <pubKey3> <pubKey4> <pubKey5> OP_5 OP_CHECKMULTISIG
    let mut script_pubkey = Script::new();
    script_pubkey.append(OP_3);
    script_pubkey.append_data(&pubkey1);
    script_pubkey.append_data(&pubkey2);
    script_pubkey.append_data(&pubkey3);
    script_pubkey.append_data(&pubkey4);
    script_pubkey.append_data(&pubkey5);
    script_pubkey.append(OP_5);
    script_pubkey.append(OP_CHECKMULTISIG);

    // Print scriptPubKey as hex (assuming Script exposes bytes; adjust if needed)
    println!("scriptPubKey (hex): {}", hex::encode(script_pubkey.0)); // Assuming pub struct Script(pub Vec<u8>);

    // Dummy signatures (~72 bytes each)
    let sig1: Vec<u8> = vec![0x30; 72]; // Dummy signature
    let sig2: Vec<u8> = vec![0x30; 72];
    let sig4: Vec<u8> = vec![0x30; 72];

    // Build scriptSig: OP_1 <sig1> <sig2> <sig4>
    // Note: OP_1 is used as per the example, but typically OP_0 is used for the off-by-one bug in OP_CHECKMULTISIG.
    let mut script_sig = Script::new();
    script_sig.append(OP_1);
    script_sig.append_data(&sig1);
    script_sig.append_data(&sig2);
    script_sig.append_data(&sig4);

    // Print scriptSig as hex
    println!("scriptSig (hex): {}", hex::encode(script_sig.0));

    // To evaluate, combine scriptSig + scriptPubKey and evaluate with a checker.
    // Note: This will fail with dummy data as signatures won't verify.
    // For real evaluation, use TransactionChecker with a valid transaction context.
    // Example (commented out):
    // let mut combined = Script::new();
    // combined.append_slice(&script_sig.0);
    // combined.append_slice(&script_pubkey.0);
    // let result = combined.eval(&mut TransactionlessChecker {}, NO_FLAGS);
    // println!("Evaluation result: {:?}", result);

    // The evaluation process would push items to the stack as described:
    // - Start empty
    // - Push from scriptSig: 1 <sig1> <sig2> <sig4>
    // - Push from scriptPubKey: 3 <pubKey1> <pubKey2> <pubKey3> <pubKey4> <pubKey5> 5
    // - Execute OP_CHECKMULTISIG, which consumes the items, verifies signatures (in order), and pushes true/false.
    // Due to the bug, the extra '1' (or typically 0) is popped but not used.
}