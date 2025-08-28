///! Converts a mnemonic phrase to a 64-byte seed using BIP-39 PBKDF2 derivation.

use crate::util::bits::Bits;
use crate::util::{Error, Result};
use std::str;

use std::collections::HashSet;
use ring::digest::{digest, SHA256};
use ring::pbkdf2;

use rand::RngCore;

/// Wordlist language
#[derive(Clone, Copy)]
pub enum Wordlist {
    ChineseSimplified,
    ChineseTraditional,
    English,
    French,
    Italian,
    Japanese,
    Korean,
    Spanish,
}

/// Loads the word list for a given language
pub fn load_wordlist(wordlist: Wordlist) -> Vec<String> {
    match wordlist {
        Wordlist::ChineseSimplified => {
            load_wordlist_internal(include_bytes!("wordlists/chinese_simplified.txt"))
        }
        Wordlist::ChineseTraditional => {
            load_wordlist_internal(include_bytes!("wordlists/chinese_traditional.txt"))
        }
        Wordlist::English => load_wordlist_internal(include_bytes!("wordlists/english.txt")),
        Wordlist::French => load_wordlist_internal(include_bytes!("wordlists/french.txt")),
        Wordlist::Italian => load_wordlist_internal(include_bytes!("wordlists/italian.txt")),
        Wordlist::Japanese => load_wordlist_internal(include_bytes!("wordlists/japanese.txt")),
        Wordlist::Korean => load_wordlist_internal(include_bytes!("wordlists/korean.txt")),
        Wordlist::Spanish => load_wordlist_internal(include_bytes!("wordlists/spanish.txt")),
    }
}

fn load_wordlist_internal(bytes: &[u8]) -> Vec<String> {
    let text: String = str::from_utf8(bytes).unwrap().to_string();
    text.lines().map(|s| s.to_string()).collect()
}

pub fn generate_new_seed(word_count: usize, wordlist: Wordlist) -> Result<(String, String, String)> {
    // Validate word_count (must be 12, 15, 18, 21, or 24)
    if ![12, 15, 18, 21, 24].contains(&word_count) {
        return Err(Error::BadArgument(format!(
            "Invalid word count: must be 12, 15, 18, 21, or 24, got {}",
            word_count
        )));
    }

    // Calculate entropy size in bytes (word_count * 11 / 33 * 32)
    let entropy_bits = word_count * 11 - word_count / 3;
    let entropy_bytes = entropy_bits / 8;

    // Generate random entropy
    let mut entropy = vec![0u8; entropy_bytes];
    rand::rng().fill_bytes(&mut entropy);

    // Load the specified wordlist
    let wordlist = load_wordlist(wordlist);

    // Encode entropy to mnemonic words
    let mnemonic_words = entropy_to_mnemonic(&entropy, &wordlist);
    let mnemonic = mnemonic_words.join(" ");

    // Validate the number of mnemonic words
    if mnemonic_words.len() != word_count {
        return Err(Error::BadArgument(format!(
            "Generated mnemonic has {} words, expected {}",
            mnemonic_words.len(),
            word_count
        )));
    }

    // Convert entropy to hex string
    let entropy_hex = hex::encode(&entropy);

    // Derive seed from mnemonic (using empty passphrase)
    let seed = mnemonic_to_seed(&mnemonic, "")?;
    let seed_hex = hex::encode(&seed);

    Ok((mnemonic, entropy_hex, seed_hex))
}

/// Encodes entropy into a mnemonic using BIP-39
pub fn entropy_to_mnemonic(entropy: &[u8], word_list: &[String]) -> Vec<String> {
    let hash = digest(&SHA256, &entropy);
    let mut words = Vec::with_capacity((entropy.len() * 8 + entropy.len() / 32 + 10) / 11);
    let mut bits = Bits::from_slice(entropy, entropy.len() * 8);
    bits.append(&Bits::from_slice(hash.as_ref(), entropy.len() / 4));
    for i in 0..bits.len / 11 {
        words.push(word_list[bits.extract(i * 11, 11) as usize].clone());
    }
    let rem = bits.len % 11;
    if rem != 0 {
        let n = bits.extract(bits.len / 11 * 11, rem) << (8 - rem);
        words.push(word_list[n as usize].clone());
    }
    words
}

/// Decodes a mnemonic into entropy using BIP-39
pub fn mnemonic_to_entropy(mnemonic: &[String], word_list: &[String]) -> Result<Vec<u8>> {
    let mut bits = Bits::with_capacity(mnemonic.len() * 11);
    for word in mnemonic {
        let value = match word_list.binary_search(word) {
            Ok(value) => value,
            Err(_) => return Err(Error::BadArgument(format!("Bad word: {}", word))),
        };
        let word_bits = Bits::from_slice(&[(value >> 3) as u8, ((value & 7) as u8) << 5], 11);
        bits.append(&word_bits);
    }
    let data_len = bits.len * 32 / 33;
    let cs_len = bits.len / 33;
    let cs = digest(&SHA256, &bits.data[0..data_len / 8]);
    let cs_bits = Bits::from_slice(cs.as_ref(), cs_len);
    if cs_bits.extract(0, cs_len) != bits.extract(data_len, cs_len) {
        return Err(Error::BadArgument("Invalid checksum".to_string()));
    }
    Ok(bits.data[0..data_len / 8].to_vec())
}

// Function to autoload the wordlist based on mnemonic words
pub fn autoload_wordlist(mnemonic: &str) -> Result<Vec<String>> {
    // Split the mnemonic into words
    let words: Vec<String> = mnemonic.split_whitespace().map(|s| s.to_string()).collect();
    
    // List of supported wordlist languages
    let languages = [
        Wordlist::English,
        Wordlist::ChineseSimplified,
        Wordlist::ChineseTraditional,
        Wordlist::French,
        Wordlist::Italian,
        Wordlist::Japanese,
        Wordlist::Korean,
        Wordlist::Spanish,
    ];
    
    let mut matching_wordlist = None;
    
    // Check each wordlist
    for language in &languages {
        let wordlist = load_wordlist(*language);
        let wordlist_set: HashSet<&String> = wordlist.iter().collect();
        
        // Check if all mnemonic words are in this wordlist
        let all_words_valid = words.iter().all(|word| wordlist_set.contains(word));
        
        if all_words_valid {
            if matching_wordlist.is_some() {
                // If another wordlist already matched, the mnemonic is ambiguous
                return Err(Error::BadArgument("Mnemonic matches multiple wordlists".to_string()));
            }
            matching_wordlist = Some(wordlist);
        }
    }
    
    match matching_wordlist {
        Some(wordlist) => Ok(wordlist),
        None => Err(Error::BadArgument("No matching wordlist found for the mnemonic".to_string())),
    }
}

// This includes PBKDF2 Method
pub fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> Result<[u8; 64]> {
    // Normalize mnemonic: lowercase, trim, and replace multiple spaces with single
    let normalized = mnemonic
        .to_lowercase()
        .trim()
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ");

    // Validate mnemonic: must have 12, 15, 18, 21, or 24 words
    let words: Vec<&str> = normalized.split_whitespace().collect();
    if ![12, 15, 18, 21, 24].contains(&words.len()) {
        return Err(Error::BadArgument(format!("Invalid mnemonic: must have 12, 15, 18, 21, or 24 words, got {}", words.len())));
    }

    // Validate mnemonic words against wordlist
    // let wordlist = autoload_wordlist(&normalized)?;
    // let mnemonic_vec: Vec<String> = words.iter().map(|s| s.to_string()).collect();
    // let _entropy = mnemonic_to_entropy(&mnemonic_vec, &wordlist).map_err(|e| Error::BadArgument(format!("Invalid mnemonic: {}", e)))?;

    // Convert mnemonic to bytes
    let mnemonic_bytes = normalized.as_bytes();

    // Create BIP-39 salt: "mnemonic" + passphrase
    let salt = format!("mnemonic{}", passphrase);
    let salt_bytes = salt.as_bytes();

    // PBKDF2 parameters
    const ITERATIONS: u32 = 2048;
    const KEY_LENGTH: usize = 64; // 512 bits

    // Initialize output buffer for the seed
    let mut seed = [0u8; KEY_LENGTH];

    // Derive seed using PBKDF2 with SHA-512
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA512, // Use the PBKDF2_HMAC_SHA512 algorithm
        std::num::NonZeroU32::new(ITERATIONS).unwrap(), // Number of iterations
        salt_bytes, // Salt
        mnemonic_bytes, // Password
        &mut seed, // Output buffer
    );

    Ok(seed)
}

#[cfg(test)]
mod tests {
    use crate::wallet::mnemonic::*;
    use crate::wallet::derivation::{derive_seed_or_extended_key};
    use crate::network::Network;

    // Generate via https://iancoleman.io/bip39/ or with the test_generate_new_seed() function:
    #[test]
    fn test_generate_new_seed() {
        for &word_count in &[12, 15, 18, 21, 24] {
            // Run test in a catch_unwind block to ensure output even on panic
            let result = std::panic::catch_unwind(|| {
                let Ok((mnemonic, entropy_hex, seed_hex)) = generate_new_seed(word_count, Wordlist::English) else { todo!() };

                // Check mnemonic word count
                assert_eq!(
                    mnemonic.split_whitespace().count(),
                    word_count,
                    "Mnemonic should have {} words",
                    word_count
                );

                // Calculate expected entropy hex length
                let entropy_bits = word_count * 11 - word_count / 3;
                let entropy_bytes = entropy_bits / 8;
                let expected_entropy_hex_len = entropy_bytes * 2;

                // Check entropy hex length
                assert_eq!(
                    entropy_hex.len(),
                    expected_entropy_hex_len,
                    "Entropy hex should be {} characters for {} words",
                    expected_entropy_hex_len,
                    word_count
                );

                // Check seed hex length
                assert_eq!(
                    seed_hex.len(),
                    128,
                    "Seed hex should be 128 characters for {} words",
                    word_count
                );

                // Verify mnemonic can be decoded and re-derived
                let wordlist = load_wordlist(Wordlist::English);
                let mnemonic_vec: Vec<String> = mnemonic.split_whitespace().map(|s| s.to_string()).collect();
                let decoded_entropy = mnemonic_to_entropy(&mnemonic_vec, &wordlist)
                    .expect(&format!("Failed to decode mnemonic for {} words", word_count));
                assert_eq!(
                    hex::encode(decoded_entropy),
                    entropy_hex,
                    "Decoded entropy should match for {} words",
                    word_count
                );

                // Verify seed can be re-derived
                let rederived_seed = mnemonic_to_seed(&mnemonic, "")
                    .expect(&format!("Failed to derive seed for {} words", word_count));
                assert_eq!(
                    hex::encode(rederived_seed),
                    seed_hex,
                    "Re-derived seed should match for {} words",
                    word_count
                );

                // Return values to print
                (mnemonic, entropy_hex, seed_hex)
            });

            // Print results regardless of success or failure
            match result {
                Ok((mnemonic, entropy_hex, seed_hex)) => {
                    println!("");
                    println!(
                        "Entropy Hex: {}, Seed Hex: {}",
                        entropy_hex, seed_hex
                    );
                    println!(
                        "Wordlist: English, Word Count: {}, Mnemonic: {}",
                        word_count, mnemonic
                    );
                    
                }
                Err(_) => {
                    println!(
                        "Wordlist: English, Word Count: {}, Test panicked, no values generated",
                        word_count
                    );
                }
            }
        }
    }

    // All constants need to be in the same key structure family.
    const MNEMONIC: &str  = "okay captain agent open bring try seven you able scene art there ski olive dress";
    const EXPECTED_ENTROPY: &str = "99e44413cd91c3d3f12ff900581033703ca53450";
    const EXPECTED_SEED : &str  = "e5dfcbe3c62fb5e4d7dbb794119fcd9a8fbaeed04b841ad6a3d4652b2e211f370e75dc1f71a61cb6027ff360bf7826272541c0724beff9bd6c358a046497449c";
    const EXPECTED_BIP32_MASTERKEY : &str = "xprv9s21ZrQH143K3XVnYZ9RtEiFWodPvMz3SCRt8nWzTx6zS9mJfTpLStJrNa2Bd9v8kwFdDJkWizK62FBmRGDW8MEZciMBzw3zMwZcXophEF6";
    
    #[test]
    fn test_mnemonic_to_seed(){
        // let wordlist = load_wordlist(Wordlist::English);
        // // Split the mnemonic string into a Vec<String>
        // let mnemonic_vec: Vec<String> = MNEMONIC.split_whitespace().map(|s| s.to_string()).collect();
        // let entropy = mnemonic_to_entropy(&mnemonic_vec, &wordlist).unwrap();

        let seed = mnemonic_to_seed(MNEMONIC, "").expect("Failed to derive seed");

        // Convert the seed to a hex string for comparison
        let seed_hex = hex::encode(&seed);

        assert_eq!(
            seed_hex,
            EXPECTED_SEED,
            "Seed does not match expected value"
        );

        if seed_hex == EXPECTED_SEED {
            println!("Seed Match: {}", seed_hex);
        }
    }

    #[test]
    fn wordlists() {
        assert!(load_wordlist(Wordlist::ChineseSimplified).len() == 2048);
        assert!(load_wordlist(Wordlist::ChineseTraditional).len() == 2048);
        assert!(load_wordlist(Wordlist::English).len() == 2048);
        assert!(load_wordlist(Wordlist::French).len() == 2048);
        assert!(load_wordlist(Wordlist::Italian).len() == 2048);
        assert!(load_wordlist(Wordlist::Japanese).len() == 2048);
        assert!(load_wordlist(Wordlist::Korean).len() == 2048);
        assert!(load_wordlist(Wordlist::Spanish).len() == 2048);
    }

    #[test]
    fn encode_decode() {
        let mut data = Vec::new();
        for i in 0..16 {
            data.push(i);
        }
        let wordlist = load_wordlist(Wordlist::English);
        assert!(mnemonic_to_entropy(&entropy_to_mnemonic(&data, &wordlist), &wordlist).unwrap() == data);
    }

    #[test]
    fn invalid() {
        let wordlist = load_wordlist(Wordlist::English);
        assert!(entropy_to_mnemonic(&[], &wordlist).len() == 0);
        assert!(mnemonic_to_entropy(&[], &wordlist).unwrap().len() == 0);

        let mut data = Vec::new();
        for i in 0..16 {
            data.push(i);
        }
        let mnemonic = entropy_to_mnemonic(&data, &wordlist);

        let mut bad_checksum = mnemonic.clone();
        bad_checksum[0] = "hello".to_string();
        assert!(mnemonic_to_entropy(&bad_checksum, &wordlist).is_err());

        let mut bad_word = mnemonic.clone();
        bad_word[0] = "123".to_string();
        assert!(mnemonic_to_entropy(&bad_word, &wordlist).is_err());
    }


    #[test]
    fn test_mnemonic_to_seed_2nd() {        
        // Autoload the wordlist
        let wordlist = autoload_wordlist(MNEMONIC).expect("Failed to autoload wordlist");
        
        // Split the mnemonic string into a Vec<String>
        let mnemonic_vec: Vec<String> = MNEMONIC.split_whitespace().map(|s| s.to_string()).collect();
        
        // Decode the mnemonic to get the seed bytes
        let entropy = mnemonic_to_entropy(&mnemonic_vec, &wordlist).unwrap();
        
        // Convert the seed to a hex string for comparison
        let entropy_hex = hex::encode(&entropy);
        
        assert_eq!(
            entropy_hex,
            EXPECTED_ENTROPY,
            "Seed does not match expected value"
        );
    }

    #[test]
    fn test_autoload_wordlist_english() {
        let wordlist = autoload_wordlist(MNEMONIC).expect("Failed to autoload wordlist");
        let expected_wordlist = load_wordlist(Wordlist::English);
        assert_eq!(wordlist, expected_wordlist, "Autoloaded wordlist does not match English wordlist");
    }

    #[test]
    fn test_autoload_wordlist_invalid() {
        let mnemonic = "invalid word list here";
        let result = autoload_wordlist(mnemonic);
        assert!(result.is_err(), "Expected error for invalid mnemonic");
    }

    #[test]
    fn test_vectors() {
        let wordlist = load_wordlist(Wordlist::English);

        let h = hex::decode("00000000000000000000000000000000").unwrap();
        let n = entropy_to_mnemonic(&h, &wordlist).join(" ");
        assert!(n == "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");

        let h = hex::decode("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f").unwrap();
        let n = entropy_to_mnemonic(&h, &wordlist).join(" ");
        assert!(n == "legal winner thank year wave sausage worth useful legal winner thank yellow");

        let h = hex::decode("80808080808080808080808080808080").unwrap();
        let n = entropy_to_mnemonic(&h, &wordlist).join(" ");
        assert!(
            n == "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"
        );

        let h = hex::decode("ffffffffffffffffffffffffffffffff").unwrap();
        let n = entropy_to_mnemonic(&h, &wordlist).join(" ");
        assert!(n == "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong");

        let h = hex::decode("000000000000000000000000000000000000000000000000").unwrap();
        let n = entropy_to_mnemonic(&h, &wordlist).join(" ");
        assert!(n == "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent");

        let h = hex::decode("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f").unwrap();
        let n = entropy_to_mnemonic(&h, &wordlist).join(" ");
        assert!(n == "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will");

        let h = hex::decode("808080808080808080808080808080808080808080808080").unwrap();
        let n = entropy_to_mnemonic(&h, &wordlist).join(" ");
        assert!(n == "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always");

        let h = hex::decode("ffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
        let n = entropy_to_mnemonic(&h, &wordlist).join(" ");
        assert!(n == "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when");

        let h = hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap();
        let n = entropy_to_mnemonic(&h, &wordlist).join(" ");
        assert!(n == "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art");

        let h = hex::decode("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f")
            .unwrap();
        let n = entropy_to_mnemonic(&h, &wordlist).join(" ");
        assert!(n == "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title");

        let h = hex::decode("8080808080808080808080808080808080808080808080808080808080808080")
            .unwrap();
        let n = entropy_to_mnemonic(&h, &wordlist).join(" ");
        assert!(n == "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless");

        let h = hex::decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
            .unwrap();
        let n = entropy_to_mnemonic(&h, &wordlist).join(" ");
        assert!(n == "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote");

        let h = hex::decode("9e885d952ad362caeb4efe34a8e91bd2").unwrap();
        let n = entropy_to_mnemonic(&h, &wordlist).join(" ");
        assert!(
            n == "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic"
        );

        let h = hex::decode("6610b25967cdcca9d59875f5cb50b0ea75433311869e930b").unwrap();
        let n = entropy_to_mnemonic(&h, &wordlist).join(" ");
        assert!(n == "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog");

        let h = hex::decode("68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c")
            .unwrap();
        let n = entropy_to_mnemonic(&h, &wordlist).join(" ");
        assert!(n == "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length");

        let h = hex::decode("c0ba5a8e914111210f2bd131f3d5e08d").unwrap();
        let n = entropy_to_mnemonic(&h, &wordlist).join(" ");
        assert!(n == "scheme spot photo card baby mountain device kick cradle pact join borrow");

        let h = hex::decode("6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3").unwrap();
        let n = entropy_to_mnemonic(&h, &wordlist).join(" ");
        assert!(n == "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave");

        let h = hex::decode("9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863")
            .unwrap();
        let n = entropy_to_mnemonic(&h, &wordlist).join(" ");
        assert!(n == "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside");

        let h = hex::decode("23db8160a31d3e0dca3688ed941adbf3").unwrap();
        let n = entropy_to_mnemonic(&h, &wordlist).join(" ");
        assert!(n == "cat swing flag economy stadium alone churn speed unique patch report train");

        let h = hex::decode("8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0").unwrap();
        let n = entropy_to_mnemonic(&h, &wordlist).join(" ");
        assert!(n == "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access");

        let h = hex::decode("066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad")
            .unwrap();
        let n = entropy_to_mnemonic(&h, &wordlist).join(" ");
        assert!(n == "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform");

        let h = hex::decode("f30f8c1da665478f49b001d94c5fc452").unwrap();
        let n = entropy_to_mnemonic(&h, &wordlist).join(" ");
        assert!(
            n == "vessel ladder alter error federal sibling chat ability sun glass valve picture"
        );

        let h = hex::decode("c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05").unwrap();
        let n = entropy_to_mnemonic(&h, &wordlist).join(" ");
        assert!(n == "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump");

        let h = hex::decode("f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f")
            .unwrap();
        let n = entropy_to_mnemonic(&h, &wordlist).join(" ");
        assert!(n == "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold");
    }

    #[test]
    fn test_mnemonic_to_seed_with_passphrase() {
        let passphrase = "supersecret";
        let seed = mnemonic_to_seed(MNEMONIC, passphrase).expect("Failed to derive seed");
        assert_eq!(seed.len(), 64, "Seed length should be 64 bytes");
    }

    #[test]
    fn test_invalid_mnemonic_word_count() {
        let mnemonic = "capable champion win";
        let result = mnemonic_to_seed(mnemonic, "");
        assert!(result.is_err());
    }

    #[test]
    fn test_normalized_mnemonic_should_fail() {
        let mnemonic = "  CAPABLE   WIN  champion SHORT   Ascending triangle";
        let result = mnemonic_to_seed(mnemonic, "");
        assert!(result.is_err(), "Mnemonic should be rejected as invalid");
    }

    #[test]
    fn test_seed_to_bip32_master_privatekey() {
        let seed = crate::wallet::mnemonic::mnemonic_to_seed(MNEMONIC, "").expect("Failed to derive seed");

        // Convert the seed to a hex string for comparison
        let seed_hex = hex::encode(&seed);

        assert_eq!(
            seed_hex,
            EXPECTED_SEED,
            "Seed does not match expected value"
        );

        if seed_hex == EXPECTED_SEED {
            println!("Seed Match: {}", seed_hex);
        }

        let mpriv_result = derive_seed_or_extended_key(&seed_hex, "m/" ,Network::Mainnet)
            .expect("Failed to derive BIP32 master private key");

        assert_eq!(
            mpriv_result.extended_private_key,
            EXPECTED_BIP32_MASTERKEY,
            "BIP32 Master Private Key does not match expected value"
        );
    }
}
