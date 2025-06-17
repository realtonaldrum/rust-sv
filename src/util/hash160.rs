use ring::digest::{digest, SHA256};
use ripemd::{Ripemd160, Digest};
use std::convert::AsRef;
use std::fmt;

#[derive(Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash160(pub [u8; 20]);

pub fn hash160(data: &[u8]) -> Hash160 {
    let sha256 = digest(&SHA256, data);
    let mut ripemd160 = Ripemd160::new();
    ripemd160.update(AsRef::<[u8]>::as_ref(&sha256.as_ref()));
    let mut hash160 = [0; 20];
    hash160.copy_from_slice(&ripemd160.finalize());
    Hash160(hash160)
}

impl From<[u8; 20]> for Hash160 {
    fn from(bytes: [u8; 20]) -> Self {
        Hash160(bytes)
    }
}

impl fmt::Debug for Hash160 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn tohash160() {
        let pubkey = "126999eabe3f84a3a9f5c09e87faab27484818a0ec1d67b94c9a02e40268499d98538cf770198550adfb9d1d473e5e926bb00e4c58baec1fb42ffa6069781003e4";
        let pubkey = hex::decode(pubkey).unwrap();
        assert!(hex::encode(hash160(&pubkey).0) == "3c231b5e624a42e99a87160c6e4231718a6d77c0");
    }

    #[test]
    fn test_from_array() {
        let bytes = [0u8; 20];
        let hash160: Hash160 = bytes.into();
        assert_eq!(hash160.0, bytes);
    }
}
