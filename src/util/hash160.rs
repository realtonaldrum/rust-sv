use hex;
use ring::digest::{digest, SHA256};
use digest::core_api::CoreWrapper;
use ripemd::{Ripemd160Core, Digest};
use std::fmt;

#[derive(Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash160(pub [u8; 20]);

pub fn hash160(data: &[u8]) -> Hash160 {
    let sha256 = digest(&SHA256, data);
    let mut ripemd160 = CoreWrapper::<Ripemd160Core>::from_core(Ripemd160Core::new());
    ripemd160.update(sha256.as_ref());
    let mut hash160 = [0; 20];
    hash160.copy_from_slice(&ripemd160.finalize());
    Hash160(hash160)
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
}
