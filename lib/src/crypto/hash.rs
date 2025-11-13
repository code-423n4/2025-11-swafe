use ark_std::rand::{CryptoRng, Error as RandError, Rng, RngCore};
use serde::Serialize;
use sha3::{digest::XofReader, Digest, Sha3_256};

pub const SIZE_HASH: usize = 32;

use crate::{crypto::BINCODE_CONFIG, encode::Tagged};

#[derive(Serialize)]
pub struct EmptyInfo;

impl Tagged for EmptyInfo {
    const SEPARATOR: &'static str = "v0:info-empty";
}

/// Hash a tagged value
///
/// A separator is used to ensure that the hash is unique for each type
/// even if they have the same serialization as bytes, this helps prevent
/// "type confusion attacks" where, e.g. a hash is signed but
/// the preimage can be interpreted as a number of different types.
pub fn hash<T: Tagged>(val: &T) -> [u8; SIZE_HASH] {
    let mut hsh = Sha3_256::new();
    let encoded_data = val.encode();
    hsh.update(&encoded_data);
    hsh.finalize().into()
}

pub fn kdf_rng<M: Serialize, T: Tagged>(ikm: &M, info: &T) -> impl RngCore + CryptoRng {
    let ikm = bincode::serde::encode_to_vec(ikm, BINCODE_CONFIG).unwrap();
    let mut hsh = sha3_kmac::KmacXof256::new(&ikm, T::SEPARATOR.as_bytes()).unwrap();
    hsh.update(&info.encode());
    XofRng(hsh.finalize_xof())
}

/// Key Derivation Function using KMAC256 in extendable output function (XOF) mode
///
/// It uses the separator of the type as the "customization string" for KMAC.
/// This allows us to also use it as a "type separated message authentication code"
///
/// This follows the book specification by encoding (domain_separator, value) as a tuple.
pub fn kdf<M: Serialize, T: Tagged>(ikm: &M, val: &T, output: &mut [u8]) {
    kdf_rng(ikm, val).fill(output);
}

/// Fixed-Size Key Derivation Function using KMAC256
pub fn kdfn<M: Serialize, T: Tagged, const N: usize>(ikm: &M, val: &T) -> [u8; N] {
    let mut buf = [0u8; N];
    kdf(ikm, val, &mut buf);
    buf
}

/// Fixed-Size Key Derivation Function using KMAC256
pub fn kdfn_ser<M: Serialize, T: Tagged, const N: usize>(ikm: &M, val: &T) -> [u8; N] {
    let ikm = bincode::serde::encode_to_vec(ikm, BINCODE_CONFIG).unwrap();
    let mut buf = [0u8; N];
    kdf(&ikm, val, &mut buf);
    buf
}

/// Enables derandomization using the KDF
pub struct XofRng<T: XofReader>(T);

impl<T: XofReader> RngCore for XofRng<T> {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.read(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
        self.fill_bytes(dest);
        Ok(())
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }
}

impl<T: XofReader> CryptoRng for XofRng<T> {}

#[cfg(test)]
mod tests {
    use super::*;

    // Create a "Tagged" struct which serializes as the raw bytes:
    // WARNING: ONLY use this if you KNOW what you're doing.
    #[derive(serde::Serialize)]
    struct Test {
        bytes: Vec<u8>,
    }

    impl Tagged for Test {
        const SEPARATOR: &'static str = "v0:test-hash";
    }

    #[test]
    fn test_hash_function() {
        let input = Test {
            bytes: b"test input".to_vec(),
        };
        let result = hash(&input);
        assert_eq!(result.len(), 32);

        // Test deterministic
        let result2 = hash(&input);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_kdf() {
        let ikm: &[u8] = b"input key materialmaterialmaterialmaterialmaterialmaterialmaterial";
        let info = Test {
            bytes: b"test info".to_vec(),
        };
        let mut result = [0u8; 32];
        kdf(&ikm, &info, &mut result);
        assert_eq!(result.len(), 32);

        // Test deterministic
        let mut result2 = [0u8; 32];
        kdf(&ikm, &info, &mut result2);
        assert_eq!(result, result2);

        // Test different info gives different result
        let info2 = Test {
            bytes: "different info".to_string().into_bytes(),
        };
        let mut result3 = [0u8; 32];
        kdf(&ikm, &info2, &mut result3);
        assert_ne!(result, result3);
    }
}
