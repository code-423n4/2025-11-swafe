use ark_std::rand::Rng;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use subtle::{self, ConstantTimeEq};

use crate::crypto::kdf;
use crate::{
    crypto::hash::kdfn,
    encode::Tagged,
    errors::{Result, SwafeError},
};

const SIZE_MAC: usize = 32;
const SIZE_NONCE: usize = 32;
pub const SIZE_KEY: usize = 32;

type Mac = [u8; SIZE_MAC];
type Nonce = [u8; SIZE_NONCE];
pub type Key = [u8; SIZE_KEY];

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug, Hash)]
pub(crate) struct AEADCiphertext {
    ct: Vec<u8>,
    mac: Mac,
    nonce: Nonce,
}

/// A unit type representing the "empty" or default "Associated Data"
#[derive(Default, Serialize)]
pub(crate) struct EmptyAD;

/// KDF input used to derive the XOR-pad from a nonce
#[derive(Serialize)]
struct KDFPad<'a>(&'a Nonce);

// The tagged type over which we compute
// the message authentication code (MAC)
#[derive(Serialize)]
struct MACTuple<'a, 'b, A: Tagged> {
    separator: (&'static str, &'static str),
    nonce: &'a Nonce,
    ct: &'a [u8],
    ad: &'b A,
}

#[derive(Serialize)]
struct NonceTuple<'a, 'b, A: Tagged> {
    separator: (&'static str, &'static str),
    nonce: &'a Nonce,
    pt: &'a [u8],
    ad: &'b A,
}

impl<'a> Tagged for KDFPad<'a> {
    const SEPARATOR: &'static str = "v0:sym-pad";
}

impl Tagged for EmptyAD {
    const SEPARATOR: &'static str = "v0:sym-ad-empty";
}

impl<'a, 'b, A: Tagged> Tagged for MACTuple<'a, 'b, A> {
    const SEPARATOR: &'static str = "v0:sym-mac";
}

impl<'a, 'b, A: Tagged> Tagged for NonceTuple<'a, 'b, A> {
    const SEPARATOR: &'static str = "v0:sym-nonce";
}

/// Key-Committing Authenticated Encryption with Associated Data (AEAD)
pub(crate) fn seal<M: Tagged, A: Tagged, R: Rng>(
    rng: &mut R,
    key: &Key,
    pt: &M,
    ad: &A,
) -> AEADCiphertext {
    // serialize the plaintext
    let pt = bincode::serde::encode_to_vec(pt, bincode::config::standard()).unwrap();

    // sample synthetic nonce
    let nonce: Nonce = kdfn(
        key,
        &NonceTuple {
            separator: (M::SEPARATOR, A::SEPARATOR),
            nonce: &rng.gen::<Nonce>(),
            pt: &pt,
            ad,
        },
    );

    // encrypt the plaintext
    let mut ct = vec![0u8; pt.len()];
    kdf(key, &KDFPad(&nonce), &mut ct);
    for i in 0..ct.len() {
        ct[i] ^= pt[i];
    }

    // generate the MAC
    let mac: [u8; SIZE_MAC] = kdfn(
        key,
        &MACTuple {
            separator: (M::SEPARATOR, A::SEPARATOR),
            nonce: &nonce,
            ct: ct.as_slice(),
            ad,
        },
    );
    AEADCiphertext { nonce, ct, mac }
}

/// Key-Committing Authenticated Encryption with Associated Data (AEAD)
pub(crate) fn open<M: Tagged + DeserializeOwned, A: Tagged>(
    key: &Key,
    ct: &AEADCiphertext,
    ad: &A,
) -> Result<M> {
    // check the MAC
    let mac_corr: Mac = kdfn(
        key,
        &MACTuple {
            separator: (M::SEPARATOR, A::SEPARATOR),
            nonce: &ct.nonce,
            ct: &ct.ct,
            ad,
        },
    );
    if mac_corr.ct_eq(&ct.mac).unwrap_u8() != 1 {
        return Err(SwafeError::DecryptionFailed);
    }

    // decrypt the raw plaintext
    let mut pt = vec![0u8; ct.ct.len()];
    kdf(key, &KDFPad(&ct.nonce), &mut pt);
    for (i, byte) in pt.iter_mut().enumerate() {
        *byte ^= ct.ct[i];
    }

    // deserialize to a message
    match bincode::serde::decode_from_slice::<M, _>(&pt, bincode::config::standard()) {
        Ok((msg, n)) => {
            if n != pt.len() {
                Err(SwafeError::DecryptionFailed)
            } else {
                Ok(msg)
            }
        }
        Err(_) => Err(SwafeError::DecryptionFailed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::Tagged;
    use rand::rngs::OsRng;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct TestMsg1 {
        content: String,
        id: u32,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct TestMsg2 {
        content: String,
        id: u32,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct TestAD {
        data: String,
    }

    impl Tagged for TestMsg1 {
        const SEPARATOR: &'static str = "v0:test-message-v1";
    }

    impl Tagged for TestMsg2 {
        const SEPARATOR: &'static str = "v0:test-message-v2";
    }

    impl Tagged for TestAD {
        const SEPARATOR: &'static str = "v0:test-ad";
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0u8; 32];
        let msg = TestMsg1 {
            content: "Hello, World!".to_string(),
            id: 42,
        };

        // encryption/decryption roundtrip
        let ct = seal(&mut OsRng, &key, &msg, &EmptyAD);
        let dec_msg: TestMsg1 = open(&key, &ct, &EmptyAD).unwrap();
        assert_eq!(msg, dec_msg);
    }

    #[test]
    fn test_decrypt_fails_for_different_types() {
        let key = [0u8; 32];
        let msg = TestMsg1 {
            content: "Hello, World!".to_string(),
            id: 42,
        };

        // encrypt with TestMessage
        let ct = seal(&mut OsRng, &key, &msg, &EmptyAD);

        // try to decrypt with DifferentMessage (different separator)
        let result: Result<TestMsg2> = open(&key, &ct, &EmptyAD);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_fails_for_different_ad() {
        let key = [0u8; 32];
        let msg = TestMsg1 {
            content: "Hello, World!".to_string(),
            id: 42,
        };

        let ad1 = TestAD {
            data: "associated data 1".to_string(),
        };
        let ad2 = TestAD {
            data: "associated data 2".to_string(),
        };

        // encrypt with ad1
        let ct = seal(&mut OsRng, &key, &msg, &ad1);

        // try to decrypt with ad2 (different AD)
        let result: Result<TestMsg1> = open(&key, &ct, &ad2);
        assert!(result.is_err());

        // decrypt with correct AD should work
        let dec_msg: TestMsg1 = open(&key, &ct, &ad1).unwrap();
        assert_eq!(msg, dec_msg);
    }
}
