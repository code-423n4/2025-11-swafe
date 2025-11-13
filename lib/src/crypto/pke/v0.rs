use std::cell::OnceCell;

use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{CryptoRng, Rng};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{
    crypto::{curve, kdfn, symmetric as sym},
    SwafeError, Tagged,
};

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Copy, Debug, Hash)]
pub(crate) struct EncryptionKey(
    #[serde(with = "crate::crypto::curve::serialize::g")] //
    curve::GAffine,
);

#[derive(Serialize)]
struct DiffieHellmanCtx {
    #[serde(with = "crate::crypto::curve::serialize::g")]
    tp: curve::GAffine,
    #[serde(with = "crate::crypto::curve::serialize::g")]
    pk: curve::GAffine,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct DecryptionKey {
    #[serde(with = "crate::crypto::curve::serialize::fr")]
    sk: curve::Fr,
    #[serde(skip)]
    pk: OnceCell<curve::GAffine>,
}

impl Drop for DecryptionKey {
    fn drop(&mut self) {
        self.sk.zeroize();
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct Ciphertext {
    #[serde(with = "crate::crypto::curve::serialize::g")]
    tp: curve::GAffine,
    ct: sym::AEADCiphertext,
}

impl Tagged for DiffieHellmanCtx {
    const SEPARATOR: &'static str = "v0:pke-dhpk-ss";
}

impl DecryptionKey {
    pub fn gen<R: CryptoRng + Rng>(rng: &mut R) -> DecryptionKey {
        DecryptionKey {
            sk: rng.gen(),
            pk: OnceCell::new(),
        }
    }

    pub fn encryption_key(&self) -> EncryptionKey {
        let pk = self
            .pk
            .get_or_init(|| (curve::GAffine::generator() * self.sk).into());
        EncryptionKey(*pk)
    }

    pub fn decrypt<M: Tagged + DeserializeOwned, A: Tagged>(
        &self,
        ct: &Ciphertext,
        ctx: &A,
    ) -> Result<M, SwafeError> {
        // compute shared secret
        let mut ikm = vec![];
        (ct.tp * self.sk)
            .into_affine()
            .serialize_compressed(&mut ikm)
            .unwrap();

        // decrypt with symmetric encryption
        sym::open(
            &kdfn(
                &ikm,
                &DiffieHellmanCtx {
                    tp: ct.tp,
                    pk: self.encryption_key().0,
                },
            ),
            &ct.ct,
            ctx,
        )
    }
}

impl EncryptionKey {
    /// Generates a single ciphertext
    ///
    /// The scheme satisfies IND-CCA2.
    pub fn encrypt<M: Tagged, A: Tagged, R: CryptoRng + Rng>(
        &self,
        rng: &mut R,
        msg: &M,
        ctx: &A,
    ) -> Ciphertext {
        // generate diffie-hellman key
        let ts: curve::Fr = rng.gen();
        let tp: curve::GAffine = (curve::GAffine::generator() * ts).into();

        // compute shared secret
        let mut ikm = vec![];
        (self.0 * ts)
            .into_affine()
            .serialize_compressed(&mut ikm)
            .unwrap();

        // encrypt with symmetric encryption
        let ct = sym::seal(
            rng,
            &kdfn(
                &ikm,
                &DiffieHellmanCtx {
                    tp, //
                    pk: self.0,
                },
            ),
            msg,
            ctx,
        );

        Ciphertext { tp, ct }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::thread_rng;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
    struct TestMessage {
        data: String,
        value: u32,
    }

    impl Tagged for TestMessage {
        const SEPARATOR: &'static str = "v0:test-message";
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
    struct TestContext {
        id: u64,
        name: String,
    }

    impl Tagged for TestContext {
        const SEPARATOR: &'static str = "v0:test-context";
    }

    #[test]
    fn test_key_generation() {
        let mut rng = thread_rng();
        let dk = DecryptionKey::gen(&mut rng);
        let ek = dk.encryption_key();

        // Test that keys are consistent
        let dk2 = DecryptionKey::gen(&mut rng);
        let ek2 = dk2.encryption_key();

        // Different keys should produce different encryption keys
        assert!(ek != ek2);
    }

    #[test]
    fn test_single_encrypt_decrypt() {
        let mut rng = thread_rng();
        let dk = DecryptionKey::gen(&mut rng);
        let ek = dk.encryption_key();

        let msg = TestMessage {
            data: "Hello, world!".to_string(),
            value: 42,
        };

        let ctx = TestContext {
            id: 1,
            name: "test".to_string(),
        };

        let ct = ek.encrypt(&mut rng, &msg, &ctx);
        let decrypted: TestMessage = dk.decrypt(&ct, &ctx).unwrap();

        assert_eq!(msg, decrypted);
    }

    #[test]
    fn test_single_decrypt_wrong_key() {
        let mut rng = thread_rng();
        let dk1 = DecryptionKey::gen(&mut rng);
        let dk2 = DecryptionKey::gen(&mut rng);
        let ek1 = dk1.encryption_key();

        let msg = TestMessage {
            data: "Hello, world!".to_string(),
            value: 42,
        };

        let ctx = TestContext {
            id: 1,
            name: "test".to_string(),
        };

        let ct = ek1.encrypt(&mut rng, &msg, &ctx);
        let result: Result<TestMessage, _> = dk2.decrypt(&ct, &ctx);

        assert!(result.is_err());
    }

    #[test]
    fn test_single_decrypt_wrong_context() {
        let mut rng = thread_rng();
        let dk = DecryptionKey::gen(&mut rng);
        let ek = dk.encryption_key();

        let msg = TestMessage {
            data: "Hello, world!".to_string(),
            value: 42,
        };

        let ctx1 = TestContext {
            id: 1,
            name: "test1".to_string(),
        };

        let ctx2 = TestContext {
            id: 2,
            name: "test2".to_string(),
        };

        let ct = ek.encrypt(&mut rng, &msg, &ctx1);
        let result: Result<TestMessage, _> = dk.decrypt(&ct, &ctx2);

        assert!(result.is_err());
    }

    #[test]
    fn test_serialization_deserialization() {
        let mut rng = thread_rng();
        let dk = DecryptionKey::gen(&mut rng);
        let ek = dk.encryption_key();

        // Test DecryptionKey serialization
        let dk_serialized = serde_json::to_string(&dk).unwrap();
        let dk_deserialized: DecryptionKey = serde_json::from_str(&dk_serialized).unwrap();

        // Test EncryptionKey serialization
        let ek_serialized = serde_json::to_string(&ek).unwrap();
        let ek_deserialized: EncryptionKey = serde_json::from_str(&ek_serialized).unwrap();

        // Test that deserialized keys work correctly
        let msg = TestMessage {
            data: "Serialization test".to_string(),
            value: 123,
        };

        let ctx = TestContext {
            id: 1,
            name: "serialization_test".to_string(),
        };

        let ct = ek_deserialized.encrypt(&mut rng, &msg, &ctx);
        let decrypted: TestMessage = dk_deserialized.decrypt(&ct, &ctx).unwrap();

        assert_eq!(msg, decrypted);
    }

    #[test]
    fn test_ciphertext_serialization() {
        let mut rng = thread_rng();
        let dk = DecryptionKey::gen(&mut rng);
        let ek = dk.encryption_key();

        let msg = TestMessage {
            data: "Ciphertext serialization test".to_string(),
            value: 456,
        };

        let ctx = TestContext {
            id: 1,
            name: "ct_serialization_test".to_string(),
        };

        let ct = ek.encrypt(&mut rng, &msg, &ctx);

        // Serialize and deserialize ciphertext
        let ct_serialized = serde_json::to_string(&ct).unwrap();
        let ct_deserialized: Ciphertext = serde_json::from_str(&ct_serialized).unwrap();

        // Decrypt deserialized ciphertext
        let decrypted: TestMessage = dk.decrypt(&ct_deserialized, &ctx).unwrap();
        assert_eq!(msg, decrypted);
    }

    #[test]
    fn test_multiple_messages_same_key() {
        let mut rng = thread_rng();
        let dk = DecryptionKey::gen(&mut rng);
        let ek = dk.encryption_key();

        let ctx = TestContext {
            id: 1,
            name: "multiple_messages".to_string(),
        };

        let messages = vec![
            TestMessage {
                data: "First".to_string(),
                value: 1,
            },
            TestMessage {
                data: "Second".to_string(),
                value: 2,
            },
            TestMessage {
                data: "Third".to_string(),
                value: 3,
            },
        ];

        // Encrypt all messages
        let ciphertexts: Vec<Ciphertext> = messages
            .iter()
            .map(|msg| ek.encrypt(&mut rng, msg, &ctx))
            .collect();

        // Decrypt all messages
        let decrypted: Vec<TestMessage> = ciphertexts
            .iter()
            .map(|ct| dk.decrypt(ct, &ctx).unwrap())
            .collect();

        assert_eq!(messages, decrypted);
    }
}
