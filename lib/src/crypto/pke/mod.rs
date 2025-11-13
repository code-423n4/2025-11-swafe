use ark_std::rand::{CryptoRng, Rng};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{crypto::sig, versioned_enum, SwafeError, Tagged};

mod v0;

versioned_enum!(
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    EncryptionKey, //
    V0(v0::EncryptionKey) = 0
);

versioned_enum!(
    #[derive(Clone)]
    DecryptionKey, //
    V0(v0::DecryptionKey) = 0
);

versioned_enum!(
    #[derive(Debug, Clone)]
    Ciphertext, //
    V0(v0::Ciphertext) = 0,
);

versioned_enum!(
    #[derive(Debug, Clone)]
    BatchCiphertext, //
    V0(BatchCiphertextV0) = 0
);

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BatchCiphertextV0Inner {
    vk: sig::VerificationKey,
    cts: Vec<Ciphertext>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BatchCiphertextV0 {
    inn: BatchCiphertextV0Inner,
    sig: sig::Signature,
}

#[derive(Serialize)]
struct BatchCtx<'a, 'b, A: Tagged> {
    vk: &'b sig::VerificationKey,
    ctx: (&'static str, &'a A),
}

impl<'a, 'b, A: Tagged> Tagged for BatchCtx<'a, 'b, A> {
    const SEPARATOR: &'static str = "v0:pke-batch-ctx";
}

impl Tagged for EncryptionKey {
    const SEPARATOR: &'static str = "v0:pke-encryption-key";
}

impl Tagged for Ciphertext {
    const SEPARATOR: &'static str = "v0:pke-ciphertext";
}

impl Tagged for BatchCiphertextV0Inner {
    const SEPARATOR: &'static str = "v0:pke-batch-inner";
}

impl DecryptionKey {
    /// Generate a new decryption key of the newest version.
    pub fn gen<R: CryptoRng + Rng>(rng: &mut R) -> DecryptionKey {
        DecryptionKey::V0(v0::DecryptionKey::gen(rng))
    }

    pub fn encryption_key(&self) -> EncryptionKey {
        match self {
            DecryptionKey::V0(key) => EncryptionKey::V0(key.encryption_key()),
        }
    }

    pub fn decrypt<M: Tagged + DeserializeOwned, A: Tagged>(
        &self,
        ct: &Ciphertext,
        ctx: &A,
    ) -> Result<M, SwafeError> {
        match self {
            DecryptionKey::V0(key) =>
            {
                #[allow(irrefutable_let_patterns)]
                if let Ciphertext::V0(ct) = ct {
                    key.decrypt(ct, ctx)
                } else {
                    Err(SwafeError::DecryptionFailed)
                }
            }
        }
    }

    pub fn decrypt_batch<M: Tagged + DeserializeOwned, A: Tagged>(
        &self,
        ct: &BatchCiphertext,
        ctx: &A,
    ) -> Result<(M, usize), SwafeError> {
        match ct {
            BatchCiphertext::V0(ct) => {
                // verify signature
                ct.inn.vk.verify(&ct.sig, &ct.inn)?;

                // try to decrypt every ct with context
                // bound to the verification key
                for (i, shr) in ct.inn.cts.iter().enumerate() {
                    if let Ok(msg) = self.decrypt(
                        shr,
                        &BatchCtx {
                            vk: &ct.inn.vk,
                            ctx: (A::SEPARATOR, ctx),
                        },
                    ) {
                        return Ok((msg, i));
                    }
                }

                // if all ciphertexts failed to decrypt, return an error
                Err(SwafeError::DecryptionFailed)
            }
        }
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
        match self {
            EncryptionKey::V0(key) => Ciphertext::V0(key.encrypt(rng, msg, ctx)),
        }
    }

    /// Generates a batched encryption.
    ///
    /// This scheme provides additional guarantees (beyond IND-CCA2).
    ///
    /// An adversary even with access to a subset of the decryption keys,
    /// cannot make the other ciphertexts invalid selectively:
    /// either all ciphertexts decrypt or all fail to decrypt.
    pub fn batch_encrypt<
        M: Tagged,
        A: Tagged,
        R: CryptoRng + Rng,
        I: Iterator<Item = (EncryptionKey, M)>,
    >(
        rng: &mut R,
        msgs: I,
        ctx: &A,
    ) -> BatchCiphertext {
        // generate a signing key
        let sk = sig::SigningKey::gen(rng);
        let vk = sk.verification_key();

        // generate ciphertexts for each message
        // with the verification key bound as context
        let cts = msgs
            .map(|(key, msg)| {
                key.encrypt(
                    rng,
                    &msg,
                    &BatchCtx {
                        vk: &vk,
                        ctx: (A::SEPARATOR, ctx),
                    },
                )
            })
            .collect::<Vec<_>>();

        // sign everything
        let inn = BatchCiphertextV0Inner { vk, cts };
        let sig = sk.sign(rng, &inn);
        BatchCiphertext::V0(BatchCiphertextV0 { inn, sig })
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
    fn test_batch_encrypt_decrypt() {
        let mut rng = thread_rng();

        // Generate multiple key pairs
        let dk1 = DecryptionKey::gen(&mut rng);
        let dk2 = DecryptionKey::gen(&mut rng);
        let dk3 = DecryptionKey::gen(&mut rng);

        let ek1 = dk1.encryption_key();
        let ek2 = dk2.encryption_key();
        let ek3 = dk3.encryption_key();

        let msg1 = TestMessage {
            data: "Message 1".to_string(),
            value: 1,
        };

        let msg2 = TestMessage {
            data: "Message 2".to_string(),
            value: 2,
        };

        let msg3 = TestMessage {
            data: "Message 3".to_string(),
            value: 3,
        };

        let ctx = TestContext {
            id: 1,
            name: "batch_test".to_string(),
        };

        let msgs = vec![
            (ek1, msg1.clone()),
            (ek2, msg2.clone()),
            (ek3, msg3.clone()),
        ];

        let batch_ct = EncryptionKey::batch_encrypt(&mut rng, msgs.into_iter(), &ctx);

        // Each decryption key should decrypt its corresponding message
        let (decrypted1, _): (TestMessage, _) = dk1.decrypt_batch(&batch_ct, &ctx).unwrap();
        let (decrypted2, _): (TestMessage, _) = dk2.decrypt_batch(&batch_ct, &ctx).unwrap();
        let (decrypted3, _): (TestMessage, _) = dk3.decrypt_batch(&batch_ct, &ctx).unwrap();

        assert_eq!(msg1, decrypted1);
        assert_eq!(msg2, decrypted2);
        assert_eq!(msg3, decrypted3);
    }

    #[test]
    fn test_batch_decrypt_returns_correct_index() {
        use rand::rngs::OsRng;

        // Generate keys
        let dk1 = DecryptionKey::gen(&mut OsRng);
        let dk2 = DecryptionKey::gen(&mut OsRng);
        let dk3 = DecryptionKey::gen(&mut OsRng);

        let ek1 = dk1.encryption_key();
        let ek2 = dk2.encryption_key();
        let ek3 = dk3.encryption_key();

        // Test messages
        let msg1 = TestMessage {
            data: "Message 1".to_string(),
            value: 42,
        };
        let msg2 = TestMessage {
            data: "Message 2".to_string(),
            value: 43,
        };
        let msg3 = TestMessage {
            data: "Message 3".to_string(),
            value: 44,
        };

        // Context
        let ctx = TestContext {
            id: 1001,
            name: "Test Batch Index".to_string(),
        };

        // Create batch encryption
        let batch_ct = EncryptionKey::batch_encrypt(
            &mut OsRng,
            vec![
                (ek1, msg1.clone()),
                (ek2, msg2.clone()),
                (ek3, msg3.clone()),
            ]
            .into_iter(),
            &ctx,
        );

        // Each decryption key should decrypt its corresponding message with correct index
        let (decrypted1, idx1) = dk1.decrypt_batch(&batch_ct, &ctx).unwrap();
        let (decrypted2, idx2) = dk2.decrypt_batch(&batch_ct, &ctx).unwrap();
        let (decrypted3, idx3) = dk3.decrypt_batch(&batch_ct, &ctx).unwrap();

        assert_eq!(msg1, decrypted1);
        assert_eq!(msg2, decrypted2);
        assert_eq!(msg3, decrypted3);

        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);
        assert_eq!(idx3, 2);
    }

    #[test]
    fn test_batch_decrypt_wrong_key() {
        let mut rng = thread_rng();

        let dk1 = DecryptionKey::gen(&mut rng);
        let dk2 = DecryptionKey::gen(&mut rng);
        let dk_wrong = DecryptionKey::gen(&mut rng);

        let ek1 = dk1.encryption_key();
        let ek2 = dk2.encryption_key();

        let msg1 = TestMessage {
            data: "Message 1".to_string(),
            value: 1,
        };

        let msg2 = TestMessage {
            data: "Message 2".to_string(),
            value: 2,
        };

        let ctx = TestContext {
            id: 1,
            name: "batch_test".to_string(),
        };

        let msgs = vec![(ek1, msg1), (ek2, msg2)];

        let batch_ct = EncryptionKey::batch_encrypt(&mut rng, msgs.into_iter(), &ctx);

        // Wrong key should fail to decrypt
        let result: Result<(TestMessage, usize), _> = dk_wrong.decrypt_batch(&batch_ct, &ctx);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SwafeError::DecryptionFailed));
    }

    #[test]
    fn test_batch_decrypt_wrong_context() {
        let mut rng = thread_rng();

        let dk1 = DecryptionKey::gen(&mut rng);
        let ek1 = dk1.encryption_key();

        let msg1 = TestMessage {
            data: "Message 1".to_string(),
            value: 1,
        };

        let ctx1 = TestContext {
            id: 1,
            name: "batch_test1".to_string(),
        };

        let ctx2 = TestContext {
            id: 2,
            name: "batch_test2".to_string(),
        };

        let msgs = vec![(ek1, msg1)];

        let batch_ct = EncryptionKey::batch_encrypt(&mut rng, msgs.into_iter(), &ctx1);

        // Wrong context should fail to decrypt
        let result: Result<(TestMessage, usize), _> = dk1.decrypt_batch(&batch_ct, &ctx2);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SwafeError::DecryptionFailed));
    }

    #[test]
    fn test_empty_batch() {
        let mut rng = thread_rng();
        let dk = DecryptionKey::gen(&mut rng);

        let ctx = TestContext {
            id: 1,
            name: "empty_batch".to_string(),
        };

        let msgs: Vec<(EncryptionKey, TestMessage)> = vec![];
        let batch_ct = EncryptionKey::batch_encrypt(&mut rng, msgs.into_iter(), &ctx);

        // Empty batch should fail to decrypt
        let result: Result<(TestMessage, usize), _> = dk.decrypt_batch(&batch_ct, &ctx);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SwafeError::DecryptionFailed));
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
    fn test_batch_ciphertext_serialization() {
        let mut rng = thread_rng();
        let dk = DecryptionKey::gen(&mut rng);
        let ek = dk.encryption_key();

        let msg = TestMessage {
            data: "Batch ciphertext serialization test".to_string(),
            value: 789,
        };

        let ctx = TestContext {
            id: 1,
            name: "batch_ct_serialization_test".to_string(),
        };

        let msgs = vec![(ek, msg.clone())];
        let batch_ct = EncryptionKey::batch_encrypt(&mut rng, msgs.into_iter(), &ctx);

        // Serialize and deserialize batch ciphertext
        let batch_ct_serialized = serde_json::to_string(&batch_ct).unwrap();
        let batch_ct_deserialized: BatchCiphertext =
            serde_json::from_str(&batch_ct_serialized).unwrap();

        // Decrypt deserialized batch ciphertext
        let (decrypted, _): (TestMessage, _) =
            dk.decrypt_batch(&batch_ct_deserialized, &ctx).unwrap();
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
