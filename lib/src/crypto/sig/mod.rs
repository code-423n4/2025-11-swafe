mod v0;

use ark_std::rand::{CryptoRng, Rng};

use crate::{versioned_enum, SwafeError, Tagged};

versioned_enum!(
    #[derive(Clone, Debug)]
    Signature,
    V0(v0::Signature) = 0
);

versioned_enum!(
    #[derive(Clone, Debug, Eq, PartialEq, Hash)]
    VerificationKey,
    V0(v0::VerificationKey) = 0
);

versioned_enum!(
    #[derive(Clone)]
    SigningKey,
    V0(v0::SigningKey) = 0
);

impl Tagged for VerificationKey {
    const SEPARATOR: &'static str = "v0:sig-verification-key";
}

impl VerificationKey {
    /// Verify this Schnorr signature against a public key and message
    pub fn verify<T: Tagged>(&self, sig: &Signature, msg: &T) -> Result<(), SwafeError> {
        match (self, sig) {
            (VerificationKey::V0(vk), Signature::V0(sig)) => vk.verify(sig, msg),
        }
    }
}

impl SigningKey {
    /// Generate a new signing key of the latest version
    pub fn gen<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        Self::V0(v0::SigningKey::gen(rng))
    }

    /// Sign a message using Schnorr signature
    pub fn sign<R: Rng + CryptoRng, T: Tagged>(&self, rng: &mut R, msg: &T) -> Signature {
        match self {
            SigningKey::V0(sk) => Signature::V0(sk.sign(rng, msg)),
        }
    }

    /// Return the verification key associated with this signing key
    pub fn verification_key(&self) -> VerificationKey {
        match self {
            SigningKey::V0(sk) => VerificationKey::V0(sk.verification_key()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[derive(serde::Serialize)]
    struct TestBytes {
        bytes: Vec<u8>,
    }

    impl Tagged for TestBytes {
        const SEPARATOR: &'static str = "v0:test-sig";
    }

    #[test]
    fn test_signature() {
        let mut rng = thread_rng();
        let sk = SigningKey::gen(&mut rng);
        let message = TestBytes {
            bytes: b"test message".to_vec(),
        };

        let signature = sk.sign(&mut rng, &message);
        let pk = sk.verification_key();
        assert!(pk.verify(&signature, &message).is_ok());

        // Test with wrong message
        let wrong_message = TestBytes {
            bytes: b"wrong message".to_vec(),
        };
        assert!(pk.verify(&signature, &wrong_message).is_err());

        // Test with wrong public key
        let wrong_keypair = SigningKey::gen(&mut rng);
        assert!(wrong_keypair
            .verification_key()
            .verify(&signature, &message)
            .is_err());
    }
}
