use ark_ec::PrimeGroup;
use ark_ff::PrimeField;
use ark_std::rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::cell::OnceCell;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    crypto::{
        hash::{hash, SIZE_HASH},
        pairing as pp,
    },
    encode::Tagged,
    SwafeError,
};

/// Schnorr signature implementation
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Signature {
    #[serde(with = "crate::crypto::pairing::serialize::g1")]
    pub r: pp::G1Affine,
    #[serde(with = "crate::crypto::pairing::serialize::fr")]
    pub s: pp::Fr,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, ZeroizeOnDrop, Hash, Debug)]
pub struct VerificationKey(
    #[serde(with = "crate::crypto::pairing::serialize::g1")] //
    pp::G1Affine,
);

impl VerificationKey {
    /// Verify this Schnorr signature against a public key and message
    pub fn verify<T: Tagged>(&self, sig: &Signature, msg: &T) -> Result<(), SwafeError> {
        let e = pp::Fr::from_le_bytes_mod_order(&hash(&SchnorrHash {
            r: sig.r,
            pk: self.clone(),
            message: hash(msg),
        }));

        // Check: [s] * G = R + [e] * PK
        let left: pp::G1Affine = (pp::G1Projective::generator() * sig.s).into();
        let right: pp::G1Affine =
            (pp::G1Projective::from(sig.r) + pp::G1Projective::from(self.0) * e).into();
        if left == right {
            Ok(())
        } else {
            Err(SwafeError::SignatureVerificationFailed)
        }
    }
}

/// Signature key pair
#[derive(Clone, Serialize, Deserialize)]
pub struct SigningKey {
    #[serde(with = "crate::crypto::pairing::serialize::fr")]
    sk: pp::Fr,
    #[serde(skip)]
    vk: OnceCell<VerificationKey>,
}

// Manual ZeroizeOnDrop implementation since OnceCell doesn't implement it
impl Drop for SigningKey {
    fn drop(&mut self) {
        self.sk.zeroize();
    }
}

#[derive(Serialize)]
struct SchnorrHash {
    #[serde(with = "crate::crypto::pairing::serialize::g1")]
    r: pp::G1Affine,
    pk: VerificationKey,
    message: [u8; SIZE_HASH],
}

impl Tagged for SchnorrHash {
    const SEPARATOR: &'static str = "v0:schnorr";
}

impl SigningKey {
    /// Generate a new Schnorr key pair
    pub fn gen<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let secret_key = rng.gen();

        Self {
            sk: secret_key,
            vk: OnceCell::new(),
        }
    }

    /// Sign a message using Schnorr signature
    pub fn sign<R: Rng + CryptoRng, T: Tagged>(&self, rng: &mut R, msg: &T) -> Signature {
        let k: pp::Fr = rng.gen();
        let r: pp::G1Affine = (pp::G1Projective::generator() * k).into();
        let e = pp::hash_to_fr(&SchnorrHash {
            r,
            pk: self.verification_key(),
            message: hash(msg),
        });
        Signature {
            r,
            s: k + e * self.sk,
        }
    }

    /// Return the verification key associated with this signing key
    pub fn verification_key(&self) -> VerificationKey {
        self.vk
            .get_or_init(|| VerificationKey((pp::G1Projective::generator() * self.sk).into()))
            .clone()
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
    fn test_schnorr_signature() {
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
