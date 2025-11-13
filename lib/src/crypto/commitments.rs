use std::ops::{Add, Mul};

use ark_ff::{AdditiveGroup, Field};
use ark_std::rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::{crypto::hash::hash, crypto::pairing as pp, encode::Tagged, SwafeError};

/// Pedersen commitment
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Hash)]
pub(crate) struct PedersenCommitment(
    #[serde(with = "crate::crypto::pairing::serialize::g1")] pub pp::G1Affine,
);

impl PedersenCommitment {
    pub fn zero() -> Self {
        Self(pp::G1Affine::identity())
    }
}

impl Mul<pp::Fr> for PedersenCommitment {
    type Output = Self;

    fn mul(self, scalar: pp::Fr) -> Self {
        Self((pp::G1Projective::from(self.0) * scalar).into())
    }
}

impl Add<PedersenCommitment> for PedersenCommitment {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self((pp::G1Projective::from(self.0) + pp::G1Projective::from(other.0)).into())
    }
}

/// Pedersen commitment generators
pub(crate) struct PedersenGenerators {
    pub h: pp::G1Affine, // Value generator
    pub g: pp::G1Affine, // Randomness generator
}

impl PedersenGenerators {
    /// Generate Pedersen commitment generators
    pub fn new() -> Self {
        #[derive(Serialize)]
        struct PedersenGenSep {
            name: &'static str,
        }

        impl Tagged for PedersenGenSep {
            const SEPARATOR: &'static str = "v0:pedersen";
        }

        Self {
            h: pp::hash_to_g1(&PedersenGenSep { name: "H" }),
            g: pp::hash_to_g1(&PedersenGenSep { name: "G" }),
        }
    }

    /// Compute Pedersen commitment: [v] * H + [r] * G
    pub fn commit(&self, open: &PedersenOpen) -> PedersenCommitment {
        let h_proj: pp::G1Projective = self.h.into();
        let g_proj: pp::G1Projective = self.g.into();
        PedersenCommitment((h_proj * open.value + g_proj * open.randomness).into())
    }
}

impl Default for PedersenGenerators {
    fn default() -> Self {
        Self::new()
    }
}

/// Secrets of a Pedersen commitment (value and randomness)
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash, ZeroizeOnDrop)]
pub(crate) struct PedersenOpen {
    #[serde(with = "crate::crypto::pairing::serialize::fr")]
    value: pp::Fr,
    #[serde(with = "crate::crypto::pairing::serialize::fr")]
    randomness: pp::Fr,
}

impl PedersenOpen {
    pub fn gen<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        PedersenOpen {
            value: rng.gen(),
            randomness: rng.gen(),
        }
    }

    #[cfg(test)]
    pub fn new(value: pp::Fr, randomness: pp::Fr) -> Self {
        PedersenOpen { value, randomness }
    }

    pub fn zero() -> Self {
        PedersenOpen {
            value: pp::Fr::ZERO,
            randomness: pp::Fr::ZERO,
        }
    }

    pub fn value(&self) -> pp::Fr {
        self.value
    }
}

impl Add<PedersenOpen> for PedersenOpen {
    type Output = PedersenOpen;

    fn add(self, rhs: PedersenOpen) -> Self::Output {
        PedersenOpen {
            value: self.value + rhs.value,
            randomness: self.randomness + rhs.randomness,
        }
    }
}

impl Mul<pp::Fr> for PedersenOpen {
    type Output = PedersenOpen;

    fn mul(self, rhs: pp::Fr) -> Self::Output {
        PedersenOpen {
            value: self.value * rhs,
            randomness: self.randomness * rhs,
        }
    }
}

/// Signature of Knowledge proof
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub(crate) struct SokProof {
    delta: PedersenCommitment,
    alpha: PedersenOpen,
}

/// Message structure for SoK hash
#[derive(Serialize)]
struct SokMessage<'a> {
    msg: [u8; 32],
    delta: PedersenCommitment,
    commitments: &'a [PedersenCommitment],
}

impl<'a> Tagged for SokMessage<'a> {
    const SEPARATOR: &'static str = "v0:schnorr-sok";
}

/// Signature-of-Knowledge implementation for Pedersen commitments
impl SokProof {
    /// Sign knowledge of secrets for multiple Pedersen commitments
    /// Implements the batched Schnorr proof as specified in notation.md
    pub fn prove<R: Rng + CryptoRng, T: Tagged>(
        rng: &mut R,
        gens: &PedersenGenerators,
        open: &[PedersenOpen],
        coms: &[PedersenCommitment],
        msg: &T,
    ) -> Result<Self, SwafeError> {
        if open.len() != coms.len() {
            return Err(SwafeError::InvalidInput(
                "Number of secrets must match number of commitments".to_string(),
            ));
        }

        if open.is_empty() {
            return Err(SwafeError::InvalidInput(
                "Cannot create SoK for empty commitment set".to_string(),
            ));
        }

        // 1. Generate random values
        let mask = PedersenOpen::gen(rng);

        // 2. Compute Delta = pedersen(v*, r*)
        let delta = gens.commit(&mask);

        // 3. Compute challenge alpha = H("SchnorrSoK", msg, Delta, C_0, ..., C_{n-1})
        let alpha = pp::hash_to_fr(&SokMessage {
            msg: hash(msg),
            delta: delta.clone(),
            commitments: coms,
        });

        // 4. Compute v_alpha = v* + alpha * (sum_i alpha^i * v_i)
        let mut alpha_power = pp::Fr::ONE;
        let mut combine = PedersenOpen::zero();
        for secret in open {
            combine = combine + secret.clone() * alpha_power;
            alpha_power *= alpha;
        }

        // 5. Compute r_alpha = r* + alpha * (sum_i alpha^i * r_i)
        Ok(SokProof {
            delta,
            alpha: mask + combine * alpha,
        })
    }

    /// Verify a SoK proof for multiple Pedersen commitments
    /// Implements the verification procedure as specified in notation.md
    pub fn verify<T: Tagged>(
        &self,
        gens: &PedersenGenerators,
        coms: &[PedersenCommitment],
        msg: &T,
    ) -> Result<(), SwafeError> {
        if coms.is_empty() {
            return Err(SwafeError::InvalidInput("Empty commitment set".to_string()));
        }

        // 1. Recompute challenge alpha = H("SchnorrSoK", msg, Delta, C_0, ..., C_{n-1})
        let alpha = pp::hash_to_fr(&SokMessage {
            msg: hash(msg),
            delta: self.delta.clone(),
            commitments: coms,
        });

        // 2. Compute C_alpha = Delta + [alpha] * (sum_i [alpha^i] * C_i)
        let mut alpha_power = pp::Fr::ONE;
        let mut combine = PedersenCommitment::zero();
        for com in coms {
            combine = combine + com.clone() * alpha_power;
            alpha_power *= alpha;
        }

        // 3. Check C_alpha = pedersen(v_alpha, r_alpha)
        if self.delta.clone() + combine * alpha == gens.commit(&self.alpha) {
            Ok(())
        } else {
            Err(SwafeError::VerificationFailed(
                "Pedersen SoK Failure".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    // Test message type that implements Tagged
    #[derive(Serialize)]
    struct TestMessage {
        content: String,
    }

    impl Tagged for TestMessage {
        const SEPARATOR: &'static str = "v0:test-message";
    }

    #[test]
    fn test_pedersen_commitment() {
        let mut rng = thread_rng();
        let generators = PedersenGenerators::new();

        let value = rng.gen();
        let randomness = rng.gen();

        // Test linearity: commit(v1, r1) + commit(v2, r2) = commit(v1+v2, r1+r2)
        let value2 = rng.gen();
        let randomness2 = rng.gen();

        let open1 = PedersenOpen::new(value, randomness);
        let open2 = PedersenOpen::new(value2, randomness2);
        let open_sum = PedersenOpen::new(value + value2, randomness + randomness2);

        let commitment1 = generators.commit(&open1);
        let commitment2 = generators.commit(&open2);
        let commitment_sum = generators.commit(&open_sum);

        let computed_sum = PedersenCommitment(
            (pp::G1Projective::from(commitment1.0) + pp::G1Projective::from(commitment2.0)).into(),
        );
        assert_eq!(commitment_sum, computed_sum);
    }

    #[test]
    fn test_sok_single_commitment() {
        let mut rng = thread_rng();
        let generators = PedersenGenerators::new();

        // Create a single commitment
        let value = rng.gen();
        let randomness = rng.gen();
        let secret = PedersenOpen { value, randomness };
        let commitment = generators.commit(&secret);

        let message = TestMessage {
            content: "test message for SoK".to_string(),
        };

        // Create SoK proof
        let proof = SokProof::prove(
            &mut rng,
            &generators,
            &[secret],
            std::slice::from_ref(&commitment),
            &message,
        )
        .unwrap();

        // Verify the proof
        assert!(proof
            .verify(&generators, std::slice::from_ref(&commitment), &message)
            .is_ok());

        // Test with wrong message
        let wrong_message = TestMessage {
            content: "wrong message".to_string(),
        };
        assert!(proof
            .verify(&generators, &[commitment], &wrong_message)
            .is_err());

        // Test with wrong commitment
        let wrong_value = rng.gen();
        let wrong_randomness = rng.gen();
        let wrong_open = PedersenOpen::new(wrong_value, wrong_randomness);
        let wrong_commitment = generators.commit(&wrong_open);
        assert!(proof
            .verify(&generators, &[wrong_commitment], &message)
            .is_err());
    }

    #[test]
    fn test_sok_multiple_commitments() {
        let mut rng = thread_rng();
        let generators = PedersenGenerators::new();

        // Create multiple commitments
        let num_commitments = 3;
        let mut secrets = Vec::new();
        let mut commitments = Vec::new();

        for _ in 0..num_commitments {
            let value = rng.gen();
            let randomness = rng.gen();
            let secret = PedersenOpen { value, randomness };
            let commitment = generators.commit(&secret);

            secrets.push(secret);
            commitments.push(commitment);
        }

        let message = TestMessage {
            content: "test message for multiple commitments".to_string(),
        };

        // Create SoK proof
        let proof =
            SokProof::prove(&mut rng, &generators, &secrets, &commitments, &message).unwrap();

        // Verify the proof
        assert!(proof.verify(&generators, &commitments, &message).is_ok());

        // Test with missing commitment
        let partial_commitments = &commitments[..num_commitments - 1];
        assert!(proof
            .verify(&generators, partial_commitments, &message)
            .is_err());

        // Test with extra commitment
        let extra_value = rng.gen();
        let extra_randomness = rng.gen();
        let extra_open = PedersenOpen::new(extra_value, extra_randomness);
        let extra_commitment = generators.commit(&extra_open);
        let mut extended_commitments = commitments.clone();
        extended_commitments.push(extra_commitment);
        assert!(proof
            .verify(&generators, &extended_commitments, &message)
            .is_err());
    }
}
