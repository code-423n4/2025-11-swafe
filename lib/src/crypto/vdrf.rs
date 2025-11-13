use std::collections::HashMap;

use ark_ec::{AffineRepr, PrimeGroup};
use ark_ff::{AdditiveGroup, PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};

use crate::{
    crypto::{hash, kdfn, pairing as pp, poly},
    encode::Tagged,
    NodeId, SwafeError,
};

impl NodeId {
    pub(crate) fn eval_point(&self) -> pp::Fr {
        let x = pp::Fr::from_le_bytes_mod_order(&hash(self));
        // this should never be the case:
        // finding such a preimage requires ~2^256 operations
        assert_ne!(x, pp::Fr::zero(), "Node ID hash cannot be zero");
        x
    }
}

/// VDRF Public Key - vector of G1 commitments
#[derive(Serialize, Deserialize, Clone)]
pub struct VdrfPublicKey {
    #[serde(with = "crate::crypto::pairing::serialize::g1")]
    c0: pp::G1Affine,
    // most significant coefficient first
    #[serde(with = "crate::crypto::pairing::serialize::vec::g1")]
    ci: Vec<pp::G1Affine>,
}

impl VdrfPublicKey {
    fn threshold(&self) -> usize {
        self.ci.len() + 1
    }
}

/// VDRF Secret Key Share - field element
#[derive(Serialize, Deserialize, Clone)]
pub struct VdrfSecretKeyShare(#[serde(with = "crate::crypto::pairing::serialize::fr")] pp::Fr);

/// VDRF Evaluation - G2 element
#[derive(Serialize, Deserialize, Clone)]
pub struct VdrfEvaluation(#[serde(with = "crate::crypto::pairing::serialize::g2")] pp::G2Affine);

/// VDRF Evaluation - G2 element
#[derive(Serialize, Deserialize, Clone)]
pub struct VdrfEvaluationShare(
    #[serde(with = "crate::crypto::pairing::serialize::g2")] pp::G2Affine,
);

/// VDRF Secret Key - vector of field elements
#[derive(Serialize, Deserialize)]
pub struct VdrfSecretKey {
    #[serde(with = "crate::crypto::pairing::serialize::fr")]
    c0: pp::Fr,
    // most significant coefficient first
    #[serde(with = "crate::crypto::pairing::serialize::vec::fr")]
    ci: Vec<pp::Fr>,
}

#[derive(Serialize)]
struct VdrfKPoint {
    #[serde(with = "crate::crypto::pairing::serialize::g1")]
    c0: pp::G1Affine,
    input: [u8; 32],
}

#[derive(Serialize)]
struct VdrfOutputInfo {
    #[serde(with = "crate::crypto::pairing::serialize::g1")]
    c0: pp::G1Affine,
    input: [u8; 32],
}

impl Tagged for VdrfKPoint {
    const SEPARATOR: &'static str = "v0:vdrf-input";
}

impl Tagged for VdrfOutputInfo {
    const SEPARATOR: &'static str = "v0:vdrf-output";
}

/// VDRF Implementation
pub struct Vdrf;

impl VdrfSecretKey {
    /// Generate VDRF secret key for a threshold `t`
    pub fn gen<R: Rng + CryptoRng>(rng: &mut R, t: usize) -> VdrfSecretKey {
        VdrfSecretKey {
            c0: rng.gen(),
            ci: (1..t).map(|_| rng.gen()).collect(),
        }
    }

    /// Deal a secret key share to party with NodeId
    pub fn deal(&self, node_id: &NodeId) -> Result<VdrfSecretKeyShare, SwafeError> {
        let xi = node_id.eval_point();
        self.share(xi)
    }

    /// Evaluate a share at a given point
    fn share(&self, xi: pp::Fr) -> Result<VdrfSecretKeyShare, SwafeError> {
        if xi.is_zero() {
            return Err(SwafeError::InvalidInput(
                "Evaluation point cannot be zero".to_string(),
            ));
        }

        // Evaluate polynomial f(X) = sum(c_j * X^j) at x_i
        let result = self.ci.iter().fold(pp::Fr::zero(), |acc, c| xi * acc + c);
        Ok(VdrfSecretKeyShare(xi * result + self.c0))
    }

    /// Obtain public key
    pub fn public_key(&self) -> VdrfPublicKey {
        VdrfPublicKey {
            c0: (pp::G1Projective::generator() * self.c0).into(),
            ci: self
                .ci
                .iter()
                .map(|c| (pp::G1Projective::generator() * c).into())
                .collect(),
        }
    }
}

impl Vdrf {
    /// Compute partial evaluation for a given input
    pub fn partial_eval<T: Tagged>(
        public_key: &VdrfPublicKey,
        secret_share: &VdrfSecretKeyShare,
        input: &T,
    ) -> Result<VdrfEvaluationShare, SwafeError> {
        // hash to point
        let pnt = pp::G2Projective::from(pp::hash_to_g2(&VdrfKPoint {
            c0: public_key.c0,
            input: hash(input),
        }));

        // return [secret_share] * png
        Ok(VdrfEvaluationShare((pnt * secret_share.0).into()))
    }

    /// Combine partial evaluations using Lagrange interpolation
    pub fn combine<T: Tagged, const N: usize>(
        public_key: &VdrfPublicKey,
        input: &T,
        shares: &[(NodeId, VdrfEvaluationShare)],
    ) -> Result<VdrfEvaluation, SwafeError> {
        // pnt = H(C_0 || input)
        let pnt = pp::hash_to_g2(&VdrfKPoint {
            c0: public_key.c0,
            input: hash(input),
        });

        // filter only for valid shares
        let mut uniq_shares: HashMap<_, _> = Default::default();
        for (id, evl) in shares.iter().cloned() {
            let xi = id.eval_point();
            // check if xi is unique
            if uniq_shares.contains_key(&xi) {
                continue;
            }

            // optimized: e(G1, eval_i) * e(-E_i, K) = 1
            if pp::check_pairing(
                &[
                    pp::G1Affine::generator(),
                    Self::compute_commitment_at_point(public_key, xi),
                ],
                &[evl.0, -pnt],
            ) {
                uniq_shares.insert(xi, evl);
                if uniq_shares.len() == public_key.threshold() {
                    break;
                }
            }
        }

        // check threshold
        if uniq_shares.len() != public_key.threshold() {
            return Err(SwafeError::NotEnoughSharesForReconstruction);
        }

        // Compute Lagrange coefficients and combine
        let uniq_shares: Vec<_> = uniq_shares.into_iter().collect();
        let xs = uniq_shares.iter().map(|(xi, _)| *xi).collect::<Vec<_>>();
        let result: pp::G2Projective = uniq_shares
            .into_iter()
            .map(|(xi, eval)| {
                pp::G2Projective::from(eval.0)
                    * poly::lagrange(
                        &xs.iter().cloned().filter(|x| *x != xi).collect::<Vec<_>>(),
                        xi,
                        pp::Fr::ZERO,
                    )
            })
            .sum();

        Ok(VdrfEvaluation(result.into()))
    }

    /// Verify the VDRF evaluation and produce the random output
    pub fn verify<T: Tagged, const N: usize>(
        public_key: &VdrfPublicKey,
        input: &T,
        evaluation: VdrfEvaluation,
    ) -> Result<[u8; N], SwafeError> {
        // hash the input type
        let input = hash(input);

        // K = H(C_0 || input)
        let pnt = pp::hash_to_g2(&VdrfKPoint {
            c0: public_key.c0,
            input,
        });

        // Check pairing:
        // e(G1, evaluation) = e(C_0, pnt)
        // e(G2, evaluation) * e(C_0, -pnt) = 1
        if !pp::check_pairing(
            &[pp::G1Affine::generator(), public_key.c0],
            &[evaluation.0, -pnt],
        ) {
            return Err(SwafeError::VdrfEvaluationVerificationFailed);
        }

        // Compute KDF(evaluation, "VDRF" || C_0 || input)
        let mut kdf_input = Vec::new();
        evaluation
            .0
            .serialize_compressed(&mut kdf_input)
            .map_err(|_| SwafeError::VdrfEvaluationVerificationFailed)?;

        Ok(kdfn(
            &kdf_input,
            &VdrfOutputInfo {
                c0: public_key.c0,
                input,
            },
        ))
    }

    /// Compute commitment at a specific point: <(1, x, x^2, ...), (C_0, C_1, ...)>
    fn compute_commitment_at_point(pk: &VdrfPublicKey, x: pp::Fr) -> pp::G1Affine {
        // Evaluate polynomial at x using Horner's method (same as in deal)
        let result = pk.ci.iter().fold(pp::G1Projective::zero(), |acc, c| {
            acc * x + pp::G1Projective::from(*c)
        });
        (result * x + pp::G1Projective::from(pk.c0)).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[derive(Debug, Clone, Serialize)]
    struct Input(String);

    impl Tagged for Input {
        const SEPARATOR: &'static str = "v0:test-input";
    }

    #[test]
    fn test_vdrf_basic_functionality() {
        let mut rng = thread_rng();
        let t = 3; // threshold

        // Key generation
        let secret_key = VdrfSecretKey::gen(&mut rng, t);
        let public_key = secret_key.public_key();
        assert_eq!(public_key.threshold(), t);

        // Generate party identifiers
        let x_values: Vec<NodeId> = (1..=t)
            .map(|i| format!("node:{}", i).parse().unwrap())
            .collect();

        // Deal secret shares
        let shares: Vec<_> = x_values
            .iter()
            .map(|id| (id, secret_key.deal(id).unwrap()))
            .collect();

        let input = Input("test input".to_string());

        // Compute partial evaluations
        let partial_evals: Vec<_> = shares
            .iter()
            .map(|(id, share)| {
                (
                    (*id).clone(),
                    Vdrf::partial_eval(&public_key, share, &input).unwrap(),
                )
            })
            .collect();

        // Combine partial evaluations
        let combined_eval = Vdrf::combine::<_, 32>(&public_key, &input, &partial_evals).unwrap();

        // Verify and get output
        let output: [u8; 32] = Vdrf::verify(&public_key, &input, combined_eval.clone()).unwrap();
        assert_eq!(output.len(), 32);

        // Test deterministic output
        let output2: [u8; 32] = Vdrf::verify(&public_key, &input, combined_eval).unwrap();
        assert_eq!(output, output2);

        // Test different input gives different output
        let different_input = Input("different input".to_string());
        let partial_evals2: Vec<_> = shares
            .iter()
            .map(|(xi, share)| {
                (
                    (*xi).clone(),
                    Vdrf::partial_eval(&public_key, share, &different_input).unwrap(),
                )
            })
            .collect();

        let combined_eval2 =
            Vdrf::combine::<_, 32>(&public_key, &different_input, &partial_evals2).unwrap();
        let output3: [u8; 32] =
            Vdrf::verify(&public_key, &different_input, combined_eval2).unwrap();
        assert_ne!(output, output3);
    }

    #[test]
    fn test_vdrf_threshold_security() {
        let mut rng = thread_rng();
        let t = 3; // threshold
        let n = 5; // total parties

        // Key generation
        let secret_key = VdrfSecretKey::gen(&mut rng, t);
        let public_key = secret_key.public_key();

        // Generate party identifiers
        let x_values: Vec<NodeId> = (1..=n)
            .map(|i| format!("node:{}", i).parse().unwrap())
            .collect();

        // Deal secret shares
        let shares: Vec<_> = x_values
            .iter()
            .map(|id| (id, secret_key.deal(id).unwrap()))
            .collect();

        let input = Input("threshold test".to_string());

        // Test with exactly threshold number of shares
        let partial_evals_1: Vec<_> = shares[..t]
            .iter()
            .map(|(id, share)| {
                (
                    (*id).clone(),
                    Vdrf::partial_eval(&public_key, share, &input).unwrap(),
                )
            })
            .collect();

        let combined_eval_1 =
            Vdrf::combine::<_, 32>(&public_key, &input, &partial_evals_1).unwrap();
        let output1: [u8; 32] = Vdrf::verify(&public_key, &input, combined_eval_1).unwrap();

        // Test with different set of threshold shares
        let partial_evals_2: Vec<_> = shares[1..=t]
            .iter()
            .map(|(id, share)| {
                (
                    (*id).clone(),
                    Vdrf::partial_eval(&public_key, share, &input).unwrap(),
                )
            })
            .collect();

        let combined_eval_2 =
            Vdrf::combine::<_, 32>(&public_key, &input, &partial_evals_2).unwrap();
        let output2: [u8; 32] = Vdrf::verify(&public_key, &input, combined_eval_2).unwrap();

        // Both should produce the same output
        assert_eq!(output1, output2);

        // Test with more than threshold shares
        let partial_evals_all: Vec<_> = shares
            .iter()
            .map(|(id, share)| {
                (
                    (*id).clone(),
                    Vdrf::partial_eval(&public_key, share, &input).unwrap(),
                )
            })
            .collect();

        let combined_eval_all =
            Vdrf::combine::<_, 32>(&public_key, &input, &partial_evals_all).unwrap();
        let output3: [u8; 32] = Vdrf::verify(&public_key, &input, combined_eval_all).unwrap();

        // Should still produce the same output
        assert_eq!(output1, output3);
    }

    #[test]
    fn test_vdrf_error_cases() {
        let mut rng = thread_rng();
        let t = 2; // threshold

        // Key generation
        let secret_key = VdrfSecretKey::gen(&mut rng, t);
        let public_key = secret_key.public_key();

        // Test zero party identifier
        assert!(secret_key.share(pp::Fr::zero()).is_err());

        // Generate party identifiers
        let x_values: Vec<NodeId> = (1..=t)
            .map(|i| format!("node:{}", i).parse().unwrap())
            .collect();

        // Deal secret shares
        let shares: Vec<_> = x_values
            .iter()
            .map(|id| (id, secret_key.deal(id).unwrap()))
            .collect();

        let input = Input("test".to_string());

        // Test insufficient shares for reconstruction
        let partial_evals_insufficient: Vec<_> = shares[..1]
            .iter()
            .map(|(id, share)| {
                (
                    (*id).clone(),
                    Vdrf::partial_eval(&public_key, share, &input).unwrap(),
                )
            })
            .collect();

        // Only one share when threshold is 2
        assert!(Vdrf::combine::<_, 32>(&public_key, &input, &partial_evals_insufficient).is_err());

        // Compute partial evaluations for all shares
        let partial_evals: Vec<_> = shares
            .iter()
            .map(|(id, share)| {
                (
                    (*id).clone(),
                    Vdrf::partial_eval(&public_key, share, &input).unwrap(),
                )
            })
            .collect();

        // Combine partial evaluations
        let combined_eval = Vdrf::combine::<_, 32>(&public_key, &input, &partial_evals).unwrap();

        // Try to verify with different input
        let wrong_input = Input("wrong input".to_string());
        assert!(Vdrf::verify::<_, 32>(&public_key, &wrong_input, combined_eval).is_err());
    }
}
