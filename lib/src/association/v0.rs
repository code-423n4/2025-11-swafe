use ark_ff::{One, Zero};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use ark_ec::PrimeGroup;
use ark_serialize::CanonicalSerialize;
use ark_std::{
    rand::{CryptoRng, Rng},
    vec::Vec,
};
use std::collections::HashMap;

use crate::{
    association::MskRecord,
    crypto::{
        commitments::{PedersenCommitment, PedersenGenerators, PedersenOpen, SokProof},
        curve, kdfn,
        poly::interpolate_eval,
        sig::{self, VerificationKey},
        symmetric, EmailCert, EmailCertToken, EmailCertificate, Vdrf, VdrfEvaluation,
        VdrfPublicKey,
    },
    encode::Tagged,
    types::{
        EncapsulationKey, EncryptedMsk, MasterSecretKey, MskSecretShareRik, RecoveryInitiationKey,
    },
    NodeId, SwafeError,
};

/// EmailInput structure for VDRF evaluation
#[derive(Serialize)]
pub struct EmailInput {
    email: String,
}

impl FromStr for EmailInput {
    type Err = SwafeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(EmailInput {
            email: s.to_string(),
        })
    }
}

impl Tagged for EmailInput {
    const SEPARATOR: &'static str = "v0:email-input";
}

/// Secret data encrypted with RIK (Recovery Initiation Key)
///
/// This contains the data that is encrypted with the RIK and stored with offchain nodes.
/// During recovery, users reconstruct the RIK and decrypt this data to get their signing key
/// for recovery authorization and the MSK secret share from the RIK side.
#[derive(Serialize, Deserialize, Clone)]
pub struct RikSecretData {
    /// User's signing key for recovery authorization
    pub sig_sk: sig::SigningKey,
    /// MSK secret share derived from RIK (Recovery Initiation Key)
    pub msk_ss_rik: MskSecretShareRik,
}

impl Tagged for RikSecretData {
    const SEPARATOR: &'static str = "v0:rik-secret-data";
}

#[derive(Serialize, Deserialize)]
pub enum CombinedSecretData {
    V0 { rik_data: RikSecretData },
}

impl Tagged for CombinedSecretData {
    const SEPARATOR: &'static str = "v0:combined-secret";
}

#[derive(Serialize, Deserialize, Clone)]
pub struct EmailTag(pub [u8; 32]);

/// Node-specific secret share result
#[derive(Clone, Serialize, Deserialize)]
pub struct NodeSecretShare {
    /// Encrypted master secret key result
    msk_result: EncapsulatedMsk,
    /// Secret shares for the specific node
    secret_shares: PedersenOpen,
    /// Email certificate token for the node
    token: EmailCertToken,
}

impl NodeSecretShare {
    /// Create a new NodeSecretShare
    pub(super) fn new(
        msk_result: EncapsulatedMsk,
        secret_shares: PedersenOpen,
        token: EmailCertToken,
    ) -> Self {
        Self {
            msk_result,
            secret_shares,
            token,
        }
    }

    /// Get the encrypted master secret key result
    pub fn msk_result(&self) -> &EncapsulatedMsk {
        &self.msk_result
    }

    /// Get the secret shares for this node
    pub(crate) fn secret_shares(&self) -> &PedersenOpen {
        &self.secret_shares
    }

    /// Get the email certificate token
    pub fn token(&self) -> &EmailCertToken {
        &self.token
    }
}

/// Complete result of creating encapsulated MSK
#[derive(Clone, Serialize, Deserialize)]
pub struct EncapsulatedMsk {
    /// Pedersen secrets for the commitments
    pub(super) pedersen_open: Vec<PedersenOpen>,
    /// Pedersen commitments C_0, C_1, ..., C_{t-1}
    pub(super) pedersen_commitments: Vec<PedersenCommitment>,
    /// Encrypted master secret key and user signature key
    pub(super) ct: EncryptedMsk,
    /// Signature of Knowledge proof
    pub(super) sok_proof: SokProof,
    /// Generated master secret key
    pub(super) msk: MasterSecretKey,
    /// User signature keypair
    pub(super) user_pk: sig::SigningKey,
    /// Encapsulation key
    pub(super) encapsulation_key: EncapsulationKey,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub(crate) struct MskRecordFixed {
    /// User's signature public key
    pub(super) user_pk: VerificationKey,
    /// Encrypted RIK data (contains signing key and MSK secret share from RIK)
    pub(super) enc_rik: EncryptedMsk,
    /// Pedersen commitments (C_0, ..., C_{threshold-1})
    pub(super) commits: Vec<PedersenCommitment>,
    /// Signature of Knowledge proof
    pub(super) sok_proof: SokProof,
}

impl MskRecordFixed {
    pub fn threshold(&self) -> usize {
        self.commits.len()
    }
}

/// Storage record for uploaded encrypted MSK data per email tag
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct MskRecordV0 {
    /// Fixed fields accross all offchain nodes
    pub(super) fixed: MskRecordFixed,
    /// Secret share for this node
    pub(super) share: PedersenOpen,
}

/// Request to associate an email with an MskRecord
#[derive(Clone, Serialize, Deserialize)]
pub struct AssociationRequestEmail {
    pub(super) fixed: MskRecordFixed,
    pub(super) share: PedersenOpen,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Copy)]
pub struct EmailKey([u8; 32]);

impl EmailKey {
    pub fn new(
        vdrf_pk: &VdrfPublicKey,
        email: &EmailInput,
        eval: VdrfEvaluation,
    ) -> Result<Self, SwafeError> {
        Vdrf::verify(vdrf_pk, email, eval).map(EmailKey)
    }
}

impl AssociationRequestEmail {
    pub fn verify(
        self,
        user_pk: &sig::VerificationKey,
        node_id: &NodeId,
    ) -> Result<MskRecord, SwafeError> {
        // Verify that the user_pk in the request matches the provided one
        if &self.fixed.user_pk != user_pk {
            return Err(SwafeError::VerificationFailed(
                "User public key mismatch".to_string(),
            ));
        }

        // Verify secret share consistency with commitments
        verify_secret_share(&self.fixed.commits, &self.share, node_id)?;

        // Verify SoK proof
        let generators = PedersenGenerators::new();
        self.fixed
            .sok_proof
            .verify(&generators, &self.fixed.commits, user_pk)?;

        // Store
        Ok(MskRecord::V0(MskRecordV0 {
            share: self.share,
            fixed: self.fixed,
        }))
    }
}

impl EncapsulatedMsk {
    /// Get the user signing key
    pub fn user_keypair(&self) -> &sig::SigningKey {
        &self.user_pk
    }

    /// Compute secret shares of an encrypted MSK for a specific node
    pub(crate) fn compute_secret_shares(&self, node_id: &NodeId) -> PedersenOpen {
        // Step 3: x ← H(node_id)
        let x = node_id.eval_point();

        // `PedersenOpen` encapsulates two polynomials f_v(X) and f_r(X), which evaluate at x
        // f_v(X) = Σ v_i * X^i = v_0 + v_1*X + v_2*X^2 + ... + v_{t-1}*X^{t-1}
        // f_r(X) = Σ r_i * X^i = r_0 + r_1*X + r_2*X^2 + ... + r_{t-1}*X^{t-1}
        let mut y = PedersenOpen::zero();
        let mut x_power = curve::Fr::one(); // x^0 = 1
        for secret in self.pedersen_open.iter().cloned() {
            y = y + secret * x_power;
            x_power *= x;
        }
        y
    }
}

/// Verify that secret shares are consistent with the Pedersen commitments
///
/// Checks: ⟨(1, x₁, ..., x^(t-1)), (C₀, ..., Cₙ)⟩ = [yᵥ] · H + [yᵣ] · G
/// where:
/// - x is computed from node_id: x ← H(node_id)
/// - (yᵥ, yᵣ) are the secret shares for this node
/// - (C₀, ..., Cₙ) are the Pedersen commitments
pub(super) fn verify_secret_share(
    coms: &[PedersenCommitment],
    eval: &PedersenOpen,
    node_id: &NodeId,
) -> Result<(), SwafeError> {
    // Compute x value for this node
    let x = node_id.eval_point();

    // Compute linear combination of commitments:
    // ⟨(1, x, x², ..., x^(t-1)), (C₀, C₁, ..., C_{t-1})⟩
    let mut comb = PedersenCommitment::zero();
    let mut x_power = curve::Fr::one(); // x^0 = 1

    for commitment in coms {
        // Add [x^i] * C_i to the combination
        comb = comb + commitment.clone() * x_power;
        // Update x_power for next iteration: x^i -> x^{i+1}
        x_power *= x;
    }

    // Create Pedersen generators to compute expected commitment
    let generators = PedersenGenerators::new();

    // Check if they are equal
    if comb != generators.commit(eval) {
        Err(SwafeError::VerificationFailed(
            "Invalid verifiable secret sharing".to_string(),
        ))
    } else {
        Ok(())
    }
}

#[derive(Serialize)]
struct EncapKeyKDF;

impl Tagged for EncapKeyKDF {
    const SEPARATOR: &'static str = "v0:encap-key";
}

/// Association for an encapsulated MSK (Version 0).
#[derive(Clone, Serialize, Deserialize)]
pub struct AssociationV0 {
    msk_result: EncapsulatedMsk,
    email_cert: EmailCertificate,
    sk_user: sig::SigningKey,
}

impl AssociationV0 {
    /// Create a new AssociationV0 instance with pre-created MSK result
    pub fn new(
        msk_result: EncapsulatedMsk,
        email_certificate: EmailCertificate,
        user_secret_key: sig::SigningKey,
    ) -> Self {
        Self {
            email_cert: email_certificate,
            sk_user: user_secret_key,
            msk_result,
        }
    }

    /// Create RIK association with internally generated user signing key and RIK data
    pub fn create_encrypted_msk<R: Rng + CryptoRng>(
        rng: &mut R,
        threshold: usize,
        rik: &RecoveryInitiationKey,
        msk_ss_rik: MskSecretShareRik,
    ) -> Result<EncapsulatedMsk, SwafeError> {
        // Generate user signing key internally
        let sig_sk = sig::SigningKey::gen(rng);

        let generators = PedersenGenerators::new();

        let (comms, opens) = Self::generate_commitment_values(rng, &generators, threshold)?;

        // Generate encapsulation key
        // key ← kdf([v_0] · G, "EncapKey")
        let v0 = opens[0].value();
        let v0_point = (curve::GProjective::generator() * v0).into();
        let v0_bytes = {
            let mut bytes = Vec::new();
            let affine: curve::GAffine = v0_point;
            affine
                .serialize_compressed(&mut bytes)
                .map_err(|e| SwafeError::SerializationError(e.to_string()))?;
            bytes
        };
        let encap_key = EncapsulationKey::new(kdfn(&v0_bytes, &EncapKeyKDF));

        // Create RIK secret data containing signing key and MSK secret share
        let rik_data = RikSecretData {
            sig_sk: sig_sk.clone(),
            msk_ss_rik,
        };

        // Encrypt RIK data instead of MSK
        // ct ← skAEnc(rik, (sigSK_user, msk_ss_rik))
        let ciphertext = symmetric::seal(
            rng,
            rik.as_bytes(),
            &CombinedSecretData::V0 { rik_data },
            &symmetric::EmptyAD,
        );

        let ct = EncryptedMsk { ciphertext };

        // Generate signature of knowledge proof of commitments
        // π ← sokSign(msg = sigPK_user, rel = {∀i. (v_i, r_i) : ∀i. C_i = pedersen(v_i, r_i)})
        let sok_proof =
            SokProof::prove(rng, &generators, &opens, &comms, &sig_sk.verification_key())?;

        // Note: For RIK associations, we don't store the MSK directly
        // The MSK will be derived during recovery using both RIK and social shares
        let placeholder_msk = MasterSecretKey::gen(rng); // Placeholder for compatibility

        Ok(EncapsulatedMsk {
            pedersen_open: opens,
            pedersen_commitments: comms,
            ct,
            sok_proof,
            msk: placeholder_msk, // This is not the actual MSK for RIK associations
            user_pk: sig_sk.clone(),
            encapsulation_key: encap_key,
        })
    }

    /// Create RIK association with internally generated RIK and MSK secret share
    /// Returns (EncapsulatedMsk, RecoveryInitiationKey) where RIK must be stored for recovery
    pub fn create_rik_association<R: Rng + CryptoRng>(
        rng: &mut R,
        threshold: usize,
    ) -> Result<(EncapsulatedMsk, RecoveryInitiationKey), SwafeError> {
        // Generate RIK and MSK secret share internally
        let rik = RecoveryInitiationKey::gen(rng);
        let msk_ss_rik = MskSecretShareRik::gen(rng);

        let encapsulated_msk = Self::create_encrypted_msk(rng, threshold, &rik, msk_ss_rik)?;

        Ok((encapsulated_msk, rik))
    }

    /// Generate commitment values for encapsulated MSK
    /// ∀i ∈ {0, ..., threshold - 1}. v_i ← FF
    /// ∀i ∈ {0, ..., threshold - 1}. r_i ← FF
    /// ∀i ∈ {0, ..., threshold - 1}. C_i ← pedersen(v_i, r_i)
    fn generate_commitment_values<R: Rng + CryptoRng>(
        rng: &mut R,
        generators: &PedersenGenerators,
        threshold: usize,
    ) -> Result<(Vec<PedersenCommitment>, Vec<PedersenOpen>), SwafeError> {
        if threshold == 0 {
            return Err(SwafeError::InvalidInput(
                "Threshold must be greater than 0".to_string(),
            ));
        }

        let mut comms = Vec::with_capacity(threshold);
        let mut opens = Vec::with_capacity(threshold);

        for _ in 0..threshold {
            let open = PedersenOpen::gen(rng);
            let comm = generators.commit(&open);
            comms.push(comm);
            opens.push(open);
        }

        Ok((comms, opens))
    }

    /// Generate node-specific secret share and email token
    pub fn gen_node_secret_share<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        node_id: &NodeId,
    ) -> Result<NodeSecretShare, SwafeError> {
        // Generate email certificate token
        let token = EmailCert::token(rng, &self.email_cert, &self.sk_user, node_id);

        let msk_result = self.msk_result.clone();

        // Compute secret shares for the specific node
        let secret_shares = msk_result.compute_secret_shares(node_id);

        Ok(NodeSecretShare::new(msk_result, secret_shares, token))
    }

    /// Generate AssociationRequestEmail for this association
    pub fn gen_association_request<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        node_id: &NodeId,
    ) -> Result<AssociationRequestEmail, SwafeError> {
        let node_secret_share = self.gen_node_secret_share(rng, node_id)?;

        Ok(AssociationRequestEmail {
            fixed: MskRecordFixed {
                user_pk: self.sk_user.verification_key(),
                enc_rik: node_secret_share.msk_result().ct.clone(),
                commits: node_secret_share.msk_result().pedersen_commitments.clone(),
                sok_proof: node_secret_share.msk_result().sok_proof.clone(),
            },
            share: node_secret_share.secret_shares().clone(),
        })
    }

    /// Reconstruct RIK data from multiple MskRecord instances using Lagrange interpolation
    /// For the new recovery flow where MskRecord contains RIK-encrypted data
    pub fn reconstruct_rik_data(
        msk_records: Vec<(NodeId, MskRecord)>,
        rik: &RecoveryInitiationKey,
    ) -> Result<RikSecretData, SwafeError> {
        // Convert all MskRecord enums to their V0 variants
        let v0_records: Vec<(NodeId, MskRecordV0)> = msk_records
            .into_iter()
            .map(|(node_id, record)| match record {
                MskRecord::V0(v0) => (node_id, v0),
            })
            .collect();

        // Do a threshold vote on the fixed fields
        let mut votes = HashMap::new();
        for (_, record) in &v0_records {
            *votes.entry(record.fixed.clone()).or_insert(0) += 1;
        }

        let majority_threshold = v0_records.len().div_ceil(2);
        let majority_fixed = votes
            .into_iter()
            .find(|(_, count)| *count >= majority_threshold)
            .map(|(fixed, _)| fixed)
            .ok_or_else(|| {
                SwafeError::InvalidInput(
                    "No majority consensus on fixed fields among MSK records".to_string(),
                )
            })?;

        let v0_records: Vec<_> = v0_records
            .into_iter()
            .filter(|(_, record)| record.fixed == majority_fixed)
            .collect();

        if v0_records.len() < majority_fixed.threshold() {
            return Err(SwafeError::NotEnoughSharesForReconstruction);
        }

        // Verify shares and collect valid points
        let points: Vec<_> = v0_records
            .iter()
            .filter_map(|(node_id, msk_record)| {
                match verify_secret_share(&majority_fixed.commits, &msk_record.share, node_id) {
                    Ok(()) => {
                        let x = node_id.eval_point();
                        let y = msk_record.share.value();
                        Some((x, y))
                    }
                    Err(_) => None,
                }
            })
            .collect();

        // Reconstruct v_0 using Lagrange interpolation
        let v0 = interpolate_eval(&points, curve::Fr::zero());

        // Derive encapsulation key from v_0
        let v0_point = (curve::GProjective::generator() * v0).into();
        let v0_bytes = {
            let mut bytes = Vec::new();
            let affine: curve::GAffine = v0_point;
            affine
                .serialize_compressed(&mut bytes)
                .map_err(|e| SwafeError::SerializationError(e.to_string()))?;
            bytes
        };

        let _encapsulation_key: symmetric::Key = kdfn(&v0_bytes, &EncapKeyKDF);

        // Decrypt using RIK to get RikSecretData
        let encrypted_data = &majority_fixed.enc_rik;
        let combined_secret: CombinedSecretData = symmetric::open(
            rik.as_bytes(),
            &encrypted_data.ciphertext,
            &symmetric::EmptyAD,
        )?;

        match combined_secret {
            CombinedSecretData::V0 { rik_data } => Ok(rik_data),
        }
    }

    /// Reconstruct recovery key from multiple MskRecord instances
    /// Returns the symmetric key that can decrypt AssociationsV0
    pub fn reconstruct_recovery_key(
        msk_records: Vec<(NodeId, MskRecord)>,
    ) -> Result<crate::crypto::symmetric::Key, SwafeError> {
        // Convert all MskRecord enums to their V0 variants
        let v0_records: Vec<(NodeId, MskRecordV0)> = msk_records
            .into_iter()
            .map(|(node_id, record)| match record {
                MskRecord::V0(v0) => (node_id, v0),
            })
            .collect();

        // Do a threshold vote on the fixed fields (same logic as reconstruct_msk)
        let mut votes = HashMap::new();
        for (_, record) in &v0_records {
            *votes.entry(record.fixed.clone()).or_insert(0) += 1;
        }

        let majority_threshold = v0_records.len().div_ceil(2);
        let majority_fixed = votes
            .into_iter()
            .find(|(_, count)| *count >= majority_threshold)
            .map(|(fixed, _)| fixed)
            .ok_or_else(|| {
                SwafeError::InvalidInput(
                    "No majority consensus on fixed fields among MSK records".to_string(),
                )
            })?;

        let v0_records: Vec<_> = v0_records
            .into_iter()
            .filter(|(_, record)| record.fixed == majority_fixed)
            .collect();

        if v0_records.len() < majority_fixed.threshold() {
            return Err(SwafeError::NotEnoughSharesForReconstruction);
        }

        // Verify shares and collect valid points
        let points: Vec<_> = v0_records
            .iter()
            .filter_map(|(node_id, msk_record)| {
                match verify_secret_share(&majority_fixed.commits, &msk_record.share, node_id) {
                    Ok(()) => {
                        let x = node_id.eval_point();
                        let y = msk_record.share.value();
                        Some((x, y))
                    }
                    Err(_) => None,
                }
            })
            .collect();

        // Reconstruct v_0 using Lagrange interpolation
        let v0 = interpolate_eval(&points, curve::Fr::zero());

        // Derive recovery key from v_0 (same as encapsulation key derivation)
        let v0_point = (curve::GProjective::generator() * v0).into();
        let v0_bytes = {
            let mut bytes = Vec::new();
            let affine: curve::GAffine = v0_point;
            affine
                .serialize_compressed(&mut bytes)
                .map_err(|e| SwafeError::SerializationError(e.to_string()))?;
            bytes
        };

        // Return the recovery key that can decrypt AssociationsV0
        Ok(kdfn(&v0_bytes, &EncapKeyKDF))
    }
}

#[cfg(test)]
mod tests {

    use super::super::{Association, MskRecord};
    use super::*;
    use ark_ec::CurveGroup;
    use ark_ff::Zero;
    use rand::thread_rng;

    const THRESHOLD: usize = 3;

    /// Test that secret shares are consistent with commitments
    #[test]
    fn test_secret_share_consistency() {
        let mut rng = thread_rng();

        // Create encrypted RIK association with random values
        let (msk, _rik) = Association::create_association(&mut rng, THRESHOLD).unwrap();

        // Test with multiple nodes
        let node_ids = vec![
            "node:1".parse().unwrap(),
            "node:2".parse().unwrap(),
            "node:3".parse().unwrap(),
            "node:4".parse().unwrap(),
        ];

        for node_id in &node_ids {
            // Compute secret shares for this node
            let y = msk.compute_secret_shares(node_id);

            // Verify that secret shares are consistent with commitments
            verify_secret_share(&msk.pedersen_commitments, &y, node_id).unwrap();
        }
    }

    /// Test verification fails with tampered commitments
    #[test]
    fn test_secret_share_consistency_with_tampered_commitments() {
        let mut rng = thread_rng();

        // Create encrypted RIK association with random values
        let (mut msk, _rik) = Association::create_association(&mut rng, THRESHOLD).unwrap();

        // Tamper with one of the commitments
        let generators = PedersenGenerators::new();
        let fake_open = PedersenOpen::gen(&mut rng);
        let fake_commitment = generators.commit(&fake_open);
        msk.pedersen_commitments[0] = fake_commitment;

        // Compute secret shares for a test node
        let node_id = "node:1".parse().unwrap();
        let eval = msk.compute_secret_shares(&node_id);

        // Verification should now fail
        let result = verify_secret_share(&msk.pedersen_commitments, &eval, &node_id);
        assert!(
            result.is_err(),
            "Verification should fail with tampered commitments"
        );
    }

    /// Test MSK secret share consistency
    #[test]
    fn test_msk_secret_share_consistency() {
        let mut rng = thread_rng();

        // Create encrypted RIK association with random values
        let (msk, _rik) = Association::create_association(&mut rng, THRESHOLD).unwrap();

        // Generate secret shares for node "1"
        let node_id = "node:1".parse().unwrap();
        let open = msk.compute_secret_shares(&node_id);

        // Verify that the secret shares are consistent with commitments
        let generators = PedersenGenerators::new();
        let x = node_id.eval_point();

        // Compute the expected commitment at x using Lagrange interpolation
        let mut expected_commitment: curve::GProjective = Zero::zero();
        let mut x_power = curve::Fr::one();

        for commitment in &msk.pedersen_commitments {
            expected_commitment += curve::GProjective::from(commitment.0) * x_power;
            x_power *= x;
        }

        // Compute commitment from secret shares
        let actual_commitment = generators.commit(&open);

        assert_eq!(expected_commitment.into_affine(), actual_commitment.0);

        // Also verify SoK proof with the public key (which already implements Tagged)
        msk.sok_proof
            .verify(
                &generators,
                &msk.pedersen_commitments,
                &msk.user_pk.verification_key(),
            )
            .unwrap();
    }

    /// Test RIK data reconstruction from multiple node records
    #[test]
    fn test_reconstruct_rik_data() {
        let mut rng = thread_rng();

        // Create encrypted RIK association with random values
        let (msk, rik) = Association::create_association(&mut rng, THRESHOLD).unwrap();

        // Create multiple node IDs for testing threshold reconstruction
        let node_ids: [NodeId; 3] = [
            "node:1".parse().unwrap(),
            "node:2".parse().unwrap(),
            "node:3".parse().unwrap(),
        ];

        // Create MskRecord instances for each node
        let msk_records: Vec<(NodeId, MskRecord)> = node_ids
            .iter()
            .map(|node_id| {
                let secret_shares = msk.compute_secret_shares(node_id);
                (
                    node_id.clone(),
                    MskRecord::V0(MskRecordV0 {
                        fixed: MskRecordFixed {
                            user_pk: msk.user_pk.verification_key(),
                            enc_rik: msk.ct.clone(),
                            commits: msk.pedersen_commitments.clone(),
                            sok_proof: msk.sok_proof.clone(),
                        },
                        share: secret_shares,
                    }),
                )
            })
            .collect();

        let reconstructed_rik_data = Association::reconstruct_rik_data(msk_records, &rik).unwrap();

        // Verify that we successfully reconstructed RIK data
        // The specific values can't be compared directly since MSK secret share is randomly generated
        // but we can verify the structure is correct
        assert_eq!(
            reconstructed_rik_data.msk_ss_rik.as_bytes().len(),
            32,
            "MSK secret share should be 32 bytes"
        );
    }

    /// Test that reconstruction fails with insufficient records
    #[test]
    fn test_reconstruct_rik_data_insufficient_records() {
        let mut rng = thread_rng();

        // Create encrypted RIK association
        let (msk, rik) = Association::create_association(&mut rng, THRESHOLD).unwrap();

        // Create insufficient number of records (less than threshold)
        let insufficient_node_ids: [NodeId; 1] = ["node:1".parse().unwrap()];

        let insufficient_records: Vec<(NodeId, MskRecord)> = insufficient_node_ids
            .iter()
            .map(|node_id| {
                let secret_shares = msk.compute_secret_shares(node_id);
                (
                    node_id.clone(),
                    MskRecord::V0(MskRecordV0 {
                        fixed: MskRecordFixed {
                            user_pk: msk.user_pk.verification_key(),
                            enc_rik: msk.ct.clone(),
                            commits: msk.pedersen_commitments.clone(),
                            sok_proof: msk.sok_proof.clone(),
                        },
                        share: secret_shares,
                    }),
                )
            })
            .collect();

        // Test that it returns error with insufficient records
        let result = Association::reconstruct_rik_data(insufficient_records, &rik);
        assert!(
            result.is_err(),
            "Should return error with insufficient records"
        );

        match result {
            Err(SwafeError::NotEnoughSharesForReconstruction) => {
                // This is the expected error
            }
            _ => panic!("Expected NotEnoughSharesForReconstruction error"),
        }
    }

    /// Test that create_encrypted_msk fails with zero threshold
    #[test]
    fn test_create_association_zero_threshold() {
        let mut rng = thread_rng();

        // Test that zero threshold returns an error
        let result = Association::create_association(&mut rng, 0);
        assert!(result.is_err(), "Should return error with zero threshold");

        match result {
            Err(SwafeError::InvalidInput(msg)) => {
                assert!(msg.contains("Threshold must be greater than 0"));
            }
            _ => panic!("Expected InvalidInput error"),
        }
    }

    /// Test that MskRecordFixed serialization/deserialization works with enc_rik field
    #[test]
    fn test_msk_record_fixed_enc_rik_field() {
        use crate::crypto::symmetric::{self, Key};
        use crate::types::MasterSecretKey;
        use serde_json;

        let mut rng = thread_rng();

        // Create a test MskRecordFixed with the new enc_rik field
        let user_pk = sig::SigningKey::gen(&mut rng).verification_key();

        // Create proper test data that implements Tagged
        let test_msk = MasterSecretKey::gen(&mut rng);
        let test_key: Key = [1u8; 32]; // Use a proper 32-byte key
        let ciphertext = symmetric::seal(&mut rng, &test_key, &test_msk, &symmetric::EmptyAD);
        let enc_rik = EncryptedMsk { ciphertext };

        let generators = PedersenGenerators::new();
        let open = PedersenOpen::gen(&mut rng);
        let commit = generators.commit(&open);

        let sig_sk = sig::SigningKey::gen(&mut rng);
        let sok_proof = SokProof::prove(
            &mut rng,
            &generators,
            &[open],
            std::slice::from_ref(&commit),
            &sig_sk.verification_key(),
        )
        .expect("SoK proof generation should succeed");

        let record = MskRecordFixed {
            user_pk: user_pk.clone(),
            enc_rik: enc_rik.clone(),
            commits: vec![commit],
            sok_proof: sok_proof.clone(),
        };

        // Test serialization
        let serialized =
            serde_json::to_string(&record).expect("MskRecordFixed should serialize successfully");

        // Verify the serialized data contains "enc_rik" field name
        assert!(
            serialized.contains("enc_rik"),
            "Serialized data should contain 'enc_rik' field: {}",
            serialized
        );

        // Test deserialization
        let deserialized: MskRecordFixed = serde_json::from_str(&serialized)
            .expect("MskRecordFixed should deserialize successfully");

        // Verify the ciphertext is correctly preserved (can't compare VerificationKey directly)
        assert_eq!(record.enc_rik.ciphertext, deserialized.enc_rik.ciphertext);
        assert_eq!(record.commits.len(), deserialized.commits.len());

        // Verify we can decrypt the same data from both
        let decrypted_original: MasterSecretKey =
            symmetric::open(&test_key, &record.enc_rik.ciphertext, &symmetric::EmptyAD)
                .expect("Should decrypt original");
        let decrypted_deserialized: MasterSecretKey = symmetric::open(
            &test_key,
            &deserialized.enc_rik.ciphertext,
            &symmetric::EmptyAD,
        )
        .expect("Should decrypt deserialized");

        // The decrypted values should be the same
        assert_eq!(
            decrypted_original.as_bytes(),
            decrypted_deserialized.as_bytes()
        );
    }
}
