pub(crate) mod v0;

use ark_std::rand::{CryptoRng, Rng};

use crate::{
    crypto::{sig, EmailCertificate},
    types::{MskSecretShareRik, RecoveryInitiationKey},
    versioned_enum, NodeId, SwafeError,
};

pub use v0::{
    AssociationRequestEmail, CombinedSecretData, EmailInput, EmailKey, EmailTag, EncapsulatedMsk,
    NodeSecretShare, RikSecretData,
};

use v0::{AssociationV0, MskRecordV0};

versioned_enum!(
    #[derive(Clone)]
    MskRecord,
    V0(MskRecordV0) = 0
);

versioned_enum!(
    #[derive(Clone)]
    Association,
    V0(AssociationV0) = 0
);

impl Association {
    /// Create a new Association instance with pre-created MSK result
    pub fn new(
        msk_result: EncapsulatedMsk,
        email_certificate: EmailCertificate,
        user_secret_key: sig::SigningKey,
    ) -> Self {
        Self::V0(AssociationV0::new(
            msk_result,
            email_certificate,
            user_secret_key,
        ))
    }

    /// Create RIK association with internally generated user signing key and RIK data
    pub fn create_encrypted_msk<R: Rng + CryptoRng>(
        rng: &mut R,
        threshold: usize,
        rik: &RecoveryInitiationKey,
        msk_ss_rik: MskSecretShareRik,
    ) -> Result<EncapsulatedMsk, SwafeError> {
        AssociationV0::create_encrypted_msk(rng, threshold, rik, msk_ss_rik)
    }

    /// Create association with internally generated RIK and MSK secret share
    /// Returns (EncapsulatedMsk, RecoveryInitiationKey) where RIK must be stored for recovery
    pub fn create_association<R: Rng + CryptoRng>(
        rng: &mut R,
        threshold: usize,
    ) -> Result<(EncapsulatedMsk, RecoveryInitiationKey), SwafeError> {
        AssociationV0::create_rik_association(rng, threshold)
    }

    /// Generate node-specific secret share and email token
    pub fn gen_node_secret_share<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        node_id: &NodeId,
    ) -> Result<NodeSecretShare, SwafeError> {
        match self {
            Association::V0(v0) => v0.gen_node_secret_share(rng, node_id),
        }
    }

    /// Generate AssociationRequestEmail for this association
    pub fn gen_association_request<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        node_id: &NodeId,
    ) -> Result<AssociationRequestEmail, SwafeError> {
        match self {
            Association::V0(v0) => v0.gen_association_request(rng, node_id),
        }
    }

    /// Reconstruct RIK data from multiple MskRecord instances using Lagrange interpolation
    /// For the new recovery flow where MskRecord contains RIK-encrypted data
    pub fn reconstruct_rik_data(
        msk_records: Vec<(NodeId, MskRecord)>,
        rik: &RecoveryInitiationKey,
    ) -> Result<RikSecretData, SwafeError> {
        AssociationV0::reconstruct_rik_data(msk_records, rik)
    }

    /// Reconstruct recovery key from multiple MskRecord instances
    /// Returns the symmetric key that can decrypt AssociationsV0
    pub fn reconstruct_recovery_key(
        msk_records: Vec<(NodeId, MskRecord)>,
    ) -> Result<crate::crypto::symmetric::Key, SwafeError> {
        AssociationV0::reconstruct_recovery_key(msk_records)
    }
}
