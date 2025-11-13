use ark_std::rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::crypto::symmetric as sym;
use crate::Tagged;
// Type alias for elliptic curve group
pub mod curve {
    pub type Fr = ark_ed25519::Fr;
    pub type Projective = ark_ed25519::EdwardsProjective;
    pub type Affine = ark_ed25519::EdwardsAffine;
}

/// Master secret key
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct MasterSecretKey(sym::Key);

impl core::fmt::Debug for MasterSecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MasterSecretKey([REDACTED])")
    }
}
impl MasterSecretKey {
    pub fn new(bytes: sym::Key) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &sym::Key {
        &self.0
    }

    pub fn gen<R: CryptoRng + Rng>(rng: &mut R) -> Self {
        Self(rng.gen())
    }
}

impl Tagged for MasterSecretKey {
    const SEPARATOR: &'static str = "v0:msk";
}

/// Encapsulation key used to encrypt the master secret key
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct EncapsulationKey(sym::Key);

impl EncapsulationKey {
    pub fn new(bytes: sym::Key) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &sym::Key {
        &self.0
    }
}

/// Encrypted master secret key
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct EncryptedMsk {
    pub(crate) ciphertext: sym::AEADCiphertext,
}

/// Recovery Initiation Key (RIK) - used to initiate recovery process
///
/// The RIK is stored with offchain nodes and encrypts the signing key and MSK secret share.
/// During recovery, users reconstruct the RIK from threshold offchain nodes, then use it
/// to decrypt their signing key for recovery authorization.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct RecoveryInitiationKey(sym::Key);

impl RecoveryInitiationKey {
    pub fn new(bytes: sym::Key) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &sym::Key {
        &self.0
    }

    pub fn gen<R: CryptoRng + Rng>(rng: &mut R) -> Self {
        Self(rng.gen())
    }
}

impl Tagged for RecoveryInitiationKey {
    const SEPARATOR: &'static str = "v0:rik";
}

/// MSK secret share derived from RIK
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, ZeroizeOnDrop, Debug)]
pub struct MskSecretShareRik(sym::Key);

impl MskSecretShareRik {
    pub fn new(bytes: sym::Key) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &sym::Key {
        &self.0
    }

    pub fn gen<R: CryptoRng + Rng>(rng: &mut R) -> Self {
        Self(rng.gen())
    }
}

/// MSK secret share from social recovery
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct MskSecretShareSocial(sym::Key);

impl MskSecretShareSocial {
    pub fn new(bytes: sym::Key) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &sym::Key {
        &self.0
    }

    pub fn gen<R: CryptoRng + Rng>(rng: &mut R) -> Self {
        Self(rng.gen())
    }
}

impl Tagged for MskSecretShareSocial {
    const SEPARATOR: &'static str = "v0:msk_ss_social";
}

/// KDF context for deriving MSK decryption key from both RIK and social shares
pub const MSK_RECOVERY_KDF_CONTEXT: &[u8] = b"swafe:v0:msk_recovery_kdf";
