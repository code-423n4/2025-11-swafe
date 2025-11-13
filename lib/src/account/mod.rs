#[cfg(test)]
mod tests;
pub(crate) mod v0;

use crate::backup::{BackupCiphertext, BackupId};
use crate::crypto::{hash::hash, pke, sig};
use crate::errors::Result;
use crate::types::{MasterSecretKey, RecoveryInitiationKey};
use crate::versioned_enum;

use ark_std::rand::{CryptoRng, Rng};

use serde::{Deserialize, Serialize};
use std::fmt::Display;

pub use v0::{AccountSecrets, RecoverySecrets};

use v0::{AccountStateV0, AccountUpdateV0};

/// Account identifier type
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
pub struct AccountId([u8; 32]);

#[cfg(test)]
impl AccountId {
    pub fn random<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        AccountId(rng.gen())
    }
}

impl AsRef<[u8; 32]> for AccountId {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Display for AccountId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "account:{}", hex::encode(self.0))
    }
}

impl AccountId {
    // This method is intentially left unexported.
    pub(crate) fn from_vk(vk: &sig::VerificationKey) -> Self {
        AccountId(hash(vk))
    }

    /// Create AccountId from a verification key (for node setup)
    pub fn from_verification_key(vk: &sig::VerificationKey) -> Self {
        Self::from_vk(vk)
    }
}

impl crate::encode::Tagged for AccountId {
    const SEPARATOR: &'static str = "v0:account-id";
}

versioned_enum!(
    #[derive(Clone)]
    AccountState,
    V0(AccountStateV0) = 0
);

versioned_enum!(
    #[derive(Clone)]
    AccountUpdate,
    V0(AccountUpdateV0) = 0
);

// AccountState implementations
impl AccountState {
    pub(crate) fn encryption_key(&self) -> pke::EncryptionKey {
        match self {
            AccountState::V0(st) => st.encryption_key(),
        }
    }

    /// Get recovery backups
    pub fn recover_backups(&self) -> Vec<&BackupCiphertext> {
        match self {
            AccountState::V0(st) => st.recover_backups(),
        }
    }

    /// Get a recovery backup by ID
    pub fn recover_id(&self, id: BackupId) -> Option<&BackupCiphertext> {
        self.recover_backups().into_iter().find(|ct| ct.id() == id)
    }

    #[allow(dead_code)]
    pub fn decrypt(&self, msk: &MasterSecretKey, acc: AccountId) -> Result<AccountSecrets> {
        match self {
            AccountState::V0(st) => st.decrypt(msk, acc),
        }
    }

    /// Initiate recovery using the RIK from offchain nodes
    pub fn initiate_recovery<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        acc: AccountId,
        rik: &RecoveryInitiationKey,
    ) -> Result<(AccountUpdate, v0::RecoverySecrets)> {
        match self {
            AccountState::V0(st) => st.initiate_recovery(rng, acc, rik),
        }
    }
}

// AccountSecrets trait implementations
impl AsRef<MasterSecretKey> for AccountSecrets {
    fn as_ref(&self) -> &MasterSecretKey {
        self.msk()
    }
}

impl AsRef<AccountId> for AccountSecrets {
    fn as_ref(&self) -> &AccountId {
        self.acc()
    }
}

// AccountUpdate implementations
impl AccountUpdate {
    /// Returns the *claimed* account id of the update
    ///
    /// We should *not* trust this to be the correct account id.
    pub fn unsafe_account_id(&self) -> AccountId {
        match self {
            AccountUpdate::V0(update) => update.acc,
        }
    }

    /// Verify an update (possible against the old state of the account)
    pub fn verify(self, old: Option<&AccountState>) -> Result<AccountState> {
        match (self, old) {
            (AccountUpdate::V0(update), None) => {
                let st = update.verify_allocation()?;
                Ok(AccountState::V0(st))
            }
            (AccountUpdate::V0(update), Some(AccountState::V0(old))) => {
                let st = update.verify_update(old)?;
                Ok(AccountState::V0(st))
            }
        }
    }
}
