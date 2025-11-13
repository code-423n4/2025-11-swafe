use ark_std::rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};

use super::{AccountId, AccountState, AccountUpdate};

use crate::{
    backup::{
        v0::{BackupCiphertextV0, BackupShareV0, DecryptedShareV0},
        AADBackup, //
        BackupCiphertext,
        BackupId,
        EncryptionContext,
        GuardianShare,
        SecretShare,
    },
    crypto::{
        hash::{self, EmptyInfo},
        pke, sig, symmetric as sym,
    },
    encode::Tagged,
    errors::Result,
    types::{
        MasterSecretKey, //
        MskSecretShareRik,
        MskSecretShareSocial,
        RecoveryInitiationKey,
    },
    SwafeError,
};

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct AccountUpdateV0 {
    pub acc: AccountId,        // id of the account to be updated
    pub msg: AccountMessageV0, //
}

#[derive(Clone)]
pub struct AccountSecretsV0Recovery {
    msk_ss_social: MskSecretShareSocial,
    msk_ss_rik: MskSecretShareRik,
    guardians: Vec<AccountId>,
    threshold: u32,
    social: BackupCiphertext,
    assoc: Vec<AssociationSecretV0>,
}

#[derive(Clone)]
pub struct AccountSecrets {
    dirty: bool,
    acc: AccountId,
    cnt: u32,
    msk: MasterSecretKey,
    backups: Vec<BackupCiphertext>,
    recover: Vec<BackupCiphertext>,
    sig: sig::SigningKey,
    pke: pke::DecryptionKey,
    old_sig: sig::SigningKey,
    old_msk: Vec<MasterSecretKey>,
    old_pke: Vec<pke::DecryptionKey>,
    recovery: AccountSecretsV0Recovery,
}

use crate::versioned_enum;

versioned_enum!(CombinedSecret, V0(CombinedSecretV0) = 0);

#[derive(Serialize, Deserialize)]
pub(crate) struct CombinedSecretV0 {
    pub(super) sig: sig::SigningKey,
    pub(super) pke: pke::DecryptionKey,
    pub(super) old_pke: Vec<pke::DecryptionKey>,
    pub(super) old_msk: Vec<MasterSecretKey>,
    pub(super) recovery: RecoverySecretV0,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct RecoverySecretV0 {
    msk_ss_social: MskSecretShareSocial,
    msk_ss_rik: MskSecretShareRik,
    guardians: Vec<AccountId>,
    threshold: u32,
    assoc: Vec<AssociationSecretV0>,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct AssociationSecretV0 {
    rik: RecoveryInitiationKey,
}

impl Tagged for CombinedSecret {
    const SEPARATOR: &'static str = "v0:combined-secret";
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct AssociationsV0 {
    pub(crate) sig: sig::VerificationKey,
    pub(crate) encap: sym::AEADCiphertext,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct RecoveryStateV0 {
    pub pke: Option<pke::EncryptionKey>, // this is set iff. recovery has been started
    pub(crate) assoc: Vec<AssociationsV0>, // encryption of the recovery authorization key
    pub(crate) social: BackupCiphertext, // social backup ciphertext
    pub(crate) enc_msk: sym::AEADCiphertext, // encrypted MSK (encrypted with key derived from RIK and social shares)
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct EncapV0 {
    pub(crate) key_sig: sig::SigningKey,
    pub(crate) msk_ss_rik: MskSecretShareRik,
}

impl Tagged for EncapV0 {
    const SEPARATOR: &'static str = "v0:encap";
}

#[derive(Serialize)]
#[cfg_attr(test, derive(Clone))]
pub(crate) struct RecoveryRequestMessage {
    pub(crate) account_id: AccountId,
    pub(crate) recovery_pke: pke::EncryptionKey,
}

impl Tagged for RecoveryRequestMessage {
    const SEPARATOR: &'static str = "v0:recovery-request";
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RecoverySecrets {
    acc: AccountId,
    rec: RecoveryStateV0,
    msk_ss_rik: sym::Key,
    dkey: pke::DecryptionKey,
}

impl RecoverySecrets {
    /// Complete recovery of the master secret key
    ///
    /// This function takes the account state and recovery secrets,
    /// along with guardian shares, and reconstructs the MSK using the dual-recovery approach.
    ///
    /// # Arguments
    /// * `shares` - Guardian shares from the social recovery system
    pub fn complete(&self, shares: &[GuardianShare]) -> Result<MasterSecretKey> {
        // recover the social secret share from the backup
        let msk_ss_social: MskSecretShareSocial = match &self.rec.social {
            BackupCiphertext::V0(v0) => {
                v0.recover(&self.dkey, &self.msk_ss_rik, &EmptyInfo, shares)?
            }
        };

        // derive the MSK decryption key from both secret shares
        let msk_dec_key = derive_msk_decryption_key(
            &self.acc,
            &MskSecretShareRik::new(self.msk_ss_rik),
            &msk_ss_social,
        );

        // decrypt the MSK using the derived key
        sym::open(&msk_dec_key, &self.rec.enc_msk, &self.acc)
    }
}

impl AccountStateV0 {
    /// Initiate recovery using the RIK from offchain nodes
    ///
    /// Decrypts the AssociationsV0 using RIK to get signing key and MSK secret share,
    /// then creates a signed recovery update for uploading to the contract
    /// which signals the start of social recovery.
    pub fn initiate_recovery<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        acc: AccountId,
        rik: &RecoveryInitiationKey,
    ) -> Result<(AccountUpdate, RecoverySecrets)> {
        // decrypt AssociationsV0 using RIK
        let encap = self
            .rec
            .assoc
            .iter()
            .find_map(|assoc| {
                // attempt to decrypt the encapsulated key using RIK
                let encap = sym::open::<EncapV0, _>(rik.as_bytes(), &assoc.encap, &acc).ok()?;

                // check if the verification key matches the expected one
                if encap.key_sig.verification_key() != assoc.sig {
                    None
                } else {
                    Some(encap)
                }
            })
            .ok_or(SwafeError::InvalidRecoveryKey)?;

        // generate new keys for this recovery session
        let dkey = pke::DecryptionKey::gen(rng);

        // sign the recovery request with the signing key from RIK
        let sig = encap.key_sig.sign(
            rng,
            &RecoveryRequestMessage {
                account_id: acc,
                recovery_pke: dkey.encryption_key(),
            },
        );

        // create the recovery update
        let update = AccountUpdate::V0(AccountUpdateV0 {
            acc,
            msg: AccountMessageV0::Recovery(AccountUpdateRecoveryV0 {
                pke: dkey.encryption_key(),
                sig,
            }),
        });

        // return public update (for contract upload) and secret data (for final recovery)
        Ok((
            update,
            RecoverySecrets {
                acc,
                rec: self.rec.clone(),
                msk_ss_rik: *encap.msk_ss_rik.as_bytes(),
                dkey,
            },
        ))
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct AccountStateV0 {
    cnt: u32, // current count of operations
    act: AccountCiphertext,
    pub(crate) rec: RecoveryStateV0,
    sig: sig::VerificationKey,
    pke: pke::EncryptionKey,
    backups: Vec<BackupCiphertext>, // backups to store
    recover: Vec<BackupCiphertext>, // backups to recover
}

impl AccountStateV0 {
    pub(crate) fn encryption_key(&self) -> pke::EncryptionKey {
        self.pke.clone()
    }

    /// Get recovery backups
    pub fn recover_backups(&self) -> Vec<&BackupCiphertext> {
        self.backups.iter().collect()
    }

    /// Decrypt the account state to allow changes
    pub fn decrypt(&self, msk: &MasterSecretKey, acc: AccountId) -> Result<AccountSecrets> {
        // decrypt the state
        match sym::open(
            msk.as_bytes(),
            &self.act.0,
            &AccountStateV0Ad {
                version: self.cnt,
                account_id: acc,
            },
        )? {
            CombinedSecret::V0(CombinedSecretV0 {
                sig,
                pke,
                old_pke,
                old_msk,
                recovery,
            }) => Ok(AccountSecrets {
                dirty: false,
                old_sig: sig.clone(),
                acc,
                msk: msk.clone(),
                sig,
                pke,
                old_pke,
                old_msk,
                backups: self.backups.clone(),
                recover: self.recover.clone(),
                cnt: self.cnt,
                recovery: AccountSecretsV0Recovery {
                    msk_ss_social: recovery.msk_ss_social,
                    msk_ss_rik: recovery.msk_ss_rik,
                    guardians: recovery.guardians,
                    threshold: recovery.threshold,
                    social: self.rec.social.clone(),
                    assoc: recovery.assoc,
                },
            }),
        }
    }
}

versioned_enum!(
    #[derive(Clone)]
    AccountMessageV0,
    Update(AccountUpdateFullV0) = 0, // update to any part of the account state
    Recovery(AccountUpdateRecoveryV0) = 1, // update to recovery state
);

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct AccountUpdateFullV0 {
    sig: sig::Signature,
    state: AccountStateV0,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct AccountUpdateRecoveryV0 {
    pke: pke::EncryptionKey, // encryption key for recovery response
    sig: sig::Signature,     // signature from recovery signing key
}

impl Tagged for AccountStateV0 {
    const SEPARATOR: &'static str = "v0:account-state";
}

#[derive(Serialize, Deserialize, Clone)]
pub(super) struct AccountCiphertext(pub(super) sym::AEADCiphertext);

#[derive(Serialize)]
pub(super) struct AccountStateV0Ad {
    pub(super) version: u32,
    pub(super) account_id: AccountId,
}

impl Tagged for AccountStateV0Ad {
    const SEPARATOR: &'static str = "v0:account-st-ad";
}

/// Derive MSK decryption key from RIK and social secret shares
fn derive_msk_decryption_key(
    acc: &AccountId,
    msk_ss_rik: &MskSecretShareRik,
    msk_ss_social: &MskSecretShareSocial,
) -> sym::Key {
    // combine the two secret shares for KDF input
    #[derive(Serialize)]
    struct MskRecoveryShares {
        msk_ss_rik: sym::Key,
        msk_ss_social: sym::Key,
    }

    // info for KDF
    #[derive(Serialize)]
    struct MskRecoveryInfo<'a> {
        acc: &'a AccountId,
    }

    impl Tagged for MskRecoveryInfo<'_> {
        const SEPARATOR: &'static str = "v0:msk-recovery-kdf";
    }

    hash::kdfn(
        &MskRecoveryShares {
            msk_ss_rik: *msk_ss_rik.as_bytes(),
            msk_ss_social: *msk_ss_social.as_bytes(),
        },
        &MskRecoveryInfo { acc },
    )
}

#[derive(Serialize)]
struct AADRecovery {
    acc: AccountId,
}

impl Tagged for AADRecovery {
    const SEPARATOR: &'static str = "v0:recovery-ct";
}

/// Update recovery using RIK-based dual-recovery system
///
/// Generates fresh RIK and sets up recovery with both offchain nodes and guardians.
/// The MSK is encrypted with a key derived from both RIK and social shares.
fn create_recovery<R: Rng + CryptoRng>(
    rng: &mut R,
    acc: AccountId,
    msk_ss_rik: &MskSecretShareRik,
    msk_ss_social: &MskSecretShareSocial,
    guardians: &[AccountState],
    threshold: usize,
) -> Result<BackupCiphertext> {
    BackupCiphertextV0::new(
        rng,
        msk_ss_social,
        &AADRecovery { acc },
        crate::backup::Metadata::new(
            "RIK Social Recovery".to_string(),
            "MSK secret share for social recovery".to_string(),
        ),
        msk_ss_rik.as_bytes(),
        guardians,
        threshold,
    )
    .map(BackupCiphertext::V0)
}

impl AccountSecrets {
    pub fn gen<R: Rng + CryptoRng>(rng: &mut R) -> Result<Self> {
        // generate fresh keys
        let msk = MasterSecretKey::new(rng.gen());
        let sig_sk = sig::SigningKey::gen(rng);
        let pke_sk = pke::DecryptionKey::gen(rng);

        // Generate account ID from verification key
        let acc = AccountId::from_vk(&sig_sk.verification_key());

        // create trivial social recovery state
        let msk_ss_social = MskSecretShareSocial::gen(rng);
        let msk_ss_rik = MskSecretShareRik::gen(rng);
        let social = create_recovery(
            rng, //
            acc,
            &msk_ss_rik,
            &msk_ss_social,
            &[],
            0,
        )?;

        // initial account state
        Ok(AccountSecrets {
            cnt: 0,
            dirty: false,
            acc,
            msk,
            sig: sig_sk.clone(),
            pke: pke_sk,
            old_sig: sig_sk.clone(),
            old_msk: vec![],
            old_pke: vec![],
            backups: vec![],
            recover: vec![],
            recovery: AccountSecretsV0Recovery {
                msk_ss_social,
                msk_ss_rik,
                guardians: vec![],
                threshold: 0,
                social,
                assoc: vec![],
            },
        })
    }

    pub fn msk(&self) -> &MasterSecretKey {
        &self.msk
    }

    pub fn sig(&self) -> &sig::SigningKey {
        &self.sig
    }

    pub fn acc(&self) -> &AccountId {
        &self.acc
    }

    pub(crate) fn pke(&self) -> &pke::DecryptionKey {
        &self.pke
    }

    pub fn version(&self) -> u32 {
        self.cnt
    }

    /// Get the public state of this account
    /// (for testing purposes)
    ///
    /// This is *NOT* part of the public API and should not be used in production code.
    #[cfg(test)]
    pub fn state<R: Rng + CryptoRng>(&self, rng: &mut R) -> Result<AccountState> {
        // Generate an update and extract the state from it
        match self.update(rng)? {
            AccountUpdate::V0(update_v0) => match update_v0.msg {
                AccountMessageV0::Update(auth) => Ok(AccountState::V0(auth.state)),
                AccountMessageV0::Recovery(_) => {
                    unreachable!("Unexpected recovery message in state()")
                }
            },
        }
    }

    /// Update the master secret key
    pub fn new_msk<R: Rng + CryptoRng>(&mut self, rng: &mut R) {
        self.dirty = true;
        self.msk = MasterSecretKey::new(rng.gen())
    }

    /// Update the signing key
    pub fn new_sig<R: Rng + CryptoRng>(&mut self, rng: &mut R) {
        self.dirty = true;
        self.sig = sig::SigningKey::gen(rng)
    }

    /// Update the encryption key (for rotation)
    pub fn new_pke<R: Rng + CryptoRng>(&mut self, rng: &mut R) {
        self.dirty = true;
        self.old_pke.push(self.pke.clone());
        self.pke = pke::DecryptionKey::gen(rng);
    }

    /// Add a ciphertext to the account state
    ///
    /// Note that since this is only run on the client side,
    /// we have no guarantee that the ids are unique:
    /// A malicious user could add the same ciphertext multiple times.
    pub fn add_backup(&mut self, ct: BackupCiphertext) -> Result<()> {
        self.dirty = true;
        self.backups.push(ct);
        Ok(())
    }

    /// Remove a ciphertext by id
    pub fn remove_backup(&mut self, id: BackupId) {
        self.dirty = true;
        self.backups.retain(|ct| ct.id() != id);
        self.recover.retain(|ct| ct.id() != id);
    }

    /// Mark a backup for recovery
    pub fn mark_recovery(&mut self, id: BackupId) -> Result<()> {
        // move the backup from "backups" to "recover"
        if let Some(index) = self.backups.iter().position(|ct| ct.id() == id) {
            self.dirty = true;
            self.recover.push(self.backups.remove(index));
            Ok(())
        } else {
            Err(SwafeError::BackupNotFound)
        }
    }

    /// Update recovery using RIK-based dual-recovery system
    ///
    /// Generates fresh RIK and sets up recovery with both offchain nodes and guardians.
    /// The MSK is encrypted with a key derived from both RIK and social shares.
    pub fn update_recovery<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
        guardians: &[AccountState],
        threshold: usize,
    ) -> Result<()> {
        // mark dirty
        self.dirty = true;

        // generate fresh "social secret"
        self.recovery.msk_ss_social = MskSecretShareSocial::gen(rng);

        // generate new ciphertext
        self.recovery.social = create_recovery(
            rng,
            self.acc,
            &self.recovery.msk_ss_rik,
            &self.recovery.msk_ss_social,
            guardians,
            threshold,
        )?;
        Ok(())
    }

    pub fn decrypt_share_backupy(
        &self,
        acc: AccountId,
        backup: &BackupCiphertext,
    ) -> Option<SecretShare> {
        self.decrypt_share(&AADBackup { acc }, backup)
    }

    pub fn decrypt_share_recovery(
        &self,
        acc: AccountId,
        backup: &BackupCiphertext,
    ) -> Option<SecretShare> {
        self.decrypt_share(&AADRecovery { acc }, backup)
    }

    fn decrypt_share<A: Tagged>(&self, aad: &A, backup: &BackupCiphertext) -> Option<SecretShare> {
        fn decrypt_v0<A: Tagged>(
            v0: &BackupCiphertextV0,
            aad: &A,
            pke: &crate::crypto::pke::DecryptionKey,
        ) -> Option<SecretShare> {
            let (data, index) = pke
                .decrypt_batch::<BackupShareV0, _>(
                    &v0.encap,
                    &EncryptionContext {
                        aad: (A::SEPARATOR, aad),
                        data: &v0.data,
                        comms: &v0.comms,
                    },
                )
                .ok()?;

            Some(SecretShare::V0(DecryptedShareV0 {
                idx: index as u32,
                share: data,
            }))
        }

        match backup {
            BackupCiphertext::V0(v0) => {
                if let Some(share) = decrypt_v0(v0, aad, &self.pke) {
                    return Some(share);
                }
                self.old_pke.last().and_then(|old| decrypt_v0(v0, aad, old))
            }
        }
    }

    pub fn add_association<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<RecoveryInitiationKey> {
        self.dirty = true;

        // generate fresh RIK for this association
        let rik = RecoveryInitiationKey::gen(rng);

        // Add to existing associations
        self.recovery
            .assoc
            .push(AssociationSecretV0 { rik: rik.clone() });
        Ok(rik)
    }

    /// Revoke a specific association by its RIK
    pub fn revoke_association(&mut self, rik: &RecoveryInitiationKey) -> Result<()> {
        let original_len = self.recovery.assoc.len();
        self.recovery.assoc.retain(|assoc| &assoc.rik != rik);

        if self.recovery.assoc.len() == original_len {
            return Err(SwafeError::InvalidRecoveryKey);
        }

        self.dirty = true;
        Ok(())
    }

    /// Produce an update transaction to store the new state of the abstract account
    pub fn update<R: Rng + CryptoRng>(&self, rng: &mut R) -> Result<AccountUpdate> {
        // new version of the account state
        let cnt = if self.dirty { self.cnt + 1 } else { self.cnt };

        // generate *all* the associations
        // this hides which association is being updated/added/removed
        let assoc = self
            .recovery
            .assoc
            .iter()
            .map(|assoc| {
                // generate keys for recovery authorization
                let key_sig = sig::SigningKey::gen(rng);

                // create EncapV0 with the recovery key
                let encap = sym::seal(
                    rng,
                    assoc.rik.as_bytes(),
                    &EncapV0 {
                        key_sig: key_sig.clone(),
                        msk_ss_rik: self.recovery.msk_ss_rik.clone(),
                    },
                    self.acc(),
                );

                // create new AssociationsV0
                AssociationsV0 {
                    sig: key_sig.verification_key(),
                    encap,
                }
            })
            .collect();

        // encrypt the secret state
        let act = AccountCiphertext(sym::seal(
            rng,
            self.msk.as_bytes(),
            &CombinedSecret::V0(CombinedSecretV0 {
                sig: self.sig.clone(),
                pke: self.pke.clone(),
                old_msk: self.old_msk.clone(),
                old_pke: self.old_pke.clone(),
                recovery: RecoverySecretV0 {
                    msk_ss_social: self.recovery.msk_ss_social.clone(),
                    msk_ss_rik: self.recovery.msk_ss_rik.clone(),
                    guardians: self.recovery.guardians.clone(),
                    threshold: self.recovery.threshold,
                    assoc: self.recovery.assoc.clone(),
                },
            }),
            &AccountStateV0Ad {
                account_id: self.acc,
                version: cnt,
            },
        ));

        // derive MSK decryption key and encrypt MSK
        let enc_msk = sym::seal(
            rng,
            &derive_msk_decryption_key(
                self.acc(),
                &self.recovery.msk_ss_rik,
                &self.recovery.msk_ss_social,
            ),
            &self.msk,
            self.acc(),
        );

        let st = AccountStateV0 {
            cnt,
            backups: self.backups.clone(),
            recover: self.recover.clone(),
            pke: self.pke.encryption_key(),
            sig: self.sig.verification_key(),
            act,
            rec: RecoveryStateV0 {
                pke: None,
                assoc,
                // TODO: unfortunately we cannot generate this anew every time
                social: self.recovery.social.clone(),
                enc_msk,
            },
        };

        let sig = self.old_sig.sign(rng, &st);
        Ok(AccountUpdate::V0(AccountUpdateV0 {
            acc: self.acc,
            msg: AccountMessageV0::Update(AccountUpdateFullV0 { sig, state: st }),
        }))
    }

    /// Guardian: Check if there's a pending recovery request and generate guardian share
    pub fn check_for_recovery<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        acc: AccountId,       // account id of the account
        state: &AccountState, // state of the account
    ) -> Result<Option<GuardianShare>> {
        // get requester's state details
        let AccountState::V0(requester_state_v0) = state;

        // check if recovery has been initiated
        let rec_st = &requester_state_v0.rec;
        if rec_st.pke.is_none() {
            return Ok(None); // Recovery not initiated yet
        }

        // decrypt our share
        let guardian_secrets = self.clone();
        let secret_share = guardian_secrets
            .decrypt_share_recovery(acc, &rec_st.social)
            .ok_or_else(|| {
                SwafeError::InvalidOperation(
                    "Guardian not authorized for this recovery or failed to decrypt share"
                        .to_string(),
                )
            })?;

        // reencrypt the share for the requester's recovery PKE key
        Ok(Some(secret_share.send_for_recovery(rng, state)?))
    }
}

impl AccountUpdateV0 {
    /// Verify an initial update (allocation) returns the initial state of the account
    pub(super) fn verify_allocation(self) -> Result<AccountStateV0> {
        match self.msg {
            AccountMessageV0::Update(auth) => {
                let st = auth.state;
                // check version must be zero
                if st.cnt != 0 {
                    return Err(SwafeError::InvalidAccountStateVersion);
                }

                // check that the account id matches the public key
                if self.acc != AccountId::from_vk(&st.sig) {
                    return Err(SwafeError::AuthenticationFailed);
                }

                // verify signature
                st.sig.verify(&auth.sig, &st)?;

                // Return the initial account state
                Ok(st)
            }
            AccountMessageV0::Recovery(_) => Err(SwafeError::InvalidOperation(
                "Cannot use recovery for initial allocation".to_string(),
            )),
        }
    }

    /// Verify an update to the account returns the new state of the account
    pub(super) fn verify_update(self, old: &AccountStateV0) -> Result<AccountStateV0> {
        match self.msg {
            AccountMessageV0::Update(auth) => {
                let st = auth.state;
                // version must increase by exactly one
                if Some(st.cnt) != old.cnt.checked_add(1) {
                    return Err(SwafeError::InvalidAccountStateVersion);
                }

                // verify signature using old verification key
                old.sig.verify(&auth.sig, &st)?;

                // Return the new state as provided in the update
                Ok(st)
            }
            AccountMessageV0::Recovery(recovery) => {
                // Handle recovery update: set the recovery pke field in the account state
                let mut new_state = old.clone();

                {
                    let rec = &mut new_state.rec;
                    // Verify the recovery request signature
                    let recovery_msg = RecoveryRequestMessage {
                        account_id: self.acc,
                        recovery_pke: recovery.pke.clone(),
                    };

                    // Find the matching association and verify signature
                    let mut verified = false;
                    for assoc in &rec.assoc {
                        // Verify signature using the recovery signing key from associations
                        if assoc.sig.verify(&recovery.sig, &recovery_msg).is_ok() {
                            verified = true;
                            break;
                        }
                    }

                    if !verified {
                        return Err(SwafeError::InvalidSignature);
                    }

                    // Set the recovery PKE to indicate recovery has been initiated
                    rec.pke = Some(recovery.pke);
                }
                Ok(new_state)
            }
        }
    }
}
