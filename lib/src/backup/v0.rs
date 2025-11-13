use std::collections::BTreeMap;

use ark_std::rand::seq::SliceRandom;
use ark_std::rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};

use crate::crypto::sss::Share;
use crate::versioned_enum;
use crate::{backup::BackupId, crypto::hash::EmptyInfo};

use super::Metadata;

use crate::{
    account::{v0::AccountSecrets, AccountId, AccountState},
    crypto::{
        hash::{hash, SIZE_HASH},
        kdfn, pke, sig, sss,
        symmetric::{self as sym, AEADCiphertext},
    },
    SwafeError, Tagged,
};
use serde::de::DeserializeOwned;

#[derive(Serialize)]
struct ShareHash<'a> {
    share: &'a Share,
}

impl Tagged for ShareHash<'_> {
    const SEPARATOR: &'static str = "v0:share-hash";
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ShareComm {
    vk: sig::VerificationKey,
    hash: [u8; SIZE_HASH],
}

impl Tagged for ShareComm {
    const SEPARATOR: &'static str = "v0:share-comm";
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct GuardianShareV0 {
    ct: pke::Ciphertext,
    idx: u32,
    sig: sig::Signature,
}

#[derive(Serialize)]
struct SignedEncryptedShare<'a> {
    idx: u32,
    ct: &'a pke::Ciphertext,
}

impl Tagged for SignedEncryptedShare<'_> {
    const SEPARATOR: &'static str = "v0:signed-encrypted-share";
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct BackupCiphertextV0 {
    pub data: sym::AEADCiphertext,   // encrypted
    pub comms: Vec<ShareComm>,       // share commitments
    pub encap: pke::BatchCiphertext, // encrypted shares
}

impl Tagged for BackupCiphertextV0 {
    const SEPARATOR: &'static str = "v0:backup-ciphertext";
}

versioned_enum!(
    #[derive(Clone)]
    BackupCiphertext,
    V0(BackupCiphertextV0) = 0
);

versioned_enum!(
    #[derive(Clone)]
    GuardianShare,
    V0(GuardianShareV0) = 0
);

impl BackupCiphertextV0 {
    pub fn id(&self) -> BackupId {
        BackupId(hash(self))
    }
}

impl BackupCiphertext {
    pub fn verify(&self, share: &GuardianShare) -> Result<u32, SwafeError> {
        match (self, share) {
            (BackupCiphertext::V0(ciphertext), GuardianShare::V0(share)) => {
                ciphertext.verify(share)
            }
        }
    }

    pub fn id(&self) -> BackupId {
        match self {
            BackupCiphertext::V0(ciphertext) => ciphertext.id(),
        }
    }
}

#[derive(Serialize)]
struct BackupKDFInput<'a> {
    key: &'a sym::Key,
    secret: sss::Secret,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct BackupShareV0 {
    sk: sig::SigningKey,
    share: sss::Share, // secret share for the ciphertext
}

// This is versioned because it is
// stored longterm by clients *outside* the library
versioned_enum!(
    #[derive(Clone)]
    SecretShare,
    V0(DecryptedShareV0) = 0,
);

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct DecryptedShareV0 {
    pub idx: u32,
    pub share: BackupShareV0,
}

impl DecryptedShareV0 {
    pub fn send<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        owner: &AccountState,
    ) -> Result<GuardianShare, SwafeError> {
        let ct = owner
            .encryption_key()
            .encrypt(rng, &self.share.share, &EmptyInfo);
        let sig = self.share.sk.sign(
            rng,
            &SignedEncryptedShare {
                ct: &ct,
                idx: self.idx,
            },
        );
        Ok(GuardianShare::V0(GuardianShareV0 {
            ct,
            idx: self.idx,
            sig,
        }))
    }

    /// Send the share encrypted for a specific recovery PKE key
    pub fn send_for_recovery<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        owner: &AccountState,
    ) -> Result<GuardianShare, SwafeError> {
        let recovery_pke =
            match owner {
                AccountState::V0(state) => state.rec.pke.as_ref().ok_or_else(|| {
                    SwafeError::InvalidOperation("Recovery not started".to_string())
                })?,
            };
        let ct = recovery_pke.encrypt(rng, &self.share.share, &EmptyInfo);
        let sig = self.share.sk.sign(
            rng,
            &SignedEncryptedShare {
                ct: &ct,
                idx: self.idx,
            },
        );
        Ok(GuardianShare::V0(GuardianShareV0 {
            ct,
            idx: self.idx,
            sig,
        }))
    }
}

impl SecretShare {
    pub fn send<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        owner: &AccountState,
    ) -> Result<GuardianShare, SwafeError> {
        match self {
            SecretShare::V0(v0) => v0.send(rng, owner),
        }
    }

    /// Send the share encrypted for a specific recovery PKE key
    pub fn send_for_recovery<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        owner: &AccountState,
    ) -> Result<GuardianShare, SwafeError> {
        match self {
            SecretShare::V0(v0) => v0.send_for_recovery(rng, owner),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct BackupMetadata {
    name: String,         // user defined name for secret
    desc: String,         // user defined description for secret
    data: AEADCiphertext, // encrypted data
    threshold: u32,       // threshold for the secret
    timestamp: u64,       // timestamp of the backup
}

#[derive(Serialize)]
struct KDFMetakey<'a> {
    comms: &'a [ShareComm],
}

impl Tagged for KDFMetakey<'_> {
    const SEPARATOR: &'static str = "v0:backup-kdf-meta";
}

impl Tagged for BackupMetadata {
    const SEPARATOR: &'static str = "v0:backup-meta";
}

impl Tagged for BackupShareV0 {
    const SEPARATOR: &'static str = "v0:backup-share";
}

impl Tagged for BackupCiphertext {
    const SEPARATOR: &'static str = "v0:backup-ciphertext";
}

#[derive(Serialize)]
pub struct EncryptionContext<'a, 'b, A: Tagged> {
    pub aad: (&'static str, &'a A),
    pub(crate) data: &'a sym::AEADCiphertext,
    pub comms: &'b [ShareComm],
}

impl<A: Tagged> Tagged for EncryptionContext<'_, '_, A> {
    const SEPARATOR: &'static str = "v0:encryption-context";
}

#[derive(Serialize)]
pub struct AADBackup {
    pub acc: AccountId,
}

impl Tagged for AADBackup {
    const SEPARATOR: &'static str = "v0:aad-backup";
}

impl AccountSecrets {
    pub fn backup<R: Rng + CryptoRng, M: Tagged>(
        &self,
        rng: &mut R,
        data: &M,
        meta: Metadata,
        guardians: &[AccountState],
        threshold: usize,
    ) -> Result<BackupCiphertext, SwafeError> {
        BackupCiphertextV0::new(
            rng,
            data,
            &AADBackup { acc: *self.acc() },
            meta,
            self.msk().as_bytes(),
            guardians,
            threshold,
        )
        .map(BackupCiphertext::V0)
    }

    pub fn recover<M: Tagged + DeserializeOwned>(
        &self,
        backup: &BackupCiphertext,
        shares: &[GuardianShare],
    ) -> Result<M, SwafeError> {
        match backup {
            BackupCiphertext::V0(v0) => {
                v0.recover(self.pke(), self.msk().as_bytes(), &EmptyInfo, shares)
            }
        }
    }
}

impl BackupCiphertextV0 {
    pub fn recover<M: Tagged + DeserializeOwned, A: Tagged>(
        &self,
        dke: &pke::DecryptionKey,
        sym: &sym::Key,
        aad: &A,
        shares: &[GuardianShare],
    ) -> Result<M, SwafeError> {
        // Verify and decrypt each share
        // Ignore invalid and duplicate shares
        let shares: Vec<(u32, Share)> = shares
            .iter()
            .filter_map(|share| {
                let GuardianShare::V0(share_v0) = share;
                let id = self.verify(share_v0).ok()?;
                let share: Share = dke.decrypt(&share_v0.ct, aad).ok()?;
                if self.comms[id as usize].hash == hash(&ShareHash { share: &share }) {
                    Some((id, share))
                } else {
                    None
                }
            })
            .collect::<BTreeMap<u32, Share>>()
            .into_iter()
            .collect();

        // derive the metadata key
        let key_meta: sym::Key = kdfn(sym, &KDFMetakey { comms: &self.comms });

        // decrypt the metadata
        let meta: BackupMetadata = sym::open(&key_meta, &self.data, &sym::EmptyAD)?;

        // check that we have enough shares to meet the threshold
        if shares.len() < meta.threshold as usize {
            return Err(SwafeError::InsufficientShares);
        }

        // recover the secret using Shamir's Secret Sharing
        let secret: sss::Secret = sss::recover(
            &shares
                .into_iter()
                .take(meta.threshold as usize)
                .map(|(idx, share)| (idx as usize, share))
                .collect::<Vec<_>>()[..],
        );

        // derive the data encryption key
        let key_data: sym::Key = kdfn(&BackupKDFInput { key: sym, secret }, &EmptyInfo);

        // decrypt the data
        sym::open(&key_data, &meta.data, &sym::EmptyAD)
    }

    pub fn verify(&self, share: &GuardianShareV0) -> Result<u32, SwafeError> {
        if share.idx > self.comms.len() as u32 {
            return Err(SwafeError::InvalidShare);
        }
        self.comms[share.idx as usize].vk.verify(
            &share.sig,
            &SignedEncryptedShare {
                ct: &share.ct,
                idx: share.idx,
            },
        )?;
        Ok(share.idx)
    }

    pub fn new<R: Rng + CryptoRng, M: Tagged, A: Tagged>(
        rng: &mut R,
        data: &M,
        aad: &A,
        meta: Metadata,
        sym_key: &sym::Key,
        guardians: &[AccountState],
        threshold: usize,
    ) -> Result<Self, SwafeError> {
        // check if there are enough guardians to meet the threshold
        // note that the threshold MAY be 0: in which case
        // only the msk is required to recover the secret
        if guardians.len() < threshold {
            return Err(SwafeError::InsufficientShares);
        }

        // shuffle guardians to prevent leaking the ordering
        let mut guardians = guardians.to_vec();
        guardians.shuffle(rng);

        // obtain current public keys for the guardians
        let pks = guardians.iter().map(|guardian| guardian.encryption_key());

        // create a shamir secret sharing
        let (secret, shares) = sss::share(rng, threshold, guardians.len());

        // plaintexts - use shuffled indices
        let pts: Vec<BackupShareV0> = (0..guardians.len())
            .map(|i| BackupShareV0 {
                sk: sig::SigningKey::gen(rng),
                share: shares[i].clone(),
            })
            .collect();

        // Form commitments to each share
        // note: this is fine because they have high entropy
        // and hence it is hiding if we assume that hash
        // can be modelled as a random oracle
        let comms: Vec<ShareComm> = (0..guardians.len())
            .map(|i| ShareComm {
                vk: pts[i].sk.verification_key(),
                hash: hash(&ShareHash { share: &shares[i] }),
            })
            .collect();

        // Derive the metadata key:
        // used to encrypt the metadata, allowing the owner to see *what*
        // a ciphertext contains before attempting to decrypt it
        let key_meta: [u8; sym::SIZE_KEY] = kdfn(sym_key, &KDFMetakey { comms: &comms });

        // Derive the data encryption key from:
        // - The msk
        // - The threshold shared secret
        let key_data: [u8; sym::SIZE_KEY] = kdfn(
            &BackupKDFInput {
                key: sym_key,
                secret,
            },
            &EmptyInfo,
        );

        // Encrypt the metadata
        let now = std::time::SystemTime::now();
        let dur = now.duration_since(std::time::UNIX_EPOCH).unwrap();
        let sealed_data = sym::seal(rng, &key_data, data, &sym::EmptyAD);
        let data = sym::seal(
            rng,
            &key_meta,
            &BackupMetadata {
                name: meta.name,
                desc: meta.desc,
                data: sealed_data,
                threshold: threshold as u32,
                timestamp: dur.as_secs(),
            },
            &sym::EmptyAD,
        );

        // create a batched encryption of the shares
        let encap = pke::EncryptionKey::batch_encrypt(
            rng,
            pks.zip(pts),
            &EncryptionContext {
                aad: (A::SEPARATOR, aad),
                data: &data,
                comms: &comms,
            },
        );

        // encrypt the signature
        Ok(BackupCiphertextV0 { data, encap, comms })
    }
}
