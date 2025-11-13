use std::fs;
use std::path::PathBuf;

use anyhow::Result;
use rand::thread_rng;
use swafe_lib::account::{AccountId, AccountState};
use swafe_lib::backup::{BackupCiphertext, GuardianShare, Metadata, SecretShare};
use swafe_lib::encode::{self, StrEncoded};
use swafe_lib::types::MasterSecretKey;

use crate::commands::utils::{
    write_json_output, BackupCiphertextOutput, GuardianSecretShareOutput, SecretData,
    VerifiedShareOutput,
};

/// Parameters for creating a backup ciphertext
pub struct CreateBackupParams {
    pub owner_account_state_str: String,
    pub owner_msk_str: String,
    pub owner_account_id_str: String,
    pub guardian_accounts_str: Vec<String>,
    pub threshold: usize,
    pub secret_data: String,
    pub name: String,
    pub description: String,
    pub output: PathBuf,
}

pub fn create_backup_ciphertext(params: CreateBackupParams) -> Result<()> {
    let CreateBackupParams {
        owner_account_state_str,
        owner_msk_str,
        owner_account_id_str,
        guardian_accounts_str,
        threshold,
        secret_data,
        name,
        description,
        output,
    } = params;
    let mut rng = thread_rng();

    let owner_account_state: AccountState = encode::deserialize_str(&owner_account_state_str)
        .map_err(|e| anyhow::anyhow!("Failed to decode owner account state: {}", e))?;

    let owner_msk: MasterSecretKey = encode::deserialize_str(&owner_msk_str)
        .map_err(|e| anyhow::anyhow!("Failed to decode owner MSK: {}", e))?;

    let owner_account_id: AccountId = encode::deserialize_str(&owner_account_id_str)
        .map_err(|e| anyhow::anyhow!("Failed to decode owner account ID: {}", e))?;

    let owner_secrets = owner_account_state
        .decrypt(&owner_msk, owner_account_id)
        .map_err(|e| anyhow::anyhow!("Failed to decrypt owner account secrets: {:?}", e))?;

    let mut guardian_states = Vec::new();
    for (i, guardian_str) in guardian_accounts_str.iter().enumerate() {
        let guardian_state: AccountState = encode::deserialize_str(guardian_str)
            .map_err(|e| anyhow::anyhow!("Failed to decode guardian {} account state: {}", i, e))?;

        guardian_states.push(guardian_state);
    }

    let secret_bytes = hex::decode(&secret_data)
        .map_err(|e| anyhow::anyhow!("Failed to decode secret data from hex: {}", e))?;

    let secret_data_wrapped = SecretData { data: secret_bytes };

    let metadata = Metadata::new(name.clone(), description.clone());

    let backup_ciphertext = owner_secrets
        .backup(
            &mut rng,
            &secret_data_wrapped,
            metadata,
            &guardian_states,
            threshold,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create backup ciphertext: {:?}", e))?;

    let backup_output = BackupCiphertextOutput {
        backup_ciphertext: StrEncoded(backup_ciphertext),
        threshold,
        guardians_count: guardian_states.len(),
        name,
        description,
    };

    write_json_output(backup_output, &output)?;

    Ok(())
}

pub fn guardian_decrypt_share(
    guardian_account_state_str: String,
    guardian_msk_str: String,
    guardian_account_id_str: String,
    owner_account_id: String,
    backup_ciphertext_str: String,
    output: PathBuf,
) -> Result<()> {
    let guardian_account_state: AccountState = encode::deserialize_str(&guardian_account_state_str)
        .map_err(|e| anyhow::anyhow!("Failed to decode guardian account state: {}", e))?;

    let guardian_msk: MasterSecretKey = encode::deserialize_str(&guardian_msk_str)
        .map_err(|e| anyhow::anyhow!("Failed to decode guardian MSK: {}", e))?;

    let guardian_account_id: AccountId = encode::deserialize_str(&guardian_account_id_str)
        .map_err(|e| anyhow::anyhow!("Failed to decode guardian account ID: {}", e))?;

    let guardian_secrets = guardian_account_state
        .decrypt(&guardian_msk, guardian_account_id)
        .map_err(|e| anyhow::anyhow!("Failed to decrypt guardian account secrets: {:?}", e))?;

    let backup_ct: BackupCiphertext = encode::deserialize_str(&backup_ciphertext_str)
        .map_err(|e| anyhow::anyhow!("Failed to decode backup ciphertext: {}", e))?;

    let owner_id = encode::deserialize_str(&owner_account_id)
        .map_err(|e| anyhow::anyhow!("Failed to decode owner account ID: {}", e))?;

    let secret_share = guardian_secrets
        .decrypt_share_backupy(owner_id, &backup_ct)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Guardian cannot decrypt share from this backup - not a guardian for this backup"
            )
        })?;

    let share_output = GuardianSecretShareOutput {
        secret_share: StrEncoded(secret_share),
        guardian_index: 0, // Will be determined when converting to GuardianShare
        owner_account_id: StrEncoded(encode::deserialize_str::<AccountId>(&owner_account_id)?),
    };

    write_json_output(share_output, &output)?;

    Ok(())
}

pub fn guardian_send_share(
    secret_share_str: String,
    owner_account_state_str: String,
    output: PathBuf,
) -> Result<()> {
    let mut rng = thread_rng();

    let secret_share: SecretShare = encode::deserialize_str(&secret_share_str)
        .map_err(|e| anyhow::anyhow!("Failed to decode secret share: {}", e))?;

    let owner_state: AccountState = encode::deserialize_str(&owner_account_state_str)
        .map_err(|e| anyhow::anyhow!("Failed to decode owner account state: {}", e))?;

    let guardian_share = secret_share
        .send(&mut rng, &owner_state)
        .map_err(|e| anyhow::anyhow!("Failed to create guardian share: {:?}", e))?;

    let share_output = VerifiedShareOutput {
        share: StrEncoded(guardian_share),
        index: 0, // Index is embedded in GuardianShare
    };

    write_json_output(share_output, &output)?;

    Ok(())
}

pub fn verify_guardian_share(
    guardian_share_str: String,
    backup_ciphertext_str: String,
    output: PathBuf,
) -> Result<()> {
    let guardian_share: GuardianShare = encode::deserialize_str(&guardian_share_str)
        .map_err(|e| anyhow::anyhow!("Failed to decode guardian share: {}", e))?;

    let backup_ct: BackupCiphertext = encode::deserialize_str(&backup_ciphertext_str)
        .map_err(|e| anyhow::anyhow!("Failed to decode backup ciphertext: {}", e))?;

    let index = backup_ct
        .verify(&guardian_share)
        .map_err(|e| anyhow::anyhow!("Failed to verify guardian share: {:?}", e))?;

    let share_output = VerifiedShareOutput {
        share: StrEncoded(guardian_share),
        index,
    };

    write_json_output(share_output, &output)?;

    Ok(())
}

pub fn recover_from_backup(
    owner_account_state_str: String,
    owner_msk_str: String,
    owner_account_id_str: String,
    backup_ciphertext_str: String,
    guardian_shares_str: Vec<String>,
    output: PathBuf,
) -> Result<()> {
    let owner_account_state: AccountState = encode::deserialize_str(&owner_account_state_str)
        .map_err(|e| anyhow::anyhow!("Failed to decode owner account state: {}", e))?;

    let owner_msk: MasterSecretKey = encode::deserialize_str(&owner_msk_str)
        .map_err(|e| anyhow::anyhow!("Failed to decode owner MSK: {}", e))?;

    let owner_account_id: AccountId = encode::deserialize_str(&owner_account_id_str)
        .map_err(|e| anyhow::anyhow!("Failed to decode owner account ID: {}", e))?;

    let owner_secrets = owner_account_state
        .decrypt(&owner_msk, owner_account_id)
        .map_err(|e| anyhow::anyhow!("Failed to decrypt owner account secrets: {:?}", e))?;

    let backup_ct: BackupCiphertext = encode::deserialize_str(&backup_ciphertext_str)
        .map_err(|e| anyhow::anyhow!("Failed to decode backup ciphertext: {}", e))?;

    let mut shares = Vec::new();
    for (i, share_str) in guardian_shares_str.iter().enumerate() {
        let share: GuardianShare = encode::deserialize_str(share_str)
            .map_err(|e| anyhow::anyhow!("Failed to decode guardian share {}: {}", i, e))?;

        shares.push(share);
    }

    let recovered_data: SecretData = owner_secrets
        .recover(&backup_ct, &shares)
        .map_err(|e| anyhow::anyhow!("Failed to recover secret from backup: {:?}", e))?;

    let recovered_str = hex::encode(&recovered_data.data);
    fs::write(&output, recovered_str)
        .map_err(|e| anyhow::anyhow!("Failed to write output file: {}", e))?;

    Ok(())
}
