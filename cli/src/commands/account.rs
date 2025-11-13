use std::fs;
use std::path::PathBuf;

use anyhow::Result;
use rand::thread_rng;
use serde::Serialize;
use swafe_lib::account::{AccountId, AccountSecrets, AccountState, AccountUpdate};
use swafe_lib::backup::BackupCiphertext;
use swafe_lib::crypto::sig::SigningKey;
use swafe_lib::encode::{self, StrEncoded};
use swafe_lib::types::{MasterSecretKey, RecoveryInitiationKey};

use crate::commands::utils::{
    load_json_file, write_json_output, AccountAllocationOutput, AccountUpdateOutput,
};

pub fn generate_keypair(keypair_output: PathBuf, public_key_output: PathBuf) -> Result<()> {
    let mut rng = thread_rng();
    let secret_key = SigningKey::gen(&mut rng);

    let keypair_str = encode::serialize_str(&secret_key.clone())?;
    let public_key_str = encode::serialize_str(&secret_key.verification_key())?;

    std::fs::write(&keypair_output, keypair_str)
        .map_err(|e| anyhow::anyhow!("Failed to write keypair: {}", e))?;
    std::fs::write(&public_key_output, public_key_str)
        .map_err(|e| anyhow::anyhow!("Failed to write public key: {}", e))?;

    Ok(())
}

pub fn generate_account_allocation(output: PathBuf) -> Result<()> {
    let mut rng = thread_rng();
    let account_secrets = AccountSecrets::gen(&mut rng)?;

    let account_update = account_secrets.update(&mut rng)?;

    let account_state = account_update
        .clone()
        .verify(None)
        .map_err(|e| anyhow::anyhow!("Failed to extract account state: {:?}", e))?;
    let account_id = account_update.unsafe_account_id();

    let allocation_output = AccountAllocationOutput {
        account_id: encode::StrEncoded(account_id),
        account_state: encode::StrEncoded(account_state),
        account_update: encode::StrEncoded(account_update),
        master_secret_key: encode::StrEncoded(account_secrets.msk().clone()),
    };

    write_json_output(allocation_output, &output)?;

    Ok(())
}

pub fn generate_account_update(initial_allocation: PathBuf, output: PathBuf) -> Result<()> {
    let mut rng = thread_rng();

    let initial_output: AccountAllocationOutput = load_json_file(&initial_allocation)?;

    let mut account_secrets = initial_output.decrypt_account_secrets()?;

    account_secrets.new_pke(&mut rng);

    let account_update = account_secrets.update(&mut rng)?;

    let account_state = account_update
        .clone()
        .verify(Some(&initial_output.account_state.0))
        .map_err(|e| anyhow::anyhow!("Failed to extract account state: {:?}", e))?;

    let update_output = AccountUpdateOutput {
        account_update: StrEncoded(account_update),
        account_id: initial_output.account_id,
        account_state: StrEncoded(account_state),
        master_secret_key: StrEncoded(account_secrets.msk().clone()),
    };

    write_json_output(update_output, &output)?;

    Ok(())
}

pub fn add_backup_to_account(
    owner_account_state_str: String,
    owner_msk_str: String,
    owner_account_id_str: String,
    backup_ciphertext_str: String,
    output: PathBuf,
) -> Result<()> {
    use serde::Serialize;
    use swafe_lib::backup::BackupId;
    use swafe_lib::encode::{self, StrEncoded};

    let mut rng = thread_rng();

    let owner_account_state: AccountState = encode::deserialize_str(&owner_account_state_str)
        .map_err(|e| anyhow::anyhow!("Failed to decode owner account state: {}", e))?;

    let owner_msk: MasterSecretKey = encode::deserialize_str(&owner_msk_str)
        .map_err(|e| anyhow::anyhow!("Failed to decode owner MSK: {}", e))?;

    let owner_account_id: AccountId = encode::deserialize_str(&owner_account_id_str)
        .map_err(|e| anyhow::anyhow!("Failed to decode owner account ID: {}", e))?;

    let mut owner_secrets = owner_account_state
        .decrypt(&owner_msk, owner_account_id)
        .map_err(|e| anyhow::anyhow!("Failed to decrypt owner account secrets: {:?}", e))?;

    let backup_ct: BackupCiphertext =
        encode::deserialize_str::<BackupCiphertext>(&backup_ciphertext_str)
            .map_err(|e| anyhow::anyhow!("Failed to decode backup ciphertext: {:?}", e))?;

    let backup_id = backup_ct.id();

    owner_secrets
        .add_backup(backup_ct)
        .map_err(|e| anyhow::anyhow!("Failed to add backup to account: {:?}", e))?;

    let account_update = owner_secrets.update(&mut rng)?;

    #[derive(Serialize)]
    struct AccountUpdateWithBackupOutput {
        account_update: StrEncoded<AccountUpdate>,
        backup_id: StrEncoded<BackupId>,
        account_state: StrEncoded<AccountState>,
        master_secret_key: StrEncoded<MasterSecretKey>,
    }

    let account_state = account_update
        .clone()
        .verify(Some(&owner_account_state))
        .map_err(|e| anyhow::anyhow!("Failed to extract account state: {:?}", e))?;

    let update_output = AccountUpdateWithBackupOutput {
        account_update: StrEncoded(account_update),
        backup_id: StrEncoded(backup_id),
        account_state: StrEncoded(account_state),
        master_secret_key: StrEncoded(owner_secrets.msk().clone()),
    };

    write_json_output(update_output, &output)?;

    Ok(())
}

pub fn extract_backup_from_account(
    account_state_str: String,
    backup_id_str: String,
    output: PathBuf,
) -> Result<()> {
    use serde::Serialize;
    use swafe_lib::backup::BackupId;
    use swafe_lib::encode::{self, StrEncoded};

    let backup_id: BackupId = encode::deserialize_str::<BackupId>(&backup_id_str)
        .map_err(|e| anyhow::anyhow!("Failed to decode backup ID: {:?}", e))?;

    let account_state: AccountState =
        encode::deserialize_str::<AccountState>(&account_state_str)
            .map_err(|e| anyhow::anyhow!("Failed to decode account state: {:?}", e))?;

    let backup_ciphertext = account_state
        .recover_id(backup_id)
        .ok_or_else(|| anyhow::anyhow!("No backup ciphertext found with ID: {}", backup_id))?;

    #[derive(Serialize)]
    struct ExtractedBackupOutput {
        backup_id: StrEncoded<BackupId>,
        backup_ciphertext: StrEncoded<BackupCiphertext>,
    }

    let extracted_output = ExtractedBackupOutput {
        backup_id: StrEncoded(backup_id),
        backup_ciphertext: StrEncoded(backup_ciphertext.clone()),
    };

    write_json_output(extracted_output, &output)?;

    Ok(())
}

/// Setup recovery for an account
pub fn setup_recovery_command(
    account_secrets_path: PathBuf,
    guardian_paths: Vec<PathBuf>,
    threshold: usize,
    output_dir: PathBuf,
) -> Result<()> {
    let mut rng = thread_rng();

    // Read account secrets file
    let allocation_output: crate::commands::utils::AccountAllocationOutput =
        load_json_file(&account_secrets_path)?;

    let mut account_secrets = allocation_output.decrypt_account_secrets()?;

    // Read guardian account states
    let mut guardian_states = Vec::new();
    for guardian_path in guardian_paths {
        let guardian_output: crate::commands::utils::AccountAllocationOutput =
            load_json_file(&guardian_path)?;

        guardian_states.push(guardian_output.account_state.0);
    }

    // Setup recovery
    account_secrets
        .update_recovery(&mut rng, &guardian_states, threshold)
        .map_err(|e| anyhow::anyhow!("Failed to update recovery: {:?}", e))?;
    let rik = account_secrets
        .add_association(&mut rng)
        .map_err(|e| anyhow::anyhow!("Failed to add association: {:?}", e))?;

    // Generate updated account state
    let account_update = account_secrets.update(&mut rng)?;
    let account_state = account_update
        .clone()
        .verify(Some(&allocation_output.account_state.0))
        .map_err(|e| anyhow::anyhow!("Failed to extract updated account state: {:?}", e))?;

    #[derive(Serialize)]
    struct SetupRecoveryOutput {
        rik: StrEncoded<RecoveryInitiationKey>,
        account_update: StrEncoded<AccountUpdate>,
        account_state: StrEncoded<AccountState>,
        account_id: StrEncoded<AccountId>,
        master_secret_key: StrEncoded<MasterSecretKey>,
    }

    let setup_output = SetupRecoveryOutput {
        rik: StrEncoded(rik),
        account_update: StrEncoded(account_update),
        account_state: StrEncoded(account_state),
        account_id: allocation_output.account_id,
        master_secret_key: StrEncoded(account_secrets.msk().clone()),
    };

    // Create output directory if it doesn't exist
    fs::create_dir_all(&output_dir)
        .map_err(|e| anyhow::anyhow!("Failed to create output directory: {}", e))?;

    // Write RIK to separate file
    let rik_path = output_dir.join("recovery_initiation_key.json");
    write_json_output(&setup_output.rik, &rik_path)?;

    // Write complete output
    let complete_path = output_dir.join("setup_recovery_complete.json");
    write_json_output(setup_output, &complete_path)?;

    Ok(())
}

/// Initiate recovery after getting RIK from nodes
pub fn initiate_recovery_command(
    account_state_path: PathBuf,
    rik_path: PathBuf,
    account_id_str: String,
    output: PathBuf,
) -> Result<()> {
    use serde::Serialize;
    use swafe_lib::{
        account::{AccountUpdate, RecoverySecrets},
        encode::StrEncoded,
        types::RecoveryInitiationKey,
    };

    let mut rng = thread_rng();

    // Read account state (expect AccountAllocationOutput JSON format)
    let state_output: crate::commands::utils::AccountAllocationOutput =
        load_json_file(&account_state_path)?;
    let account_state = state_output.account_state.0;

    // Read RIK (expect StrEncoded<RecoveryInitiationKey> JSON format)
    let rik_str: String = load_json_file(&rik_path)?;
    let rik: RecoveryInitiationKey = encode::deserialize_str(&rik_str)
        .map_err(|e| anyhow::anyhow!("Failed to decode RIK: {}", e))?;

    let account_id: AccountId = encode::deserialize_str(&account_id_str)
        .map_err(|e| anyhow::anyhow!("Failed to decode account ID: {}", e))?;

    let (recovery_update, secret_data) = account_state
        .initiate_recovery(&mut rng, account_id, &rik)
        .map_err(|e| anyhow::anyhow!("Failed to initiate recovery: {:?}", e))?;

    #[derive(Serialize)]
    struct RecoveryInitiationOutput {
        account_id: StrEncoded<AccountId>,
        recovery_update: StrEncoded<AccountUpdate>,
        secret_data: StrEncoded<RecoverySecrets>,
    }

    let recovery_output = RecoveryInitiationOutput {
        account_id: StrEncoded(account_id),
        recovery_update: StrEncoded(recovery_update),
        secret_data: StrEncoded(secret_data),
    };

    write_json_output(recovery_output, &output)?;

    Ok(())
}

/// Guardian processes recovery request
pub fn guardian_process_recovery_command(
    guardian_secrets_path: PathBuf,
    requester_state_path: PathBuf,
    requester_account_id: String,
    output: PathBuf,
) -> Result<()> {
    use serde::Serialize;
    use swafe_lib::{backup::GuardianShare, encode::StrEncoded};

    let mut rng = thread_rng();

    // Read guardian secrets
    let guardian_output: crate::commands::utils::AccountAllocationOutput =
        load_json_file(&guardian_secrets_path)?;

    let guardian_secrets = guardian_output.decrypt_account_secrets()?;

    // Read requester account state (expect AccountAllocationOutput JSON format)
    let requester_output: crate::commands::utils::AccountAllocationOutput =
        load_json_file(&requester_state_path)?;
    let requester_state = requester_output.account_state.0;

    // Parse requester account ID
    let requester_id: AccountId = encode::deserialize_str(&requester_account_id)
        .map_err(|e| anyhow::anyhow!("Failed to decode requester account ID: {}", e))?;

    // Check for recovery request and generate guardian share if needed
    let guardian_share = guardian_secrets
        .check_for_recovery(&mut rng, requester_id, &requester_state)
        .map_err(|e| anyhow::anyhow!("Failed to check for recovery: {:?}", e))?;

    let guardian_share = match guardian_share {
        Some(share) => share,
        None => {
            return Err(anyhow::anyhow!(
                "No pending recovery request found for the specified account"
            ));
        }
    };

    #[derive(Serialize)]
    struct GuardianProcessOutput {
        guardian_share: StrEncoded<GuardianShare>,
    }

    let process_output = GuardianProcessOutput {
        guardian_share: StrEncoded(guardian_share),
    };

    write_json_output(process_output, &output)?;

    Ok(())
}

/// Complete recovery with all shares
pub fn complete_recovery_command(
    recovery_secrets_path: PathBuf,
    guardian_shares_paths: Vec<PathBuf>,
    _account_state_path: PathBuf,
    output: PathBuf,
) -> Result<()> {
    use serde::Serialize;
    use swafe_lib::{account::RecoverySecrets, backup::GuardianShare, encode::StrEncoded};

    // Read recovery secrets (contains msk_ss_rik and recovery_pke)
    #[derive(serde::Deserialize)]
    struct RecoverySecretsInput {
        secret_data: StrEncoded<RecoverySecrets>,
    }

    let secrets_input: RecoverySecretsInput = load_json_file(&recovery_secrets_path)?;
    let recovery_secrets = secrets_input.secret_data.0;

    // Read guardian shares
    let mut guardian_shares = Vec::new();
    for share_path in guardian_shares_paths {
        #[derive(serde::Deserialize)]
        struct GuardianShareInput {
            guardian_share: StrEncoded<GuardianShare>,
        }

        let share_input: GuardianShareInput = load_json_file(&share_path)?;

        guardian_shares.push(share_input.guardian_share.0);
    }

    // Complete recovery using the new interface
    let recovered_msk = recovery_secrets
        .complete(&guardian_shares)
        .map_err(|e| anyhow::anyhow!("Failed to complete recovery: {:?}", e))?;

    #[derive(Serialize)]
    struct CompleteRecoveryOutput {
        recovered_msk: StrEncoded<MasterSecretKey>,
    }

    let recovery_output = CompleteRecoveryOutput {
        recovered_msk: StrEncoded(recovered_msk),
    };

    write_json_output(recovery_output, &output)?;

    Ok(())
}
