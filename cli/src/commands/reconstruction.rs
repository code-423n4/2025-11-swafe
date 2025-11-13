use std::fs;
use std::path::PathBuf;

use anyhow::Result;
use swafe_api::reconstruction::{get_shares, upload_share};
use swafe_lib::account::AccountId;
use swafe_lib::backup::{BackupId, GuardianShare};
use swafe_lib::encode::StrEncoded;

/// Create an upload guardian share request for the reconstruction endpoint
pub fn create_upload_guardian_share_request(
    account_id_str: String,
    backup_id_str: String,
    guardian_share_str: String,
) -> Result<upload_share::Request> {
    let account_id: AccountId = StrEncoded::try_from(account_id_str.as_str())
        .map_err(|e| anyhow::anyhow!("Failed to decode account ID: {}", e))?
        .0;
    let backup_id: BackupId = StrEncoded::try_from(backup_id_str.as_str())
        .map_err(|e| anyhow::anyhow!("Failed to decode backup ID: {}", e))?
        .0;
    let guardian_share: GuardianShare = StrEncoded::try_from(guardian_share_str.as_str())
        .map_err(|e| anyhow::anyhow!("Failed to decode guardian share: {}", e))?
        .0;

    let request = upload_share::Request {
        account_id: StrEncoded(account_id),
        backup_id: StrEncoded(backup_id),
        share: StrEncoded(guardian_share),
    };

    Ok(request)
}

/// CLI command to create upload guardian share request
pub fn create_upload_guardian_share_request_command(
    account_id: String,
    backup_id: String,
    guardian_share: String,
    output: PathBuf,
) -> Result<()> {
    let request = create_upload_guardian_share_request(account_id, backup_id, guardian_share)?;
    let json = serde_json::to_string_pretty(&request)?;
    fs::write(output, json)?;
    Ok(())
}

/// Create a get guardian shares request for the reconstruction endpoint
pub fn create_get_guardian_shares_request(
    account_id_str: String,
    backup_id_str: String,
) -> Result<get_shares::Request> {
    let account_id: AccountId = StrEncoded::try_from(account_id_str.as_str())
        .map_err(|e| anyhow::anyhow!("Failed to decode account ID: {}", e))?
        .0;
    let backup_id: BackupId = StrEncoded::try_from(backup_id_str.as_str())
        .map_err(|e| anyhow::anyhow!("Failed to decode backup ID: {}", e))?
        .0;

    let request = get_shares::Request {
        account_id: StrEncoded(account_id),
        backup_id: StrEncoded(backup_id),
    };

    Ok(request)
}

/// CLI command to create get guardian shares request
pub fn create_get_guardian_shares_request_command(
    account_id: String,
    backup_id: String,
    output: PathBuf,
) -> Result<()> {
    let request = create_get_guardian_shares_request(account_id, backup_id)?;
    let json = serde_json::to_string_pretty(&request)?;
    fs::write(output, json)?;
    Ok(())
}
