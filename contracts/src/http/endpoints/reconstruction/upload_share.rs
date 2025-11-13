use std::collections::BTreeMap;

use matchit::Params;
use pbc_contract_common::off_chain::{HttpRequestData, HttpResponseData, OffChainContext};
use read_write_state_derive::ReadWriteState;
use serde::{Deserialize, Serialize};
use swafe_api::reconstruction::upload_share;
use swafe_lib::account::AccountId;
use swafe_lib::backup::{BackupCiphertext, BackupId, GuardianShare};

use crate::storage::Mapping;
use crate::{
    http::error::{ContractError, ServerError},
    http::{create_json_response, deserialize_request_body},
    ContractState,
};

pub const PATH: &str = upload_share::PATH;

pub type Request = upload_share::Request;
pub type Response = upload_share::Response;

#[derive(ReadWriteState, Serialize, Deserialize, Clone, Default)]
pub struct GuardianShareCollection {}

impl Mapping for GuardianShareCollection {
    type Key = (AccountId, BackupId);
    type Value = BTreeMap<u32, GuardianShare>;

    const COLLECTION_NAME: &'static str = "map:guardian_shares";
}

pub fn handler(
    mut ctx: OffChainContext,
    state: ContractState,
    request: HttpRequestData,
    _params: Params,
) -> Result<HttpResponseData, ContractError> {
    let request: Request = deserialize_request_body(&request)?;

    let backup_id = request.backup_id.0;
    let account_id = request.account_id.0;

    let account = state
        .get_account(account_id)
        .ok_or_else(|| ServerError::NotFound("Account not found".to_string()))?;

    let backup: &BackupCiphertext = account.recover_id(backup_id).ok_or_else(|| {
        ServerError::NotFound(format!("Backup not found for backup_id: {}", backup_id))
    })?;

    // The share id will be in the range [0, |shares|)
    let share_id = backup
        .verify(&request.share.0)
        .map_err(|_| ServerError::InvalidParameter("Invalid guardian share".to_string()))?;

    // Update the share mapping for this backup
    // usually, the share will not already exist in this map:
    // we allow overwriting in case of a buggy client library and to
    // simplify a client which fails during the upload process: it can simply retry all uploads.
    //
    // Potentially different multiple versions of the same share are all equivalent.
    // Hence no replay protection is required here.
    let storage_key = (account_id, backup_id);
    let mut shares = GuardianShareCollection::load(&mut ctx, storage_key).unwrap_or_default();
    shares.insert(share_id, request.share.0);
    GuardianShareCollection::store(&mut ctx, storage_key, shares);

    let response = Response {
        success: true,
        message: "Share uploaded successfully".to_string(),
    };
    create_json_response(200, &response).map_err(|e| e.into())
}
