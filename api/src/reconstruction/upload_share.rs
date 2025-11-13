use serde::{Deserialize, Serialize};
use swafe_lib::account::AccountId;
use swafe_lib::backup::{BackupId, GuardianShare};
use swafe_lib::encode::StrEncoded;

pub const PATH: &str = "/reconstruction/upload-share";

#[derive(Serialize, Deserialize)]
pub struct Request {
    pub account_id: StrEncoded<AccountId>,
    pub backup_id: StrEncoded<BackupId>,
    pub share: StrEncoded<GuardianShare>,
}

#[derive(Serialize, Deserialize)]
pub struct Response {
    pub success: bool,
    pub message: String,
}
