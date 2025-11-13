use serde::{Deserialize, Serialize};
use swafe_lib::account::AccountId;
use swafe_lib::backup::{BackupId, GuardianShare};
use swafe_lib::encode::StrEncoded;

pub const PATH: &str = "/reconstruction/get-shares";

#[derive(Serialize, Deserialize)]
pub struct Request {
    pub account_id: StrEncoded<AccountId>,
    pub backup_id: StrEncoded<BackupId>,
}

#[derive(Serialize, Deserialize)]
pub struct Response {
    pub shares: Vec<StrEncoded<GuardianShare>>,
}
