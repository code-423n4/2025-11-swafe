use serde::{Deserialize, Serialize};
use swafe_lib::account::{AccountId, AccountState};
use swafe_lib::encode::StrEncoded;

pub const PATH: &str = "/account/get";

#[derive(Deserialize)]
pub struct Request {
    pub account_id: StrEncoded<AccountId>,
}

#[derive(Serialize)]
pub struct Response {
    pub account_state: StrEncoded<AccountState>,
}
