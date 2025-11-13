use matchit::Params;
use pbc_contract_common::off_chain::{HttpRequestData, HttpResponseData, OffChainContext};
use swafe_api::account::get;
use swafe_lib::account::AccountState;
use swafe_lib::encode::StrEncoded;

use crate::{
    http::error::{ContractError, ServerError},
    http::{create_json_response, deserialize_request_body},
    ContractState,
};

pub const PATH: &str = get::PATH;

pub type Request = get::Request;
pub type Response = get::Response;

pub fn handler(
    _ctx: OffChainContext,
    state: ContractState,
    request: HttpRequestData,
    _params: Params,
) -> Result<HttpResponseData, ContractError> {
    let request: Request = deserialize_request_body(&request)?;
    let account: AccountState = state
        .get_account(request.account_id.0)
        .ok_or_else(|| ServerError::NotFound("Account not found".to_string()))?;

    create_json_response(
        200,
        &Response {
            account_state: StrEncoded(account),
        },
    )
    .map_err(|e| e.into())
}
