use matchit::Params;
use pbc_contract_common::off_chain::{HttpRequestData, HttpResponseData, OffChainContext};
use swafe_api::reconstruction::get_shares;
use swafe_lib::encode::StrEncoded;

use super::upload_share::GuardianShareCollection;
use crate::storage::Mapping;
use crate::{
    http::error::ContractError,
    http::{create_json_response, deserialize_request_body},
    ContractState,
};

pub const PATH: &str = get_shares::PATH;

pub type Request = get_shares::Request;
pub type Response = get_shares::Response;

pub fn handler(
    mut ctx: OffChainContext,
    _state: ContractState,
    request: HttpRequestData,
    _params: Params,
) -> Result<HttpResponseData, ContractError> {
    let request = deserialize_request_body::<Request>(&request)?;
    let account_id = request.account_id.0;
    let backup_id = request.backup_id.0;
    let shares: Vec<_> = GuardianShareCollection::load(&mut ctx, (account_id, backup_id))
        .unwrap_or_default()
        .values()
        .cloned()
        .map(StrEncoded)
        .collect();
    create_json_response(200, &Response { shares }).map_err(|e| e.into())
}
