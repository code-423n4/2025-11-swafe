use matchit::Params;
use pbc_contract_common::off_chain::{HttpRequestData, HttpResponseData, OffChainContext};
use swafe_api::association::get_secret_share;
use swafe_lib::association::{EmailInput, EmailKey};
use swafe_lib::crypto::vdrf::VdrfPublicKey;
use swafe_lib::crypto::EmailCert;
use swafe_lib::encode;

use super::upload_msk::MskRecordCollection;
use crate::http::endpoints::init::OffchainSecrets;
use crate::storage::Mapping;
use crate::{
    http::error::{ContractError, ServerError},
    http::{create_json_response, deserialize_request_body},
    ContractState,
};

pub const PATH: &str = get_secret_share::PATH;

pub type Request = get_secret_share::Request;
pub type Response = get_secret_share::Response;

pub fn handler(
    mut ctx: OffChainContext,
    state: ContractState,
    request: HttpRequestData,
    _params: Params,
) -> Result<HttpResponseData, ContractError> {
    let request: Request = deserialize_request_body(&request)?;

    let swafe_pk = encode::deserialize(&state.swafe_public_key).map_err(|_| {
        ServerError::SerializationError("Failed to deserialize Swafe public key".to_owned())
    })?;

    let stored_secret =
        OffchainSecrets::load(&mut ctx, ()).ok_or(ServerError::VdrfNodeNotInitialized)?;

    let vdrf_pk: VdrfPublicKey = encode::deserialize(&state.vdrf_public_key).map_err(|_| {
        ServerError::SerializationError("Failed to deserialize VDRF public key".to_owned())
    })?;

    let node_id: swafe_lib::NodeId = stored_secret.node_id.0;
    let (email, _) = EmailCert::verify(&swafe_pk, &node_id, &request.token.0, ctx.current_time())?;

    let email: EmailInput = email.parse()?;
    let email_tag: EmailKey = EmailKey::new(&vdrf_pk, &email, request.vdrf_eval.0)?;

    let msk_record = MskRecordCollection::load(&mut ctx, email_tag)
        .ok_or_else(|| ServerError::InvalidParameter("MSK record not found".to_string()))?;

    create_json_response(
        200,
        &Response {
            entry: encode::StrEncoded(msk_record),
        },
    )
    .map_err(|e| e.into())
}
