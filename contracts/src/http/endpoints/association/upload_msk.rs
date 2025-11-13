use matchit::Params;
use pbc_contract_common::off_chain::{HttpRequestData, HttpResponseData, OffChainContext};
use read_write_state_derive::ReadWriteState;
use serde::{Deserialize, Serialize};
use swafe_api::association::upload_msk;
use swafe_lib::association::{EmailInput, EmailKey, MskRecord};
use swafe_lib::crypto::EmailCert;
use swafe_lib::encode;

use crate::http::endpoints::init::OffchainSecrets;
use crate::storage::Mapping;
use crate::{
    http::error::{ContractError, ServerError},
    http::{create_json_response, deserialize_request_body},
    ContractState,
};

pub const PATH: &str = upload_msk::PATH;

pub type Request = upload_msk::Request;
pub type Response = upload_msk::Response;

#[derive(ReadWriteState, Serialize, Deserialize, Clone, Default)]
pub struct MskRecordCollection {}

impl Mapping for MskRecordCollection {
    type Key = EmailKey;
    type Value = MskRecord;

    const COLLECTION_NAME: &'static str = "map:associations";
}

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

    let vdrf_pk = encode::deserialize(&state.vdrf_public_key).map_err(|_| {
        ServerError::SerializationError("Failed to deserialize VDRF public key".to_owned())
    })?;

    let node_id: swafe_lib::NodeId = stored_secret.node_id.0;

    let (email, user_pk) =
        EmailCert::verify(&swafe_pk, &node_id, &request.token.0, ctx.current_time())?;

    let email: EmailInput = email.parse()?;
    let email_tag: EmailKey = EmailKey::new(&vdrf_pk, &email, request.vdrf_eval.0)?;

    MskRecordCollection::store(
        &mut ctx,
        email_tag,
        request.association.0.verify(user_pk, &node_id)?,
    );

    create_json_response(
        200,
        &Response {
            success: true,
            message: "Association uploaded successfully".to_string(),
        },
    )
    .map_err(|e| e.into())
}
