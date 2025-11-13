use matchit::Params;
use pbc_contract_common::off_chain::{HttpRequestData, HttpResponseData, OffChainContext};
use swafe_api::association::vdrf::eval;
use swafe_lib::association::EmailInput;
use swafe_lib::crypto::vdrf::VdrfPublicKey;
use swafe_lib::crypto::{EmailCert, Vdrf};
use swafe_lib::encode;
use swafe_lib::NodeId;

use crate::http::endpoints::init::OffchainSecrets;
use crate::storage::Mapping;
use crate::{
    http::error::{ContractError, ServerError},
    http::{create_json_response, deserialize_request_body},
    ContractState,
};

pub const PATH: &str = eval::PATH;

pub type Request = eval::Request;
pub type Response = eval::Response;

pub fn handler(
    mut ctx: OffChainContext,
    state: ContractState,
    request: HttpRequestData,
    _params: Params,
) -> Result<HttpResponseData, ContractError> {
    let request = deserialize_request_body::<Request>(&request)?;
    let swafe_public_key = encode::deserialize(&state.swafe_public_key).map_err(|_| {
        ServerError::SerializationError("Failed to deserialize Swafe public key".to_owned())
    })?;

    let stored_secret =
        OffchainSecrets::load(&mut ctx, ()).ok_or(ServerError::VdrfNodeNotInitialized)?;

    // Now we have access to the node_id from stored_secret
    let node_id: NodeId = stored_secret.node_id.0;

    let (email, _) = EmailCert::verify(
        &swafe_public_key,
        &node_id,
        &request.token.0,
        ctx.current_time(),
    )?;

    let secret_share = &stored_secret.secret.secret_share;
    let vdrf_public_key: VdrfPublicKey = encode::deserialize(&state.vdrf_public_key)?;
    let email_input: EmailInput = email.parse()?;
    let evaluation_result = Vdrf::partial_eval(&vdrf_public_key, secret_share, &email_input)?;

    create_json_response(
        200,
        &Response {
            eval_share: encode::StrEncoded(evaluation_result),
        },
    )
    .map_err(|e| e.into())
}
