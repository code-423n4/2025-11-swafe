use matchit::Params;
use pbc_contract_common::off_chain::{HttpRequestData, HttpResponseData, OffChainContext};
use read_write_state_derive::ReadWriteState;
use serde::{Deserialize, Serialize};
use swafe_api::init;
use swafe_lib::crypto::hash;
use swafe_lib::encode::StrEncoded;
use swafe_lib::NodeId;

use crate::storage::Mapping;
use crate::{
    http::error::{ContractError, ServerError},
    http::{create_json_response, deserialize_request_body},
    ContractState,
};

pub const PATH: &str = init::PATH;

pub type Request = init::Request;
pub type Response = init::Response;

#[derive(Serialize, Deserialize, Clone)]
pub struct StoredOffchainSecret {
    pub node_id: StrEncoded<NodeId>,
    pub secret: init::OffchainSecret, // Direct storage of OffchainSecret
}

#[derive(ReadWriteState, Serialize, Deserialize, Clone, Default)]
pub struct OffchainSecrets {}

impl Mapping for OffchainSecrets {
    type Key = ();
    type Value = StoredOffchainSecret;

    const COLLECTION_NAME: &'static str = "map:node-secret";
}

pub fn handler(
    mut ctx: OffChainContext,
    state: ContractState,
    request: HttpRequestData,
    _params: Params,
) -> Result<HttpResponseData, ContractError> {
    if OffchainSecrets::load(&mut ctx, ()).is_some() {
        return Err(ServerError::VdrfNodeAlreadyInitialized.into());
    }

    let request: Request = deserialize_request_body(&request)?;

    // Get the node config from state to compare against the commitment
    let node_id = &request.node_id.0;
    let node_config = state.nodes.get(node_id.as_ref()).ok_or_else(|| {
        ServerError::InvalidParameter(format!("Node with id '{}' not found", node_id))
    })?;

    // Verify that the computed hash matches the stored commitment
    let secret = request.secret.0;
    if hash(&secret) != node_config.comm {
        return Err(ServerError::InvalidParameter(
            "Secret commitment mismatch - provided secret does not match on-chain commitment"
                .to_string(),
        )
        .into());
    }

    let stored_secret = StoredOffchainSecret {
        node_id: request.node_id,
        secret,
    };

    OffchainSecrets::store(&mut ctx, (), stored_secret);

    create_json_response(
        200,
        &Response {
            success: true,
            message: "Offchain node initialized successfully".to_string(),
        },
    )
    .map_err(|e| e.into())
}
