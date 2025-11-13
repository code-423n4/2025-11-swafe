use serde::{Deserialize, Serialize};
use swafe_lib::crypto::vdrf::{VdrfPublicKey, VdrfSecretKeyShare};
use swafe_lib::encode::StrEncoded;
use swafe_lib::NodeId;

pub const PATH: &str = "/init";

#[derive(Serialize, Deserialize, Clone)]
pub struct OffchainSecret {
    pub public_key: VdrfPublicKey,
    pub secret_share: VdrfSecretKeyShare,
    pub randomizer: [u8; 32],
}

impl swafe_lib::encode::Tagged for OffchainSecret {
    const SEPARATOR: &'static str = "v0:offchain-secret";
}

#[derive(Serialize, Deserialize)]
pub struct Request {
    pub node_id: StrEncoded<NodeId>,
    pub secret: StrEncoded<OffchainSecret>,
}

#[derive(Serialize, Deserialize)]
pub struct Response {
    pub success: bool,
    pub message: String,
}
