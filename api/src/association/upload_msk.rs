use serde::{Deserialize, Serialize};
use swafe_lib::association::AssociationRequestEmail;
use swafe_lib::crypto::{EmailCertToken, VdrfEvaluation};
use swafe_lib::encode::StrEncoded;

pub const PATH: &str = "/association/upload-association";

#[derive(Serialize, Deserialize)]
pub struct Request {
    pub token: StrEncoded<EmailCertToken>,
    pub vdrf_eval: StrEncoded<VdrfEvaluation>,
    pub association: StrEncoded<AssociationRequestEmail>,
}

#[derive(Serialize, Deserialize)]
pub struct Response {
    pub success: bool,
    pub message: String,
}
