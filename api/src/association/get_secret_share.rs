use serde::{Deserialize, Serialize};
use swafe_lib::association::MskRecord;
use swafe_lib::crypto::{EmailCertToken, VdrfEvaluation};
use swafe_lib::encode::StrEncoded;

pub const PATH: &str = "/association/get-ss";

#[derive(Clone, Serialize, Deserialize)]
pub struct Request {
    pub vdrf_eval: StrEncoded<VdrfEvaluation>,
    pub token: StrEncoded<EmailCertToken>,
}

#[derive(Serialize)]
pub struct Response {
    pub entry: StrEncoded<MskRecord>,
}
