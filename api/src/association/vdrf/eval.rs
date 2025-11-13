use serde::{Deserialize, Serialize};
use swafe_lib::crypto::vdrf::VdrfEvaluationShare;
use swafe_lib::crypto::EmailCertToken;
use swafe_lib::encode::StrEncoded;

pub const PATH: &str = "/association/vdrf/eval";

#[derive(Deserialize)]
pub struct Request {
    pub token: StrEncoded<EmailCertToken>,
}

#[derive(Serialize)]
pub struct Response {
    pub eval_share: StrEncoded<VdrfEvaluationShare>,
}
