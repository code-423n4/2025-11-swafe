use pbc_contract_common::off_chain::HttpResponseData;
use serde::{Deserialize, Serialize};
use swafe_lib::SwafeError;

/// Contract-specific error types
pub enum ContractError {
    /// Error from the swafe library
    LibError(SwafeError),
    /// Server-side errors specific to the contract
    ServerError(ServerError),
}

impl From<SwafeError> for ContractError {
    fn from(error: SwafeError) -> Self {
        ContractError::LibError(error)
    }
}

impl From<ServerError> for ContractError {
    fn from(error: ServerError) -> Self {
        ContractError::ServerError(error)
    }
}

/// Server-side error variants
#[derive(Debug)]
pub enum ServerError {
    /// VDRF node not initialized
    VdrfNodeNotInitialized,
    /// VDRF node already initialized
    VdrfNodeAlreadyInitialized,
    /// Invalid request body (e.g. not UTF-8)
    InvalidRequestBody,
    /// Serialization error (e.g. failed to decode hex)
    SerializationError(String),
    /// Invalid parameter error
    InvalidParameter(String),
    /// Resource not found
    NotFound(String),
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerError::VdrfNodeNotInitialized => write!(f, "VDRF node not initialized"),
            ServerError::VdrfNodeAlreadyInitialized => write!(f, "VDRF node already initialized"),
            ServerError::InvalidRequestBody => write!(f, "Invalid request body"),
            ServerError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            ServerError::InvalidParameter(msg) => write!(f, "Invalid parameter: {}", msg),
            ServerError::NotFound(msg) => write!(f, "Resource not found: {}", msg),
        }
    }
}

/// Error response structure
#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// Helper function to convert ContractError to HttpResponseData
pub fn contract_error_to_http_response(error: ContractError) -> HttpResponseData {
    let (status_code, message): (u32, String) = match error {
        ContractError::LibError(swafe_error) => {
            let status_code = match swafe_error {
                SwafeError::CryptoError(_) => 400,
                SwafeError::SerializationError(_) => 400,
                SwafeError::InvalidParameter(_) => 400,
                SwafeError::VerificationFailed(_) => 400,
                SwafeError::DecryptionFailed => 400,
                SwafeError::AuthenticationFailed => 401,
                SwafeError::ProofVerificationFailed => 400,
                SwafeError::InvalidCommitmentCount => 400,
                SwafeError::InvalidData(_) => 400,
                SwafeError::CertificateExpired => 400,
                SwafeError::CertificateFromFuture => 400,
                SwafeError::SignatureVerificationFailed => 400,
                SwafeError::InvalidInput(_) => 400,
                SwafeError::NotEnoughSharesForReconstruction => 400,
                SwafeError::VdrfEvaluationVerificationFailed => 400,
                SwafeError::InvalidAccountStateVersion => 400,
                SwafeError::InsufficientShares => 400,
                SwafeError::InvalidNonce => 400,
                SwafeError::InvalidShare => 400,
                SwafeError::BackupNotFound => 404,
                SwafeError::InvalidSignature => 400,
                SwafeError::InvalidRecoveryKey => 400,
                SwafeError::InvalidOperation(_) => 400,
            };
            (status_code, swafe_error.to_string())
        }
        ContractError::ServerError(server_error) => {
            let status_code = match server_error {
                ServerError::VdrfNodeNotInitialized => 503,
                ServerError::VdrfNodeAlreadyInitialized => 409,
                ServerError::InvalidRequestBody => 400,
                ServerError::SerializationError(_) => 400,
                ServerError::InvalidParameter(_) => 400,
                ServerError::NotFound(_) => 404,
            };
            (status_code, server_error.to_string())
        }
    };

    // Create JSON error response
    let error_response = ErrorResponse { error: message };
    let json_str = crate::http::json::to_string(&error_response)
        .unwrap_or_else(|_| crate::http::json::json_error("Failed to serialize error response"));
    HttpResponseData::new_with_str(status_code, &json_str)
}
