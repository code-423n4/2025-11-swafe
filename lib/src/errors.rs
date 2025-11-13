use thiserror::Error;

#[derive(Error, Debug)]
pub enum SwafeError {
    #[error("Backup not found")]
    BackupNotFound,

    #[error("Invalid share")]
    InvalidShare,

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Proof verification failed")]
    ProofVerificationFailed,

    #[error("Invalid commitment count")]
    InvalidCommitmentCount,

    #[error("Invalid data: {0}")]
    InvalidData(String),

    #[error("Certificate has expired")]
    CertificateExpired,

    #[error("Certificate timestamp is in the future")]
    CertificateFromFuture,

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Not enough shares for reconstruction")]
    NotEnoughSharesForReconstruction,

    #[error("VDRF evaluation verification failed")]
    VdrfEvaluationVerificationFailed,

    #[error("Invalid account state version")]
    InvalidAccountStateVersion,

    #[error("Insufficient shares for reconstruction")]
    InsufficientShares,

    #[error("Invalid nonce: must be higher than existing nonces")]
    InvalidNonce,

    #[error("Invalid recovery key")]
    InvalidRecoveryKey,

    #[error("Invalid operation: {0}")]
    InvalidOperation(String),
}

pub type Result<T> = std::result::Result<T, SwafeError>;
