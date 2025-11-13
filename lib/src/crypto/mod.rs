//! Cryptographic primitives and protocols for Swafe
//!
//! This module contains implementations of various cryptographic primitives used in Swafe:
//! - Hash functions and key derivation (hash module)
//! - Symmetric encryption (symmetric module)
//! - Digital signatures (signatures module)
//! - Commitment schemes and proofs (commitments module)
//! - Verifiable Distributed Random Functions (vdrf module)
//! - Email certificates (email_cert module)
//! - Pairing-based cryptography (pairing module)

const BINCODE_CONFIG: bincode::config::Configuration = bincode::config::standard();

// Low-level cryptographic primitives - internal use only
pub(crate) mod commitments;
pub(crate) mod curve;
pub(crate) mod pairing;
pub(crate) mod pke;
pub(crate) mod poly;
pub(crate) mod sss;
pub(crate) mod symmetric;

// High-level cryptographic modules - public API
pub mod email_cert;
pub mod hash;
pub mod sig;
pub mod vdrf;

// Re-export commonly used items
pub use email_cert::{EmailCert, EmailCertToken, EmailCertificate};
pub use hash::{hash, kdf, kdfn};
pub use sig::Signature;
pub use vdrf::{Vdrf, VdrfEvaluation, VdrfPublicKey, VdrfSecretKeyShare};
