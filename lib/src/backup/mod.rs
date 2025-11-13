#[cfg(test)]
mod tests;
pub(crate) mod v0;

use core::fmt;
use std::fmt::Display;

use serde::{Deserialize, Serialize};
pub use v0::{
    AADBackup, BackupCiphertext, EncryptionContext, GuardianShare, SecretShare, ShareComm,
};

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Debug, Clone, Copy)]
pub struct BackupId([u8; 32]);

impl BackupId {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl Display for BackupId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "backup-id:{}", hex::encode(self.0))
    }
}

pub struct Metadata {
    name: String,
    desc: String,
}

impl Metadata {
    /// Create new metadata
    pub fn new(name: String, desc: String) -> Self {
        Self { name, desc }
    }

    /// Get the name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the description
    pub fn desc(&self) -> &str {
        &self.desc
    }
}
