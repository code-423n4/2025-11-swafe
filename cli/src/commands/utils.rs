use std::fs;
use std::path::PathBuf;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use swafe_lib::account::{AccountId, AccountSecrets, AccountState, AccountUpdate};
use swafe_lib::backup::{BackupCiphertext, GuardianShare, SecretShare};
use swafe_lib::crypto::sig::VerificationKey;
use swafe_lib::crypto::{hash, VdrfPublicKey};
use swafe_lib::encode::{self, StrEncoded};
use swafe_lib::types::MasterSecretKey;
use swafe_lib::{NodeId, SwafeError, Tagged};

#[derive(Serialize, Deserialize, Clone)]
pub struct SecretData {
    pub data: Vec<u8>,
}

impl Tagged for SecretData {
    const SEPARATOR: &'static str = "v0:cli-secret-data";
}

pub fn write_output<T>(value: T, output_path: &PathBuf) -> Result<()>
where
    T: serde::Serialize,
{
    let str_output = encode::serialize_str(&value).map_err(anyhow::Error::from)?;
    fs::write(output_path, &str_output)
        .map_err(|e| SwafeError::SerializationError(e.to_string()).into())
}

pub fn write_json_output<T>(value: T, output_path: &PathBuf) -> Result<()>
where
    T: serde::Serialize,
{
    let json_output = serde_json::to_string_pretty(&value)?;
    fs::write(output_path, json_output)
        .map_err(|e| anyhow::anyhow!("Failed to write output file: {}", e))?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
pub struct AccountAllocationOutput {
    pub account_update: StrEncoded<AccountUpdate>,
    pub account_id: StrEncoded<AccountId>,
    pub account_state: StrEncoded<AccountState>,
    pub master_secret_key: StrEncoded<MasterSecretKey>,
}

#[derive(Serialize, Deserialize)]
pub struct AccountUpdateOutput {
    pub account_update: StrEncoded<AccountUpdate>,
    pub account_id: StrEncoded<AccountId>,
    pub account_state: StrEncoded<AccountState>,
    pub master_secret_key: StrEncoded<MasterSecretKey>,
}

#[derive(Serialize, Deserialize)]
pub struct VdrfTestSetup {
    pub vdrf_public_key: StrEncoded<VdrfPublicKey>,
    pub signed_shares:
        std::collections::HashMap<String, StrEncoded<swafe_api::init::OffchainSecret>>,
    pub node_configs: Vec<NodeTestConfig>,
    pub num_nodes: usize,
}

#[derive(Serialize, Deserialize)]
pub struct NodeTestConfig {
    pub node_id: String,
    pub public_key_str: StrEncoded<VerificationKey>,
}

#[derive(Serialize, Deserialize)]
pub struct BackupCiphertextOutput {
    pub backup_ciphertext: StrEncoded<BackupCiphertext>,
    pub threshold: usize,
    pub guardians_count: usize,
    pub name: String,
    pub description: String,
}

#[derive(Serialize, Deserialize)]
pub struct GuardianSecretShareOutput {
    pub secret_share: StrEncoded<SecretShare>,
    pub guardian_index: u32,
    pub owner_account_id: StrEncoded<AccountId>,
}

#[derive(Serialize, Deserialize)]
pub struct VerifiedShareOutput {
    pub share: StrEncoded<GuardianShare>,
    pub index: u32,
}

#[derive(Serialize)]
pub struct VdrfEvaluationResult {
    pub input: String,
    pub evaluation: String,
    pub random_output: String,
}

impl AccountAllocationOutput {
    /// Decrypt the account state to get AccountSecrets using the stored master secret key
    pub fn decrypt_account_secrets(&self) -> Result<AccountSecrets> {
        self.account_state
            .0
            .decrypt(&self.master_secret_key.0, self.account_id.0)
            .map_err(|e| anyhow::anyhow!("Failed to decrypt account secrets: {:?}", e))
    }
}

impl AccountUpdateOutput {}

pub fn load_json_file<T>(path: &PathBuf) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let json_str = fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Failed to read file {}: {}", path.display(), e))?;

    serde_json::from_str(&json_str)
        .map_err(|e| anyhow::anyhow!("Failed to parse JSON from {}: {}", path.display(), e))
}

pub fn compute_commitment(input: PathBuf) -> Result<()> {
    // Read the serialized OffchainSecret from the input file
    let serialized_secret = std::fs::read_to_string(&input)
        .map_err(|e| anyhow::anyhow!("Failed to read input file: {}", e))?
        .trim()
        .to_string();

    // Deserialize the OffchainSecret
    let offchain_secret: swafe_api::init::OffchainSecret =
        encode::deserialize_str(&serialized_secret)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize OffchainSecret: {}", e))?;

    // Compute the Tagged hash
    let commitment = hash(&offchain_secret);

    // Output as hex string
    println!("{}", hex::encode(commitment));

    Ok(())
}

pub fn encode_node_id(node_id_str: String) -> Result<()> {
    // Parse the NodeId from string (assumes NodeId implements FromStr)
    let node_id: NodeId = node_id_str
        .parse()
        .map_err(|e| anyhow::anyhow!("Failed to parse NodeId '{}': {:?}", node_id_str, e))?;

    // Create StrEncoded<NodeId>
    let encoded = StrEncoded(node_id);

    // Convert to string (base64 of bincode-serialized NodeId)
    let encoded_string: String = encoded.into();

    // Output the StrEncoded string
    println!("{}", encoded_string);

    Ok(())
}
