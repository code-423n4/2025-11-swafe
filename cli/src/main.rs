//! This CLI demonstrates some of the Swafe workflows using the Swafe library.
//! It is mainly purposed to work for the java tests, which can simulate the partisia blockchain
//! behaviors. In other words, this CLI is only for testing purposes, and is not intended for
//! production use.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

mod commands;
use commands::*;

#[derive(Parser)]
#[command(name = "swafe-cli")]
#[command(about = "A CLI tool for Swafe proof generation and verification")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Combine VDRF partial evaluations and verify the result
    CombineVdrfEvaluations {
        /// VDRF public key
        #[arg(long)]
        public_key: String,

        /// Partial evaluations as arguments: "node_id=evaluation"
        #[arg(short, long)]
        evaluations: Vec<String>,

        /// Output file path for the combined result
        #[arg(short, long, default_value = "vdrf_result.txt")]
        output: PathBuf,

        /// The input data that was evaluated (plain text, e.g., email address)
        #[arg(long, default_value = "")]
        input_data: String,
    },
    /// Generate a key pair (for operator or user)
    GenerateKeypair {
        /// Output file path for the private key
        #[arg(short = 's', long, default_value = "private_key.txt")]
        keypair_output: PathBuf,

        /// Output file path for the public key
        #[arg(short = 'p', long, default_value = "public_key.txt")]
        public_key_output: PathBuf,
    },
    /// Generate email certificate signed by Swafe operator
    GenerateEmailCert {
        /// Email address to certify
        #[arg(short, long)]
        email: String,

        /// User public key
        #[arg(short = 'u', long)]
        user_public_key: String,

        /// Operator private key
        #[arg(short = 'k', long)]
        operator_private_key: String,

        /// Output file path for the certificate
        #[arg(short, long, default_value = "email_cert.txt")]
        output: PathBuf,
    },
    /// Generate EmailCert token signed by user
    GenerateEmailCertToken {
        /// Email certificate
        #[arg(short, long)]
        certificate: String,

        /// Node ID that will process the request
        #[arg(short, long)]
        node_id: String,

        /// User private key
        #[arg(short = 'k', long)]
        user_private_key: String,

        /// Output file path for the token
        #[arg(short, long, default_value = "email_cert_token.txt")]
        output: PathBuf,
    },

    /// Create GetSecretShareRequest from email cert token and VDRF evaluation
    CreateGetSecretShareRequest {
        /// Email certificate token
        #[arg(long)]
        email_cert_token: String,

        /// VDRF evaluation
        #[arg(long)]
        vdrf_evaluation: String,

        /// Output file path for the request
        #[arg(short, long, default_value = "get_secret_share_request.txt")]
        output: PathBuf,
    },

    /// Test command: Reconstruct RIK data from association records
    ReconstructRik {
        /// Input files containing MskRecords - one per node
        #[arg(short, long)]
        msk_records: Vec<PathBuf>,

        /// RIK file (from create-encrypted-msk output)
        #[arg(long)]
        rik_file: PathBuf,

        /// Output file path for the reconstructed RIK data
        #[arg(short, long, default_value = "reconstructed_rik.txt")]
        output: PathBuf,
    },

    /// Create encrypted MSK that can be reused across nodes
    CreateEncryptedMsk {
        /// Threshold value for secret sharing
        #[arg(short, long, default_value = "3")]
        threshold: usize,

        /// Output file path for the encrypted MSK result
        #[arg(short, long, default_value = "encrypted_msk.txt")]
        output: PathBuf,
    },

    /// Generate complete upload encrypted MSK request
    GenerateUploadMskRequest {
        /// Email certificate
        #[arg(long)]
        certificate: String,

        /// Encrypted MSK result file
        #[arg(long)]
        encrypted_msk: String,

        /// Node ID to generate token
        #[arg(long)]
        node_id: String,

        /// VDRF evaluation for the email
        #[arg(long)]
        vrf_eval_email: String,

        /// Output file path for the request body
        #[arg(short, long, default_value = "upload_msk_request.txt")]
        output: PathBuf,
    },

    /// Extract user signing keys from encrypted MSK
    ExtractKeys {
        /// Encrypted MSK result file
        #[arg(long)]
        encrypted_msk: String,

        /// Output file path for the user private key
        #[arg(long)]
        private_key_output: PathBuf,

        /// Output file path for the user public key
        #[arg(long)]
        public_key_output: PathBuf,
    },

    /// Generate account allocation request data for contract (AccountUpdateV0 only)
    GenerateAccountAllocation {
        /// Output file path for the AccountUpdateV0 data
        #[arg(short, long, default_value = "account_update_v0.json")]
        output: PathBuf,
    },

    /// Generate account update request data for an existing account
    GenerateAccountUpdate {
        /// Path to the initial account secrets file (JSON containing account_update_str and
        /// account_id_str)
        #[arg(long)]
        initial_allocation: PathBuf,

        /// Output file path for the AccountUpdateV0 data
        #[arg(short, long, default_value = "account_update_v0.json")]
        output: PathBuf,
    },

    /// Generate complete VDRF test setup (shares + keys + signatures) in one call
    GenerateVdrfTestSetup {
        /// Number of VDRF nodes
        #[arg(short, long, default_value = "3")]
        num_nodes: usize,

        /// VDRF threshold (number of nodes needed for reconstruction)
        #[arg(short, long)]
        threshold: usize,

        /// Node IDs (comma-separated, e.g., "node1,node2,node3"). If not provided, will generate
        /// "node1", "node2", etc.
        #[arg(long, value_delimiter = ',')]
        node_ids: Option<Vec<String>>,

        /// Output file path for the complete VDRF setup JSON
        #[arg(short, long, default_value = "vdrf_test_setup.json")]
        output: PathBuf,
    },

    /// Create social recovery backup ciphertext with threshold secret sharing
    CreateBackupCiphertext {
        /// Owner account state (AccountState)
        #[arg(long)]
        owner_account_state_str: String,

        /// Owner master secret key (MasterSecretKey)
        #[arg(long)]
        owner_msk_str: String,

        /// Owner account ID (AccountId)
        #[arg(long)]
        owner_account_id_str: String,

        /// Guardian account states (AccountState), can be specified multiple times
        #[arg(long)]
        guardian_accounts_str: Vec<String>,

        /// Threshold (minimum number of guardians needed for recovery)
        #[arg(long)]
        threshold: usize,

        /// Secret data to backup
        #[arg(long)]
        secret_data: String,

        /// Backup name/title
        #[arg(long, default_value = "Social Recovery Backup")]
        name: String,

        /// Backup description
        #[arg(long, default_value = "Generated via CLI")]
        description: String,

        /// Output file path for the backup ciphertext
        #[arg(short, long, default_value = "backup_ciphertext.json")]
        output: PathBuf,
    },

    /// Guardian decrypts their share from backup ciphertext
    GuardianDecryptShare {
        /// Guardian account state (AccountState)
        #[arg(long)]
        guardian_account_state_str: String,

        /// Guardian master secret key (MasterSecretKey)
        #[arg(long)]
        guardian_msk_str: String,

        /// Guardian account ID (AccountId)
        #[arg(long)]
        guardian_account_id_str: String,

        /// Owner account ID (AccountId)
        #[arg(long)]
        owner_account_id: String,

        /// Backup ciphertext (BackupCiphertext)
        #[arg(long)]
        backup_ciphertext_str: String,

        /// Output file path for the secret share
        #[arg(short, long, default_value = "guardian_secret_share.json")]
        output: PathBuf,
    },

    /// Guardian converts secret share to guardian share
    GuardianSendShare {
        /// Secret share (SecretShare)
        #[arg(long)]
        secret_share_str: String,

        /// Owner account state (AccountState)
        #[arg(long)]
        owner_account_state_str: String,

        /// Output file path for the guardian share
        #[arg(short, long, default_value = "guardian_share.json")]
        output: PathBuf,
    },

    /// Verify guardian share against backup ciphertext
    VerifyGuardianShare {
        /// Guardian share (GuardianShare)
        #[arg(long)]
        guardian_share_str: String,

        /// Backup ciphertext (BackupCiphertext)
        #[arg(long)]
        backup_ciphertext_str: String,

        /// Output file path for the verified share
        #[arg(short, long, default_value = "verified_share.json")]
        output: PathBuf,
    },

    /// Recover secret data from backup using guardian shares
    RecoverFromBackup {
        /// Owner account state (AccountState)
        #[arg(long)]
        owner_account_state_str: String,

        /// Owner master secret key (MasterSecretKey)
        #[arg(long)]
        owner_msk_str: String,

        /// Owner account ID (AccountId)
        #[arg(long)]
        owner_account_id_str: String,

        /// Backup ciphertext (BackupCiphertext)
        #[arg(long)]
        backup_ciphertext_str: String,

        /// Guardian shares (GuardianShare), can be specified multiple times
        #[arg(long)]
        guardian_shares_str: Vec<String>,

        /// Output file path for the recovered secret
        #[arg(short, long, default_value = "recovered_secret.txt")]
        output: PathBuf,
    },

    /// Add a backup to an account and generate account update
    AddBackupToAccount {
        /// Owner account state (AccountState)
        #[arg(long)]
        owner_account_state_str: String,

        /// Owner master secret key (MasterSecretKey)
        #[arg(long)]
        owner_msk_str: String,

        /// Owner account ID (AccountId)
        #[arg(long)]
        owner_account_id_str: String,

        /// Backup ciphertext (encoded BackupCiphertext)
        #[arg(long)]
        backup_ciphertext: String,

        /// Output file path for the account update
        #[arg(short, long, default_value = "account_update_with_backup.json")]
        output: PathBuf,
    },

    /// Extract a specific backup ciphertext from account state
    ExtractBackupFromAccount {
        /// Account state (encoded AccountState)
        #[arg(long)]
        account_state: String,

        /// ID of the backup to extract (StrEncoded<BackupId>)
        #[arg(long)]
        backup_id: String,

        /// Output file path for the extracted backup ciphertext
        #[arg(short, long, default_value = "extracted_backup.json")]
        output: PathBuf,
    },

    /// Convert EmailCertToken to JSON format
    EmailCertTokenToJson {
        /// EmailCertToken
        #[arg(long)]
        token_str: String,

        /// Output file path for the JSON token
        #[arg(short, long, default_value = "email_cert_token.json")]
        output: PathBuf,
    },

    /// Compute commitment hash for an OffchainSecret
    ComputeCommitment {
        /// Input file containing the serialized OffchainSecret
        #[arg(long)]
        input: PathBuf,
    },

    /// Encode a NodeId as StrEncoded<NodeId>
    EncodeNodeId {
        /// NodeId string to encode (e.g., "node:node1")
        node_id: String,
    },

    /// Create upload guardian share request for reconstruction endpoint
    CreateUploadGuardianShareRequest {
        /// Account ID (StrEncoded<AccountId>)
        #[arg(long)]
        account_id: String,

        /// Backup ID (StrEncoded<BackupId>)
        #[arg(long)]
        backup_id: String,

        /// Guardian share (StrEncoded<GuardianShare>)
        #[arg(long)]
        guardian_share: String,

        /// Output file path for the request JSON
        #[arg(short, long, default_value = "upload_guardian_share_request.json")]
        output: PathBuf,
    },

    /// Create get guardian shares request for reconstruction endpoint
    CreateGetGuardianSharesRequest {
        /// Account ID (StrEncoded<AccountId>)
        #[arg(long)]
        account_id: String,

        /// Backup ID (StrEncoded<BackupId>)
        #[arg(long)]
        backup_id: String,

        /// Output file path for the request JSON
        #[arg(short, long, default_value = "get_guardian_shares_request.json")]
        output: PathBuf,
    },

    /// Setup recovery for an account with guardians
    SetupRecovery {
        /// Path to account secrets file (JSON)
        #[arg(long)]
        account_secrets: PathBuf,

        /// Paths to guardian account files (JSON), can be specified multiple times
        #[arg(long)]
        guardians: Vec<PathBuf>,

        /// Threshold number of guardians needed for recovery
        #[arg(short, long)]
        threshold: usize,

        /// Output directory for recovery setup files
        #[arg(short, long, default_value = "recovery_setup")]
        output_dir: PathBuf,
    },

    /// Initiate recovery after reconstructing RIK from offchain nodes
    InitiateRecovery {
        /// Path to account state file
        #[arg(long)]
        account_state: PathBuf,

        /// Path to Recovery Initiation Key (RIK) file
        #[arg(long)]
        rik: PathBuf,

        /// Account ID (StrEncoded<AccountId>)
        #[arg(long)]
        account_id: String,

        /// Output file path for recovery request
        #[arg(short, long, default_value = "recovery_request.json")]
        output: PathBuf,
    },

    /// Guardian processes recovery request and provides share
    GuardianProcessRecovery {
        /// Path to guardian secrets file (JSON)
        #[arg(long)]
        guardian_secrets: PathBuf,

        /// Path to requester's account state file
        #[arg(long)]
        requester_state: PathBuf,

        /// Requester's account ID (encoded string)
        #[arg(long)]
        requester_account_id: String,

        /// Output file path for guardian share
        #[arg(short, long, default_value = "guardian_share.json")]
        output: PathBuf,
    },

    /// Complete recovery using all guardian shares
    CompleteRecovery {
        /// Path to recovery secrets file (from initiate recovery)
        #[arg(long)]
        recovery_secrets: PathBuf,

        /// Paths to guardian share files, can be specified multiple times
        #[arg(long)]
        guardian_shares: Vec<PathBuf>,

        /// Path to account state file (contains enc_msk)
        #[arg(long)]
        account_state: PathBuf,

        /// Output file path for recovered MSK
        #[arg(short, long, default_value = "recovered_msk.json")]
        output: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::CreateBackupCiphertext {
            owner_account_state_str,
            owner_msk_str,
            owner_account_id_str,
            guardian_accounts_str,
            threshold,
            secret_data,
            name,
            description,
            output,
        } => {
            backup::create_backup_ciphertext(backup::CreateBackupParams {
                owner_account_state_str,
                owner_msk_str,
                owner_account_id_str,
                guardian_accounts_str,
                threshold,
                secret_data,
                name,
                description,
                output,
            })?;
        }

        Commands::GuardianDecryptShare {
            guardian_account_state_str,
            guardian_msk_str,
            guardian_account_id_str,
            owner_account_id,
            backup_ciphertext_str,
            output,
        } => {
            backup::guardian_decrypt_share(
                guardian_account_state_str,
                guardian_msk_str,
                guardian_account_id_str,
                owner_account_id,
                backup_ciphertext_str,
                output,
            )?;
        }

        Commands::GuardianSendShare {
            secret_share_str,
            owner_account_state_str,
            output,
        } => {
            backup::guardian_send_share(secret_share_str, owner_account_state_str, output)?;
        }

        Commands::VerifyGuardianShare {
            guardian_share_str,
            backup_ciphertext_str,
            output,
        } => {
            backup::verify_guardian_share(guardian_share_str, backup_ciphertext_str, output)?;
        }

        Commands::RecoverFromBackup {
            owner_account_state_str,
            owner_msk_str,
            owner_account_id_str,
            backup_ciphertext_str,
            guardian_shares_str,
            output,
        } => {
            backup::recover_from_backup(
                owner_account_state_str,
                owner_msk_str,
                owner_account_id_str,
                backup_ciphertext_str,
                guardian_shares_str,
                output,
            )?;
        }

        Commands::AddBackupToAccount {
            owner_account_state_str,
            owner_msk_str,
            owner_account_id_str,
            backup_ciphertext,
            output,
        } => {
            account::add_backup_to_account(
                owner_account_state_str,
                owner_msk_str,
                owner_account_id_str,
                backup_ciphertext,
                output,
            )?;
        }

        Commands::CreateGetSecretShareRequest {
            email_cert_token,
            vdrf_evaluation,
            output,
        } => {
            association::create_get_secret_share_request_command(
                email_cert_token,
                vdrf_evaluation,
                output,
            )?;
        }

        Commands::ReconstructRik {
            msk_records,
            rik_file,
            output,
        } => {
            association::reconstruct_rik_command(msk_records, rik_file, output)?;
        }

        Commands::CombineVdrfEvaluations {
            public_key,
            evaluations,
            output,
            input_data,
        } => {
            vdrf::combine_vdrf_evaluations_command(public_key, evaluations, output, input_data)?;
        }

        Commands::GenerateKeypair {
            keypair_output,
            public_key_output,
        } => {
            account::generate_keypair(keypair_output, public_key_output)?;
        }

        Commands::GenerateEmailCert {
            email,
            user_public_key,
            operator_private_key,
            output,
        } => {
            association::generate_email_cert_command(
                email,
                user_public_key,
                operator_private_key,
                output,
            )?;
        }

        Commands::GenerateEmailCertToken {
            certificate,
            node_id,
            user_private_key,
            output,
        } => {
            association::generate_email_cert_token_command(
                certificate,
                node_id,
                user_private_key,
                output,
            )?;
        }

        Commands::CreateEncryptedMsk { threshold, output } => {
            association::create_encrypted_msk_command(threshold, output)?;
        }

        Commands::GenerateUploadMskRequest {
            certificate,
            encrypted_msk,
            node_id,
            vrf_eval_email,
            output,
        } => {
            association::generate_upload_msk_request_command(
                certificate,
                encrypted_msk,
                node_id,
                vrf_eval_email,
                output,
            )?;
        }

        Commands::ExtractKeys {
            encrypted_msk,
            private_key_output,
            public_key_output,
        } => {
            association::extract_keys(encrypted_msk, private_key_output, public_key_output)?;
        }

        Commands::GenerateAccountAllocation { output } => {
            account::generate_account_allocation(output)?;
        }

        Commands::GenerateAccountUpdate {
            initial_allocation,
            output,
        } => {
            account::generate_account_update(initial_allocation, output)?;
        }

        Commands::GenerateVdrfTestSetup {
            num_nodes,
            threshold,
            node_ids,
            output,
        } => {
            vdrf::generate_vdrf_test_setup(num_nodes, threshold, node_ids, output)?;
        }

        Commands::ExtractBackupFromAccount {
            account_state,
            backup_id,
            output,
        } => {
            account::extract_backup_from_account(account_state, backup_id, output)?;
        }

        Commands::EmailCertTokenToJson { token_str, output } => {
            association::email_cert_token_to_json(token_str, output)?;
        }

        Commands::ComputeCommitment { input } => {
            utils::compute_commitment(input)?;
        }

        Commands::EncodeNodeId { node_id } => {
            utils::encode_node_id(node_id)?;
        }

        Commands::CreateUploadGuardianShareRequest {
            account_id,
            backup_id,
            guardian_share,
            output,
        } => {
            reconstruction::create_upload_guardian_share_request_command(
                account_id,
                backup_id,
                guardian_share,
                output,
            )?;
        }

        Commands::CreateGetGuardianSharesRequest {
            account_id,
            backup_id,
            output,
        } => {
            reconstruction::create_get_guardian_shares_request_command(
                account_id, backup_id, output,
            )?;
        }

        Commands::SetupRecovery {
            account_secrets,
            guardians,
            threshold,
            output_dir,
        } => {
            account::setup_recovery_command(account_secrets, guardians, threshold, output_dir)?;
        }

        Commands::InitiateRecovery {
            account_state,
            rik,
            account_id,
            output,
        } => {
            account::initiate_recovery_command(account_state, rik, account_id, output)?;
        }

        Commands::GuardianProcessRecovery {
            guardian_secrets,
            requester_state,
            requester_account_id,
            output,
        } => {
            account::guardian_process_recovery_command(
                guardian_secrets,
                requester_state,
                requester_account_id,
                output,
            )?;
        }

        Commands::CompleteRecovery {
            recovery_secrets,
            guardian_shares,
            account_state,
            output,
        } => {
            account::complete_recovery_command(
                recovery_secrets,
                guardian_shares,
                account_state,
                output,
            )?;
        }
    }

    Ok(())
}
