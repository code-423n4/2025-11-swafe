use std::fs;
use std::path::PathBuf;

use anyhow::Result;
use rand::thread_rng;
use swafe_api::association::{get_secret_share, upload_msk};
use swafe_lib::association::{Association, EncapsulatedMsk, MskRecord, RikSecretData};
use swafe_lib::crypto::sig::{SigningKey, VerificationKey};
use swafe_lib::crypto::{EmailCert, EmailCertToken, EmailCertificate, VdrfEvaluation};
use swafe_lib::encode::{self, StrEncoded};
use swafe_lib::types::RecoveryInitiationKey;
use swafe_lib::NodeId;

use crate::commands::utils::{load_json_file, write_json_output, write_output};

/// Generate email certificate from email, user public key and operator secret key
pub fn generate_email_cert(
    email: String,
    user_public_key: VerificationKey,
    operator_secret_key: SigningKey,
) -> Result<EmailCertificate, anyhow::Error> {
    let mut rng = thread_rng();
    let certificate = EmailCert::issue(&mut rng, &operator_secret_key, &user_public_key, email);
    Ok(certificate)
}

pub fn generate_email_cert_command(
    email: String,
    user_public_key: String,
    operator_private_key: String,
    output: PathBuf,
) -> Result<()> {
    let user_public_key_parsed: VerificationKey = StrEncoded::try_from(user_public_key.as_str())
        .map_err(|e| anyhow::anyhow!("Failed to decode user public key: {}", e))?
        .0;
    let operator_secret_key: SigningKey = StrEncoded::try_from(operator_private_key.as_str())
        .map_err(|e| anyhow::anyhow!("Failed to decode operator private key: {}", e))?
        .0;

    let certificate =
        generate_email_cert(email.clone(), user_public_key_parsed, operator_secret_key)?;

    write_output(certificate, &output)?;

    Ok(())
}

pub fn generate_email_cert_token(
    certificate: EmailCertificate,
    node_id_str: String,
    user_secret_key: SigningKey,
) -> Result<EmailCertToken> {
    let mut rng = thread_rng();

    let node_id: NodeId = node_id_str
        .parse()
        .map_err(|e| anyhow::anyhow!("Failed to parse NodeId: {}", e))?;

    let token = EmailCert::token(&mut rng, &certificate, &user_secret_key, &node_id);

    Ok(token)
}

pub fn generate_email_cert_token_command(
    certificate: String,
    node_id: String,
    user_private_key: String,
    output: PathBuf,
) -> Result<()> {
    let certificate_parsed: EmailCertificate =
        encode::deserialize_str::<EmailCertificate>(&certificate)
            .map_err(|e| anyhow::anyhow!("Failed to decode certificate: {}", e))?;
    let user_secret_key: SigningKey = encode::deserialize_str::<SigningKey>(&user_private_key)
        .map_err(|e| anyhow::anyhow!("Failed to decode user private key: {}", e))?;

    let token = generate_email_cert_token(certificate_parsed, node_id.clone(), user_secret_key)?;

    write_output(token, &output)?;

    Ok(())
}

pub fn create_encrypted_msk_command(threshold: usize, output: PathBuf) -> Result<()> {
    let mut rng = thread_rng();
    let (encapsulated_msk, rik) = Association::create_association(&mut rng, threshold)?;

    // Create JSON output with both encapsulated MSK and RIK for full compatibility
    let output_data = serde_json::json!({
        "encapsulated_msk": encode::serialize_str(&encapsulated_msk)?,
        "recovery_initiation_key": encode::serialize_str(&rik)?,
        "threshold": threshold,
        "success": true,
        "message": format!("Created RIK association with threshold {}", threshold)
    });

    fs::write(&output, serde_json::to_string_pretty(&output_data)?)?;
    println!(
        "Created RIK association with threshold {} and saved to {}",
        threshold,
        output.display()
    );
    Ok(())
}

pub fn generate_upload_msk_request(
    certificate: EmailCertificate,
    msk: EncapsulatedMsk,
    node_id_str: String,
    vdrf_evaluation: VdrfEvaluation,
) -> Result<upload_msk::Request> {
    let node_id: NodeId = node_id_str
        .parse()
        .map_err(|e| anyhow::anyhow!("Failed to parse NodeId: {}", e))?;

    let user_secret_key = msk.user_keypair().clone();
    let association = Association::new(msk, certificate.clone(), user_secret_key.clone());

    let mut rng = thread_rng();
    let association_request = association.gen_association_request(&mut rng, &node_id)?;

    // Generate email certificate token for this node
    let token = EmailCert::token(&mut rng, &certificate, &user_secret_key, &node_id);

    // Create the full AssociationRequest structure
    let full_request = upload_msk::Request {
        token: StrEncoded(token),
        vdrf_eval: StrEncoded(vdrf_evaluation),
        association: StrEncoded(association_request),
    };

    Ok(full_request)
}

pub fn generate_upload_msk_request_command(
    certificate: String,
    encrypted_msk: String,
    node_id: String,
    vrf_eval_email: String,
    output: PathBuf,
) -> Result<()> {
    let certificate_parsed: EmailCertificate =
        encode::deserialize_str::<EmailCertificate>(&certificate)
            .map_err(|e| anyhow::anyhow!("Failed to decode certificate: {}", e))?;
    let encrypted_msk_parsed: EncapsulatedMsk =
        encode::deserialize_str::<EncapsulatedMsk>(&encrypted_msk)
            .map_err(|e| anyhow::anyhow!("Failed to decode encrypted MSK: {}", e))?;
    let vdrf_evaluation: VdrfEvaluation =
        encode::deserialize_str::<VdrfEvaluation>(&vrf_eval_email)
            .map_err(|e| anyhow::anyhow!("Failed to decode VDRF evaluation: {}", e))?;

    let request = generate_upload_msk_request(
        certificate_parsed,
        encrypted_msk_parsed,
        node_id.clone(),
        vdrf_evaluation,
    )?;

    write_json_output(request, &output)?;

    Ok(())
}

pub fn extract_keys(
    encrypted_msk: String,
    private_key_output: PathBuf,
    public_key_output: PathBuf,
) -> Result<()> {
    let msk_result: EncapsulatedMsk = encode::deserialize_str::<EncapsulatedMsk>(&encrypted_msk)
        .map_err(|e| anyhow::anyhow!("Failed to decode encrypted MSK: {}", e))?;

    let user_signing_key = msk_result.user_keypair();

    write_output(user_signing_key.clone(), &private_key_output)?;
    write_output(user_signing_key.verification_key(), &public_key_output)?;

    Ok(())
}

pub fn create_get_secret_share_request(
    token: EmailCertToken,
    vdrf_eval: VdrfEvaluation,
) -> Result<get_secret_share::Request> {
    let request = get_secret_share::Request {
        vdrf_eval: StrEncoded(vdrf_eval),
        token: StrEncoded(token),
    };

    Ok(request)
}

pub fn create_get_secret_share_request_command(
    email_cert_token: String,
    vdrf_evaluation: String,
    output: PathBuf,
) -> Result<()> {
    let token: EmailCertToken = encode::deserialize_str::<EmailCertToken>(&email_cert_token)
        .map_err(|e| anyhow::anyhow!("Failed to decode email cert token: {}", e))?;
    let vdrf_eval: VdrfEvaluation = encode::deserialize_str::<VdrfEvaluation>(&vdrf_evaluation)
        .map_err(|e| anyhow::anyhow!("Failed to decode VDRF evaluation: {}", e))?;

    let request = create_get_secret_share_request(token, vdrf_eval)?;

    write_json_output(request, &output)?;

    Ok(())
}

// Legacy function removed - use new RIK-based recovery system instead

// Legacy command removed - use new RIK-based recovery commands instead

/// Test command: Reconstruct RIK data from association records (for testing purposes)
/// This simulates getting the RIK from offchain nodes and extracting the signing key
/// Note: This is only for testing - real recovery should use the full RIK system
pub fn reconstruct_rik_from_associations(
    msk_records: Vec<(NodeId, MskRecord)>,
    rik: &RecoveryInitiationKey,
) -> Result<RikSecretData> {
    // Use the RIK reconstruction method from the association module
    let rik_data = Association::reconstruct_rik_data(msk_records, rik)?;
    Ok(rik_data)
}

/// Test command: CLI wrapper for RIK reconstruction from associations
pub fn reconstruct_rik_command(
    msk_records: Vec<PathBuf>,
    rik_file: PathBuf,
    output: PathBuf,
) -> Result<()> {
    let mut msk_records_parsed = Vec::new();

    // Parse MSK records
    for (idx, file_path) in msk_records.iter().enumerate() {
        let json: serde_json::Value = load_json_file(file_path)?;

        let record_str = json.get("entry").and_then(|v| v.as_str()).ok_or_else(|| {
            anyhow::anyhow!(
                "JSON missing 'entry' field in file: {}",
                file_path.display()
            )
        })?;

        let msk_record = encode::deserialize_str::<MskRecord>(record_str).map_err(|e| {
            anyhow::anyhow!(
                "Failed to deserialize MSK record from file {}: {}",
                file_path.display(),
                e
            )
        })?;

        // Parse node ID from filename like "msk_record_node_node:node1.txt"
        let filename = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid file path: {}", file_path.display()))?;

        let node_id = if filename.starts_with("msk_record_node_") && filename.ends_with(".txt") {
            let node_part = &filename[16..filename.len() - 4];
            node_part.parse::<NodeId>().map_err(|e| {
                anyhow::anyhow!("Failed to parse node ID from filename {}: {}", filename, e)
            })?
        } else {
            format!("node:node{}", idx + 1)
                .parse::<NodeId>()
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to parse node ID from generated string node:node{}: {}",
                        idx + 1,
                        e
                    )
                })?
        };

        msk_records_parsed.push((node_id, msk_record));
    }

    // Read RIK from file
    // Parse RIK (expect JSON format with recovery_initiation_key field)
    let json: serde_json::Value = load_json_file(&rik_file)?;
    let rik_encoded = json["recovery_initiation_key"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing recovery_initiation_key field in JSON"))?;
    let rik = encode::deserialize_str::<RecoveryInitiationKey>(rik_encoded)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize RIK: {}", e))?;

    // Reconstruct RIK data
    let rik_data = reconstruct_rik_from_associations(msk_records_parsed, &rik)?;

    // Create output in compatible format for testing
    let output_data = serde_json::json!({
        "success": true,
        "message": "Successfully reconstructed RIK data from associations",
        "signing_key": encode::serialize_str(&rik_data.sig_sk)?,
        "msk_secret_share": encode::serialize_str(&rik_data.msk_ss_rik)?,
        "note": "This is partial recovery - for full MSK recovery, use the complete recovery system"
    });

    fs::write(&output, serde_json::to_string_pretty(&output_data)?)?;
    println!(
        "Reconstructed RIK data from associations and saved to {}",
        output.display()
    );
    Ok(())
}

pub fn email_cert_token_to_json(token_str: String, output: PathBuf) -> Result<()> {
    let token: EmailCertToken = encode::deserialize_str::<EmailCertToken>(&token_str)
        .map_err(|e| anyhow::anyhow!("Failed to decode EmailCertToken: {}", e))?;

    write_json_output(token, &output)?;

    Ok(())
}
