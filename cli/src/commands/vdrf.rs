use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use anyhow::Result;
use rand::{thread_rng, Rng};
use swafe_api;
use swafe_lib::association::EmailInput;
use swafe_lib::crypto::vdrf::{Vdrf, VdrfEvaluationShare, VdrfPublicKey, VdrfSecretKey};
use swafe_lib::encode::{self, StrEncoded};
use swafe_lib::{NodeId, SwafeError};

use crate::commands::utils::{
    write_json_output, NodeTestConfig, VdrfEvaluationResult, VdrfTestSetup,
};

pub fn combine_vdrf_evaluations(
    public_key: VdrfPublicKey,
    partial_evaluations: Vec<(NodeId, VdrfEvaluationShare)>,
    input_data: String,
) -> Result<VdrfEvaluationResult, SwafeError> {
    let email_input: EmailInput = input_data.parse()?;

    let combined_evaluation =
        Vdrf::combine::<_, 32>(&public_key, &email_input, &partial_evaluations)?;

    let random_output: [u8; 32] =
        Vdrf::verify(&public_key, &email_input, combined_evaluation.clone())?;

    let evaluation_str = encode::serialize_str(&combined_evaluation)
        .map_err(|e| SwafeError::SerializationError(e.to_string()))?;

    Ok(VdrfEvaluationResult {
        input: input_data,
        evaluation: evaluation_str,
        random_output: hex::encode(random_output),
    })
}

pub fn combine_vdrf_evaluations_command(
    public_key: String,
    partial_evals: Vec<String>,
    output: PathBuf,
    input_data: String,
) -> Result<()> {
    let public_key_parsed: VdrfPublicKey = encode::deserialize_str(&public_key)
        .map_err(|e| anyhow::anyhow!("Failed to decode VDRF public key: {}", e))?;

    let mut partial_evaluations = Vec::new();

    for eval_arg in &partial_evals {
        let eq_pos = eval_arg.find('=').ok_or_else(|| {
            anyhow::anyhow!("Invalid evaluation format. Expected 'node_id=evaluation'")
        })?;

        let node_id_str = &eval_arg[..eq_pos];
        let evaluation_str = &eval_arg[eq_pos + 1..];

        let node_id: NodeId = node_id_str
            .parse()
            .map_err(|e| anyhow::anyhow!("Failed to parse NodeId: {}", e))?;

        let evaluation_share: VdrfEvaluationShare = encode::deserialize_str(evaluation_str)
            .map_err(|e| anyhow::anyhow!("Failed to decode VDRF evaluation share: {}", e))?;

        partial_evaluations.push((node_id.clone(), evaluation_share));
    }

    if partial_evals.is_empty() {
        return Err(anyhow::anyhow!("No evaluations provided"));
    }

    let result = combine_vdrf_evaluations(public_key_parsed, partial_evaluations, input_data)?;

    let output_content = format!(
        "# VDRF Combination Result\n\
         # Input: {}\n\
         # Combined Evaluation: {}\n\
         # Random Output: {}\n\
         \n\
         input:{}\n\
         evaluation:{}\n\
         random_output:{}\n",
        result.input,
        result.evaluation,
        result.random_output,
        result.input,
        result.evaluation,
        result.random_output
    );

    fs::write(&output, output_content)
        .map_err(|e| anyhow::anyhow!("Failed to write output file: {}", e))?;

    Ok(())
}

pub fn generate_vdrf_test_setup(
    num_nodes: usize,
    threshold: usize,
    node_ids: Option<Vec<String>>,
    output: PathBuf,
) -> Result<()> {
    let mut rng = thread_rng();

    let node_id_labels =
        node_ids.unwrap_or_else(|| (1..=num_nodes).map(|i| format!("node{}", i)).collect());

    if node_id_labels.len() != num_nodes {
        return Err(anyhow::anyhow!(
            "Number of node IDs ({}) doesn't match num_nodes ({})",
            node_id_labels.len(),
            num_nodes
        ));
    }

    if threshold == 0 || threshold > num_nodes {
        return Err(anyhow::anyhow!(
            "Invalid threshold {}. Must be between 1 and {} (num_nodes)",
            threshold,
            num_nodes
        ));
    }

    let vdrf_secret_key = VdrfSecretKey::gen(&mut rng, threshold);
    let vdrf_public_key = vdrf_secret_key.public_key();
    let _vdrf_public_key_str = encode::serialize_str(&vdrf_public_key)?;

    let mut node_configs = Vec::new();
    let mut signed_shares = HashMap::new();

    for label in node_id_labels.iter() {
        use swafe_lib::crypto::sig::SigningKey;
        let node_signing_key = SigningKey::gen(&mut rng);
        let node_public_key = node_signing_key.verification_key();

        let node_id: NodeId = format!("node:{}", label).parse().unwrap();

        let config = NodeTestConfig {
            node_id: node_id.to_string(),
            public_key_str: StrEncoded(node_public_key),
        };
        node_configs.push(config);

        let secret_share = vdrf_secret_key
            .deal(&node_id)
            .map_err(|e| anyhow::anyhow!("Failed to generate share for {}: {:?}", label, e))?;

        // Generate randomizer for hiding the secret
        let randomizer: [u8; 32] = rng.gen();

        let offchain_secret = swafe_api::init::OffchainSecret {
            public_key: vdrf_public_key.clone(),
            secret_share,
            randomizer,
        };

        signed_shares.insert(node_id.to_string(), StrEncoded(offchain_secret));
    }

    let configs = VdrfTestSetup {
        vdrf_public_key: StrEncoded(vdrf_public_key),
        signed_shares,
        node_configs,
        num_nodes,
    };

    write_json_output(configs, &output)?;

    Ok(())
}
