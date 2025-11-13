# This demo script is probably outdated. Please refer to the java test for demo.

#!/bin/bash


# This script tests the complete VDRF workflow including share generation, 
# initialization, evaluation, MSK upload, secret share retrieval, and MSK reconstruction

set -e

CONTRACT_ADDRESS="02b5d9431f00d28b49987ff543527b2e5eee03554b"
# Define number of nodes
NUM_NODES=3
# Define node IDs (using string identifiers instead of numbers)
NODE_IDS=("node1" "node2" "node3")
# Define execution engine URLs for each node
EXECUTION_ENGINE_URLS=(
    "http://localhost:8001"  # (node1)
    "http://localhost:8002"  # (node2) 
    "http://localhost:8003"  # (node3)
)
EMAIL="test@example.com"
# Define reusable paths - resolve absolute paths from relative paths
SWAFE_KEYS_DIR="$(realpath .)"
LIB_DIR="$(realpath ../lib)"

echo "🚀 Starting Complete VDRF Workflow Test"
echo "Contract Address: $CONTRACT_ADDRESS"
echo "Email: $EMAIL"

## swafe operator ##
SWAFE_PRIVATE_KEY=$(cat $SWAFE_KEYS_DIR/swafe_private_key.txt)

# Step 2: Generate VDRF shares with node IDs
echo "🔐 Step 2: Generating VDRF shares..."
(cd $LIB_DIR && cargo run --bin main -- generate-vdrf-shares \
  --node-ids "${NODE_IDS[*]}" \
  --output $SWAFE_KEYS_DIR/vdrf_shares.json)

if [ ! -f "$SWAFE_KEYS_DIR/vdrf_shares.json" ]; then
    echo "❌ Failed to generate VDRF shares"
    exit 1
fi

echo "✅ VDRF shares generated successfully"

# Step 2.5: Sign VDRF shares with node operator keys
echo "🔏 Step 2.5: Signing VDRF shares with node operator keys..."

# First, generate node operator keypairs if they don't exist
for i in "${!NODE_IDS[@]}"; do
    NODE_ID="${NODE_IDS[$i]}"
    NODE_NUM=$((i + 1))
    
    # Generate keypair for this node operator if it doesn't exist
    if [ ! -f "$SWAFE_KEYS_DIR/node_${NODE_NUM}_private_key.txt" ]; then
        echo "Generating keypair for node operator $NODE_NUM..."
        (cd $LIB_DIR && cargo run --bin main -- generate-keypair \
          -s "$SWAFE_KEYS_DIR/node_${NODE_NUM}_private_key.txt" \
          -p "$SWAFE_KEYS_DIR/node_${NODE_NUM}_public_key.txt")
    fi
done

# Sign each share with the corresponding node operator's private key
for i in "${!NODE_IDS[@]}"; do
    NODE_ID="${NODE_IDS[$i]}"
    NODE_NUM=$((i + 1))
    
    echo "Signing VDRF share for node $NODE_ID..."
    
    # Extract the unsigned share for this node
    UNSIGNED_SHARE=$(jq -r ".shares[\"$NODE_ID\"]" $SWAFE_KEYS_DIR/vdrf_shares.json)
    NODE_PRIVATE_KEY=$(cat $SWAFE_KEYS_DIR/node_${NODE_NUM}_private_key.txt)
    
    # Sign the share using CLI
    (cd $LIB_DIR && cargo run --bin main -- sign-vdrf-share-info \
      --share-info "$UNSIGNED_SHARE" \
      --node-private-key "$NODE_PRIVATE_KEY" \
      --output $SWAFE_KEYS_DIR/signed_share_$NODE_ID.txt)
    
    echo "✅ Share signed for node $NODE_ID"
done

echo "✅ All VDRF shares signed successfully"

# Step 3: Initialize VDRF nodes
echo "🔧 Step 3: Initializing VDRF nodes with signed shares..."

# Initialize each node with its signed share
for i in "${!NODE_IDS[@]}"; do
    NODE_ID="${NODE_IDS[$i]}"
    echo "Initializing node $NODE_ID..."
    
    # Get execution engine URL for this node
    EXECUTION_ENGINE_URL="${EXECUTION_ENGINE_URLS[$i]}"
    echo "Using execution engine: $EXECUTION_ENGINE_URL"
    
    # Read signed share directly from file
    SIGNED_SHARE_HEX=$(cat $SWAFE_KEYS_DIR/signed_share_$NODE_ID.txt)
    
    # Initialize node via HTTP with signed share
    INIT_RESPONSE=$(curl -X POST \
      "$EXECUTION_ENGINE_URL/offchain/$CONTRACT_ADDRESS/vdrf/init" \
      -H "Content-Type: text/plain" \
      -d "$SIGNED_SHARE_HEX" \
      -w "Status: %{http_code}\n" \
      -s)
    
    echo "Node $NODE_ID initialized: $INIT_RESPONSE"
done

echo "✅ All VDRF nodes initialized"

## user ##


# Step 4: Generate encrypted MSK and extract user keys
echo "👤 Step 4: Setting up EmailCert workflow..."

# Generate encrypted MSK (user signing key is generated internally)
(cd $LIB_DIR && cargo run --bin main -- create-encrypted-msk \
  --output $SWAFE_KEYS_DIR/encrypted_msk.txt)

# Extract user signing keys from the generated MSK
(cd $LIB_DIR && cargo run --bin main -- extract-keys \
  --encrypted-msk "$(cat $SWAFE_KEYS_DIR/encrypted_msk.txt)" \
  --private-key-output $SWAFE_KEYS_DIR/user_private_key.txt \
  --public-key-output $SWAFE_KEYS_DIR/user_public_key.txt)

# Generate email certificate 
USER_PUBLIC_KEY=$(cat $SWAFE_KEYS_DIR/user_public_key.txt)
SWAFE_PRIVATE_KEY=$(cat $SWAFE_KEYS_DIR/swafe_private_key.txt)

(cd $LIB_DIR && cargo run --bin main -- generate-email-cert \
  -e "$EMAIL" \
  -u "$USER_PUBLIC_KEY" \
  -k "$SWAFE_PRIVATE_KEY" \
  -o $SWAFE_KEYS_DIR/email_cert.txt)

# cd $SWAFE_KEYS_DIR

echo "✅ EmailCert setup completed"

# Step 5: Test VDRF evaluation with each node
echo "🔍 Step 5: Testing VDRF evaluation..."

EVALUATIONS=()
for i in "${!NODE_IDS[@]}"; do
    NODE_ID="${NODE_IDS[$i]}"
    echo "Testing evaluation with node $NODE_ID..."
    
    # Get execution engine URL for this node
    EXECUTION_ENGINE_URL="${EXECUTION_ENGINE_URLS[$i]}"
    echo "Using execution engine: $EXECUTION_ENGINE_URL"
    
    # Generate email certificate token for this node
    EMAIL_CERT=$(cat $SWAFE_KEYS_DIR/email_cert.txt)
    USER_PRIVATE_KEY=$(cat $SWAFE_KEYS_DIR/user_private_key.txt)
    
    (cd $LIB_DIR && cargo run --bin main -- generate-email-cert-token \
      -c "$EMAIL_CERT" \
      -n "$NODE_ID" \
      -k "$USER_PRIVATE_KEY" \
      -o $SWAFE_KEYS_DIR/email_cert_token_$NODE_ID.txt)
    
    # Send evaluation request
    TOKEN=$(cat $SWAFE_KEYS_DIR/email_cert_token_$NODE_ID.txt)
    
    EVALUATION=$(curl -X POST \
      "$EXECUTION_ENGINE_URL/offchain/$CONTRACT_ADDRESS/vdrf/eval/$NODE_ID" \
      -H "Content-Type: text/plain" \
      -d "$TOKEN" \
      -s)
    
    EVALUATIONS+=("$EVALUATION")
    echo "Node $NODE_ID evaluation: $EVALUATION"
done

echo "✅ VDRF evaluations completed"

# Step 6: Combine VDRF evaluations
echo "🔗 Step 6: Combining VDRF evaluations..."

VDRF_PUBLIC_KEY=$(jq -r '.public_key' $SWAFE_KEYS_DIR/vdrf_shares.json)

# Create evaluation arguments for CLI
EVAL_ARGS=""
for i in "${!EVALUATIONS[@]}"; do
    NODE_ID="${NODE_IDS[$i]}"
    EVAL_ARGS="$EVAL_ARGS --evaluations $NODE_ID:${EVALUATIONS[$i]}"
done

(cd $LIB_DIR && cargo run --bin main -- combine-vdrf-evaluations \
  --input-data "$EMAIL" \
  --public-key "$VDRF_PUBLIC_KEY" \
  $EVAL_ARGS \
  --output $SWAFE_KEYS_DIR/vdrf_result.txt)

echo "✅ VDRF evaluations combined"

# Step 7: Upload encrypted MSK to nodes
echo "🔐 Step 7: Uploading encrypted MSK..."

# Extract email tag from VDRF result
echo "📋 Checking VDRF result file content:"
cat $SWAFE_KEYS_DIR/vdrf_result.txt

EMAIL_TAG=$(grep "random_output:" $SWAFE_KEYS_DIR/vdrf_result.txt | cut -d':' -f2)
VDRF_EVALUATION=$(grep "evaluation:" $SWAFE_KEYS_DIR/vdrf_result.txt | cut -d':' -f2)

if [ -z "$EMAIL_TAG" ]; then
    echo "❌ Failed to extract email tag from VDRF result"
    echo "VDRF result file content:"
    cat $SWAFE_KEYS_DIR/vdrf_result.txt
    exit 1
fi

if [ -z "$VDRF_EVALUATION" ]; then
    echo "❌ Failed to extract VDRF evaluation from VDRF result"
    echo "VDRF result file content:"
    cat $SWAFE_KEYS_DIR/vdrf_result.txt
    exit 1
fi

echo "Email tag: $EMAIL_TAG"
echo "VDRF evaluation: $VDRF_EVALUATION"

# Upload MSK to each node
for i in "${!NODE_IDS[@]}"; do
    NODE_ID="${NODE_IDS[$i]}"
    echo "Uploading MSK to node $NODE_ID..."
    
    # Get execution engine URL for this node
    EXECUTION_ENGINE_URL="${EXECUTION_ENGINE_URLS[$i]}"
    echo "Using execution engine: $EXECUTION_ENGINE_URL"
    
    EMAIL_CERT=$(cat $SWAFE_KEYS_DIR/email_cert.txt)
    ENCRYPTED_MSK=$(cat $SWAFE_KEYS_DIR/encrypted_msk.txt)
    
    # Generate upload MSK request
    (cd $LIB_DIR && cargo run --bin main -- generate-upload-msk-request \
      --certificate "$EMAIL_CERT" \
      --encrypted-msk "$ENCRYPTED_MSK" \
      --node-id "$NODE_ID" \
      --vrf-eval-email "$VDRF_EVALUATION" \
      --output $SWAFE_KEYS_DIR/upload_msk_request_$NODE_ID.txt)
    
    # Upload to contract
    UPLOAD_REQUEST=$(cat $SWAFE_KEYS_DIR/upload_msk_request_$NODE_ID.txt)
    
    UPLOAD_RESPONSE=$(curl -X POST \
      "$EXECUTION_ENGINE_URL/offchain/$CONTRACT_ADDRESS/association/upload-msk" \
      -H "Content-Type: text/plain" \
      -d "$UPLOAD_REQUEST" \
      -w "Status: %{http_code}\n" \
      -s)
    
    echo "MSK uploaded to node $NODE_ID: \n $UPLOAD_RESPONSE"
done

echo "✅ MSK upload completed"

# Step 8: MSK Recovery Workflow - Secret Share Retrieval
echo "🔄 Step 8: Retrieving secret shares for MSK reconstruction..."

MSK_RECORD_FILES=()
for i in "${!NODE_IDS[@]}"; do
    NODE_ID="${NODE_IDS[$i]}"
    echo "Retrieving secret share from node $NODE_ID..."
    
    # Get execution engine URL for this node
    EXECUTION_ENGINE_URL="${EXECUTION_ENGINE_URLS[$i]}"
    echo "Using execution engine: $EXECUTION_ENGINE_URL"
    
    # Get email cert token for this node
    EMAIL_CERT_TOKEN=$(cat $SWAFE_KEYS_DIR/email_cert_token_$NODE_ID.txt)
    
    # Create GetSecretShareRequest using CLI
    (cd $LIB_DIR && cargo run --bin main -- create-get-secret-share-request \
      --email-cert-token "$EMAIL_CERT_TOKEN" \
      --vdrf-evaluation "$VDRF_EVALUATION" \
      --output $SWAFE_KEYS_DIR/get_secret_share_request_$NODE_ID.txt)
    
    # Send request to contract to retrieve secret share
    GET_REQUEST=$(cat $SWAFE_KEYS_DIR/get_secret_share_request_$NODE_ID.txt)
    
    MSK_RECORD=$(curl -X POST \
      "$EXECUTION_ENGINE_URL/offchain/$CONTRACT_ADDRESS/association/get-ss" \
      -H "Content-Type: text/plain" \
      -d "$GET_REQUEST" \
      -s)
    
    # Save MSK record to file
    echo "$MSK_RECORD" > $SWAFE_KEYS_DIR/msk_record_node_$NODE_ID.txt
    MSK_RECORD_FILES+=("$SWAFE_KEYS_DIR/msk_record_node_$NODE_ID.txt")
    
    echo "Secret share retrieved from node $NODE_ID "
done

echo "✅ Secret share retrieval completed"

# Step 8: Reconstruct MSK from collected records
echo "� Step 9: Reconstructing MSK from secret shares..."

# Build MSK record arguments for CLI
MSK_ARGS=""
for FILE in "${MSK_RECORD_FILES[@]}"; do
    MSK_ARGS="$MSK_ARGS --msk-records $FILE"
done

(cd $LIB_DIR && cargo run --bin main -- reconstruct-msk \
  $MSK_ARGS \
  --output $SWAFE_KEYS_DIR/reconstructed_msk.txt)



echo ""
echo "🎉 Complete VDRF Workflow Test Completed Successfully!"
echo ""
echo "Summary of generated files:"
echo "- vdrf_shares.json: VDRF share configuration (unsigned shares)"
echo "- signed_share_*.txt: Individual signed VDRF shares per node"
echo "- node_*_private_key.txt / node_*_public_key.txt: Node operator keypairs"
echo "- user_private_key.txt / user_public_key.txt: User keypair"
echo "- email_cert.txt: Email certificate"
echo "- email_cert_token_*.txt: Node-specific email tokens"
echo "- vdrf_result.txt: Combined VDRF evaluation result"
echo "- encrypted_msk.txt: Encrypted master secret key"
echo "- upload_msk_request_*.txt: MSK upload requests per node"
echo "- get_secret_share_request_*.txt: Secret share retrieval requests"
echo "- msk_record_node_*.txt: Secret shares from each node"
echo "- reconstructed_msk.txt: Reconstructed MSK"
