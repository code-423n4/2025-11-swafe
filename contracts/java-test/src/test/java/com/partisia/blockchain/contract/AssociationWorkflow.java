package com.partisia.blockchain.contract;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.partisiablockchain.container.execution.protocol.HttpRequestData;
import com.partisiablockchain.container.execution.protocol.HttpResponseData;
import com.partisiablockchain.language.testenvironment.executionengine.TestExecutionEngine;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Association workflow helper that handles complete association operations including VDRF
 * evaluation, MSK operations, key generation, email certificates, association uploads, and secret
 * share retrieval. Assumes VDRF nodes are already initialized during setup phase. Uses CLI as a
 * serialization library rather than managing complex file operations in Java.
 */
public final class AssociationWorkflow {

  private static final Logger logger = LoggerFactory.getLogger(AssociationWorkflow.class);

  private static com.partisiablockchain.BlockchainAddress swafeAddress;
  private static Map<String, String> mskRecords = new HashMap<>();
  private static KeyManager keyManager = new KeyManager();

  private AssociationWorkflow() {
    // Utility class - no instantiation
  }

  /** Data structure for VDRF node share information */
  public static class VdrfShare {

    public final String nodeId;
    public final String serializedShareStr;

    public VdrfShare(String nodeId, String serializedShareStr) {
      this.nodeId = nodeId;
      this.serializedShareStr = serializedShareStr;
    }
  }

  /** Data structure for VDRF evaluation results */
  public static class VdrfEvaluation {

    public final String nodeId;
    public final String evaluationStr;

    public VdrfEvaluation(String nodeId, String evaluationStr) {
      this.nodeId = nodeId;
      this.evaluationStr = evaluationStr;
    }
  }

  /** Data structure for combined VDRF result */
  public static class VdrfResult {

    public final String combinedEvaluationStr;
    public final String randomOutputStr;

    public VdrfResult(String combinedEvaluationStr, String randomOutputStr) {
      this.combinedEvaluationStr = combinedEvaluationStr;
      this.randomOutputStr = randomOutputStr;
    }
  }

  /** Data structure for MSK workflow components */
  public static class MskAndEmailCert {

    public final String encryptedMskStr;
    public final String rikStr; // Recovery Initiation Key for RIK-based system
    public final String userPrivateKeyStr;
    public final String userPublicKeyStr;
    public final String emailCertStr;

    public MskAndEmailCert(
        String encryptedMskStr,
        String rikStr,
        String userPrivateKeyStr,
        String userPublicKeyStr,
        String emailCertStr) {
      this.encryptedMskStr = encryptedMskStr;
      this.rikStr = rikStr;
      this.userPrivateKeyStr = userPrivateKeyStr;
      this.userPublicKeyStr = userPublicKeyStr;
      this.emailCertStr = emailCertStr;
    }
  }

  /**
   * Initialize AssociationWorkflow with just the SWAFE address Gets VDRF data directly from
   * VdrfSetup which already contains testEngines and nodeIds
   */
  public static void initialize(com.partisiablockchain.BlockchainAddress swafeAddr) {
    swafeAddress = swafeAddr;
    keyManager = new KeyManager();

    logger.debug(
        "AssociationWorkflow initialized with {} nodes and KeyManager",
        VdrfSetup.getNodeIds().length);
  }

  /** Get stored SWAFE address */
  public static com.partisiablockchain.BlockchainAddress getSwafeAddress() {
    if (swafeAddress == null) {
      throw new IllegalStateException("No SWAFE address available. Call initialize() first.");
    }
    return swafeAddress;
  }

  /** Generate email certificate separately */
  public static String generateEmailCertificate(
      String email, String userPublicKeyStr, String swafePrivateKeyStr)
      throws IOException, InterruptedException {
    logger.debug("Generating email certificate...");

    Path outputPath = Path.of("src/test/resources/email_certificate.txt");

    List<String> command =
        CliHelper.buildCommand(
            "generate-email-cert",
            "--email=" + email,
            "--user-public-key=" + userPublicKeyStr,
            "--operator-private-key=" + swafePrivateKeyStr,
            "--output=" + outputPath.toAbsolutePath().toString());

    CliHelper.runCommand(command, "Generating email certificate");

    return Files.readString(outputPath).trim();
  }

  /**
   * Generate MSK and Email certificate with share threshold. The threshold determines how many
   * shares are needed to reconstruct the MSK.
   */
  public static MskAndEmailCert generateMskAndEmailCert(
      String email, String swafePrivateKeyStr, int threshold)
      throws IOException, InterruptedException {
    logger.debug("Generating MSK with threshold {}...", threshold);

    // Step 1: Create encrypted MSK
    Path encryptedMskPath = Path.of("src/test/resources/encrypted_msk.txt");
    List<String> createMskCommand =
        CliHelper.buildCommand(
            "create-encrypted-msk",
            "--threshold=" + String.valueOf(threshold),
            "--output=" + encryptedMskPath.toAbsolutePath().toString());
    CliHelper.runCommand(createMskCommand, "Creating encrypted MSK");

    // Parse JSON response from CLI
    String jsonResponse = Files.readString(encryptedMskPath).trim();
    JsonNode jsonNode = new ObjectMapper().readTree(jsonResponse);

    if (!jsonNode.get("success").asBoolean()) {
      throw new RuntimeException("CLI command failed: " + jsonNode.get("message").asText());
    }

    String encryptedMskStr = jsonNode.get("encapsulated_msk").asText();
    String rikStr = jsonNode.get("recovery_initiation_key").asText();

    // Step 2: Get user keys
    Path privateKeyPath = Path.of("src/test/resources/user_private_key.txt");
    Path publicKeyPath = Path.of("src/test/resources/user_public_key.txt");

    List<String> extractKeysCommand =
        CliHelper.buildCommand(
            "extract-keys",
            "--encrypted-msk=" + encryptedMskStr,
            "--private-key-output=" + privateKeyPath.toAbsolutePath().toString(),
            "--public-key-output=" + publicKeyPath.toAbsolutePath().toString());
    CliHelper.runCommand(extractKeysCommand, "Extracting user keys");

    String userPrivateKeyStr = Files.readString(privateKeyPath).trim();
    String userPublicKeyStr = Files.readString(publicKeyPath).trim();

    // Step 3: Generate email certificate
    String emailCertStr = generateEmailCertificate(email, userPublicKeyStr, swafePrivateKeyStr);

    return new MskAndEmailCert(
        encryptedMskStr, rikStr, userPrivateKeyStr, userPublicKeyStr, emailCertStr);
  }

  /** Workflow to */
  public static AssociationResult executeAssociationWorkflow(
      String email, String swafePrivateKeyStr, int threshold)
      throws IOException, InterruptedException {
    logger.debug("Executing association workflow...");

    // Step 1: Generate MSK workflow data
    logger.debug("Step 1: Generating MSK and email certificate...");
    MskAndEmailCert mskCert = generateMskAndEmailCert(email, swafePrivateKeyStr, threshold);

    // Step 2: Generate email certificate tokens for all nodes in batch
    logger.debug("Step 2: Generating email certificate tokens for all nodes...");
    Map<String, String> emailCertTokens = generateEmailCertTokensForAllNodes(mskCert);

    // Step 3: Perform VDRF evaluations
    logger.debug("Step 3: Performing VDRF evaluations...");
    List<VdrfEvaluation> evaluations = performVdrfEvaluations(emailCertTokens);

    // Step 4: Combine VDRF evaluations
    logger.debug("Step 4: Combining VDRF evaluations...");
    VdrfResult vdrfResult = combineVdrfEvaluations(email, evaluations);

    logger.debug("Association workflow finished successfully!");

    return new AssociationResult(mskCert, vdrfResult);
  }

  /** Data structure for complete association workflow result */
  public static class AssociationResult {

    public final MskAndEmailCert mskData;
    public final VdrfResult vdrfResult;

    public AssociationResult(MskAndEmailCert mskData, VdrfResult vdrfResult) {
      this.mskData = mskData;
      this.vdrfResult = vdrfResult;
    }
  }

  /** Generate email certificate tokens for all nodes using stored data */
  public static Map<String, String> generateEmailCertTokensForAllNodes(MskAndEmailCert mskData)
      throws IOException, InterruptedException {
    String[] nodeIds = VdrfSetup.getNodeIds();
    logger.debug("Generating email certificate tokens for {} nodes...", nodeIds.length);

    Map<String, String> tokens = new HashMap<>();
    for (String nodeId : nodeIds) {
      String token = generateEmailCertToken(mskData, nodeId);
      tokens.put(nodeId, token);
    }

    logger.debug("Generated email certificate tokens for all nodes!");
    return tokens;
  }

  /** Execute complete MSK recovery workflow with new user key pair (no new MSK generation) */
  public static String executeMskRecoveryWorkflow(String email, String swafePrivateKeyStr)
      throws IOException, InterruptedException {
    logger.debug("Executing MSK recovery workflow with new user key pair...");

    // Step 1: Load original user key pair for recovery (from association workflow)
    logger.debug("Step 1: Loading original user key pair for recovery...");
    Path privateKeyPath = Path.of("src/test/resources/user_private_key.txt");
    Path publicKeyPath = Path.of("src/test/resources/user_public_key.txt");

    String userPrivateKey = Files.readString(privateKeyPath).trim();
    String userPublicKey = Files.readString(publicKeyPath).trim();

    // Step 2: Generate only email certificate (no MSK creation)
    logger.debug("Step 2: Generating email certificate for recovery...");
    String emailCertStr = generateEmailCertificate(email, userPublicKey, swafePrivateKeyStr);

    // Step 3: Create recovery data structure (without encrypted MSK)
    MskAndEmailCert recoveryData =
        new MskAndEmailCert(
            null, // No encrypted MSK needed for recovery - will reconstruct from shares
            null, // No RIK needed for recovery
            userPrivateKey,
            userPublicKey,
            emailCertStr);

    // Step 4: Generate email certificate tokens for all nodes
    logger.debug("Step 4: Generating email certificate tokens...");
    Map<String, String> emailCertTokens = generateEmailCertTokensForAllNodes(recoveryData);

    // Step 5: Perform VDRF evaluations for recovery
    logger.debug("Step 5: Performing VDRF evaluations for recovery...");
    List<VdrfEvaluation> evaluations = performVdrfEvaluations(emailCertTokens);

    // Step 6: Combine VDRF evaluations
    logger.debug("Step 6: Combining VDRF evaluations...");
    VdrfResult recoveryVdrfResult = combineVdrfEvaluations(email, evaluations);

    // Step 7: Retrieve secret shares from all nodes
    logger.debug("Step 7: Retrieving secret shares from all nodes...");
    List<String> mskRecordFiles =
        retrieveSecretSharesFromAllNodes(recoveryVdrfResult.combinedEvaluationStr, emailCertTokens);

    // Step 8: Load RIK from original encrypted MSK file
    logger.debug("Step 8: Loading RIK from encrypted MSK file...");
    Path encryptedMskPath = Path.of("src/test/resources/encrypted_msk.txt");
    String encryptedMskJson = Files.readString(encryptedMskPath).trim();
    JsonNode jsonNode = new ObjectMapper().readTree(encryptedMskJson);
    String rikStr = jsonNode.get("recovery_initiation_key").asText();

    // Step 9: Reconstruct RIK data from secret shares
    logger.debug("Step 9: Reconstructing RIK data from secret shares...");
    reconstructMsk(mskRecordFiles, rikStr);

    logger.debug("MSK recovery workflow finished successfully!");
    logger.debug("New user key pair generated for recovery access");
    logger.debug("Original MSK reconstructed from stored secret shares");

    return recoveryVdrfResult.combinedEvaluationStr;
  }

  /** Retrieve secret shares from all nodes in batch */
  public static List<String> retrieveSecretSharesFromAllNodes(
      String vdrfEvaluationStr, Map<String, String> emailCertTokens)
      throws IOException, InterruptedException {
    String[] nodeIds = VdrfSetup.getNodeIds();
    com.partisiablockchain.BlockchainAddress swafeAddress = getSwafeAddress();

    logger.debug("Retrieving secret shares from {} nodes...", nodeIds.length);

    List<String> mskRecordFiles = new ArrayList<>();

    for (String nodeId : nodeIds) {
      String emailCertToken = emailCertTokens.get(nodeId);
      if (emailCertToken == null) {
        throw new RuntimeException(
            "Email cert token not found for node " + nodeId + ". Ensure tokens are provided.");
      }

      logger.debug(
          "Using email cert token for node {}: {}...",
          nodeId,
          emailCertToken.substring(0, Math.min(20, emailCertToken.length())));

      // Create GetSecretShareRequest
      String requestBody = createGetSecretShareRequest(emailCertToken, vdrfEvaluationStr, nodeId);

      // Make HTTP request to retrieve secret share
      HttpRequestData getRequest =
          new HttpRequestData("POST", "/association/get-ss", Map.of(), requestBody);

      TestExecutionEngine engine = getEngineForNode(nodeId);
      HttpResponseData response = engine.makeHttpRequest(swafeAddress, getRequest).response();

      if (response.statusCode() != 200) {
        throw new RuntimeException(
            "Failed to retrieve secret share from node "
                + nodeId
                + ": "
                + response.statusCode()
                + " - "
                + response.bodyAsText());
      }

      String responseText = response.bodyAsText().trim();

      // Parse JSON response to extract the entry field
      String mskRecord;
      try {
        JsonNode responseJson = new ObjectMapper().readTree(responseText);
        mskRecord = responseJson.get("entry").asText();
        if (mskRecord == null) {
          throw new RuntimeException(
              "Missing entry field in secret share response from node " + nodeId);
        }
      } catch (Exception e) {
        throw new RuntimeException(
            "Failed to parse secret share response from node "
                + nodeId
                + ": "
                + responseText
                + " - "
                + e.getMessage());
      }

      // Store MSK record in memory
      mskRecords.put(nodeId, mskRecord);
      mskRecordFiles.add(nodeId); // Store nodeId instead of file path

      logger.debug("Stored MSK record for node {} in memory", nodeId);
    }

    logger.debug("Retrieved secret shares from all nodes!");
    return mskRecordFiles;
  }

  /** Execute association upload workflow for all nodes using stored data */
  public static void executeAssociationUploadWorkflow(
      MskAndEmailCert mskData, String vdrfEvaluationStr) throws IOException, InterruptedException {
    executeAssociationUploadWorkflowForAllNodes(mskData, vdrfEvaluationStr);
  }

  /** Execute association upload workflow for all nodes */
  public static void executeAssociationUploadWorkflowForAllNodes(
      MskAndEmailCert mskData, String vdrfEvaluationStr) throws IOException, InterruptedException {
    String[] nodeIds = VdrfSetup.getNodeIds();
    com.partisiablockchain.BlockchainAddress swafeAddress = getSwafeAddress();

    logger.debug("Executing association upload workflow for {} nodes...", nodeIds.length);

    for (String nodeId : nodeIds) {
      logger.debug("Testing association upload to node {}...", nodeId);

      // Generate upload request
      String requestStr = generateUploadRequest(mskData, nodeId, vdrfEvaluationStr);

      // Make HTTP request
      HttpRequestData uploadRequest =
          new HttpRequestData("POST", "/association/upload-association", Map.of(), requestStr);

      TestExecutionEngine engine = getEngineForNode(nodeId);
      HttpResponseData response = engine.makeHttpRequest(swafeAddress, uploadRequest).response();

      // Verify response
      if (response.statusCode() != 200) {
        throw new RuntimeException(
            "Association upload failed for node "
                + nodeId
                + ": "
                + response.statusCode()
                + " - "
                + response.bodyAsText());
      }

      String responseText = response.bodyAsText();

      // Parse JSON response to validate success
      try {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode jsonResponse = mapper.readTree(responseText);
        boolean success = jsonResponse.get("success").asBoolean();
        String message = jsonResponse.get("message").asText();

        if (!success) {
          throw new RuntimeException(
              "Association upload failed for node " + nodeId + ": " + message);
        }

        logger.debug("Node {} association upload: {}", nodeId, message);
      } catch (Exception e) {
        throw new RuntimeException(
            "Failed to parse association upload response for node "
                + nodeId
                + ": "
                + responseText
                + " - "
                + e.getMessage());
      }
    }

    logger.debug("Association upload workflow completed for all nodes!");
  }

  /** Generate upload request for a specific node - simplified to one CLI call */
  public static String generateUploadRequest(
      MskAndEmailCert workflowData, String nodeId, String vdrfEvaluationStr)
      throws IOException, InterruptedException {
    // Generate hex upload request
    Path requestPath = Path.of("src/test/resources/upload_request_" + nodeId + ".json");

    List<String> command =
        CliHelper.buildCommand(
            "generate-upload-msk-request",
            "--certificate=" + workflowData.emailCertStr,
            "--encrypted-msk=" + workflowData.encryptedMskStr,
            "--node-id=" + nodeId,
            "--vrf-eval-email=" + vdrfEvaluationStr,
            "--output=" + requestPath.toAbsolutePath().toString());

    CliHelper.runCommand(command, "Generating upload request for node " + nodeId);

    // The request is already in JSON format, just return it
    return Files.readString(requestPath).trim();
  }

  /** Generate email certificate token for a specific node using workflow data */
  public static String generateEmailCertToken(MskAndEmailCert workflowData, String nodeId)
      throws IOException, InterruptedException {
    Path tokenPath = Path.of("src/test/resources/email_cert_token_" + nodeId + ".txt");
    Path jsonTokenPath = Path.of("src/test/resources/email_cert_token_" + nodeId + ".json");

    List<String> command =
        CliHelper.buildCommand(
            "generate-email-cert-token",
            "-c=" + workflowData.emailCertStr,
            "-n=" + nodeId,
            "-k=" + workflowData.userPrivateKeyStr,
            "-o=" + tokenPath.toAbsolutePath().toString());

    CliHelper.runCommand(command, "Generating email certificate token for node " + nodeId);

    // Read the hex token
    String strToken = Files.readString(tokenPath).trim();

    // Convert hex token to JSON format for VDRF endpoint
    List<String> jsonCommand =
        CliHelper.buildCommand(
            "email-cert-token-to-json",
            "--token-str",
            strToken,
            "-o",
            jsonTokenPath.toAbsolutePath().toString());

    CliHelper.runCommand(jsonCommand, "Converting token to JSON for VDRF endpoint " + nodeId);

    // Return the hex token for CLI commands that expect hex format
    return strToken;
  }

  /** Create a GetSecretShareRequest using the CLI command */
  public static String createGetSecretShareRequest(
      String emailCertToken, String vdrfEvaluation, String nodeId)
      throws IOException, InterruptedException {
    Path requestPath = Path.of("src/test/resources/get_secret_share_request_" + nodeId + ".json");

    List<String> command =
        CliHelper.buildCommand(
            "create-get-secret-share-request",
            "--email-cert-token",
            emailCertToken,
            "--vdrf-evaluation",
            vdrfEvaluation,
            "--output",
            requestPath.toAbsolutePath().toString());

    CliHelper.runCommand(command, "Creating GetSecretShareRequest using CLI for node " + nodeId);

    // The request is already in JSON format, just return it
    return Files.readString(requestPath).trim();
  }

  /** Use CLI to reconstruct RIK from multiple MskRecord files */
  public static void reconstructMsk(List<String> nodeIds, String rikStr)
      throws IOException, InterruptedException {
    Path outputPath = Path.of("src/test/resources/reconstructed_msk.txt");

    // Create temporary file for RIK (write as JSON with recovery_initiation_key field)
    Path rikPath = Path.of("src/test/resources/temp_rik.txt");
    ObjectMapper mapper = new ObjectMapper();
    Map<String, String> rikJson = new HashMap<>();
    rikJson.put("recovery_initiation_key", rikStr);
    String jsonString = mapper.writeValueAsString(rikJson);
    Files.write(rikPath, jsonString.getBytes());

    // Build the command to reconstruct RIK
    List<String> command =
        CliHelper.buildCommand(
            "reconstruct-rik",
            "--rik-file",
            rikPath.toAbsolutePath().toString(),
            "--output",
            outputPath.toAbsolutePath().toString());

    // Add each MSK record from memory, creating temporary files for CLI
    for (String nodeId : nodeIds) {
      String mskRecord = mskRecords.get(nodeId);
      if (mskRecord == null) {
        throw new RuntimeException("MSK record not found for node " + nodeId);
      }

      // Create temporary file for CLI (write as API response format with "entry" field)
      Path tempFile = Path.of("src/test/resources/msk_record_node_" + nodeId + ".txt");
      Map<String, String> apiResponse = new HashMap<>();
      apiResponse.put("entry", mskRecord);
      String jsonResponse = mapper.writeValueAsString(apiResponse);
      Files.write(tempFile, jsonResponse.getBytes());

      command.add("--msk-records");
      command.add(tempFile.toAbsolutePath().toString());
    }

    CliHelper.runCommand(command, "Reconstructing RIK data using Swafe CLI");

    // Verify the reconstructed RIK file exists and has content
    if (!Files.exists(outputPath)) {
      throw new RuntimeException("Reconstructed RIK file was not created");
    }

    String reconstructedRik = Files.readString(outputPath).trim();
    if (reconstructedRik.isEmpty()) {
      throw new RuntimeException("Reconstructed RIK file is empty");
    }

    logger.debug("RIK data successfully reconstructed!");
    logger.debug("Reconstructed RIK saved to: {}", outputPath.getFileName());
    logger.debug("RIK length: {} hex characters", reconstructedRik.length());
  }

  /** Perform VDRF evaluation with email certificate tokens for all nodes */
  public static List<VdrfEvaluation> performVdrfEvaluations(Map<String, String> tokens)
      throws IOException, InterruptedException {
    logger.debug("Performing VDRF evaluations...");

    String[] nodeIds = VdrfSetup.getNodeIds();
    com.partisiablockchain.BlockchainAddress swafeAddress = getSwafeAddress();

    List<VdrfEvaluation> evaluations = new ArrayList<>();

    for (String nodeId : nodeIds) {
      // Get the string-encoded (base64) token for VDRF endpoint
      String encodedToken = tokens.get(nodeId);
      if (encodedToken == null) {
        throw new RuntimeException(
            "Email cert token not found for node " + nodeId + ". Ensure tokens are provided.");
      }

      // Create VdrfEvalRequest object and serialize with Jackson
      Map<String, String> vdrfEvalRequest = Map.of("token", encodedToken);
      String requestJson;
      try {
        requestJson = new ObjectMapper().writeValueAsString(vdrfEvalRequest);
      } catch (Exception e) {
        throw new RuntimeException("Failed to serialize VdrfEvalRequest: " + e.getMessage());
      }

      HttpRequestData evalRequest =
          new HttpRequestData("POST", "/association/vdrf/eval", Map.of(), requestJson);

      TestExecutionEngine engine = getEngineForNode(nodeId);
      HttpResponseData response = engine.makeHttpRequest(swafeAddress, evalRequest).response();

      if (response.statusCode() != 200) {
        throw new RuntimeException(
            "VDRF evaluation failed for node "
                + nodeId
                + ": "
                + response.statusCode()
                + " - "
                + response.bodyAsText());
      }

      String responseText = response.bodyAsText();

      // Parse the JSON response to extract the eval_share
      JsonNode responseJson;
      try {
        responseJson = new ObjectMapper().readTree(responseText);
      } catch (Exception e) {
        throw new RuntimeException(
            "Failed to parse VDRF evaluation response from node " + nodeId + ": " + e.getMessage());
      }

      String evalShare = responseJson.get("eval_share").asText();
      if (evalShare == null) {
        throw new RuntimeException(
            "Missing eval_share in VDRF evaluation response from node " + nodeId);
      }

      evaluations.add(new VdrfEvaluation(nodeId, evalShare));
      logger.debug("Node {} evaluation completed", nodeId);
    }

    logger.debug("All VDRF evaluations completed successfully!");
    return evaluations;
  }

  /** Combine VDRF partial evaluations into final result using stored data */
  public static VdrfResult combineVdrfEvaluations(
      String inputData, List<VdrfEvaluation> evaluations) throws IOException, InterruptedException {
    return combineVdrfEvaluations(inputData, evaluations, VdrfSetup.getVdrfPublicKey());
  }

  /** Combine VDRF partial evaluations into final result */
  public static VdrfResult combineVdrfEvaluations(
      String inputData, List<VdrfEvaluation> evaluations, String vdrfPublicKeyHex)
      throws IOException, InterruptedException {
    logger.debug("Combining VDRF evaluations...");

    Path resultPath = Path.of("src/test/resources/vdrf_result.txt");

    // Build the command to combine VDRF evaluations
    List<String> command =
        CliHelper.buildCommand(
            "combine-vdrf-evaluations",
            "--public-key",
            vdrfPublicKeyHex,
            "--output",
            resultPath.toAbsolutePath().toString(),
            "--input-data",
            inputData);

    // Add each evaluation as a separate argument
    for (VdrfEvaluation evaluation : evaluations) {
      command.add("--evaluations");
      command.add(evaluation.nodeId + "=" + evaluation.evaluationStr);
    }

    // Run the CLI command with custom tag
    runCliCommandWithTag(command, "Combining VDRF evaluations using Swafe CLI", "CLI-Combine");

    // Parse the result
    VdrfResult result = parseVdrfResult(resultPath);

    logger.debug("Combined evaluation: {}", result.combinedEvaluationStr);
    logger.debug("Random output: {}", result.randomOutputStr);
    logger.debug("VDRF combination completed successfully!");

    return result;
  }

  /** Helper method to get the appropriate execution engine for a VDRF node */
  public static TestExecutionEngine getEngineForNode(String nodeId) {
    TestExecutionEngine[] testEngines = VdrfSetup.getTestEngines();
    String[] nodeIds = VdrfSetup.getNodeIds();

    for (int i = 0; i < nodeIds.length; i++) {
      if (nodeIds[i].equals(nodeId)) {
        return testEngines[i];
      }
    }
    throw new IllegalArgumentException(
        "Invalid node ID: " + nodeId + ". Valid IDs are: " + String.join(", ", nodeIds));
  }

  /** Parse VDRF result from the output file */
  private static VdrfResult parseVdrfResult(Path resultPath) throws IOException {
    List<String> resultLines = Files.readAllLines(resultPath);

    String combinedEvaluation = null;
    String randomOutput = null;

    for (String line : resultLines) {
      if (line.startsWith("evaluation:")) {
        combinedEvaluation = line.substring("evaluation:".length());
      } else if (line.startsWith("random_output:")) {
        randomOutput = line.substring("random_output:".length());
      }
    }

    if (combinedEvaluation == null) {
      throw new RuntimeException("Could not find evaluation in VDRF result file");
    }
    if (randomOutput == null) {
      throw new RuntimeException("Could not find random_output in VDRF result file");
    }

    return new VdrfResult(combinedEvaluation, randomOutput);
  }

  /** Helper method to run CLI commands with custom tag for output */
  private static void runCliCommandWithTag(List<String> command, String description, String tag)
      throws IOException, InterruptedException {
    logger.debug("{}...", description);

    Path cliDir = Path.of("../../cli");
    ProcessBuilder builder = new ProcessBuilder(command);
    builder.directory(cliDir.toFile());
    builder.environment().put("RUSTFLAGS", "-Awarnings");
    builder.redirectErrorStream(true);

    Process process = builder.start();

    try (java.io.BufferedReader reader =
        new java.io.BufferedReader(new java.io.InputStreamReader(process.getInputStream()))) {
      String line;
      while ((line = reader.readLine()) != null) {
        logger.debug("[{}] {}", tag, line);
      }
    }

    int exitCode = process.waitFor();
    if (exitCode != 0) {
      throw new RuntimeException(description + " failed with exit code: " + exitCode);
    }

    logger.debug("{} completed successfully!", description);
  }
}
