package com.partisia.blockchain.contract;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.partisiablockchain.BlockchainAddress;
import com.partisiablockchain.container.execution.protocol.HttpRequestData;
import com.partisiablockchain.container.execution.protocol.HttpResponseData;
import com.partisiablockchain.crypto.KeyPair;
import com.partisiablockchain.language.abicodegen.SwafeContract;
import com.partisiablockchain.language.abicodegen.SwafeContract.OffchainNodeSetup;
import com.partisiablockchain.language.abicodegen.SwafeContract.OffchainNodeState;
import com.partisiablockchain.language.junit.TestBlockchain;
import com.partisiablockchain.language.testenvironment.executionengine.TestExecutionEngine;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class VdrfSetup {

  private static final Logger logger = LoggerFactory.getLogger(VdrfSetup.class);

  private static VdrfSetupData setupData;

  private static Map<String, TestExecutionEngine> nodeEngineMap;

  private VdrfSetup() {}

  public static class VdrfSetupData {

    public final String vdrfPublicKeyStr;
    public final Map<String, String> signedShares;
    public final List<NodeConfig> nodeConfigs;
    public final int numNodes;

    public VdrfSetupData(
        String vdrfPublicKeyStr,
        Map<String, String> signedShares,
        List<NodeConfig> nodeConfigs,
        int numNodes) {
      this.vdrfPublicKeyStr = vdrfPublicKeyStr;
      this.signedShares = signedShares;
      this.nodeConfigs = nodeConfigs;
      this.numNodes = numNodes;
    }
  }

  public static class NodeConfig {

    public final String nodeId;
    public final String publicKeyStr;

    public NodeConfig(String nodeId, String publicKeyStr) {
      this.nodeId = nodeId;
      this.publicKeyStr = publicKeyStr;
    }
  }

  /**
   * Generate VDRF secret shares for the nodes, and simulate signing VDRF shares by the node
   * operators.
   */
  public static java.util.List<SwafeContract.OffchainNodeSetup> generateVdrfSetup(
      String[] nodeIds, TestExecutionEngine[] testEngines, BlockchainAddress[] nodeAddresses)
      throws IOException, InterruptedException {
    logger.debug("Setup VDRF...");

    int numNodes = nodeIds.length;

    if (testEngines.length != numNodes) {
      throw new IllegalArgumentException(
          "Number of execution engines ("
              + testEngines.length
              + ") must match number of nodes ("
              + numNodes
              + ")");
    }

    Path outputPath = Path.of("src/test/resources/vdrf_test_setup.json");

    List<String> command =
        CliHelper.buildCommand(
            "generate-vdrf-test-setup",
            "--num-nodes",
            String.valueOf(numNodes),
            "--threshold",
            String.valueOf(numNodes - 1), // Use n-1 threshold for fault tolerance
            "--output",
            outputPath.toAbsolutePath().toString());

    if (nodeIds != null && nodeIds.length > 0) {
      command.add("--node-ids");
      command.add(String.join(",", nodeIds));
    }

    CliHelper.runCommand(command, "Generating VDRF test setup");

    String jsonContent = Files.readString(outputPath);
    ObjectMapper mapper = new ObjectMapper();
    JsonNode data = mapper.readTree(jsonContent);

    JsonNode sharesNode = data.get("signed_shares");
    Map<String, String> signedShares =
        mapper.convertValue(
            sharesNode,
            mapper.getTypeFactory().constructMapType(Map.class, String.class, String.class));

    JsonNode configsNode = data.get("node_configs");
    List<NodeConfig> nodeConfigs = new ArrayList<>();
    for (JsonNode configNode : configsNode) {
      nodeConfigs.add(
          new NodeConfig(
              configNode.get("node_id").asText(), configNode.get("public_key_str").asText()));
    }

    VdrfSetupData result =
        new VdrfSetupData(
            data.get("vdrf_public_key").asText(),
            signedShares,
            nodeConfigs,
            data.get("num_nodes").asInt());

    setupData = result;

    nodeEngineMap = new java.util.HashMap<>();
    for (int i = 0; i < nodeConfigs.size(); i++) {
      nodeEngineMap.put(nodeConfigs.get(i).nodeId, testEngines[i]);
    }

    return createVdrfNodeConfigsFromSetup(nodeAddresses);
  }

  /**
   * Reset test engines so that it can sync the latest contract state. But the offchain storage will
   * be lost. This is a workaround hack for the testing, as the test engine from the testing
   * framework doesn't sync the latest contract state automatically.
   */
  public static void resetTestEngines(TestBlockchain bc, KeyPair key) {
    logger.debug("Resetting test engines to sync latest contract state...");
    for (Map.Entry<String, TestExecutionEngine> entry : nodeEngineMap.entrySet()) {
      // re-add an engine from blockchain, and override nodeEngineMap using the same key
      TestExecutionEngine newEngine = bc.addExecutionEngine(p -> true, key);
      nodeEngineMap.put(entry.getKey(), newEngine);
    }
  }

  public static java.util.List<
          com.partisiablockchain.language.abicodegen.SwafeContract.OffchainNodeSetup>
      generateVdrfSetup(String[] nodeIds) throws IOException, InterruptedException {
    logger.debug("Generating complete VDRF setup...");

    int numNodes = nodeIds.length;

    Path outputPath = Path.of("src/test/resources/vdrf_test_setup.json");

    List<String> command =
        CliHelper.buildCommand(
            "generate-vdrf-test-setup",
            "--num-nodes",
            String.valueOf(numNodes),
            "--threshold",
            String.valueOf(numNodes - 1), // Use n-1 threshold for fault tolerance
            "--output",
            outputPath.toAbsolutePath().toString());

    if (nodeIds != null && nodeIds.length > 0) {
      command.add("--node-ids");
      command.add(String.join(",", nodeIds));
    }

    CliHelper.runCommand(command, "Generating VDRF test setup");

    String jsonContent = Files.readString(outputPath);
    ObjectMapper mapper = new ObjectMapper();
    JsonNode data = mapper.readTree(jsonContent);

    JsonNode sharesNode = data.get("signed_shares");
    Map<String, String> signedShares =
        mapper.convertValue(
            sharesNode,
            mapper.getTypeFactory().constructMapType(Map.class, String.class, String.class));

    JsonNode configsNode = data.get("node_configs");
    List<NodeConfig> nodeConfigs = new ArrayList<>();
    for (JsonNode configNode : configsNode) {
      nodeConfigs.add(
          new NodeConfig(
              configNode.get("node_id").asText(), configNode.get("public_key_str").asText()));
    }

    VdrfSetupData result =
        new VdrfSetupData(
            data.get("vdrf_public_key").asText(),
            signedShares,
            nodeConfigs,
            data.get("num_nodes").asInt());

    setupData = result;

    return createVdrfNodeConfigsFromSetup(
        null); // TODO: This path needs blockchain for proper address generation
  }

  private static void saveVdrfSetupToFiles(VdrfSetupData setupData) throws IOException {
    Files.write(
        Path.of("src/test/resources/vdrf_public_key.txt"), setupData.vdrfPublicKeyStr.getBytes());

    ObjectMapper mapper = new ObjectMapper();
    Map<String, Object> vdrfSharesJson =
        Map.of("public_key", setupData.vdrfPublicKeyStr, "shares", setupData.signedShares);
    String sharesJson = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(vdrfSharesJson);
    Files.write(Path.of("src/test/resources/vdrf_shares.json"), sharesJson.getBytes());

    for (NodeConfig config : setupData.nodeConfigs) {
      String nodeNumber = config.nodeId.replaceAll("[^0-9]", "");
      Files.write(
          Path.of("src/test/resources/node_" + nodeNumber + "_public_key.txt"),
          config.publicKeyStr.getBytes());
    }

    logger.debug("VDRF setup saved to individual files for compatibility");
  }

  /** Save VDRF setup data to individual files using stored setup data */
  public static void saveVdrfSetupToFiles() throws IOException {
    if (setupData == null) {
      throw new IllegalStateException(
          "No VDRF setup data available. Call generateVdrfSetup() first.");
    }
    saveVdrfSetupToFiles(setupData);
  }

  private static List<AssociationWorkflow.VdrfShare> createVdrfSharesFromSetup(
      VdrfSetupData setupData) {
    List<AssociationWorkflow.VdrfShare> shares = new ArrayList<>();

    for (Map.Entry<String, String> entry : setupData.signedShares.entrySet()) {
      shares.add(new AssociationWorkflow.VdrfShare(entry.getKey(), entry.getValue()));
    }

    return shares;
  }

  private static List<OffchainNodeSetup> createVdrfNodeConfigsFromSetup(
      BlockchainAddress[] nodeAddresses) {
    logger.debug("Creating VDRF node configurations from setup data...");

    List<OffchainNodeSetup> vdrfNodes = new ArrayList<>();

    int nodeIndex = 0;
    for (NodeConfig config : setupData.nodeConfigs) {
      // Use the provided node address from the test setup
      BlockchainAddress nodeAddress = nodeAddresses[nodeIndex++];

      // Get the corresponding offchain secret for this node to compute its commitment
      String serializedSecret = setupData.signedShares.get(config.nodeId);
      if (serializedSecret == null) {
        throw new RuntimeException(
            "No secret found for node: "
                + config.nodeId
                + ". Available keys: "
                + setupData.signedShares.keySet());
      }

      // Compute the hash commitment of the offchain secret
      // Note: This is a simplified hash for testing - in production you'd use the proper Tagged
      // hash
      byte[] secretCommitment = computeSecretCommitment(serializedSecret);

      OffchainNodeState state =
          new OffchainNodeState(
              nodeAddress, // Generated unique address for testing
              Base64.getUrlDecoder().decode(config.publicKeyStr),
              "https://node.example.com/", // Dummy URL
              secretCommitment // Hash commitment of the offchain secret (now called 'comm')
              );
      OffchainNodeSetup nodeConfig = new OffchainNodeSetup(state, config.nodeId);
      vdrfNodes.add(nodeConfig);

      logger.debug(
          "Added node {} config - Public key: {}...",
          config.nodeId,
          config.publicKeyStr.substring(0, 16));
    }

    return vdrfNodes;
  }

  private static byte[] computeSecretCommitment(String serializedSecret) {
    // Use the CLI to compute the proper Tagged hash commitment
    // This ensures we match the exact Rust implementation
    try {
      Path tempFile = Files.createTempFile("secret_", ".txt");
      Files.write(tempFile, serializedSecret.getBytes());

      List<String> command =
          CliHelper.buildCommand("compute-commitment", "--input", tempFile.toString());

      CliHelper.ProcessResult result =
          CliHelper.runCommandWithOutput(command, "Computing secret commitment");

      // Clean up temp file
      Files.delete(tempFile);

      // Parse the hex output from CLI (get the last line, which contains the hash)
      String[] lines = result.output.trim().split("\n");
      String hexCommitment = lines[lines.length - 1].trim();

      if (hexCommitment.isEmpty()) {
        throw new RuntimeException("CLI returned empty output");
      }

      // Validate that it looks like a hex string
      if (!hexCommitment.matches("[0-9a-fA-F]+")) {
        throw new RuntimeException("CLI output doesn't look like hex: '" + hexCommitment + "'");
      }

      return hexStringToBytes(hexCommitment);
    } catch (Exception e) {
      logger.error("Failed to compute secret commitment", e);
      throw new RuntimeException(
          "Failed to compute secret commitment using CLI: " + e.getMessage(), e);
    }
  }

  private static byte[] hexStringToBytes(String hex) {
    if (hex.length() % 2 != 0) {
      throw new IllegalArgumentException("Hex string must have even length");
    }
    byte[] bytes = new byte[hex.length() / 2];
    for (int i = 0; i < hex.length(); i += 2) {
      bytes[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
  }

  private static String encodeNodeId(String nodeId) {
    // Use CLI to properly encode the NodeId as StrEncoded<NodeId>
    try {
      List<String> command = CliHelper.buildCommand("encode-node-id", nodeId);
      CliHelper.ProcessResult result = CliHelper.runCommandWithOutput(command, "Encoding NodeId");

      // Parse the CLI output (get the last line, which contains the encoded NodeId)
      String[] lines = result.output.trim().split("\n");
      String encodedNodeId = lines[lines.length - 1].trim();

      if (encodedNodeId.isEmpty()) {
        throw new RuntimeException("CLI returned empty output");
      }

      return encodedNodeId;
    } catch (Exception e) {
      throw new RuntimeException("Failed to encode NodeId: " + e.getMessage(), e);
    }
  }

  public static String getVdrfPublicKey() {
    return setupData.vdrfPublicKeyStr;
  }

  public static String[] getNodeIds() {
    return setupData.nodeConfigs.stream().map(config -> config.nodeId).toArray(String[]::new);
  }

  public static TestExecutionEngine[] getTestEngines() {
    if (nodeEngineMap == null) {
      throw new IllegalStateException("No test engines available. Call generateVdrfSetup() first.");
    }

    String[] nodeIds = getNodeIds();
    TestExecutionEngine[] engines = new TestExecutionEngine[nodeIds.length];

    for (int i = 0; i < nodeIds.length; i++) {
      engines[i] = nodeEngineMap.get(nodeIds[i]);
      if (engines[i] == null) {
        throw new IllegalStateException("No test engine found for node: " + nodeIds[i]);
      }
    }

    return engines;
  }

  /**
   * Simulating the node operators signing the VDRF shares and initializing their offchain nodes.
   */
  public static void initializeVdrfNodes(BlockchainAddress swafeAddress)
      throws IOException, InterruptedException {
    List<AssociationWorkflow.VdrfShare> vdrfShares = createVdrfSharesFromSetup(setupData);

    logger.debug("Initializing VDRF nodes...");

    ObjectMapper mapper = new ObjectMapper();

    for (AssociationWorkflow.VdrfShare share : vdrfShares) {
      // Create the new init request format with node_id and secret
      // The nodeId needs to be properly encoded as StrEncoded<NodeId>
      // The secret is already StrEncoded<OffchainSecret> from CLI generation
      String encodedNodeId = encodeNodeId(share.nodeId);
      Map<String, String> initRequestBody =
          Map.of("node_id", encodedNodeId, "secret", share.serializedShareStr);
      String jsonBody = mapper.writeValueAsString(initRequestBody);

      logger.debug("Sending init request for {}: {}", share.nodeId, jsonBody);

      HttpRequestData initRequest = new HttpRequestData("POST", "/init", Map.of(), jsonBody);

      TestExecutionEngine engine = nodeEngineMap.get(share.nodeId);
      if (engine == null) {
        throw new RuntimeException(
            "No test engine found for nodeId: '"
                + share.nodeId
                + "'. Available: "
                + nodeEngineMap.keySet());
      }

      HttpResponseData response = engine.makeHttpRequest(swafeAddress, initRequest).response();

      if (response.statusCode() != 200) {
        throw new RuntimeException(
            "VDRF initialization failed for node "
                + share.nodeId
                + ": "
                + response.statusCode()
                + " - "
                + response.bodyAsText());
      }

      logger.debug("Initialized node {}: {}", share.nodeId, response.bodyAsText());
    }

    logger.debug("All VDRF nodes initialized successfully!");
  }
}
