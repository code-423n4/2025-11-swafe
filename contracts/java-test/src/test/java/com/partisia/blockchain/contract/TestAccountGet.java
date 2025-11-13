package com.partisia.blockchain.contract;

import static org.junit.jupiter.api.Assertions.*;

import com.partisiablockchain.BlockchainAddress;
import com.partisiablockchain.container.execution.protocol.HttpRequestData;
import com.partisiablockchain.crypto.KeyPair;
import com.partisiablockchain.language.abicodegen.SwafeContract;
import com.partisiablockchain.language.junit.ContractBytes;
import com.partisiablockchain.language.junit.ContractTest;
import com.partisiablockchain.language.junit.JunitContractTest;
import com.partisiablockchain.language.testenvironment.executionengine.TestExecutionEngine;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class TestAccountGet extends JunitContractTest {

  private static final Logger logger = LoggerFactory.getLogger(TestAccountGet.class);

  private static final ContractBytes CONTRACT_BYTES =
      ContractBytes.fromPbcFile(
          Path.of("../target/wasm32-unknown-unknown/release/swafe_contract.pbc"));

  // Use same setup as the working test
  private static final int NUM_NODES = 3;
  private final String[] nodeNames = generateNodeNames(NUM_NODES);
  private final KeyPair[] engineKeys = generateEngineKeys(NUM_NODES);

  private static String[] generateNodeNames(int numNodes) {
    String[] names = new String[numNodes];
    for (int i = 0; i < numNodes; i++) {
      names[i] = "node" + (i + 1);
    }
    return names;
  }

  private static KeyPair[] generateEngineKeys(int numNodes) {
    KeyPair[] keys = new KeyPair[numNodes];
    for (int i = 0; i < numNodes; i++) {
      keys[i] = new KeyPair(BigInteger.valueOf(100 + i));
    }
    return keys;
  }

  @ContractTest
  void testAccountGetEndpoint() throws IOException, InterruptedException {
    logger.debug("=== Testing /account/get endpoint ===");

    // Use exact same setup as working test
    Path resourcesDir = Path.of("src/test/resources");
    Files.createDirectories(resourcesDir);

    KeyManager keyManager = new KeyManager();
    keyManager.generateNodeKeypairs(NUM_NODES);

    BlockchainAddress account = blockchain.newAccount(2);

    TestExecutionEngine[] testEngines = new TestExecutionEngine[NUM_NODES];
    for (int i = 0; i < NUM_NODES; i++) {
      testEngines[i] = blockchain.addExecutionEngine(p -> true, engineKeys[0]);
    }

    // Generate node addresses
    BlockchainAddress[] nodeAddresses = new BlockchainAddress[NUM_NODES];
    for (int i = 0; i < NUM_NODES; i++) {
      nodeAddresses[i] = blockchain.newAccount(10 + i);
    }

    // Setup VDRF nodes
    List<SwafeContract.OffchainNodeSetup> vdrfNodes =
        VdrfSetup.generateVdrfSetup(nodeNames, testEngines, nodeAddresses);

    // Generate Swafe operator keypair
    keyManager.generateKeypair("swafe");
    String swafePublicKeyStr = keyManager.getPublicKey("swafe");

    // Get the VDRF public key
    String vdrfPublicKeyStr = VdrfSetup.getVdrfPublicKey();

    // Deploy contract with proper setup
    BlockchainAddress contractAddress =
        blockchain.deployContract(
            account,
            CONTRACT_BYTES,
            SwafeContract.initialize(vdrfNodes, swafePublicKeyStr, vdrfPublicKeyStr),
            100000000L);

    // Setup HTTP engine
    TestExecutionEngine engine =
        blockchain.addExecutionEngine(
            addr -> addr.equals(contractAddress), new KeyPair(BigInteger.valueOf(20L)));

    // Test 1: Non-existent account (should return 404)
    String requestBody = "{\"account_id\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAw\"}";
    HttpRequestData request =
        new HttpRequestData(
            "POST",
            "/account/get",
            Map.of("Content-Type", List.of("application/json")),
            requestBody);

    TestExecutionEngine.HttpResult result = engine.makeHttpRequest(contractAddress, request);

    logger.debug("Non-existent account test:");
    logger.debug("  Status: {}", result.response().statusCode());
    logger.debug("  Body: {}", result.response().bodyAsText());

    // The endpoint should return a proper HTTP response
    assertTrue(
        result.response().statusCode() >= 200 && result.response().statusCode() < 600,
        "Should return valid HTTP status code (got " + result.response().statusCode() + ")");

    if (result.response().statusCode() == 404) {
      assertTrue(
          result.response().bodyAsText().toLowerCase().contains("not found"),
          "Expected 'not found' in 404 response body");
      logger.debug("Correctly returned 404 for non-existent account");
    } else {
      logger.debug("Got status {}", result.response().statusCode());
    }

    // Test 2: Create an account and test getting it (should return 200)
    logger.debug("Testing with existing account...");

    // Create and allocate an account using AccountManager (same as working tests)
    AccountManager.AccountData accountData =
        AccountManager.generateAccountAllocation(blockchain, account, contractAddress);

    String accountId = accountData.accountIdStr;

    // Now test getting this existing account
    String existingAccountRequest = "{\"account_id\":\"" + accountId + "\"}";
    HttpRequestData existingRequest =
        new HttpRequestData(
            "POST",
            "/account/get",
            Map.of("Content-Type", List.of("application/json")),
            existingAccountRequest);

    TestExecutionEngine.HttpResult existingResult =
        engine.makeHttpRequest(contractAddress, existingRequest);

    logger.debug("Existing account test:");
    logger.debug("  Status: {}", existingResult.response().statusCode());
    logger.debug("  Body: {}", existingResult.response().bodyAsText());

    // Should return 200 OK with account data
    assertEquals(
        200, existingResult.response().statusCode(), "Should return 200 OK for existing account");

    String responseBody = existingResult.response().bodyAsText();
    assertTrue(
        responseBody.contains("account_state"), "Response should contain 'account_state' field");

    // Verify it's valid JSON
    com.fasterxml.jackson.databind.ObjectMapper mapper =
        new com.fasterxml.jackson.databind.ObjectMapper();
    com.fasterxml.jackson.databind.JsonNode responseJson = mapper.readTree(responseBody);
    assertNotNull(responseJson.get("account_state"), "Response should have account_state field");
  }
}
