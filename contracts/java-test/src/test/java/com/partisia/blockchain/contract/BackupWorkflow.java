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
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * BackupWorkflow - Social Recovery Backup Management
 *
 * <p>This class encapsulates the complete social recovery backup workflow: - Creating backup
 * ciphertext with threshold secret sharing - Guardian share encryption/decryption - Signature
 * verification and contract storage - Secret recovery using guardian shares
 *
 * <p>Implements the same cryptographic workflow as test_full_backup_decrypt_flow from the Rust unit
 * tests but provides a Java interface for integration testing.
 */
public class BackupWorkflow {

  private static final Logger logger = LoggerFactory.getLogger(BackupWorkflow.class);

  /** Result of creating a backup ciphertext */
  public static class BackupResult {

    public final String backupCiphertextDataStr;
    public final String accountIdStr;
    public final int threshold;
    public final int guardiansCount;
    public final String backupIdStr; // StrEncoded BackupId

    public BackupResult(
        String backupCiphertextDataStr, String accountIdStr, int threshold, int guardiansCount) {
      this.backupCiphertextDataStr = backupCiphertextDataStr;
      this.accountIdStr = accountIdStr;
      this.threshold = threshold;
      this.guardiansCount = guardiansCount;
      this.backupIdStr = null;
    }

    public BackupResult(
        String backupCiphertextDataStr,
        String accountIdStr,
        int threshold,
        int guardiansCount,
        String backupIdStr) {
      this.backupCiphertextDataStr = backupCiphertextDataStr;
      this.accountIdStr = accountIdStr;
      this.threshold = threshold;
      this.guardiansCount = guardiansCount;
      this.backupIdStr = backupIdStr;
    }
  }

  /** Guardian's decrypted secret share */
  public static class GuardianSecretShare {

    public final String secretShareStr;
    public final int guardianIndex;
    public final String ownerAccountId;

    public GuardianSecretShare(String secretShareStr, int guardianIndex, String ownerAccountId) {
      this.secretShareStr = secretShareStr;
      this.guardianIndex = guardianIndex;
      this.ownerAccountId = ownerAccountId;
    }
  }

  /** Guardian share ready for recovery */
  public static class GuardianShare {

    public final String shareStr;
    public final int index;

    public GuardianShare(String shareStr, int index) {
      this.shareStr = shareStr;
      this.index = index;
    }
  }

  /**
   * Create a social recovery backup with threshold secret sharing and upload to blockchain.
   *
   * <p>This follows the exact same workflow as test_full_backup_decrypt_flow: - Owner creates
   * backup with guardian public keys - Secret is split using Shamir's secret sharing - Each
   * guardian gets an encrypted share - Threshold number of guardians needed for recovery - Adds
   * backup to account and uploads update to blockchain
   *
   * @param ownerAccount Owner's account data
   * @param guardianAccounts List of guardian account data
   * @param threshold Minimum number of guardians needed for recovery
   * @param secretData Secret data to backup
   * @param name Backup name
   * @param description Backup description
   * @param blockchain Blockchain instance for uploading backup
   * @param account Blockchain account for transactions
   * @param swafeAddress Contract address
   * @return BackupResult containing signed backup ready for contract storage
   */
  public static BackupResult createAndUploadBackup(
      AccountManager.AccountData ownerAccount,
      List<AccountManager.AccountData> guardianAccounts,
      int threshold,
      String secretData,
      String name,
      String description,
      Object blockchain, // Use Object to avoid import issues
      com.partisiablockchain.BlockchainAddress account,
      com.partisiablockchain.BlockchainAddress swafeAddress)
      throws IOException, InterruptedException {
    // First create the backup locally
    BackupResult backupResult =
        createBackup(ownerAccount, guardianAccounts, threshold, secretData, name, description);

    // Now we need to add the backup to the account and create an account update
    logger.debug("Adding backup to account and uploading to blockchain...");
    logger.debug("Account ID: {}", backupResult.accountIdStr);
    logger.debug("Backup data length: {}", backupResult.backupCiphertextDataStr.length());

    Path tempOutput = Files.createTempFile("account_update_with_backup", ".json");

    try {
      // Use CLI to add backup to account and generate account update
      List<String> addBackupCommand =
          CliHelper.buildCommand(
              "add-backup-to-account",
              "--owner-account-state-str=" + ownerAccount.accountStateStr,
              "--owner-msk-str=" + ownerAccount.masterSecretKeyStr,
              "--owner-account-id-str=" + ownerAccount.accountIdStr,
              "--backup-ciphertext=" + backupResult.backupCiphertextDataStr,
              "--output",
              tempOutput.toString());

      CliHelper.runCommand(addBackupCommand, "Adding backup to account");

      // Parse the account update result
      String updateJson = Files.readString(tempOutput);
      ObjectMapper mapper = new ObjectMapper();
      JsonNode updateNode = mapper.readTree(updateJson);

      String accountUpdateStr = updateNode.get("account_update").asText();
      String backupIdStr = updateNode.get("backup_id").asText();

      // Update the backup result with the actual backup ID from the blockchain
      backupResult =
          new BackupResult(
              backupResult.backupCiphertextDataStr,
              backupResult.accountIdStr,
              backupResult.threshold,
              backupResult.guardiansCount,
              backupIdStr);

      // Send the account update to the blockchain
      byte[] updateRpc =
          com.partisiablockchain.language.abicodegen.SwafeContract.updateAccount(accountUpdateStr);

      java.lang.reflect.Method sendAction =
          blockchain
              .getClass()
              .getMethod(
                  "sendAction",
                  com.partisiablockchain.BlockchainAddress.class,
                  com.partisiablockchain.BlockchainAddress.class,
                  byte[].class);
      sendAction.invoke(blockchain, account, swafeAddress, updateRpc);

      logger.debug("Backup uploaded to blockchain successfully!");

      // Note: Updated account secrets are available in the JSON result:
      // updateNode.get("account_secrets").asText()
      // The owner account is modified in place by the contract update
    } catch (Exception e) {
      throw new RuntimeException("Failed to upload backup to blockchain", e);
    } finally {
      Files.deleteIfExists(tempOutput);
    }

    return backupResult;
  }

  /** Debug method to examine contract state and account IDs */
  public static void debugContractState(
      String expectedAccountId,
      com.partisiablockchain.language.abicodegen.SwafeContract swafeContract) {
    logger.debug("Expected account ID: {}", expectedAccountId);

    // Get contract state
    com.partisiablockchain.language.abicodegen.SwafeContract.ContractState contractState =
        swafeContract.getState();
    com.partisiablockchain.language.codegenlib.AvlTreeMap<byte[], byte[]> accounts =
        contractState.accounts();

    logger.debug("Contract has {} accounts stored", accounts.size());

    // Try to decode the expected account ID and see if it matches any stored keys
    try {
      byte[] expectedBytes = java.util.Base64.getUrlDecoder().decode(expectedAccountId);
      logger.debug("Expected account ID decodes to {} bytes", expectedBytes.length);

      byte[] found = accounts.get(expectedBytes);
      logger.debug("Direct lookup result: {}", (found != null ? "FOUND" : "NOT FOUND"));

      // Test if the issue is with the HTTP request format
      // Try manually creating what the Rust endpoint expects
      logger.debug("Testing HTTP request format...");
      logger.debug("Sending account_id as: {}", expectedAccountId);
    } catch (Exception e) {
      logger.debug("Failed to decode expected account ID: {}", e.getMessage());
    }
  }

  /**
   * Query account state via HTTP endpoint to debug backup storage
   *
   * @param ownerAccountId Owner's account ID
   * @param swafeAddress Contract address
   * @param engine Test execution engine to use for the HTTP call
   * @return JSON response with account state details
   */
  public static String queryAccountState(
      String ownerAccountId,
      com.partisiablockchain.BlockchainAddress swafeAddress,
      TestExecutionEngine engine)
      throws IOException, InterruptedException {
    logger.debug(
        "Querying account state via HTTP for account: {}...", ownerAccountId.substring(0, 16));

    // Create request body using Jackson
    ObjectMapper mapper = new ObjectMapper();
    java.util.Map<String, String> requestData = java.util.Map.of("account_id", ownerAccountId);
    String requestBody = mapper.writeValueAsString(requestData);

    // Make HTTP POST request to /account/get-state
    HttpRequestData accountRequest =
        new HttpRequestData(
            "POST",
            "/account/get",
            java.util.Map.of("Content-Type", java.util.List.of("application/json")),
            requestBody);

    HttpResponseData response = engine.makeHttpRequest(swafeAddress, accountRequest).response();

    if (response.statusCode() == 200) {
      String jsonResponse = response.bodyAsText();
      logger.debug("Account state query successful!");
      logger.debug("Response: {}", jsonResponse);
      return jsonResponse;
    } else {
      String errorMsg =
          "Account state query failed: " + response.statusCode() + " - " + response.bodyAsText();
      logger.error(errorMsg);
      throw new RuntimeException(errorMsg);
    }
  }

  /**
   * Convert serialized bytes to StrEncoded format (base64url without padding) This matches the Rust
   * StrEncoded serialization format
   */
  private static String toStrEncoded(byte[] serializedBytes) {
    return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(serializedBytes);
  }

  /**
   * Load backup ciphertext from the blockchain contract state for a specific backup.
   *
   * @param ownerAccountId Owner's account ID
   * @param backupIdStr StrEncoded backup ID
   * @param swafeContract Contract instance to query state
   * @return Backup ciphertext hex string for the specified backup
   */
  public static String loadBackupFromContract(
      String ownerAccountId,
      String backupIdStr,
      com.partisiablockchain.language.abicodegen.SwafeContract swafeContract)
      throws IOException, InterruptedException {
    logger.debug("Loading backup from blockchain contract for backup ID: {}...", backupIdStr);

    // Get contract state and find the account
    com.partisiablockchain.language.abicodegen.SwafeContract.ContractState contractState =
        swafeContract.getState();
    com.partisiablockchain.language.codegenlib.AvlTreeMap<byte[], byte[]> accounts =
        contractState.accounts();

    // Debug: Print contract state info
    logger.debug("Contract state retrieved");
    logger.debug("Total accounts in contract: {}", accounts.size());

    byte[] accountIdBytes = java.util.Base64.getUrlDecoder().decode(ownerAccountId);
    byte[] accountStateBytes = accounts.get(accountIdBytes);
    if (accountStateBytes == null) {
      logger.debug("Account not found for ID: {}", ownerAccountId);
      throw new RuntimeException("Account not found in contract state: " + ownerAccountId);
    }

    logger.debug("Account found in contract state");

    // Use CLI to extract the specific backup ciphertext from the account state
    Path tempOutput = Files.createTempFile("extracted_backup", ".json");

    try {
      // Convert the serialized account state bytes to StrEncoded format for the CLI
      String accountStateStr = toStrEncoded(accountStateBytes);

      List<String> extractCommand =
          CliHelper.buildCommand(
              "extract-backup-from-account",
              "--account-state",
              accountStateStr,
              "--backup-id",
              backupIdStr,
              "--output",
              tempOutput.toString());

      CliHelper.runCommand(
          extractCommand, "Extracting backup ciphertext for backup ID " + backupIdStr);

      // Parse the extracted backup result
      String extractedJson = Files.readString(tempOutput);
      ObjectMapper mapper = new ObjectMapper();
      JsonNode extractedNode = mapper.readTree(extractedJson);

      // Extract backup ciphertext - updated field name
      String backupCiphertextStr = null;
      if (extractedNode.has("backup_ciphertext")) {
        backupCiphertextStr = extractedNode.get("backup_ciphertext").asText();
      } else {
        // Debug: print available fields
        logger.debug("Available fields in extracted JSON: {}", extractedNode.fieldNames());
        throw new RuntimeException(
            "Could not find backup ciphertext in extracted result. Available fields: "
                + extractedNode.fieldNames());
      }

      logger.debug("Backup loaded from blockchain successfully!");
      logger.debug("Backup ID: {}", backupIdStr);
      if (extractedNode.has("available_backup_ids")) {
        logger.debug("Available backup IDs: {}", extractedNode.get("available_backup_ids"));
      }

      return backupCiphertextStr;
    } finally {
      Files.deleteIfExists(tempOutput);
    }
  }

  public static BackupResult createBackup(
      AccountManager.AccountData ownerAccount,
      List<AccountManager.AccountData> guardianAccounts,
      int threshold,
      String secretData,
      String name,
      String description)
      throws IOException, InterruptedException {
    logger.debug("Creating backup with {}-of-{} threshold...", threshold, guardianAccounts.size());

    // Create temporary directory for output files
    Path tempDir = Files.createTempDirectory("backup_workflow");
    Path backupFile = tempDir.resolve("backup.json");
    // Step 1: Create backup ciphertext using repeated arguments for guardians
    List<String> backupCommand = new ArrayList<>();
    backupCommand.add("cargo");
    backupCommand.add("run");
    backupCommand.add("--bin");
    backupCommand.add("swafe-cli");
    backupCommand.add("--");
    backupCommand.add("create-backup-ciphertext");
    backupCommand.add("--owner-account-state-str=" + ownerAccount.accountStateStr);
    backupCommand.add("--owner-msk-str=" + ownerAccount.masterSecretKeyStr);
    backupCommand.add("--owner-account-id-str=" + ownerAccount.accountIdStr);

    // Add each guardian account as separate argument
    for (AccountManager.AccountData guardian : guardianAccounts) {
      backupCommand.add("--guardian-accounts-str=" + guardian.accountStateStr);
    }

    backupCommand.add("--threshold=" + String.valueOf(threshold));
    backupCommand.add("--secret-data=" + secretData);
    backupCommand.add("--name=" + name);
    backupCommand.add("--description=" + description);
    backupCommand.add("--output=" + backupFile.toString());

    CliHelper.runCommand(backupCommand, "Creating backup ciphertext");

    // Parse backup result to get all the necessary data
    String backupJson = Files.readString(backupFile);
    ObjectMapper mapper = new ObjectMapper();
    JsonNode backupNode = mapper.readTree(backupJson);

    return new BackupResult(
        backupNode.get("backup_ciphertext").asText(),
        ownerAccount.accountIdStr,
        threshold,
        guardianAccounts.size());
  }

  /**
   * Guardian decrypts their share from the backup ciphertext.
   *
   * @param guardianAccount Guardian's account data
   * @param backupResult The backup result from createBackup
   * @return GuardianSecretShare containing the decrypted secret share
   */
  public static GuardianSecretShare guardianDecryptShare(
      AccountManager.AccountData guardianAccount, BackupResult backupResult)
      throws IOException, InterruptedException {
    logger.debug("Guardian decrypting share...");

    // Create temporary file for output
    Path tempOutput = Files.createTempFile("guardian_secret_share", ".json");
    // Use runCommand with file output - updated to use owner account ID instead of backup
    // ciphertext
    List<String> decryptCommand =
        CliHelper.buildCommand(
            "guardian-decrypt-share",
            "--guardian-account-state-str=" + guardianAccount.accountStateStr,
            "--guardian-msk-str=" + guardianAccount.masterSecretKeyStr,
            "--guardian-account-id-str=" + guardianAccount.accountIdStr,
            "--owner-account-id=" + backupResult.accountIdStr,
            "--backup-ciphertext-str=" + backupResult.backupCiphertextDataStr,
            "--output=" + tempOutput.toString());

    CliHelper.runCommand(decryptCommand, "Guardian decrypting share");

    // Parse the JSON output file
    String outputJson = Files.readString(tempOutput);
    ObjectMapper mapper = new ObjectMapper();
    JsonNode shareNode = mapper.readTree(outputJson);

    return new GuardianSecretShare(
        shareNode.get("secret_share").asText(),
        shareNode.get("guardian_index").asInt(),
        backupResult.accountIdStr);
  }

  /**
   * Convert secret share to guardian share and verify it.
   *
   * @param ownerAccount Owner's account data
   * @param secretShare Guardian's decrypted secret share
   * @param backupResult Backup result containing the backup ciphertext
   * @return GuardianShare ready for recovery
   */
  public static GuardianShare createGuardianShare(
      AccountManager.AccountData ownerAccount,
      GuardianSecretShare secretShare,
      BackupResult backupResult)
      throws IOException, InterruptedException {
    logger.debug("Converting secret share to guardian share...");

    // Step 1: Convert secret share to guardian share
    Path tempShareOutput = Files.createTempFile("guardian_share", ".json");

    List<String> sendCommand =
        CliHelper.buildCommand(
            "guardian-send-share",
            "--secret-share-str=" + secretShare.secretShareStr,
            "--owner-account-state-str=" + ownerAccount.accountStateStr,
            "--output=" + tempShareOutput.toString());

    CliHelper.runCommand(sendCommand, "Converting secret share to guardian share");

    // Parse the guardian share result
    String shareJson = Files.readString(tempShareOutput);
    ObjectMapper mapper = new ObjectMapper();
    JsonNode shareNode = mapper.readTree(shareJson);
    String guardianShareStr = shareNode.get("share").asText();

    // Step 2: Verify the guardian share
    Path tempVerifyOutput = Files.createTempFile("verified_share", ".json");

    List<String> verifyCommand =
        CliHelper.buildCommand(
            "verify-guardian-share",
            "--guardian-share-str",
            guardianShareStr,
            "--backup-ciphertext-str",
            backupResult.backupCiphertextDataStr,
            "--output",
            tempVerifyOutput.toString());

    CliHelper.runCommand(verifyCommand, "Verifying guardian share");

    // Parse the verified result
    String verifiedJson = Files.readString(tempVerifyOutput);
    JsonNode verifiedNode = mapper.readTree(verifiedJson);

    // Clean up temp files
    Files.deleteIfExists(tempShareOutput);
    Files.deleteIfExists(tempVerifyOutput);

    return new GuardianShare(
        guardianShareStr, // Use the guardian share hex
        verifiedNode.get("index").asInt());
  }

  /**
   * Recover the original secret using guardian shares.
   *
   * <p>This completes the social recovery workflow by reconstructing the secret from the threshold
   * number of guardian shares.
   *
   * @param ownerAccount Owner's account data
   * @param backupResult Original backup result
   * @param guardianShares List of guardian shares from guardians
   * @return Recovered secret data
   */
  public static String recoverSecret(
      AccountManager.AccountData ownerAccount,
      BackupResult backupResult,
      List<GuardianShare> guardianShares)
      throws IOException, InterruptedException {
    logger.debug("Recovering secret using {} shares...", guardianShares.size());

    // Create temporary file for output
    Path tempOutput = Files.createTempFile("recovered_secret", ".txt");

    try {
      // Use repeated arguments for guardian shares
      List<String> recoverCommand = new ArrayList<>();
      recoverCommand.add("cargo");
      recoverCommand.add("run");
      recoverCommand.add("--bin");
      recoverCommand.add("swafe-cli");
      recoverCommand.add("--");
      recoverCommand.add("recover-from-backup");
      recoverCommand.add("--owner-account-state-str=" + ownerAccount.accountStateStr);
      recoverCommand.add("--owner-msk-str=" + ownerAccount.masterSecretKeyStr);
      recoverCommand.add("--owner-account-id-str=" + ownerAccount.accountIdStr);
      recoverCommand.add("--backup-ciphertext-str=" + backupResult.backupCiphertextDataStr);

      // Add each guardian share as separate argument
      for (GuardianShare share : guardianShares) {
        recoverCommand.add("--guardian-shares-str=" + share.shareStr);
      }

      recoverCommand.add("--output=" + tempOutput.toString());

      CliHelper.runCommand(recoverCommand, "Recovering secret from backup");

      // Read the recovered secret from file
      return Files.readString(tempOutput).trim();
    } finally {
      // Clean up temporary file
      Files.deleteIfExists(tempOutput);
    }
  }

  /**
   * Guardian decrypts their share from backup stored on the blockchain.
   *
   * @param guardianAccount Guardian's account data
   * @param ownerAccountId Owner's account ID to look up backup in contract
   * @param nonce Nonce of the backup to decrypt
   * @param swafeContract Contract instance to query state
   * @return GuardianClaim containing the decrypted share claim
   */
  public static GuardianSecretShare guardianDecryptShareFromContract(
      AccountManager.AccountData guardianAccount,
      String ownerAccountId,
      String backupIdStr,
      com.partisiablockchain.language.abicodegen.SwafeContract swafeContract)
      throws IOException, InterruptedException {
    // Load backup from contract
    String backupCiphertextStr = loadBackupFromContract(ownerAccountId, backupIdStr, swafeContract);

    // Create a temporary BackupResult to use existing logic
    BackupResult backupResult =
        new BackupResult(backupCiphertextStr, ownerAccountId, 0, 0, backupIdStr);

    return guardianDecryptShare(guardianAccount, backupResult);
  }

  /**
   * Recover secret data from backup stored on blockchain using verified guardian shares.
   *
   * @param ownerAccount Owner's account data
   * @param ownerAccountId Owner's account ID to look up backup in contract
   * @param backupIdStr StrEncoded backup ID
   * @param verifiedShares List of verified shares from guardians
   * @param swafeContract Contract instance to query state
   * @return Recovered secret data as hex string
   */
  public static String recoverSecretFromContract(
      AccountManager.AccountData ownerAccount,
      String ownerAccountId,
      String backupIdStr,
      List<GuardianShare> guardianShares,
      com.partisiablockchain.language.abicodegen.SwafeContract swafeContract)
      throws IOException, InterruptedException {
    // Load backup from contract
    String backupCiphertextStr = loadBackupFromContract(ownerAccountId, backupIdStr, swafeContract);

    // Create a temporary BackupResult to use existing logic
    BackupResult backupResult =
        new BackupResult(backupCiphertextStr, ownerAccountId, 0, 0, backupIdStr);

    return recoverSecret(ownerAccount, backupResult, guardianShares);
  }

  /** Get list of recoverable backups from account state */
  public static List<Integer> getRecoverableBackupIds(
      AccountManager.AccountData ownerAccount,
      TestExecutionEngine engine,
      com.partisiablockchain.BlockchainAddress swafeAddress)
      throws IOException {
    logger.debug(
        "Getting recoverable backups for account: {}...",
        ownerAccount.accountIdStr.substring(0, 16));

    // Create request to get account state
    String requestBody = "{\"account_id\":\"" + ownerAccount.accountIdStr + "\"}";

    HttpRequestData getStateRequest =
        new HttpRequestData("POST", "/account/get", java.util.Map.of(), requestBody);

    HttpResponseData response = engine.makeHttpRequest(swafeAddress, getStateRequest).response();

    if (response.statusCode() == 200) {
      // Parse the response to extract backup IDs
      ObjectMapper mapper = new ObjectMapper();
      JsonNode jsonNode = mapper.readTree(response.bodyAsText());
      String accountStateStr = jsonNode.get("account_state").asText();

      // The account state contains the list of recoverable backups
      // For now, we'll return a placeholder list - this would need proper parsing
      logger.debug("Retrieved account state with recoverable backups");
      List<Integer> backupIds = new ArrayList<>();
      // TODO: Parse the account state to extract backup IDs from the backups field
      return backupIds;
    } else {
      throw new RuntimeException(
          "Failed to get account state: " + response.statusCode() + " - " + response.bodyAsText());
    }
  }

  /**
   * Upload a guardian share to the contract via the reconstruction endpoint
   *
   * @param guardianShare The guardian share to upload
   * @param accountIdStr The owner account ID
   * @param backupIdStr The backup ID
   * @param swafeAddress The contract address
   * @param swafeContract The contract instance for validation
   * @return Response from the upload request
   */
  public static HttpResponseData uploadGuardianShareToContract(
      GuardianShare guardianShare,
      String accountIdStr,
      String backupIdStr,
      com.partisiablockchain.BlockchainAddress swafeAddress,
      com.partisiablockchain.language.abicodegen.SwafeContract swafeContract)
      throws IOException, InterruptedException {
    logger.debug("Uploading guardian share to contract via reconstruction endpoint...");

    // First verify the account exists in the contract state
    try {
      com.partisiablockchain.language.abicodegen.SwafeContract.ContractState contractState =
          swafeContract.getState();
      com.partisiablockchain.language.codegenlib.AvlTreeMap<byte[], byte[]> accounts =
          contractState.accounts();

      byte[] accountIdBytes = java.util.Base64.getUrlDecoder().decode(accountIdStr);
      byte[] accountBytes = accounts.get(accountIdBytes);

      if (accountBytes == null) {
        throw new RuntimeException("Account not found in contract state: " + accountIdStr);
      }

      logger.debug("Account found in contract state, proceeding with guardian share upload");
    } catch (Exception e) {
      logger.error("Error verifying account state: {}", e.getMessage());
      throw new RuntimeException("Failed to verify account state before upload", e);
    }

    // Create upload guardian share request using CLI
    Path requestPath = Files.createTempFile("upload_guardian_share_request", ".json");

    List<String> command =
        CliHelper.buildCommand(
            "create-upload-guardian-share-request",
            "--account-id",
            accountIdStr,
            "--backup-id",
            backupIdStr,
            "--guardian-share",
            guardianShare.shareStr,
            "--output",
            requestPath.toString());

    CliHelper.runCommand(command, "Creating upload guardian share request");

    String requestJson = Files.readString(requestPath);

    // Make HTTP request to reconstruction/upload-share endpoint
    HttpRequestData uploadRequest =
        new HttpRequestData(
            "POST", "/reconstruction/upload-share", java.util.Map.of(), requestJson);

    TestExecutionEngine engine = VdrfSetup.getTestEngines()[0]; // Use first engine
    return engine.makeHttpRequest(swafeAddress, uploadRequest).response();
  }

  /**
   * Get all guardian shares from the contract via the reconstruction endpoint
   *
   * @param accountIdStr The owner account ID
   * @param backupIdStr The backup ID
   * @param swafeAddress The contract address
   * @param swafeContract The contract instance for validation
   * @return List of guardian shares retrieved from the contract
   */
  public static List<GuardianShare> getGuardianSharesFromContract(
      String accountIdStr,
      String backupIdStr,
      com.partisiablockchain.BlockchainAddress swafeAddress,
      com.partisiablockchain.language.abicodegen.SwafeContract swafeContract)
      throws IOException, InterruptedException {
    logger.debug("Getting guardian shares from contract via reconstruction endpoint...");

    // Create get guardian shares request using CLI
    Path requestPath = Files.createTempFile("get_guardian_shares_request", ".json");

    List<String> command =
        CliHelper.buildCommand(
            "create-get-guardian-shares-request",
            "--account-id",
            accountIdStr,
            "--backup-id",
            backupIdStr,
            "--output",
            requestPath.toString());

    CliHelper.runCommand(command, "Creating get guardian shares request");

    String requestJson = Files.readString(requestPath);

    // Make HTTP request to reconstruction/get-shares endpoint
    HttpRequestData getRequest =
        new HttpRequestData("POST", "/reconstruction/get-shares", java.util.Map.of(), requestJson);

    TestExecutionEngine engine = VdrfSetup.getTestEngines()[0]; // Use first engine
    HttpResponseData response = engine.makeHttpRequest(swafeAddress, getRequest).response();

    if (response.statusCode() != 200) {
      throw new RuntimeException(
          "Failed to get guardian shares: "
              + response.statusCode()
              + " - "
              + response.bodyAsText());
    }

    // Parse response to extract guardian shares
    ObjectMapper mapper = new ObjectMapper();
    JsonNode responseJson = mapper.readTree(response.bodyAsText());
    JsonNode sharesArray = responseJson.get("shares");

    List<GuardianShare> guardianShares = new ArrayList<>();
    for (JsonNode shareNode : sharesArray) {
      String shareStr = shareNode.asText();
      GuardianShare guardianShare = new GuardianShare(shareStr, -1); // Index not used here
      guardianShares.add(guardianShare);
    }

    logger.debug("Retrieved {} guardian shares from contract", guardianShares.size());
    return guardianShares;
  }

  /**
   * Test the complete reconstruction endpoint workflow: 1. Create backup and upload to contract 2.
   * Guardians decrypt their shares 3. Guardians upload shares via /reconstruction/upload-share 4.
   * Owner retrieves shares via /reconstruction/get-shares 5. Owner recovers secret using retrieved
   * shares
   */
  public static void testReconstructionEndpointWorkflow(
      AccountManager.AccountData ownerAccount,
      List<AccountManager.AccountData> guardianAccounts,
      int threshold,
      String secretData,
      String backupName,
      String backupDescription,
      Object blockchain,
      com.partisiablockchain.BlockchainAddress account,
      com.partisiablockchain.BlockchainAddress swafeAddress,
      com.partisiablockchain.language.abicodegen.SwafeContract swafeContract)
      throws IOException, InterruptedException {
    logger.debug("===== RECONSTRUCTION ENDPOINT WORKFLOW =====");
    logger.debug(
        "Testing complete workflow using /reconstruction/upload-share and /reconstruction/get-shares endpoints");

    // Step 1: Create backup and upload to contract
    logger.debug("Step 1: Creating and uploading backup to contract...");
    BackupResult backupResult =
        createAndUploadBackup(
            ownerAccount,
            guardianAccounts,
            threshold,
            secretData,
            backupName,
            backupDescription,
            blockchain,
            account,
            swafeAddress);

    // Step 2: Guardian share decryption
    logger.debug("Step 2: Guardian share decryption...");
    List<GuardianSecretShare> secretShares = new ArrayList<>();
    List<GuardianShare> guardianShares = new ArrayList<>();

    for (int i = 0; i < guardianAccounts.size(); i++) {
      AccountManager.AccountData guardianAccount = guardianAccounts.get(i);

      // Guardian decrypts their share (local operation)
      GuardianSecretShare secretShare = guardianDecryptShare(guardianAccount, backupResult);
      secretShares.add(secretShare);

      // Convert to guardian share for reconstruction
      GuardianShare guardianShare = createGuardianShare(ownerAccount, secretShare, backupResult);
      guardianShares.add(guardianShare);
    }

    // Step 3: Debug account state before upload
    logger.debug("Account ID for reconstruction: {}", backupResult.accountIdStr);
    logger.debug("Backup ID for reconstruction: {}", backupResult.backupIdStr);

    // Step 3: Guardians upload shares via reconstruction endpoint
    logger.debug("Step 3: Uploading guardian shares via reconstruction endpoint...");
    for (int i = 0; i < guardianShares.size(); i++) {
      GuardianShare guardianShare = guardianShares.get(i);

      HttpResponseData uploadResponse =
          uploadGuardianShareToContract(
              guardianShare,
              backupResult.accountIdStr,
              backupResult.backupIdStr,
              swafeAddress,
              swafeContract);

      if (uploadResponse.statusCode() != 200) {
        logger.error(
            "Failed to upload guardian share {}: {} - {}",
            i,
            uploadResponse.statusCode(),
            uploadResponse.bodyAsText());
        logger.error("Account ID: {}", backupResult.accountIdStr);
        logger.error("Backup ID: {}", backupResult.backupIdStr);
        throw new RuntimeException(
            "Failed to upload guardian share "
                + i
                + ": "
                + uploadResponse.statusCode()
                + " - "
                + uploadResponse.bodyAsText());
      }

      logger.debug("Guardian {} share uploaded successfully", i + 1);
    }

    // Step 4: Owner retrieves shares via reconstruction endpoint
    logger.debug("Step 4: Owner retrieving shares via reconstruction endpoint...");
    List<GuardianShare> retrievedShares =
        getGuardianSharesFromContract(
            backupResult.accountIdStr, backupResult.backupIdStr, swafeAddress, swafeContract);

    // Verify we got the expected number of shares
    if (retrievedShares.size() != guardianShares.size()) {
      throw new RuntimeException(
          String.format(
              "Expected %d guardian shares but got %d",
              guardianShares.size(), retrievedShares.size()));
    }

    // Step 5: Recover secret using retrieved shares (use threshold number)
    logger.debug("Step 5: Recovering secret using retrieved guardian shares...");
    List<GuardianShare> thresholdShares = retrievedShares.subList(0, threshold);

    String recoveredSecret = recoverSecret(ownerAccount, backupResult, thresholdShares);

    // Verify recovery worked
    if (!recoveredSecret.equals(secretData)) {
      throw new RuntimeException(
          "Recovered secret does not match original! "
              + "Expected: "
              + secretData
              + ", Got: "
              + recoveredSecret);
    }

    logger.debug("===== RECONSTRUCTION ENDPOINT WORKFLOW COMPLETED SUCCESSFULLY! =====");
    logger.debug(
        "Successfully tested both /reconstruction/upload-share and /reconstruction/get-shares endpoints");
    logger.debug("Secret recovered successfully using reconstruction endpoints");
  }
}
