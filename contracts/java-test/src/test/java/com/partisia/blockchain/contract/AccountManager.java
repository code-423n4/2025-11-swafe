package com.partisia.blockchain.contract;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.partisiablockchain.BlockchainAddress;
import com.partisiablockchain.language.abicodegen.SwafeContract;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Account management helper that handles account allocation and updates. */
public final class AccountManager {

  private static final Logger logger = LoggerFactory.getLogger(AccountManager.class);

  private AccountManager() {
    // Utility class - no instantiation
  }

  /** Account allocation data */
  public static class AccountData {

    public final String accountUpdateStr;
    public final String accountIdStr;
    public final String accountStateStr;
    public final String masterSecretKeyStr;

    public AccountData(
        String accountUpdateStr,
        String accountIdStr,
        String accountStateStr,
        String masterSecretKeyStr) {
      this.accountUpdateStr = accountUpdateStr;
      this.accountIdStr = accountIdStr;
      this.accountStateStr = accountStateStr;
      this.masterSecretKeyStr = masterSecretKeyStr;
    }
  }

  /** Generate account allocation data and perform blockchain allocation */
  public static AccountData generateAccountAllocation(
      Object blockchain, BlockchainAddress account, BlockchainAddress swafeAddress)
      throws IOException, InterruptedException {
    logger.debug("Generating account allocation...");

    // Use the simple file name directly since we only need one allocation file for the account
    // update workflow
    Path outputPath = Path.of("src/test/resources/account_allocation_simple.json");

    List<String> command =
        CliHelper.buildCommand(
            "generate-account-allocation", "--output", outputPath.toAbsolutePath().toString());

    CliHelper.runCommand(command, "Generating account allocation");

    // Parse the JSON response
    String jsonContent = Files.readString(outputPath);
    ObjectMapper mapper = new ObjectMapper();
    JsonNode data = mapper.readTree(jsonContent);

    AccountData accountData =
        new AccountData(
            data.get("account_update").asText(),
            data.get("account_id").asText(),
            data.get("account_state").asText(),
            data.get("master_secret_key").asText());

    // Perform blockchain allocation
    logger.debug(
        "Generated account allocation: {}...",
        accountData.accountUpdateStr.substring(
            0, Math.min(50, accountData.accountUpdateStr.length())));
    logger.debug(
        "Account ID: {}...",
        accountData.accountIdStr.substring(0, Math.min(20, accountData.accountIdStr.length())));

    // Call the contract function to update the account (initial allocation)
    byte[] allocationRpc = SwafeContract.updateAccount(accountData.accountUpdateStr);

    // Use reflection to call sendAction since we can't import the blockchain type directly
    try {
      java.lang.reflect.Method sendAction =
          blockchain
              .getClass()
              .getMethod(
                  "sendAction", BlockchainAddress.class, BlockchainAddress.class, byte[].class);
      sendAction.invoke(blockchain, account, swafeAddress, allocationRpc);
      logger.debug("Account allocated successfully onchain!");
    } catch (Exception e) {
      throw new RuntimeException("Failed to perform blockchain allocation", e);
    }

    return accountData;
  }

  /** Generate account update data using previous allocation */
  public static AccountData generateAccountUpdate(String initialAllocationFile)
      throws IOException, InterruptedException {
    logger.debug("Generating account update...");

    Path outputPath = Path.of("src/test/resources/account_update_simple.json");

    List<String> command =
        CliHelper.buildCommand(
            "generate-account-update",
            "--initial-allocation",
            new java.io.File(initialAllocationFile).getAbsolutePath(),
            "--output",
            outputPath.toAbsolutePath().toString());

    CliHelper.runCommand(command, "Generating account update");

    // Parse the JSON response
    String jsonContent = Files.readString(outputPath);
    ObjectMapper mapper = new ObjectMapper();
    JsonNode data = mapper.readTree(jsonContent);

    return new AccountData(
        data.get("account_update").asText(),
        data.get("account_id").asText(),
        data.get("account_state").asText(),
        data.get("master_secret_key").asText());
  }
}
