package com.partisia.blockchain.contract;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Helper class for running CLI commands with the Swafe Rust binary. This class provides a
 * consistent interface for executing CLI operations using static factory methods.
 */
public final class CliHelper {

  private static final Logger logger = LoggerFactory.getLogger(CliHelper.class);

  private CliHelper() {
    // Utility class - no instantiation
  }

  /**
   * Build a CLI command with the given subcommand and arguments.
   *
   * @param subcommand The CLI subcommand to execute
   * @param args Additional arguments for the command
   * @return List of command components ready for ProcessBuilder
   */
  public static List<String> buildCommand(String subcommand, String... args) {
    List<String> command = new ArrayList<>();
    command.add("cargo");
    command.add("run");
    command.add("--bin");
    command.add("swafe-cli");
    command.add("--");
    command.add(subcommand);
    for (String arg : args) {
      command.add(arg);
    }
    return command;
  }

  /**
   * Execute a CLI command with proper error handling and output capture.
   *
   * @param command The command to execute (from buildCommand)
   * @param description Description of the operation for logging
   * @throws IOException If process execution fails
   * @throws InterruptedException If process is interrupted
   * @throws RuntimeException If command exits with non-zero code
   */
  public static void runCommand(List<String> command, String description)
      throws IOException, InterruptedException {
    ProcessResult result = runCommandWithOutput(command, description);
    // For compatibility, this method doesn't return anything
  }

  /**
   * Execute a CLI command and return the result with output.
   *
   * @param command The command to execute (from buildCommand)
   * @param description Description of the operation for logging
   * @return ProcessResult containing output and exit code
   * @throws IOException If process execution fails
   * @throws InterruptedException If process is interrupted
   * @throws RuntimeException If command exits with non-zero code
   */
  public static ProcessResult runCommandWithOutput(List<String> command, String description)
      throws IOException, InterruptedException {
    logger.debug("{}...", description);

    ProcessBuilder builder = new ProcessBuilder(command);
    builder.directory(Path.of("../../cli").toFile());
    builder.environment().put("RUSTFLAGS", "-Awarnings");
    builder.redirectErrorStream(true);

    Process process = builder.start();

    // Simple output handling
    String output = new String(process.getInputStream().readAllBytes());
    int exitCode = process.waitFor();

    if (exitCode != 0) {
      throw new RuntimeException(
          description + " failed with exit code: " + exitCode + "\nOutput: " + output);
    }

    logger.debug("{} completed!", description);
    return new ProcessResult(output, exitCode);
  }

  /** Simple container for process execution results. */
  public static class ProcessResult {

    public final String output;
    public final int exitCode;

    public ProcessResult(String output, int exitCode) {
      this.output = output;
      this.exitCode = exitCode;
    }
  }
}
