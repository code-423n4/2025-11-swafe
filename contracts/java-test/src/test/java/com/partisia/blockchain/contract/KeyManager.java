package com.partisia.blockchain.contract;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Key manager that handles key generation and storage for test scenarios. Stores keys in memory to
 * avoid repeated file I/O operations.
 */
public class KeyManager {

  private static final Logger logger = LoggerFactory.getLogger(KeyManager.class);

  // In-memory storage for generated keys
  private final Map<String, KeyPair> keys = new HashMap<>();

  public static class KeyPair {

    public final String privateKey;
    public final String publicKey;

    public KeyPair(String privateKey, String publicKey) {
      this.privateKey = privateKey;
      this.publicKey = publicKey;
    }
  }

  /** Generate a keypair and store it in memory */
  public KeyPair generateKeypair(String keyName) throws IOException, InterruptedException {
    if (keys.containsKey(keyName)) {
      return keys.get(keyName);
    }

    Path privateKeyPath = Path.of("src/test/resources/" + keyName + "_private_key.txt");
    Path publicKeyPath = Path.of("src/test/resources/" + keyName + "_public_key.txt");

    List<String> command =
        CliHelper.buildCommand(
            "generate-keypair",
            "-s",
            privateKeyPath.toAbsolutePath().toString(),
            "-p",
            publicKeyPath.toAbsolutePath().toString());

    CliHelper.runCommand(command, "Generating " + keyName + " keypair");

    // Read the generated keys
    String privateKey = java.nio.file.Files.readString(privateKeyPath).trim();
    String publicKey = java.nio.file.Files.readString(publicKeyPath).trim();

    KeyPair keyPair = new KeyPair(privateKey, publicKey);
    keys.put(keyName, keyPair);

    return keyPair;
  }

  /** Generate multiple node keypairs */
  public void generateNodeKeypairs(int nodeCount) throws IOException, InterruptedException {
    logger.debug("Generating keypairs for {} VDRF nodes...", nodeCount);

    for (int i = 1; i <= nodeCount; i++) {
      generateKeypair("node_" + i);
    }

    logger.debug("Generated keypairs for {} nodes!", nodeCount);
  }

  /** Get a keypair by name */
  public KeyPair getKeyPair(String keyName) {
    KeyPair keyPair = keys.get(keyName);
    if (keyPair == null) {
      throw new IllegalArgumentException("Key not found: " + keyName);
    }
    return keyPair;
  }

  /** Get public key by name */
  public String getPublicKey(String keyName) {
    return getKeyPair(keyName).publicKey;
  }

  /** Get private key by name */
  public String getPrivateKey(String keyName) {
    return getKeyPair(keyName).privateKey;
  }

  /** Check if a key exists */
  public boolean hasKey(String keyName) {
    return keys.containsKey(keyName);
  }
}
