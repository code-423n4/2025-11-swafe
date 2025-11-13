# Swafe Blockchain Components

This Repository contains the Swafe library, which can be used as SDK for building Swafe-based clients, as well as for creating Swafe-based partisia contracts.

The protocol implementation is based on the [Swafe Book](https://github.com/zksecurity/swafe-book) specification.

## Project Structure

- `/lib` - Core Rust library implementation with cryptographic primitives
- `/contracts` - Smart contract code for Partisia blockchain deployment
- `/cli` - Command-line interface for testing wallet operations and recovery
- `/api` - REST API implementation for wallet services

## Building and Testing

### Prerequisites

- Rust toolchain (latest stable)
- Java 11+ for contract testing
- Maven for Java dependencies

### Quick Start

```bash
# Run all tests
just test

# Format code
just fmt

# Check code formatting
just check-fmt
```

### Integration Testing

End-to-end testing is available through:
- [Java test suite](./contracts/java-test/src/test/java/com/partisia/blockchain/contract/SwafeContractTest.java) - Full workflow testing on Partisia blockchain
- [CLI demonstrations](./lib/src/bin/main.rs) - Client-side library usage examples
- [Shell scripts](./build-and-deploy.sh) - Contract deployment and [full cycle testing](./integration-test/test_vdrf_workflow.sh)

The integration test Docker image can be built from the [Partisia execution container repository](https://gitlab.com/partisiablockchain/core/execution-container/-/blob/656359ed432fd85d6f864ae225f9c09bdc11f4af/execution-engine-standalone/README.md#L10).
