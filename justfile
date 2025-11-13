# Default recipe
default:
    @just --list

check-fmt-lib:
    cd lib && cargo fmt -- --check

check-fmt-cli:
    cd cli && cargo fmt -- --check

check-fmt-contracts:
    cd contracts && cargo fmt -- --check

check-fmt-api:
    cd api && cargo fmt -- --check

check-fmt-java:
    cd contracts/java-test && mvn fmt:check

check-fmt: \
    check-fmt-lib \
    check-fmt-cli \
    check-fmt-contracts \
    check-fmt-api \
    check-fmt-java

cargo-deny-api:
    cd api && cargo deny check

cargo-deny-lib:
    cd lib && cargo deny check

cargo-deny-contracts:
    cd contracts && cargo deny check

cargo-deny: \
    cargo-deny-api \
    cargo-deny-lib \
    cargo-deny-contracts

cargo-audit-api:
    cd api && cargo audit

cargo-audit-lib:
    cd lib && cargo audit

cargo-audit-contracts:
    cd contracts && cargo audit

cargo-audit: \
    cargo-audit-api \
    cargo-audit-lib \
    cargo-audit-contracts

# Test the entire project (lib tests + contract build + Java integration tests)
test: clean build test-lib test-java

# Test only the Rust library
test-lib:
    cd lib && cargo test

# Test only the Java integration tests (requires contract to be built)
test-java:
    #!/usr/bin/env bash
    set -e
    cd contracts
    cargo pbc build --release
    cd java-test
    mvn clean test

# Build everything (contract + CLI)
build: build-contract build-cli

# Build only the contract
build-contract:
    #!/usr/bin/env bash
    set -e
    cd contracts
    echo "Building Rust contract..."
    cargo clean
    cargo pbc build --release

# Build only the CLI
build-cli:
    #!/usr/bin/env bash
    set -e
    cd lib
    echo "Building CLI..."
    cargo build --release

# Deploy the contract to testnet
deploy:
    #!/usr/bin/env bash
    set -e

    echo "Building and deploying Swafe contract..."

    # Generate keypairs using Swafe CLI
    echo "Generating Swafe operator keypair..."
    cd lib
    cargo run --bin main -- generate-keypair -s ../deploy_swafe_private_key.txt -p ../deploy_swafe_public_key.txt 2>/dev/null

    echo "Generating user keypair..."
    cargo run --bin main -- generate-keypair -s ../deploy_user_private_key.txt -p ../deploy_user_public_key.txt 2>/dev/null

    # Read the Swafe public key for contract initialization
    SWAFE_PUBLIC_KEY=$(cat ../deploy_swafe_public_key.txt)
    echo "Using Swafe public key: $SWAFE_PUBLIC_KEY"

    # Build and deploy
    cd ../contracts
    echo "Building Rust contract to WASM..."
    cargo clean 2>/dev/null
    cargo pbc build --release 2>/dev/null

    echo "Deploying contract to testnet..."
    cargo pbc transaction deploy --net testnet --privatekey ../alice.json --abi target/wasm32-unknown-unknown/release/swafe_contract.abi target/wasm32-unknown-unknown/release/swafe_contract.wasm \[ \] "$SWAFE_PUBLIC_KEY"

    echo "Contract deployed successfully!"

# Clean all build artifacts
clean:
    #!/usr/bin/env bash
    cd lib && cargo clean
    cd ../contracts && cargo clean
    cd java-test && mvn clean

# Format all code (Rust + Java)
fmt: fmt-rust fmt-java

# Format all Rust code
fmt-rust-lib:
    cd lib && cargo fmt

fmt-rust-contracts:
    cd contracts && cargo fmt

fmt-rust-cli:
    cd cli && cargo fmt

fmt-rust-api:
    cd api && cargo fmt

fmt-rust: fmt-rust-lib fmt-rust-contracts fmt-rust-cli fmt-rust-api

# Format Java code
fmt-java:
    cd contracts/java-test && mvn fmt:format

# Lint all Rust code
lint: lint-lib lint-contracts lint-cli lint-api

lint-lib:
    cd lib && cargo clippy

lint-contracts:
    cd contracts && cargo clippy

lint-cli:
	cd cli && cargo clippy

lint-api:
	cd api && cargo clippy

# Install dependencies (pbc CLI)
install-deps:
    cargo install cargo-partisia-contract
