# Swafe audit details
- Total Prize Pool: $100,000 in USDC 
    - HM awards: up to $81,600 in USDC
        - If no valid Highs or Mediums are found, the HM pool is $0
    - QA awards: $3,400 in USDC
    - Judge awards: $2,500 in USDC
    - Scout awards: $500 in USDC
    - Mitigation Review: $12,000 in USDC
- [Read our guidelines for more details](https://docs.code4rena.com/competitions)
- Starts November 18, 2025 20:00 UTC 
- Ends December 9, 2025 20:00 UTC 

### ❗ Important notes for wardens
1. Judging phase risk adjustments (upgrades/downgrades):
    - High- or Medium-risk submissions downgraded by the judge to Low-risk (QA) will be ineligible for awards.
    - Upgrading a Low-risk finding from a QA report to a Medium- or High-risk finding is not supported.
    - As such, wardens are encouraged to select the appropriate risk level carefully during the submission phase.

## Publicly known issues

_Anything included in this section is considered a publicly known issue and is therefore ineligible for awards._

### API

Denial-of-Service attacks for HTTP endpoints are not considered in scope as HM issues, and should be submitted as part of a QA report.

# Overview

This Repository contains the Swafe library, which can be used as SDK for building Swafe-based clients, as well as for creating Swafe-based partisia contracts.

The protocol implementation is based on the [Swafe Book](https://github.com/zksecurity/swafe-book) specification.

## Project Structure

- `/lib` - Core Rust library implementation with cryptographic primitives
- `/contracts` - Smart contract code for Partisia blockchain deployment
- `/cli` - Command-line interface for testing wallet operations and recovery
- `/api` - REST API implementation for wallet services

## Links

- **Previous audits:**  No previous audit reports.
- **Documentation:** https://github.com/swafe-io/swafe-book
- **Website:** https://swafe.io/
- **X/Twitter:** https://x.com/swafe_io
- **Code walk-through:** https://youtu.be/FO2jbib8C7o

---

# Scope

### Files in scope

| File   | nSLOC |
| ------ | ----- |
|[api/src/account/get.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/api/src/account/get.rs)| 12 |
|[api/src/account/mod.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/api/src/account/mod.rs)| 1 |
|[api/src/association/get_secret_share.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/api/src/association/get_secret_share.rs)| 14 |
|[api/src/association/mod.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/api/src/association/mod.rs)| 3 |
|[api/src/association/upload_msk.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/api/src/association/upload_msk.rs)| 16 |
|[api/src/association/vdrf/eval.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/api/src/association/vdrf/eval.rs)| 13 |
|[api/src/association/vdrf/mod.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/api/src/association/vdrf/mod.rs)| 1 |
|[api/src/init.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/api/src/init.rs)| 24 |
|[api/src/lib.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/api/src/lib.rs)| 4 |
|[api/src/reconstruction/get_shares.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/api/src/reconstruction/get_shares.rs)| 14 |
|[api/src/reconstruction/mod.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/api/src/reconstruction/mod.rs)| 2 |
|[api/src/reconstruction/upload_share.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/api/src/reconstruction/upload_share.rs)| 16 |
|[contracts/src/http/endpoints/account/get.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/contracts/src/http/endpoints/account/get.rs)| 31 |
|[contracts/src/http/endpoints/account/mod.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/contracts/src/http/endpoints/account/mod.rs)| 10 |
|[contracts/src/http/endpoints/association/get_secret_share.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/contracts/src/http/endpoints/association/get_secret_share.rs)| 47 |
|[contracts/src/http/endpoints/association/mod.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/contracts/src/http/endpoints/association/mod.rs)| 21 |
|[contracts/src/http/endpoints/association/upload_msk.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/contracts/src/http/endpoints/association/upload_msk.rs)| 59 |
|[contracts/src/http/endpoints/association/vdrf/eval.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/contracts/src/http/endpoints/association/vdrf/eval.rs)| 49 |
|[contracts/src/http/endpoints/association/vdrf/mod.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/contracts/src/http/endpoints/association/vdrf/mod.rs)| 10 |
|[contracts/src/http/endpoints/init.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/contracts/src/http/endpoints/init.rs)| 65 |
|[contracts/src/http/endpoints/mod.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/contracts/src/http/endpoints/mod.rs)| 4 |
|[contracts/src/http/endpoints/reconstruction/get_shares.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/contracts/src/http/endpoints/reconstruction/get_shares.rs)| 31 |
|[contracts/src/http/endpoints/reconstruction/mod.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/contracts/src/http/endpoints/reconstruction/mod.rs)| 19 |
|[contracts/src/http/endpoints/reconstruction/upload_share.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/contracts/src/http/endpoints/reconstruction/upload_share.rs)| 52 |
|[contracts/src/http/error.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/contracts/src/http/error.rs)| 89 |
|[contracts/src/http/json.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/contracts/src/http/json.rs)| 25 |
|[contracts/src/http/mod.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/contracts/src/http/mod.rs)| 115 |
|[contracts/src/lib.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/contracts/src/lib.rs)| 88 |
|[contracts/src/storage.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/contracts/src/storage.rs)| 22 |
|[lib/src/account/mod.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/lib/src/account/mod.rs)| 112 |
|[lib/src/account/tests.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/lib/src/account/tests.rs)| 635 |
|[lib/src/account/v0.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/lib/src/account/v0.rs)| 646 |
|[lib/src/association/mod.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/lib/src/association/mod.rs)| 78 |
|[lib/src/association/v0.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/lib/src/association/v0.rs)| 628 |
|[lib/src/backup/mod.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/lib/src/backup/mod.rs)| 36 |
|[lib/src/backup/tests.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/lib/src/backup/tests.rs)| 450 |
|[lib/src/backup/v0.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/lib/src/backup/v0.rs)| 359 |
|[lib/src/crypto/commitments.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/lib/src/crypto/commitments.rs)| 283 |
|[lib/src/crypto/curve.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/lib/src/crypto/curve.rs)| 8 |
|[lib/src/crypto/email_cert.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/lib/src/crypto/email_cert.rs)| 131 |
|[lib/src/crypto/hash.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/lib/src/crypto/hash.rs)| 97 |
|[lib/src/crypto/mod.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/lib/src/crypto/mod.rs)| 16 |
|[lib/src/crypto/pairing.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/lib/src/crypto/pairing.rs)| 348 |
|[lib/src/crypto/pke/mod.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/lib/src/crypto/pke/mod.rs)| 469 |
|[lib/src/crypto/pke/v0.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/lib/src/crypto/pke/v0.rs)| 268 |
|[lib/src/crypto/poly.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/lib/src/crypto/poly.rs)| 128 |
|[lib/src/crypto/sig/mod.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/lib/src/crypto/sig/mod.rs)| 75 |
|[lib/src/crypto/sig/v0.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/lib/src/crypto/sig/v0.rs)| 124 |
|[lib/src/crypto/sss.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/lib/src/crypto/sss.rs)| 148 |
|[lib/src/crypto/symmetric.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/lib/src/crypto/symmetric.rs)| 188 |
|[lib/src/crypto/vdrf.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/lib/src/crypto/vdrf.rs)| 336 |
|[lib/src/encode.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/lib/src/encode.rs)| 243 |
|[lib/src/errors.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/lib/src/errors.rs)| 51 |
|[lib/src/lib.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/lib/src/lib.rs)| 12 |
|[lib/src/node.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/lib/src/node.rs)| 52 |
|[lib/src/types.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/lib/src/types.rs)| 91 |
|[lib/src/venum.rs](https://github.com/code-423n4/2025-11-swafe/blob/main/lib/src/venum.rs)| 259 |
|**Totals**| **7128** |

*For a machine-readable version, see [scope.txt](https://github.com/code-423n4/2025-11-swafe/blob/main/scope.txt)*

### Files out of scope

Any file that is not explicitly listed in the aforementioned list is considered out-of-scope for the purposes of this audit contest.

| File         |
| ------------ |
| [cli/\*\*.\*\*](https://github.com/code-423n4/2025-11-swafe/tree/main/cli) |
| Totals: 8 |

*For a machine-readable version, see [out_of_scope.txt](https://github.com/code-423n4/2025-11-swafe/blob/main/out_of_scope.txt)*

# Additional context

## Areas of concern (where to focus for bugs)

- Unauthorized Backup Reconstruction
- Unauthorized Account Recovery - Without email verification and (optionally) guardian approval
- Backup Ciphertext Security - Stealing or lack of binding for backup ciphertexts to accounts
- Integrity Attacks - Mauling of stored secrets/backups
- Privacy Violations - Anonymity violations from on-chain content or off-chain node interaction, including leakage of user identity (e.g., email addresses)

## Main invariants

- Only the owner of an account should be able to request the reconstruction of a backup.
- Only the owner of an email should be able to request the recovery of an account.
- Recovery of an account only occurs when more than the specified threshold of Guardians has approved the request.
- Recovery of a backup only occurs when more than the specified threshold of Guardians has approved the request.
- After recovering an account, the owner should be able to request and complete recovery of backups as long as there are sufficient Guardians online and off-chain nodes available for relaying shares.
- An email should be associated to at most one account at a time.
- An account may have multiple emails associated for recovery.
- A user should be able to recover his account with only access to his email (and an out-of-band channel for communicating with Guardians).

## All trusted roles in the protocol

### Swafe-io

#### Trust Assumptions

- Keeping user emails confidential.
- Providing "email certificates" only after users prove email possession.
- Generating shares for the VPRF used to hide email ↔ account association during a one-time setup ceremony.

#### Prohibitions

Must not be able to unilaterally cause Guardians to reconstruct or recover an account without explicit permission provided by each guardian.

### Guardians

#### Trust Assumptions

- If a user specifies a reconstruction threshold of `t` out of `n` nodes, we assume at least `t` of the selected guardians for that backup are honest for liveness and `n-t` for secrecy.

#### General Assumptions

- Any number of corrupted guardians may exist in the system.
- Honest users manually select guardians they trust (friends, family, trusted institutions).
- The user-selected threshold `t` infers that at least `t `guardians are willing to reconstruct.
- The user-selected threshold `t` infers that at most `t-1` guardians are corrupted/malicious.

#### Exception

If both of the following conditions hold:
- Swafe-io is honest
- Off-chain nodes are honest

Then backups/accounts remain unrecoverable even if all Guardians are corrupted.

### Off-Chain Nodes

#### Varying Security Model

Off-chain nodes are full nodes capable of running off-chain computation and holding secret state. Security guarantees vary based on the corruption model:

#### No Corrupted Off-Chain Nodes

- User emails remain hidden even at registration/recovery time.

#### Minority of Off-Chain Nodes Corrupted

- Snapshot of corrupted off-chain node states hides user emails and account associations.
- Leaking an off-chain node's state does not reveal user emails or their association to on-chain contracts.
- Secrets without specified guardians remain decryptable without a valid "email certificate" from Swafe.
- The system remains available even if a minority subset of off-chain nodes are offline or unresponsive.

#### Minority of Off-Chain Nodes Honest

- Secrets specifying guardians remain undecryptable

## Running tests

### Prerequisites

The Swafe codebase represents a library meant to assist in the programming of Partisia blockchain contracts. Beyond the Rust runtime and Just dependency required for compiling the system, the project also relies on the Java runtime and Apache Maven toolkit to execute tests. 

The codebase was successfully compiled with the following dependencies on an Ubuntu `24.04.3` LTS system:

- Java (`javac`): 17.0.16
- Apache Maven: 3.8.7 
- Rust (`rustc`): 1.91.1
- Just: 1.43.1
- Partisia (`cargo-pbc`): 5.411.0

To note, **the Java, Rust, and Partisia dependencies pertain to the Partisia contract system and are not related to the code of the project itself**.

#### Installing Java & Apache Maven

The codebase requires the JDK version `17` and upward to be able to run tests. For Unix-like systems, please install Java through your respective package manager, f.e.:

```bash!
sudo apt install openjdk-17-jdk
```

Once Java is installed and available, the Apache Maven package can either be [downloaded](https://maven.apache.org/download.cgi) or installed through your respective package manager, f.e.:

```bash!
sudo apt install maven
```

#### Installing Rust & Just

Rust can be installed via a bundled script available in the [official Rust page](https://rust-lang.org/tools/install/), f.e.:

```bash!
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

The `stable` release is sufficient for compiling the project. After `rust` has been properly installed, the `just` script execution tool must be installed [via the relevant steps for your OS](https://github.com/casey/just), f.e.:

```bash!
apt install just
```

#### Partisia Contract Builder

This section covers the installation of the Partisia Contract Builder, which can also be found at [this link](https://docs.partisia.com/platform/build-on/development-setup.html).

For the system to compile, the `pbc` command must be available through the `cargo` Rust toolkit. To achieve this, the `cargo-partisia-contract` package must be installed. It depends on OpenSSL as well as the `pkg-config` packages:

```bash!
sudo apt install pkg-config
```

Afterward, the package can be installed via the following command:

```bash!
cargo install cargo-partisia-contract
```

### Running Tests

To run tests, the `just` tool's `test` script must be executed:

```bash!
just test
```

## Miscellaneous

Employees of Swafe and employees' family members are ineligible to participate in this audit.

Code4rena's rules cannot be overridden by the contents of this README. In case of doubt, please check with C4 staff.

