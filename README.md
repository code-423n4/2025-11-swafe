# Swafe audit details
- Total Prize Pool: XXX XXX USDC (Airtable: Total award pool)
    - HM awards: up to XXX XXX USDC (Airtable: HM (main) pool)
        - If no valid Highs or Mediums are found, the HM pool is $0 (🐺 C4 EM: adjust in case of tiered pools)
    - QA awards: XXX XXX USDC (Airtable: QA pool)
    - Judge awards: XXX XXX USDC (Airtable: Judge Fee)
    - Scout awards: $500 USDC (Airtable: Scout fee - but usually $500 USDC)
    - (this line can be removed if there is no mitigation) Mitigation Review: XXX XXX USDC
- [Read our guidelines for more details](https://docs.code4rena.com/competitions)
- Starts XXX XXX XX 20:00 UTC (ex. `Starts March 22, 2023 20:00 UTC`)
- Ends XXX XXX XX 20:00 UTC (ex. `Ends March 30, 2023 20:00 UTC`)

### ❗ Important notes for wardens
(🐺 C4 staff: delete the PoC requirement section if not applicable - i.e. for non-Solidity/EVM audits.)
1. A coded, runnable PoC is required for all High/Medium submissions to this audit. 
    - This repo includes a basic template to run the test suite.
    - PoCs must use the test suite provided in this repo.
    - Your submission will be marked as Insufficient if the POC is not runnable and working with the provided test suite.
    - Exception: PoC is optional (though recommended) for wardens with signal ≥ 0.68.
1. Judging phase risk adjustments (upgrades/downgrades):
    - High- or Medium-risk submissions downgraded by the judge to Low-risk (QA) will be ineligible for awards.
    - Upgrading a Low-risk finding from a QA report to a Medium- or High-risk finding is not supported.
    - As such, wardens are encouraged to select the appropriate risk level carefully during the submission phase.

## V12 findings (🐺 C4 staff: remove this section for non-Solidity/EVM audits)

[V12](https://v12.zellic.io/) is [Zellic](https://zellic.io)'s in-house AI auditing tool. It is the only autonomous Solidity auditor that [reliably finds Highs and Criticals](https://www.zellic.io/blog/introducing-v12/). All issues found by V12 will be judged as out of scope and ineligible for awards.

V12 findings will be posted in this section within the first two days of the competition.  

## Publicly known issues

_Anything included in this section is considered a publicly known issue and is therefore ineligible for awards._

## 🐺 C4: Begin Gist paste here (and delete this line)





# Scope

*See [scope.txt](https://github.com/code-423n4/2025-11-swafe/blob/main/scope.txt)*

### Files in scope


| File   | Logic Contracts | Interfaces | nSLOC | Purpose | Libraries used |
| ------ | --------------- | ---------- | ----- | -----   | ------------ |
| /api/src/account/get.rs | ****| **** | 12 | ||
| /api/src/account/mod.rs | ****| **** | 1 | ||
| /api/src/association/get_secret_share.rs | ****| **** | 14 | ||
| /api/src/association/mod.rs | ****| **** | 3 | ||
| /api/src/association/upload_msk.rs | ****| **** | 16 | ||
| /api/src/association/vdrf/eval.rs | ****| **** | 13 | ||
| /api/src/association/vdrf/mod.rs | ****| **** | 1 | ||
| /api/src/init.rs | ****| **** | 24 | ||
| /api/src/lib.rs | ****| **** | 4 | ||
| /api/src/reconstruction/get_shares.rs | ****| **** | 14 | ||
| /api/src/reconstruction/mod.rs | ****| **** | 2 | ||
| /api/src/reconstruction/upload_share.rs | ****| **** | 16 | ||
| /cli/src/commands/account.rs | ****| **** | 299 | ||
| /cli/src/commands/association.rs | ****| **** | 241 | ||
| /cli/src/commands/backup.rs | ****| **** | 182 | ||
| /cli/src/commands/mod.rs | ****| **** | 6 | ||
| /cli/src/commands/reconstruction.rs | ****| **** | 65 | ||
| /cli/src/commands/utils.rs | ****| **** | 126 | ||
| /cli/src/commands/vdrf.rs | ****| **** | 135 | ||
| /cli/src/main.rs | ****| **** | 540 | ||
| /contracts/src/http/endpoints/account/get.rs | ****| **** | 31 | ||
| /contracts/src/http/endpoints/account/mod.rs | ****| **** | 10 | ||
| /contracts/src/http/endpoints/association/get_secret_share.rs | ****| **** | 47 | ||
| /contracts/src/http/endpoints/association/mod.rs | ****| **** | 21 | ||
| /contracts/src/http/endpoints/association/upload_msk.rs | ****| **** | 59 | ||
| /contracts/src/http/endpoints/association/vdrf/eval.rs | ****| **** | 49 | ||
| /contracts/src/http/endpoints/association/vdrf/mod.rs | ****| **** | 10 | ||
| /contracts/src/http/endpoints/init.rs | ****| **** | 65 | ||
| /contracts/src/http/endpoints/mod.rs | ****| **** | 4 | ||
| /contracts/src/http/endpoints/reconstruction/get_shares.rs | ****| **** | 31 | ||
| /contracts/src/http/endpoints/reconstruction/mod.rs | ****| **** | 19 | ||
| /contracts/src/http/endpoints/reconstruction/upload_share.rs | ****| **** | 52 | ||
| /contracts/src/http/error.rs | ****| **** | 89 | ||
| /contracts/src/http/json.rs | ****| **** | 25 | ||
| /contracts/src/http/mod.rs | ****| **** | 115 | ||
| /contracts/src/lib.rs | ****| **** | 88 | ||
| /contracts/src/storage.rs | ****| **** | 22 | ||
| /lib/src/account/mod.rs | ****| **** | 112 | ||
| /lib/src/account/tests.rs | ****| **** | 635 | ||
| /lib/src/account/v0.rs | ****| **** | 646 | ||
| /lib/src/association/mod.rs | ****| **** | 78 | ||
| /lib/src/association/v0.rs | ****| **** | 628 | ||
| /lib/src/backup/mod.rs | ****| **** | 36 | ||
| /lib/src/backup/tests.rs | ****| **** | 450 | ||
| /lib/src/backup/v0.rs | ****| **** | 359 | ||
| /lib/src/crypto/commitments.rs | ****| **** | 283 | ||
| /lib/src/crypto/curve.rs | ****| **** | 8 | ||
| /lib/src/crypto/email_cert.rs | ****| **** | 131 | ||
| /lib/src/crypto/hash.rs | ****| **** | 97 | ||
| /lib/src/crypto/mod.rs | ****| **** | 16 | ||
| /lib/src/crypto/pairing.rs | ****| **** | 348 | ||
| /lib/src/crypto/pke/mod.rs | ****| **** | 469 | ||
| /lib/src/crypto/pke/v0.rs | ****| **** | 268 | ||
| /lib/src/crypto/poly.rs | ****| **** | 128 | ||
| /lib/src/crypto/sig/mod.rs | ****| **** | 75 | ||
| /lib/src/crypto/sig/v0.rs | ****| **** | 124 | ||
| /lib/src/crypto/sss.rs | ****| **** | 148 | ||
| /lib/src/crypto/symmetric.rs | ****| **** | 188 | ||
| /lib/src/crypto/vdrf.rs | ****| **** | 336 | ||
| /lib/src/encode.rs | ****| **** | 243 | ||
| /lib/src/errors.rs | ****| **** | 51 | ||
| /lib/src/lib.rs | ****| **** | 12 | ||
| /lib/src/node.rs | ****| **** | 52 | ||
| /lib/src/types.rs | ****| **** | 91 | ||
| /lib/src/venum.rs | ****| **** | 259 | ||
| **Totals** | **** | **** | **8722** | | |

### Files out of scope

*See [out_of_scope.txt](https://github.com/code-423n4/2025-11-swafe/blob/main/out_of_scope.txt)*

| File         |
| ------------ |
| Totals: 0 |

