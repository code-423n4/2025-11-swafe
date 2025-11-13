#[macro_use]
extern crate pbc_contract_codegen;

mod http;
mod storage;

use pbc_contract_common::address::Address;
use pbc_contract_common::avl_tree_map::AvlTreeMap;

use pbc_contract_common::context::ContractContext;
use read_write_rpc_derive::ReadWriteRPC;
use swafe_lib::account::{AccountId, AccountState, AccountUpdate};
use swafe_lib::crypto::{sig, vdrf::VdrfPublicKey};
use swafe_lib::encode;
use swafe_lib::NodeId;

use create_type_spec_derive::CreateTypeSpec;
use read_write_state_derive::ReadWriteState;

/// State of the contract
#[state]
struct ContractState {
    /// Offchain node configurations mapped by node_id
    nodes: AvlTreeMap<String, OffchainNodeState>,
    /// Swafe public key for EmailCert verification
    swafe_public_key: Vec<u8>,
    /// VDRF public key for VDRF operations
    vdrf_public_key: Vec<u8>,
    /// Map account id to serialized account object
    accounts: AvlTreeMap<[u8; 32], Vec<u8>>,
}

impl ContractState {
    fn get_account(&self, id: AccountId) -> Option<AccountState> {
        self.accounts
            .get(id.as_ref())
            .map(|data| encode::deserialize(&data).expect("failed to deserialize account"))
    }

    fn set_account(&mut self, id: AccountId, account: AccountState) {
        self.accounts.insert(
            *id.as_ref(),
            encode::serialize(&account).expect("failed to serialize account"),
        );
    }
}

#[derive(Clone, ReadWriteState, CreateTypeSpec, ReadWriteRPC)]
struct OffchainNodeState {
    /// Node's Partisia address
    pub address: Address,
    /// Node's public key for signature verification
    pub public_key: Vec<u8>,
    /// Node off-chain url (must be HTTPS),
    /// e.g. https://node.example.com/node_url/
    pub url: String,
    /// Commitment to the node's offchain secret (hash of OffchainSecret)
    pub comm: [u8; 32],
}

#[derive(Clone, ReadWriteRPC, CreateTypeSpec, ReadWriteState)]
struct OffchainNodeSetup {
    pub state: OffchainNodeState,
    pub node_id: String,
}

/// Initialize a new Swafe contract with VDRF node configurations.
///
/// # Arguments
///
/// * `_ctx` - the contract context containing information about the sender and the blockchain.
/// * `nodes` - configurations for VDRF nodes
/// * `swafe_public_key` - Swafe public key string for EmailCert verification
/// * `vdrf_public_key` - VDRF public key string for VDRF operations
///
/// # Returns
///
/// The initial state of the Swafe contract.
#[init]
fn initialize(
    _ctx: ContractContext,
    nodes: Vec<OffchainNodeSetup>,
    swafe_public_key: String,
    vdrf_public_key: String,
) -> ContractState {
    // Insert nodes into the map using their node_id as the key
    let mut node_map = AvlTreeMap::new();
    for node in nodes.into_iter() {
        let node_id: NodeId = node.node_id.parse().expect("Failed to parse node ID");
        node_map.insert(node_id.to_string(), node.state);
    }

    let swafe_public_key: sig::VerificationKey = encode::deserialize_str(swafe_public_key.as_str())
        .expect("Failed to deserialize swafe public key");

    let vdrf_public_key: VdrfPublicKey = encode::deserialize_str(vdrf_public_key.as_str())
        .expect("Failed to deserialize vdrf public key");

    ContractState {
        nodes: node_map,
        swafe_public_key: encode::serialize(&swafe_public_key).unwrap(),
        vdrf_public_key: encode::serialize(&vdrf_public_key).unwrap(),
        accounts: AvlTreeMap::new(),
    }
}

#[action]
fn update_account(
    _ctx: ContractContext,
    mut state: ContractState,
    update_str: String,
) -> ContractState {
    // deserialize the account update from a string,
    let update: AccountUpdate =
        encode::deserialize_str(update_str.as_str()).expect("Failed to decode account update");

    // retrieve the *claimed* account ID
    let account_id = update.unsafe_account_id();

    // retrieve the old account state
    let st_old: Option<AccountState> = state
        .accounts
        .get(account_id.as_ref())
        .map(|bytes| encode::deserialize(&bytes).expect("failed to deserialize account state"));

    // verify the update using the lib
    let st_new = update
        .verify(st_old.as_ref())
        .expect("Failed to verify account update");

    // store the updated account state
    state.set_account(account_id, st_new);
    state
}
