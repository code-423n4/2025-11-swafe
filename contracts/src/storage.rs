use pbc_contract_common::off_chain::{OffChainContext, OffChainStorage};

use serde::de::DeserializeOwned;
use serde::Serialize;
use swafe_lib::encode;

/// Generic mapping trait for off-chain storage operations
pub trait Mapping {
    type Key: Serialize;
    type Value: Serialize + DeserializeOwned;

    const COLLECTION_NAME: &'static str;

    fn load(ctx: &mut OffChainContext, key: Self::Key) -> Option<Self::Value> {
        let storage: OffChainStorage<Vec<u8>, Vec<u8>> =
            ctx.storage(Self::COLLECTION_NAME.as_bytes());
        let key = encode::serialize(&key).unwrap();
        encode::deserialize::<Self::Value>(storage.get(&key)?.as_ref()).ok()
    }

    fn store(ctx: &mut OffChainContext, key: Self::Key, value: Self::Value) {
        let mut storage: OffChainStorage<Vec<u8>, Vec<u8>> =
            ctx.storage(Self::COLLECTION_NAME.as_bytes());
        let key = encode::serialize(&key).unwrap();
        let value = encode::serialize(&value).unwrap();
        storage.insert(key, value);
    }
}
