// JSON serialization helpers using serde-json-wasm

use crate::http::error::ServerError;
use serde::Serialize;

/// Serialize a value to JSON string using serde-json-wasm
pub fn to_string<T: Serialize>(value: &T) -> Result<String, ServerError> {
    serde_json_wasm::to_string(value).map_err(|_| {
        ServerError::SerializationError(format!(
            "Failed to serialize {} to JSON",
            std::any::type_name::<T>()
        ))
    })
}

/// Deserialize a value from JSON string using serde-json-wasm
pub fn from_str<T: serde::de::DeserializeOwned>(s: &str) -> Result<T, ServerError> {
    serde_json_wasm::from_str::<T>(s).map_err(|_| {
        ServerError::SerializationError(format!(
            "Failed to deserialize {} from JSON",
            std::any::type_name::<T>()
        ))
    })
}

/// Create a simple JSON error response
pub fn json_error(error: &str) -> String {
    #[derive(Serialize)]
    struct ErrorResponse<'a> {
        error: &'a str,
    }
    to_string(&ErrorResponse { error }).unwrap()
}
