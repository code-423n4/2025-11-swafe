use crate::errors::SwafeError;
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine as _};
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize, Serializer};

/// Standard bincode configuration used throughout the library
const BINCODE_CONFIG: bincode::config::Configuration = bincode::config::standard();

pub trait Tagged: Serialize {
    const SEPARATOR: &'static str;

    /// Encode with domain separator for domain seperated hashing/committing/signatures
    ///
    /// This means that *every* instance of any "Tagged" value,
    /// will have a unique encoding as bytes: "encode" is an injective
    /// map from the set of all Tagged values to the set of all Vec<u8>
    ///
    /// Concretely, this is ensured because bincode encodes a string as a sequence of bytes:
    /// a (var-encoded) length field, followed by the bytes of the string.
    /// https://git.sr.ht/~stygianentity/bincode/tree/trunk/item/docs/spec.md#encoding-details
    fn encode(&self) -> Vec<u8>
    where
        Self: Sized,
    {
        #[derive(Serialize)]
        struct DomainTuple<'a, T: Tagged + ?Sized> {
            sep: &'a str,
            val: &'a T,
        }
        bincode::serde::encode_to_vec(
            &DomainTuple {
                sep: Self::SEPARATOR,
                val: self,
            },
            BINCODE_CONFIG,
        )
        .unwrap()
    }
}

/// Convert bytes into a string encoded value
pub fn bytes_to_str(bytes: &[u8]) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(bytes)
}

/// Convert the string into raw bytes
pub fn str_to_bytes(s: &str) -> Result<Vec<u8>, SwafeError> {
    BASE64_URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| SwafeError::SerializationError(format!("Failed to decode string {}", s)))
}

/// Deserialize a string encoded value
pub fn deserialize_str<T: DeserializeOwned>(s: &str) -> Result<T, SwafeError> {
    StrEncoded::<T>::try_from(s).map(|encoded| encoded.0)
}

/// Serialize a value into a string encoding
pub fn serialize_str<T: Serialize>(value: &T) -> Result<String, SwafeError> {
    Ok(StrEncoded(value).into())
}

pub fn deserialize<T>(bytes: &[u8]) -> Result<T, SwafeError>
where
    T: serde::de::DeserializeOwned,
{
    bincode::serde::decode_from_slice::<T, _>(bytes, BINCODE_CONFIG)
        .map(|(data, _)| data)
        .map_err(|_| {
            SwafeError::SerializationError(format!(
                "Failed to deserialize {}",
                std::any::type_name::<T>()
            ))
        })
}

pub fn serialize<T>(data: &T) -> Result<Vec<u8>, SwafeError>
where
    T: serde::Serialize,
{
    bincode::serde::encode_to_vec(data, BINCODE_CONFIG).map_err(|_| {
        SwafeError::SerializationError(format!(
            "Failed to serialize {}",
            std::any::type_name::<T>()
        ))
    })
}

#[derive(Clone)]
pub struct StrEncoded<T>(pub T);

impl<T: Serialize> Serialize for StrEncoded<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = bincode::serde::encode_to_vec(&self.0, BINCODE_CONFIG)
            .map_err(|e| serde::ser::Error::custom(format!("Failed to serialize: {}", e)))?;
        let str = bytes_to_str(&bytes);
        serializer.serialize_str(&str)
    }
}

impl<'de, T> Deserialize<'de> for StrEncoded<T>
where
    T: DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let str = String::deserialize(deserializer)?;
        StrEncoded::try_from(str.as_str()).map_err(serde::de::Error::custom)
    }
}

impl<T> TryFrom<&str> for StrEncoded<T>
where
    T: DeserializeOwned,
{
    type Error = SwafeError;

    fn try_from(str: &str) -> Result<Self, Self::Error> {
        let bytes = str_to_bytes(str).map_err(|e| {
            SwafeError::SerializationError(format!("Failed to decode string: {}", e))
        })?;
        Ok(StrEncoded(
            bincode::serde::decode_from_slice(&bytes, BINCODE_CONFIG)
                .map_err(|e| {
                    SwafeError::SerializationError(format!("Failed to deserialize: {}", e))
                })?
                .0,
        ))
    }
}

impl<T> From<StrEncoded<T>> for String
where
    T: Serialize,
{
    fn from(val: StrEncoded<T>) -> Self {
        (&val).into()
    }
}

impl<T> From<&StrEncoded<T>> for String
where
    T: Serialize,
{
    fn from(val: &StrEncoded<T>) -> Self {
        let bytes = bincode::serde::encode_to_vec(&val.0, BINCODE_CONFIG)
            .map_err(|e| SwafeError::SerializationError(format!("Failed to serialize: {}", e)))
            .unwrap();
        bytes_to_str(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
    struct TestStruct {
        value: String,
        number: u32,
    }

    impl Tagged for TestStruct {
        const SEPARATOR: &'static str = "test:encode";
    }

    #[test]
    fn test_tagged_encode() {
        let test = TestStruct {
            value: "hello".to_string(),
            number: 42,
        };

        let encoded1 = test.encode();
        let encoded2 = test.encode();

        // Same input should produce same output
        assert_eq!(encoded1, encoded2);

        // Different input should produce different output
        let test2 = TestStruct {
            value: "world".to_string(),
            number: 43,
        };
        let encoded3 = test2.encode();
        assert_ne!(encoded1, encoded3);
    }

    #[test]
    fn test_bytes_to_str_and_back() {
        let bytes = vec![1, 2, 3, 4, 5];
        let str = bytes_to_str(&bytes);
        let decoded = str_to_bytes(&str).unwrap();
        assert_eq!(bytes, decoded);
    }

    #[test]
    fn test_str_to_bytes_invalid() {
        let invalid = "not-valid-base64!@#$%^&*()";
        let result = str_to_bytes(invalid);
        assert!(result.is_err());
        match result {
            Err(SwafeError::SerializationError(msg)) => {
                assert!(msg.contains("Failed to decode string"));
            }
            _ => panic!("Expected SerializationError"),
        }
    }

    #[test]
    fn test_serialize_deserialize_str() {
        let test = TestStruct {
            value: "test value".to_string(),
            number: 123,
        };

        let serialized = serialize_str(&test).unwrap();
        let deserialized: TestStruct = deserialize_str(&serialized).unwrap();
        assert_eq!(test, deserialized);
    }

    #[test]
    fn test_str_encoded_serialize_deserialize() {
        let test = TestStruct {
            value: "encoded test".to_string(),
            number: 456,
        };

        let encoded = StrEncoded(test.clone());
        let json = serde_json::to_string(&encoded).unwrap();
        let decoded: StrEncoded<TestStruct> = serde_json::from_str(&json).unwrap();
        assert_eq!(test, decoded.0);
    }

    #[test]
    fn test_str_encoded_try_from() {
        let test = TestStruct {
            value: "try from test".to_string(),
            number: 789,
        };

        let str: String = StrEncoded(test.clone()).into();
        let decoded = StrEncoded::<TestStruct>::try_from(str.as_str()).unwrap();
        assert_eq!(test, decoded.0);
    }

    #[test]
    fn test_str_encoded_into_string() {
        let test = TestStruct {
            value: "into string".to_string(),
            number: 999,
        };

        let encoded = StrEncoded(test.clone());
        let str1: String = encoded.clone().into();
        let str2: String = (&encoded).into();
        assert_eq!(str1, str2);
    }

    #[test]
    fn test_serialize_deserialize_binary() {
        let test = TestStruct {
            value: "binary test".to_string(),
            number: 555,
        };

        let bytes = serialize(&test).unwrap();
        let deserialized: TestStruct = deserialize(&bytes).unwrap();
        assert_eq!(test, deserialized);
    }

    #[test]
    fn test_deserialize_invalid_bytes() {
        let invalid_bytes = vec![255, 254, 253]; // Invalid bincode data
        let result = deserialize::<TestStruct>(&invalid_bytes);
        assert!(result.is_err());
        match result {
            Err(SwafeError::SerializationError(msg)) => {
                assert!(msg.contains("Failed to deserialize"));
            }
            _ => panic!("Expected SerializationError"),
        }
    }

    #[test]
    fn test_str_encoded_invalid_deserialize() {
        let invalid_str = "not-valid-encoding";
        let result = StrEncoded::<TestStruct>::try_from(invalid_str);
        assert!(result.is_err());
    }
}
