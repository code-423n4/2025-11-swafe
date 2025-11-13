use ark_bls12_381::{g1::Config as G1Config, g2::Config as G2Config, Bls12_381};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    pairing::Pairing,
};
use ark_ff::{field_hashers::DefaultFieldHasher, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{de::Error as DeError, Deserializer, Serializer};
use sha3::Sha3_256;

use crate::{crypto::hash, Tagged};

pub type Fr = ark_bls12_381::Fr; // Field elements
pub type G1Projective = ark_bls12_381::G1Projective; // Group elements
pub type G1Affine = ark_bls12_381::G1Affine;
pub type G2Projective = ark_bls12_381::G2Projective; // Group elements
pub type G2Affine = ark_bls12_381::G2Affine;

pub fn check_pairing(lhs: &[G1Affine], rhs: &[G2Affine]) -> bool {
    assert!(lhs.len() == rhs.len(),);
    Bls12_381::multi_pairing(lhs, rhs) == Default::default()
}

pub fn hash_to_fr<T: Tagged>(input: &T) -> Fr {
    Fr::from_le_bytes_mod_order(&hash(input))
}

/// Hash to BLS G2 group element using hash-to-curve
pub fn hash_to_g2<T: Tagged>(input: &T) -> G2Affine {
    let hasher = MapToCurveBasedHasher::<
        G2Projective,
        DefaultFieldHasher<Sha3_256, 128>,
        WBMap<G2Config>,
    >::new(format!("swafe-bls12-381-g2 : {}", T::SEPARATOR).as_bytes())
    .expect("Failed to create G2 hash-to-curve hasher");
    hasher.hash(&input.encode()).unwrap()
}

/// Hash to G1 group element using hash-to-curve
pub fn hash_to_g1<T: Tagged>(input: &T) -> G1Affine {
    let hasher = MapToCurveBasedHasher::<
        G1Projective,
        DefaultFieldHasher<Sha3_256, 128>,
        WBMap<G1Config>,
    >::new(format!("swafe-bls12-381-g1 : {}", T::SEPARATOR).as_bytes())
    .expect("Failed to create G1 hash-to-curve hasher");
    hasher.hash(&input.encode()).unwrap()
}

// Serialization modules for pairing group elements
pub mod serialize {
    use super::*;

    // For G1 elements (48 bytes compressed)
    pub mod g1 {
        use super::*;

        pub fn serialize<S>(data: &G1Affine, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut bytes = Vec::new();
            data.serialize_compressed(&mut bytes)
                .map_err(|e| serde::ser::Error::custom(format!("Failed to serialize G1: {}", e)))?;

            if bytes.len() != 48 {
                return Err(serde::ser::Error::custom(format!(
                    "G1 compressed should be 48 bytes, got {}",
                    bytes.len()
                )));
            }

            // Serialize as fixed-size array to avoid length prefix
            use serde::ser::SerializeTuple;
            let mut tuple = serializer.serialize_tuple(48)?;
            for byte in bytes {
                tuple.serialize_element(&byte)?;
            }
            tuple.end()
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<G1Affine, D::Error>
        where
            D: Deserializer<'de>,
        {
            use serde::de::{SeqAccess, Visitor};

            struct G1Visitor;

            impl<'de> Visitor<'de> for G1Visitor {
                type Value = G1Affine;

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("a 48-byte G1 element")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<G1Affine, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    let mut bytes = [0u8; 48];
                    for byte in &mut bytes {
                        *byte = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::custom("Not enough bytes for G1"))?;
                    }
                    G1Affine::deserialize_compressed(&bytes[..])
                        .map_err(|e| A::Error::custom(format!("Failed to deserialize G1: {}", e)))
                }
            }

            deserializer.deserialize_tuple(48, G1Visitor)
        }
    }

    // For Fr elements (32 bytes)
    pub mod fr {
        use super::*;

        pub fn serialize<S>(data: &Fr, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut bytes = Vec::new();
            data.serialize_compressed(&mut bytes)
                .map_err(|e| serde::ser::Error::custom(format!("Failed to serialize Fr: {}", e)))?;

            if bytes.len() != 32 {
                return Err(serde::ser::Error::custom(format!(
                    "Fr should be 32 bytes, got {}",
                    bytes.len()
                )));
            }

            // Serialize as fixed-size array to avoid length prefix
            use serde::ser::SerializeTuple;
            let mut tuple = serializer.serialize_tuple(32)?;
            for byte in bytes {
                tuple.serialize_element(&byte)?;
            }
            tuple.end()
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Fr, D::Error>
        where
            D: Deserializer<'de>,
        {
            use serde::de::{SeqAccess, Visitor};

            struct FrVisitor;

            impl<'de> Visitor<'de> for FrVisitor {
                type Value = Fr;

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("a 32-byte Fr element")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Fr, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    let mut bytes = [0u8; 32];
                    for byte in &mut bytes {
                        *byte = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::custom("Not enough bytes for Fr"))?;
                    }
                    Fr::deserialize_compressed(&bytes[..])
                        .map_err(|e| A::Error::custom(format!("Failed to deserialize Fr: {}", e)))
                }
            }

            deserializer.deserialize_tuple(32, FrVisitor)
        }
    }

    // For G2 elements (96 bytes compressed)
    pub mod g2 {
        use super::*;

        pub fn serialize<S>(data: &G2Affine, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut bytes = Vec::new();
            data.serialize_compressed(&mut bytes)
                .map_err(|e| serde::ser::Error::custom(format!("Failed to serialize G2: {}", e)))?;

            if bytes.len() != 96 {
                return Err(serde::ser::Error::custom(format!(
                    "G2 compressed should be 96 bytes, got {}",
                    bytes.len()
                )));
            }

            // Serialize as fixed-size array to avoid length prefix
            use serde::ser::SerializeTuple;
            let mut tuple = serializer.serialize_tuple(96)?;
            for byte in bytes {
                tuple.serialize_element(&byte)?;
            }
            tuple.end()
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<G2Affine, D::Error>
        where
            D: Deserializer<'de>,
        {
            use serde::de::{SeqAccess, Visitor};

            struct G2Visitor;

            impl<'de> Visitor<'de> for G2Visitor {
                type Value = G2Affine;

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("a 96-byte G2 element")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<G2Affine, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    let mut bytes = [0u8; 96];
                    for byte in &mut bytes {
                        *byte = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::custom("Not enough bytes for G2"))?;
                    }
                    G2Affine::deserialize_compressed(&bytes[..])
                        .map_err(|e| A::Error::custom(format!("Failed to deserialize G2: {}", e)))
                }
            }

            deserializer.deserialize_tuple(96, G2Visitor)
        }
    }

    // Vector serialization modules
    pub mod vec {
        use super::*;

        // For Vec<Fr>
        pub mod fr {
            use super::*;

            pub fn serialize<S>(data: &Vec<Fr>, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let mut bytes = Vec::new();
                data.serialize_compressed(&mut bytes).map_err(|e| {
                    serde::ser::Error::custom(format!("Failed to serialize Vec<Fr>: {}", e))
                })?;
                serializer.serialize_bytes(&bytes)
            }

            pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Fr>, D::Error>
            where
                D: Deserializer<'de>,
            {
                let bytes: Vec<u8> = serde::de::Deserialize::deserialize(deserializer)?;
                Vec::<Fr>::deserialize_compressed(&bytes[..])
                    .map_err(|e| D::Error::custom(format!("Failed to deserialize Vec<Fr>: {}", e)))
            }
        }

        // For Vec<G1Affine>
        pub mod g1 {
            use super::*;

            pub fn serialize<S>(data: &Vec<G1Affine>, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let mut bytes = Vec::new();
                data.serialize_compressed(&mut bytes).map_err(|e| {
                    serde::ser::Error::custom(format!("Failed to serialize Vec<G1>: {}", e))
                })?;
                serializer.serialize_bytes(&bytes)
            }

            pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<G1Affine>, D::Error>
            where
                D: Deserializer<'de>,
            {
                let bytes: Vec<u8> = serde::de::Deserialize::deserialize(deserializer)?;
                Vec::<G1Affine>::deserialize_compressed(&bytes[..])
                    .map_err(|e| D::Error::custom(format!("Failed to deserialize Vec<G1>: {}", e)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;
    use ark_std::UniformRand;
    use rand::Rng;
    use serde::{Deserialize, Serialize};

    #[test]
    fn test_g1_serialization_size() {
        let mut rng = test_rng();
        let point = G1Affine::rand(&mut rng);

        // Test our custom serialization
        #[derive(Serialize, Deserialize)]
        struct TestG1(#[serde(with = "crate::crypto::pairing::serialize::g1")] G1Affine);

        let test_point = TestG1(point);
        let serialized =
            bincode::serde::encode_to_vec(&test_point, bincode::config::standard()).unwrap();
        println!("Custom G1 serialization bincode size: {}", serialized.len());

        // Check if it's reasonable (48 bytes for fixed-size tuple)
        // With serialize_tuple, bincode should produce exactly 48 bytes
        assert_eq!(
            serialized.len(),
            48,
            "G1 serialized size should be exactly 48 bytes, but got {}",
            serialized.len()
        );
    }

    #[test]
    fn test_fr_serialization_size() {
        let mut rng = test_rng();
        let scalar = rng.gen();

        // Test our custom serialization
        #[derive(Serialize, Deserialize)]
        struct TestFr(#[serde(with = "crate::crypto::pairing::serialize::fr")] Fr);

        let test_scalar = TestFr(scalar);
        let serialized =
            bincode::serde::encode_to_vec(&test_scalar, bincode::config::standard()).unwrap();
        println!("Custom Fr serialization bincode size: {}", serialized.len());

        // With serialize_tuple, bincode should produce exactly 32 bytes
        assert_eq!(
            serialized.len(),
            32,
            "Fr serialized size should be exactly 32 bytes, but got {}",
            serialized.len()
        );
    }

    #[test]
    fn test_g2_serialization_size() {
        let mut rng = test_rng();
        let point = rng.gen();

        // Test our custom serialization
        #[derive(Serialize, Deserialize)]
        struct TestG2(#[serde(with = "crate::crypto::pairing::serialize::g2")] G2Affine);

        let test_point = TestG2(point);
        let serialized =
            bincode::serde::encode_to_vec(&test_point, bincode::config::standard()).unwrap();
        println!("Custom G2 serialization bincode size: {}", serialized.len());

        // With serialize_tuple, bincode should produce exactly 96 bytes
        assert_eq!(
            serialized.len(),
            96,
            "G2 serialized size should be exactly 96 bytes, but got {}",
            serialized.len()
        );
    }

    #[test]
    fn test_fixed_size_serialization() {
        use ark_serialize::CanonicalSerialize;
        let mut rng = test_rng();

        // Test that arkworks compressed sizes are as expected
        let g1 = G1Affine::rand(&mut rng);
        let mut g1_bytes = Vec::new();
        g1.serialize_compressed(&mut g1_bytes).unwrap();
        assert_eq!(g1_bytes.len(), 48, "G1 compressed should be 48 bytes");

        let g2 = G2Affine::rand(&mut rng);
        let mut g2_bytes = Vec::new();
        g2.serialize_compressed(&mut g2_bytes).unwrap();
        assert_eq!(g2_bytes.len(), 96, "G2 compressed should be 96 bytes");

        let fr = Fr::rand(&mut rng);
        let mut fr_bytes = Vec::new();
        fr.serialize_compressed(&mut fr_bytes).unwrap();
        assert_eq!(fr_bytes.len(), 32, "Fr should be 32 bytes");
    }

    #[test]
    fn test_round_trip_serialization() {
        let mut rng = test_rng();

        // Test G1 round-trip
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct TestG1(#[serde(with = "crate::crypto::pairing::serialize::g1")] G1Affine);

        let original_g1 = TestG1(G1Affine::rand(&mut rng));
        let serialized =
            bincode::serde::encode_to_vec(&original_g1, bincode::config::standard()).unwrap();
        let deserialized: TestG1 =
            bincode::serde::decode_from_slice(&serialized, bincode::config::standard())
                .unwrap()
                .0;
        assert_eq!(original_g1, deserialized, "G1 round-trip failed");

        // Test Fr round-trip
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct TestFr(#[serde(with = "crate::crypto::pairing::serialize::fr")] Fr);

        let original_fr = TestFr(Fr::rand(&mut rng));
        let serialized =
            bincode::serde::encode_to_vec(&original_fr, bincode::config::standard()).unwrap();
        let deserialized: TestFr =
            bincode::serde::decode_from_slice(&serialized, bincode::config::standard())
                .unwrap()
                .0;
        assert_eq!(original_fr, deserialized, "Fr round-trip failed");

        // Test G2 round-trip
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct TestG2(#[serde(with = "crate::crypto::pairing::serialize::g2")] G2Affine);

        let original_g2 = TestG2(G2Affine::rand(&mut rng));
        let serialized =
            bincode::serde::encode_to_vec(&original_g2, bincode::config::standard()).unwrap();
        let deserialized: TestG2 =
            bincode::serde::decode_from_slice(&serialized, bincode::config::standard())
                .unwrap()
                .0;
        assert_eq!(original_g2, deserialized, "G2 round-trip failed");
    }
}
