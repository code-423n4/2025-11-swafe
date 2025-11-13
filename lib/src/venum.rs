/// Macro to generate versioned enums with typed variants.
/// Serializes as u8 tag (< 128) followed by the variant data.
///
/// Usage:
/// ```rust
/// use swafe_lib::versioned_enum;
///
/// versioned_enum!(
///     #[derive(Debug, PartialEq)]
///     MyEnum,
///     V0(String) = 0,
///     V1(u32) = 1,
///     V2(bool) = 2
/// );
/// ```
///
/// Generates:
/// ```rust
/// #[derive(Debug, PartialEq)]
/// #[repr(u8)]
/// enum MyEnum {
///     V0(String) = 0,
///     V1(u32) = 1,
///     V2(bool) = 2,
/// }
/// ```
#[macro_export]
macro_rules! versioned_enum {
    (
        $(#[$enum_meta:meta])*
        $name:ident,
        $($variant:ident($type:ty) = $value:expr),* $(,)?
    ) => {
        // Compile-time validation: ensure all values are < 128
        const _: () = {
            $(
                const _: () = {
                    if $value >= 128 {
                        panic!(concat!(
                            "versioned_enum! error: variant ",
                            stringify!($variant),
                            " has value ",
                            stringify!($value),
                            " but maximum allowed is 127 (u8 range 0-127)"
                        ));
                    }
                };
            )*
        };

        $(#[$enum_meta])*
        #[repr(u8)]
        #[allow(clippy::large_enum_variant)]
        #[allow(private_interfaces)]
        pub enum $name {
            $(
                $variant($type) = $value
            ),*
        }

        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                use serde::ser::SerializeTuple;
                match self {
                    $(
                        $name::$variant(data) => {
                            let mut tuple = serializer.serialize_tuple(2)?;
                            tuple.serialize_element(&($value as u8))?;
                            tuple.serialize_element(data)?;
                            tuple.end()
                        }
                    ),*
                }
            }
        }

        impl<'de> serde::de::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                use serde::de::{SeqAccess, Visitor};

                struct EnumVisitor;

                impl<'de> Visitor<'de> for EnumVisitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                        formatter.write_str("a tuple of (u8, data)")
                    }

                    fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
                    where
                        A: SeqAccess<'de>,
                    {
                        let tag: u8 = seq.next_element()?
                            .ok_or_else(|| serde::de::Error::custom("missing tag"))?;

                        match tag {
                            $(
                                $value => {
                                    let data: $type = seq.next_element()?
                                        .ok_or_else(|| serde::de::Error::custom("missing data"))?;
                                    Ok($name::$variant(data))
                                }
                            ),*
                            _ => Err(serde::de::Error::custom("invalid enum variant"))
                        }
                    }
                }

                deserializer.deserialize_tuple(2, EnumVisitor)
            }
        }
    };
}

#[cfg(test)]
#[allow(clippy::approx_constant)]
mod tests {
    use std::collections::HashSet;

    use crate::encode::{deserialize, serialize};
    use serde::{Deserialize, Serialize};

    // Direct enum definition matching the macro output
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[repr(u8)]
    enum DirectEnum {
        V0(String) = 0,
        V1(u32) = 1,
        V2(bool) = 2,
        V3(f64) = 3,
        V4(Vec<u8>) = 4,
        V5(char) = 5,
        V6(i64) = 6,
        V7(u16) = 7,
        V8(Option<String>) = 8,
        V9([u8; 4]) = 9,
    }

    // Use the macro to define an equivalent enum
    versioned_enum!(
        #[derive(Debug, PartialEq)]
        MacroEnum,
        V0(String) = 0,
        V1(u32) = 1,
        V2(bool) = 2,
        V3(f64) = 3,
        V4(Vec<u8>) = 4,
        V5(char) = 5,
        V6(i64) = 6,
        V7(u16) = 7,
        V8(Option<String>) = 8,
        V9([u8; 4]) = 9
    );

    #[test]
    fn macro_and_direct_enum_bincode_encoding_match() {
        let direct = DirectEnum::V1(42);
        let macroed = MacroEnum::V1(42);
        assert_eq!(
            serialize(&direct).expect("bincode serialize direct"),
            serialize(&macroed).expect("bincode serialize macro"),
            "Bincode encoding should match for macro and direct enum"
        );
    }

    #[test]
    fn macro_and_direct_enum_bincode_encoding_match_all_variants() {
        let cases = vec![
            (
                DirectEnum::V0("hello".to_string()),
                MacroEnum::V0("hello".to_string()),
            ),
            (
                DirectEnum::V1(123), //
                MacroEnum::V1(123),
            ),
            (
                DirectEnum::V2(true), //
                MacroEnum::V2(true),
            ),
            (
                DirectEnum::V2(false), //
                MacroEnum::V2(false),
            ),
            (
                DirectEnum::V3(3.1415), //
                MacroEnum::V3(3.1415),
            ),
            (
                DirectEnum::V4(vec![1, 2, 3]), //
                MacroEnum::V4(vec![1, 2, 3]),
            ),
            (
                DirectEnum::V5('x'), //
                MacroEnum::V5('x'),
            ),
            (
                DirectEnum::V6(-42), //
                MacroEnum::V6(-42),
            ),
            (
                DirectEnum::V7(65535), //
                MacroEnum::V7(65535),
            ),
            (
                DirectEnum::V8(Some("option".to_string())),
                MacroEnum::V8(Some("option".to_string())),
            ),
            (
                DirectEnum::V8(None), //
                MacroEnum::V8(None),
            ),
            (
                DirectEnum::V9([10, 20, 30, 40]),
                MacroEnum::V9([10, 20, 30, 40]),
            ),
        ];
        let mut bytes: HashSet<Vec<u8>> = HashSet::new();
        for (direct, macroed) in cases {
            assert_eq!(
                serialize(&direct).expect("bincode serialize direct"),
                serialize(&macroed).expect("bincode serialize macro"),
                "Bincode encoding should match for macro and direct enum"
            );
            assert!(
                bytes.insert(serialize(&direct).expect("bincode serialize direct")),
                "Bincode encoding should match for macro and direct enum"
            );
        }
    }

    #[test]
    fn forward_compatibility_deserialize_old_variant_with_new_enum() {
        // Old version: only V0 and V1
        versioned_enum!(
            #[derive(Debug, PartialEq)]
            OldEnum,
            V0(String) = 0,
            V1(u32) = 1
        );

        // New version: adds V2 and V3
        versioned_enum!(
            #[derive(Debug, PartialEq)]
            NewEnum,
            V0(String) = 0,
            V1(u32) = 1,
            V2(bool) = 2,
            V3(f64) = 3
        );

        // Serialize old variants using OldEnum
        let old_v0 = OldEnum::V0("forward".to_string());
        let old_v1 = OldEnum::V1(2024);

        let bytes_v0 = serialize(&old_v0).expect("serialize old_v0");
        let bytes_v1 = serialize(&old_v1).expect("serialize old_v1");

        // Deserialize using NewEnum
        let new_v0: NewEnum = deserialize(&bytes_v0).expect("deserialize new_v0");
        let new_v1: NewEnum = deserialize(&bytes_v1).expect("deserialize new_v1");

        assert_eq!(new_v0, NewEnum::V0("forward".to_string()));
        assert_eq!(new_v1, NewEnum::V1(2024));
    }

    #[test]
    fn forward_compatibility_with_removed_unused_variants() {
        // Old version: V0, V1, V2 (unused), V3
        versioned_enum!(
            #[derive(Debug, PartialEq)]
            OldEnumWithUnused,
            V0(String) = 0,
            V1(u32) = 1,
            V2(bool) = 2, // unused
            V3(f64) = 3
        );

        // New version: V0, V1, V3 (V2 removed)
        versioned_enum!(
            #[derive(Debug, PartialEq)]
            NewEnumWithoutUnused,
            V0(String) = 0,
            V1(u32) = 1,
            V3(f64) = 3
        );

        // Serialize old variants using OldEnumWithUnused
        let old_v0 = OldEnumWithUnused::V0("removed_unused".to_string());
        let old_v1 = OldEnumWithUnused::V1(2025);
        let old_v3 = OldEnumWithUnused::V3(2.718);

        let bytes_v0 = serialize(&old_v0).expect("serialize old_v0");
        let bytes_v1 = serialize(&old_v1).expect("serialize old_v1");
        let bytes_v3 = serialize(&old_v3).expect("serialize old_v3");

        // Deserialize using NewEnumWithoutUnused
        let new_v0: NewEnumWithoutUnused = deserialize(&bytes_v0).expect("deserialize new_v0");
        let new_v1: NewEnumWithoutUnused = deserialize(&bytes_v1).expect("deserialize new_v1");
        let new_v3: NewEnumWithoutUnused = deserialize(&bytes_v3).expect("deserialize new_v3");

        assert_eq!(
            new_v0,
            NewEnumWithoutUnused::V0("removed_unused".to_string())
        );
        assert_eq!(new_v1, NewEnumWithoutUnused::V1(2025));
        assert_eq!(new_v3, NewEnumWithoutUnused::V3(2.718));

        // If we try to deserialize a removed variant, it should error
        let old_v2 = OldEnumWithUnused::V2(true);
        let bytes_v2 = serialize(&old_v2).expect("serialize old_v2");
        let result_v2: Result<NewEnumWithoutUnused, _> = deserialize(&bytes_v2);
        assert!(
            result_v2.is_err(),
            "Deserializing removed variant should error"
        );
    }
}
