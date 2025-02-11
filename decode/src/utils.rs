// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! Utilities to make decoding various map data less terrible.

use crate::Error;

/// Extract a bit from a byte.
pub const fn extract_bit(word: u8, bit: u8) -> Result<bool, Error> {
    if bit > 7 {
        return Err(Error::BitOutOfRange);
    }
    Ok((word & (1 << bit)) != 0)
}

mod private {
    pub trait ScalableSealed: Sized + Copy + Into<f32> {}
}

pub trait Scalable: private::ScalableSealed {
    fn from_bytes(buf: [u8; 2]) -> Self;
}

impl private::ScalableSealed for i16 {}

impl Scalable for i16 {
    fn from_bytes(buf: [u8; 2]) -> Self {
        Self::from_be_bytes(buf)
    }
}

impl private::ScalableSealed for u16 {}

impl Scalable for u16 {
    fn from_bytes(buf: [u8; 2]) -> Self {
        Self::from_be_bytes(buf)
    }
}

/// Decode a 2-byte word into a float with a defined scale factor.
pub fn decode_with_scale<T: Scalable>(buf: [u8; 2], scale: f32) -> f32 {
    T::from_bytes(buf).into() * scale
}

/// A helper macro to generate an enum from a bitfield.
///
/// Bitfields are common in the CMIS spec. These are often just a few bits, and
/// are used to represent a set of distinct values, making it attractive to
/// represent them in Rust with an enum. This macro can be used to generate an
/// enum that maps a set of bits to enum variants.
///
/// It also generates a `TryFrom<u8>` implementation and a `Display`
/// implementation.
///
/// # Example
/// ```ignore
/// /// Suppose we have a 2-bit pattern, that maps to some defined values.
/// ///
/// /// 0b00 -> First
/// /// 0b01 -> Second
/// /// 0b10 -> Third
/// /// 0b11 -> Fourth
/// ///
/// /// And suppose this appears in bits [3:2] of a single byte. Then we can
/// /// make an enum to represent this with:
///
/// transceiver_decode::utils::bitfield_enum! {
///     Foo,
///     "A bit pattern representing foo",
///     3:2,
///     0b00, First, "The first value",
///     0b01, Second, "The second value",
///     0b10, Third, "The third value",
///     0b11, Fourth, "The fourth value",
/// }
/// ```
#[macro_export]
macro_rules! bitfield_enum {
    (
        name = $name:ident,
        description = $docstring:literal,
        variants = { $( $bits:literal, $variant:ident, $display:literal $(,)? ),+ },
        other_variants = { $( $other_variant:ident : $other_pattern:pat $(,)? ),* }
        $(,)?
    ) => {
        #[doc = $docstring]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        #[cfg_attr(
            any(feature = "api-traits", test),
            derive(serde::Deserialize, serde::Serialize)
        )]
        #[cfg_attr(
            any(feature = "api-traits", test),
            serde(into = "String", try_from = "String")
        )]
        #[cfg_attr(any(test), derive(strum::EnumIter))]
        pub enum $name {
            $($variant),+,
            $($other_variant(u8)),+
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                use $name::*;
                #[deny(overlapping_range_endpoints)]
                match self {
                    $( $variant => write!(f, "{}", $display), )+
                    $( $other_variant(x) => write!(f, "{} (0x{x:02x})", stringify!($other_variant)), )+
                }
            }
        }

        impl ::core::convert::From<u8> for $name {
            fn from(x: u8) -> Self {
                use $name::*;
                #[deny(overlapping_range_endpoints)]
                match x {
                    $( $bits => $variant, )+
                    $( $other_pattern => $other_variant(x), )+
                }
            }
        }

        impl ::core::convert::From<$name> for u8 {
            fn from(x: $name) -> u8 {
                use $name::*;
                #[deny(overlapping_range_endpoints)]
                match x {
                    $( $variant => $bits, )+
                    $( $other_variant(x) => x, )+
                }
            }
        }

        #[cfg(any(feature = "api-traits", test))]
        impl ::core::str::FromStr for $name {
            type Err = &'static str;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                use $name::*;
                match s {
                    $( $display => return Ok($variant), )+
                    _ => {}
                }

                $(
                    if let Some(value) = crate::utils::parse_u8_bitfield_variant(
                        s, stringify!($other_variant)
                    ) {
                        return Ok($other_variant(value));
                    }
                )+

                Err(concat!("Invalid or malformed value for ", stringify!($name)))
            }
        }

        #[cfg(any(feature = "api-traits", test))]
        impl From<$name> for String {
            fn from(value: $name) -> String {
                value.to_string()
            }
        }

        #[cfg(any(feature = "api-traits", test))]
        impl ::core::convert::TryFrom<String> for $name {
            type Error = <Self as ::core::str::FromStr>::Err;

            fn try_from(s: String) -> Result<Self, Self::Error> {
                s.parse()
            }
        }

        #[cfg(any(feature = "api-traits", test))]
        impl ::schemars::JsonSchema for $name {
            fn schema_name() -> String {
                String::from(stringify!($name))
            }

            fn json_schema(
                gen: &mut ::schemars::gen::SchemaGenerator
            ) -> ::schemars::schema::Schema
            {
                // Use the JSONSchema for a string, but ensure we keep the
                // description from the original type itself.
                let mut s = String::json_schema(gen);
                let ::schemars::schema::Schema::Object(obj) = &mut s else {
                    unreachable!();
                };
                obj
                    .metadata
                    .get_or_insert_with(Default::default)
                    .description = Some(String::from($docstring));
                s
            }
        }
    };

    (
        name = $name:ident,
        description = $docstring:literal,
        bits = $high_bit:literal : $low_bit:literal,
        variants = { $( $bits:literal, $variant:ident, $display:literal $(,)? ),+ }
        $(,)?
    ) => {
        // Sanity checks on the bit ranges.
        static_assertions::const_assert!($high_bit < 8);
        static_assertions::const_assert!($low_bit < 8);
        static_assertions::const_assert!($low_bit <= $high_bit);

        // Sanity check that the bit patterns are all within the mask.
        $( static_assertions::const_assert_eq!($name::MASK | $bits, $name::MASK); )+

        // Sanity check that the mask is _equal_ to all the bit patterns OR'd
        // together.
        static_assertions::const_assert_eq!( $name::MASK, $( $bits )|+ );

        impl $name {
            #[allow(dead_code)]
            pub const HIGH_BIT: u8 = $high_bit;
            #[allow(dead_code)]
            pub const LOW_BIT: u8 = $low_bit;
            pub const MASK: u8 = (0xff << $low_bit) & (0xff >> (7 - $high_bit));
        }

        #[doc = $docstring]
        #[derive(Clone, Copy, Debug, PartialEq)]
        #[cfg_attr(
            any(feature = "api-traits", test),
            derive(serde::Deserialize, serde::Serialize)
        )]
        #[cfg_attr(
            any(feature = "api-traits", test),
            serde(into = "String", try_from = "String")
        )]
        #[cfg_attr(any(test), derive(strum::EnumIter))]
        pub enum $name {
            $($variant),+
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                use $name::*;
                #[deny(overlapping_range_endpoints)]
                match self {
                    $( $variant => write!(f, "{}", $display), )+
                }
            }
        }

        impl ::core::convert::TryFrom<u8> for $name {
            type Error = Error;

            fn try_from(x: u8) -> Result<Self, Self::Error> {
                use $name::*;
                #[deny(overlapping_range_endpoints)]
                match (x & Self::MASK) >> $low_bit {
                    $( $bits => Ok($variant), )+
                    _ => Err(Error::InvalidBitField),
                }
            }
        }

        impl ::core::convert::From<$name> for u8 {
            fn from(x: $name) -> u8 {
                use $name::*;
                #[deny(overlapping_range_endpoints)]
                match x {
                    $( $variant => $bits, )+
                }
            }
        }

        #[cfg(any(feature = "api-traits", test))]
        impl ::core::str::FromStr for $name {
            type Err = &'static str;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                use $name::*;
                match s {
                    $( $display => Ok($variant), )+
                    _ => Err(concat!("Invalid or malformed value for ", stringify!($name)))
                }
            }
        }

        #[cfg(any(feature = "api-traits", test))]
        impl From<$name> for String {
            fn from(value: $name) -> String {
                value.to_string()
            }
        }

        #[cfg(any(feature = "api-traits", test))]
        impl ::core::convert::TryFrom<String> for $name {
            type Error = <Self as ::core::str::FromStr>::Err;

            fn try_from(s: String) -> Result<Self, Self::Error> {
                s.parse()
            }
        }

        #[cfg(any(feature = "api-traits", test))]
        impl ::schemars::JsonSchema for $name {
            fn schema_name() -> String {
                String::from(stringify!($name))
            }

            fn json_schema(
                gen: &mut ::schemars::gen::SchemaGenerator
            ) -> ::schemars::schema::Schema
            {
                String::json_schema(gen)
            }
        }
    };
}

/// Parse the u8 inside a bitfield enum.
///
/// Many of the enums we create with `bitfield_enum!()` have a catchall variant,
/// like "Other" or "Reserved". We want to serialize these variants as strings,
/// which means we also need to parse them on deserialization.
///
/// This method pulls out the hex-formatted u8 from a string, assuming it is
/// formatted as: `<variant> (0xAA)`. `None` is returned if the prefix doesn't
/// match or parsing fails.
#[allow(dead_code)]
pub(crate) fn parse_u8_bitfield_variant(s: &str, variant: &str) -> Option<u8> {
    let Some(inner) = s
        .strip_suffix(")")
        .and_then(|s| s.strip_prefix(variant))
        .and_then(|s| s.strip_prefix(" (0x"))
    else {
        return None;
    };
    u8::from_str_radix(inner, 16).ok()
}

#[cfg(test)]
mod tests {
    use crate::utils::parse_u8_bitfield_variant;

    use super::extract_bit;

    #[test]
    fn test_extract_bit() {
        for shift in 0..8 {
            let expected = 1 << shift;
            assert_eq!(extract_bit(expected, shift).unwrap(), true);
            for other_shift in 0..8 {
                if shift == other_shift {
                    continue;
                }
                assert_eq!(extract_bit(expected, other_shift).unwrap(), false);
            }
        }

        for shift in 8..=255 {
            assert!(extract_bit(0, shift).is_err());
        }
    }

    #[test]
    fn test_parse_u8_bitfield_variant() {
        assert_eq!(3, parse_u8_bitfield_variant("Foo (0x03)", "Foo").unwrap());

        // Wrong name.
        assert!(parse_u8_bitfield_variant("Foo (0x03)", "Bar").is_none());

        // Missing closing, opening, or both parentheses.
        assert!(parse_u8_bitfield_variant("Foo (0x03", "Foo").is_none());
        assert!(parse_u8_bitfield_variant("Foo 0x03)", "Foo").is_none());
        assert!(parse_u8_bitfield_variant("Foo 0x03", "Foo").is_none());

        // Invalid hex
        assert!(parse_u8_bitfield_variant("Foo (0x)", "Foo").is_none());
        assert!(parse_u8_bitfield_variant("Foo (3)", "Foo").is_none());

        // Out of range
        assert!(parse_u8_bitfield_variant("Foo (0xFFFF)", "Foo").is_none());
    }
}
