/*
 * Created on Sat Sep 09 2023
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use core::{fmt::Debug, ops::Deref};

use alloc::boxed::Box;
use serde::{
    de::{self, Unexpected, Visitor},
    Deserialize, Serialize,
};

pub mod client;

#[derive(Clone, PartialEq, Eq)]
/// 11 bytes string padded with `\0`
pub struct Method {
    len: usize,
    buf: [u8; 11],
}

impl Method {
    /// Create new [`Method`]
    ///
    /// Returns `None` if string is longer than 11 bytes
    pub fn new(string: &str) -> Option<Self> {
        let bytes = string.as_bytes();
        let len = bytes.len();
        if len > 11 {
            return None;
        }

        let mut buf = [0_u8; 11];
        buf[..len].copy_from_slice(bytes);

        Some(Self { len, buf })
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub const fn len(&self) -> usize {
        self.len
    }
}

impl Debug for Method {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Method").field(&self.deref()).finish()
    }
}

impl Deref for Method {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        core::str::from_utf8(&self.buf[..self.len]).unwrap()
    }
}

impl Serialize for Method {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_newtype_struct("Method", &self.buf)
    }
}

impl<'de> Deserialize<'de> for Method {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct MethodVisitor;

        impl<'a> Visitor<'a> for MethodVisitor {
            type Value = Method;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(formatter, "utf-8 byte array that has 11 length")
            }

            fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: serde::Deserializer<'a>,
            {
                deserializer.deserialize_tuple(11, MethodVisitor)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'a>,
            {
                let mut buf = [0_u8; 11];

                for item in &mut buf {
                    *item = seq.next_element::<u8>()?.ok_or(de::Error::invalid_length(
                        11,
                        &"an array of size 11 was expected",
                    ))?;
                }

                let len = core::str::from_utf8(&buf)
                    .map_err(|_| {
                        de::Error::invalid_type(
                            Unexpected::Bytes(&buf),
                            &"a valid utf-8 array was expected",
                        )
                    })?
                    .trim_matches(char::from(0))
                    .len();

                Ok(Method { len, buf })
            }
        }

        deserializer.deserialize_newtype_struct("Method", MethodVisitor)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Header {
    pub id: u32,
    pub status: u16,
    pub method: Method,
    pub data_type: u8,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Command<T: ?Sized> {
    pub header: Header,
    pub data: T,
}

pub type BoxedCommand = Command<Box<[u8]>>;
