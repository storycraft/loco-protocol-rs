/*
 * Created on Sat Sep 09 2023
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::ops::Deref;

use serde::{Deserialize, Serialize};

pub mod client;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// 11 bytes string padded with `\0`
pub struct Method([u8; 11]);

impl Method {
    /// Create new [`Method`]
    ///
    /// Returns `None` if string is longer than 11 bytes
    pub fn new(string: &str) -> Option<Self> {
        if string.as_bytes().len() > 11 {
            return None;
        }

        let mut buf = [0_u8; 11];
        buf[..string.len()].copy_from_slice(string.as_bytes());

        Some(Self(buf))
    }
}

impl Deref for Method {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        std::str::from_utf8(&self.0).unwrap()
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
