/*
 * Created on Sat Nov 28 2020
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

pub mod builder;

pub mod codec;

use std::string::FromUtf8Error;

use serde::{Deserialize, Serialize};

pub const HEADER_SIZE: usize = 18;
pub const HEAD_SIZE: usize = HEADER_SIZE + 4;

/// Command packet header
#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug)]
pub struct Header {
    pub id: i32,
    pub status: i16,
    pub method: [u8; 11],
    pub data_type: i8,
}

impl Header {
    /// Extract String from method field
    pub fn method(&self) -> Result<String, FromUtf8Error> {
        let size = self.method.iter().position(|&c| c == b'\0').unwrap_or(11);

        String::from_utf8(self.method[..size].into())
    }

    /// set method field from str. Will be sliced to 11 bytes max.
    pub fn set_method(&mut self, method: &str) {
        self.method = Self::to_method(method);
    }

    pub fn to_method(method: &str) -> [u8; 11] {
        let bytes = method.as_bytes();
        let mut method = [0_u8; 11];

        method[..bytes.len().min(11)].copy_from_slice(bytes);

        method
    }
}

/// Loco protocol Command packet
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Command {
    pub header: Header,
    pub data: Vec<u8>,
}
