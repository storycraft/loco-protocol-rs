/*
 * Created on Sat Nov 28 2020
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use serde::{Deserialize, Serialize};

use crate::command::Command;

pub mod crypto;
pub mod layer;
pub mod session;
pub mod stream;

pub const SECURE_HEADER_SIZE: u32 = 20;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SecureHeader {
    pub data_size: u32,
    pub iv: [u8; 16],
}

#[derive(Debug)]
pub struct SecureCommand {
    pub header: SecureHeader,
    pub command: Command,
}

pub const SECURE_HANDSHAKE_HEADER_SIZE: u32 = 12;

#[derive(Debug, Serialize, Deserialize)]
pub struct SecureHandshakeHeader {
    pub encrypted_key_len: u32,
    pub key_encrypt_type: u32,
    pub encrypt_type: u32,
}
