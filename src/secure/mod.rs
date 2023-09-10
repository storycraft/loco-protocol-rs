/*
 * Created on Sat Sep 09 2023
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use serde::{Deserialize, Serialize};

pub mod client;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurePacket<T: ?Sized> {
    pub iv: [u8; 16],
    pub data: T,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HandshakePacket<T: ?Sized> {
    key_type: u32,
    encrypt_type: u32,
    encrypted_key: T,
}
