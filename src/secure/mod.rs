/*
 * Created on Sat Sep 09 2023
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use serde::{Serialize, Deserialize};

pub mod client;

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurePacket<T: ?Sized> {
    pub iv: [u8; 16],
    pub data: T,
}
