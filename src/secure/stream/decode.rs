/*
 * Created on Mon Aug 02 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::io::Cursor;

use byteorder::{LittleEndian, ReadBytesExt};

use crate::secure::SecureHeader;

use super::SecureError;

/// Decode data_size and [SecureHeader]
pub fn decode_secure_head(buf: &[u8]) -> Result<(u32, SecureHeader), SecureError> {
    let data_size = Cursor::new(&buf[..4]).read_u32::<LittleEndian>()?;

    let header = bincode::deserialize::<SecureHeader>(&buf[4..])?;
    Ok((data_size, header))
}
