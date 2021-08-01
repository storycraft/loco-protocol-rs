/*
 * Created on Sun Aug 01 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::io::Cursor;

use byteorder::{LittleEndian, ReadBytesExt};

use crate::command::{HEADER_SIZE, Header};

use super::StreamError;

/// Decode [Header] and data_size.
pub fn decode_head(buf: &[u8]) -> Result<(Header, u32), StreamError> {
    let header = bincode::deserialize::<Header>(&buf[..HEADER_SIZE])?;
    let data_size = Cursor::new(&buf[HEADER_SIZE..]).read_u32::<LittleEndian>()?;

    Ok((header, data_size))
}