/*
 * Created on Sun Aug 01 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::io::Cursor;

use byteorder::{LittleEndian, ReadBytesExt};

use crate::command::{Command, HEADER_SIZE, HEAD_SIZE, Header};

use super::StreamError;

/// Decode [Header] and data_size into empty [Command].
pub fn decode_head(buf: &[u8]) -> Result<Command, StreamError> {
    let header = bincode::deserialize::<Header>(&buf[..HEADER_SIZE])?;
    let data_size = Cursor::new(&buf[HEADER_SIZE..HEAD_SIZE]).read_u32::<LittleEndian>()?;

    Ok(Command {
        header,
        data: vec![0_u8; data_size as usize]
    })
}