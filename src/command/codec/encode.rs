/*
 * Created on Sun Aug 01 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use byteorder::{LittleEndian, WriteBytesExt};

use crate::command::Command;

/// Encode header and data_size to bytes.
/// The result Vec's length is same with HEADER_SIZE + 4.
pub fn encode_head(command: &Command) -> Result<Vec<u8>, bincode::Error> {
    let mut head = bincode::serialize(&command.header)?;
    head.write_u32::<LittleEndian>(command.data.len() as u32)?;

    Ok(head)
}
