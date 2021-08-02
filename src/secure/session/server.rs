/*
 * Created on Mon Aug 02 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::io::Cursor;

use byteorder::{LittleEndian, ReadBytesExt};

use crate::secure::{SecureHandshake, SecureHandshakeHeader, SECURE_HANDSHAKE_HEAD_SIZE};

use super::SecureHandshakeError;

/// Decode key_size and [SecureHandshakeHeader] into empty [SecureHandshake].
pub fn decode_handshake_head(buf: &[u8]) -> Result<SecureHandshake, SecureHandshakeError> {
    let key_size = Cursor::new(&buf[..4]).read_u32::<LittleEndian>()?;
    let header =
        bincode::deserialize::<SecureHandshakeHeader>(&buf[4..SECURE_HANDSHAKE_HEAD_SIZE])?;

    Ok(SecureHandshake {
        header,
        encrypted_key: vec![0_u8; key_size as usize],
    })
}
