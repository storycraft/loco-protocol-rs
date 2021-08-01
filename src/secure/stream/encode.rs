/*
 * Created on Mon Aug 02 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use crate::secure::{SecureHeader, crypto::CryptoStore};

use super::SecureError;

/// Encrypt data using provided [CryptoStore] and make it packet 
pub fn to_encrypted_packet(crypto: &CryptoStore, data: &[u8]) -> Result<Vec<u8>, SecureError> {
    let mut iv = [0_u8; 16];
    CryptoStore::gen_random(&mut iv);

    let data_buf = crypto.encrypt_aes(&data, &iv)?;

    let data_size = (data_buf.len() + iv.len()) as u32;

    let buf = bincode::serialize(&SecureHeader {
        iv,
    })?;

    Ok([data_size.to_le_bytes().into(), buf, data_buf].concat())
}
