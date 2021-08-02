/*
 * Created on Mon Aug 02 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use rsa::RsaPublicKey;

use crate::secure::{
    crypto::{CryptoStore, EncryptType, KeyEncryptType},
    SecureHandshakeHeader,
};

use super::SecureHandshakeError;

pub fn to_handshake_packet(
    crypto: &CryptoStore,
    key: &RsaPublicKey,
) -> Result<Vec<u8>, SecureHandshakeError> {
    let encrypted_key = crypto.encrypt_key(key)?;

    let handshake_header = SecureHandshakeHeader {
        key_encrypt_type: KeyEncryptType::RsaOaepSha1Mgf1Sha1 as u32,
        encrypt_type: EncryptType::AesCfb128 as u32,
    };
    let header_data = bincode::serialize(&handshake_header)?;

    Ok([
        encrypted_key.len().to_le_bytes().into(),
        header_data,
        encrypted_key,
    ]
    .concat())
}
