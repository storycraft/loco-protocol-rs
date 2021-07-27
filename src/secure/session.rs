/*
 * Created on Sun Jul 25 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use rsa::{PaddingScheme, RSAPrivateKey, RSAPublicKey};

use super::{
    crypto::{CryptoError, CryptoStore, EncryptType, KeyEncryptType},
    layer::SecureLayer,
    stream::SecureStream,
};
use crate::secure::{SecureHandshakeHeader, SECURE_HANDSHAKE_HEADER_SIZE};

use std::io::{self, Read, Write};

#[derive(Debug)]
pub enum SecureHandshakeError {
    Bincode(bincode::Error),
    Io(io::Error),
    Crypto(CryptoError),
}

impl From<bincode::Error> for SecureHandshakeError {
    fn from(err: bincode::Error) -> Self {
        Self::Bincode(err)
    }
}

impl From<io::Error> for SecureHandshakeError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<CryptoError> for SecureHandshakeError {
    fn from(err: CryptoError) -> Self {
        Self::Crypto(err)
    }
}

/// Secure session before handshake
pub trait SecureSession<S>: Sized {
    /// Handshake and returns secure layer on success
    fn handshake(self) -> Result<SecureLayer<S>, SecureHandshakeError>;

    /// Handshake and returns secure stream on success
    fn handshake_stream(self) -> Result<SecureStream<S>, SecureHandshakeError> {
        Ok(self.handshake()?.into())
    }
}

/// Client side connection
#[derive(Debug)]
pub struct SecureClientSession<S> {
    stream: S,
    crypto: CryptoStore,
    key: RSAPublicKey,
}

impl<S> SecureClientSession<S> {
    pub fn new(key: RSAPublicKey, crypto: CryptoStore, stream: S) -> Self {
        Self {
            stream,
            crypto,
            key,
        }
    }
}

impl<S: Write> SecureSession<S> for SecureClientSession<S> {
    fn handshake(mut self) -> Result<SecureLayer<S>, SecureHandshakeError> {
        let encrypted_key = self.crypto.encrypt_key(&self.key)?;

        let handshake_header = SecureHandshakeHeader {
            encrypted_key_len: encrypted_key.len() as u32,
            key_encrypt_type: KeyEncryptType::RsaOaepSha1Mgf1Sha1 as u32,
            encrypt_type: EncryptType::AesCfb128 as u32,
        };
        let header_data = bincode::serialize(&handshake_header)?;

        self.stream
            .write_all(&header_data)
            .and(self.stream.write_all(&encrypted_key))?;

        Ok(SecureLayer::new(self.crypto, self.stream))
    }
}

/// Server side connection
#[derive(Debug)]
pub struct SecureServerSession<S> {
    stream: S,
    key: RSAPrivateKey,
    current_header: Option<SecureHandshakeHeader>,
}

impl<S> SecureServerSession<S> {
    pub fn new(key: RSAPrivateKey, stream: S) -> Self {
        Self {
            stream,
            key,
            current_header: None,
        }
    }
}

impl<S: Read> SecureSession<S> for SecureServerSession<S> {
    fn handshake(mut self) -> Result<SecureLayer<S>, SecureHandshakeError> {
        let handshake_header = match self.current_header.take() {
            Some(header) => header,
            None => {
                let mut handshake_header_buf = [0_u8; SECURE_HANDSHAKE_HEADER_SIZE];
                self.stream.read_exact(&mut handshake_header_buf)?;

                bincode::deserialize::<SecureHandshakeHeader>(&handshake_header_buf)?
            }
        };

        let mut encrypted_key = vec![0_u8; handshake_header.encrypted_key_len as usize];
        if let Err(err) = self.stream.read_exact(&mut encrypted_key) {
            self.current_header = Some(handshake_header);

            return Err(SecureHandshakeError::from(err));
        }

        let key = [0_u8; 16];
        self.key
            .decrypt(PaddingScheme::new_oaep::<sha1::Sha1>(), &encrypted_key)
            .map_err(|_| CryptoError::CorruptedData)?;

        let crypto = CryptoStore::new_with_key(key);

        Ok(SecureLayer::new(crypto, self.stream))
    }
}
