/*
 * Created on Sun Jul 25 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

pub mod client;
pub mod server;

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use rsa::{PaddingScheme, RsaPrivateKey, RsaPublicKey};

use self::{client::to_handshake_packet, server::decode_handshake_head};

use super::{
    crypto::{CryptoError, CryptoStore},
    stream::SecureStream,
};
use crate::secure::SECURE_HANDSHAKE_HEAD_SIZE;

use std::{
    convert::TryInto,
    error::Error,
    fmt::Display,
    io::{self, Read, Write},
};

#[derive(Debug)]
pub enum SecureHandshakeError {
    Bincode(bincode::Error),
    Io(io::Error),
    Crypto(CryptoError),
    InvalidKey,
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

impl Display for SecureHandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecureHandshakeError::Bincode(err) => err.fmt(f),
            SecureHandshakeError::Io(err) => err.fmt(f),
            SecureHandshakeError::Crypto(err) => err.fmt(f),
            SecureHandshakeError::InvalidKey => write!(f, "Invalid key"),
        }
    }
}

impl Error for SecureHandshakeError {}

/// Client side credential session
#[derive(Debug)]
pub struct SecureClientSession {
    key: RsaPublicKey,
}

impl SecureClientSession {
    pub const fn new(key: RsaPublicKey) -> Self {
        Self { key }
    }
}

impl SecureClientSession {
    /// Do client handshake
    pub fn handshake<S: Write>(
        &self,
        secure_stream: &mut SecureStream<S>,
    ) -> Result<(), SecureHandshakeError> {
        let handshake = to_handshake_packet(secure_stream.crypto(), &self.key)?;

        secure_stream.stream_mut().write_all(&handshake)?;

        Ok(())
    }

    /// Do client handshake async
    pub async fn handshake_async<'a, S: AsyncWrite + Unpin>(
        &self,
        secure_stream: &'a mut SecureStream<S>,
    ) -> Result<(), SecureHandshakeError> {
        let handshake = to_handshake_packet(secure_stream.crypto(), &self.key)?;

        secure_stream.stream_mut().write_all(&handshake).await?;

        Ok(())
    }
}

/// Server side credential session
#[derive(Debug)]
pub struct SecureServerSession {
    key: RsaPrivateKey,
}

impl SecureServerSession {
    pub const fn new(key: RsaPrivateKey) -> Self {
        Self { key }
    }

    /// Do server handshake and returns CryptoStore on success
    pub fn handshake<S: Read>(
        &mut self,
        stream: &mut S,
    ) -> Result<CryptoStore, SecureHandshakeError> {
        let mut handshake_head_buf = [0_u8; SECURE_HANDSHAKE_HEAD_SIZE];
        stream.read_exact(&mut handshake_head_buf)?;

        let mut handshake = decode_handshake_head(&handshake_head_buf)?;
        stream.read_exact(&mut handshake.encrypted_key)?;

        let key = self
            .key
            .decrypt(
                PaddingScheme::new_oaep::<sha1::Sha1>(),
                &handshake.encrypted_key,
            )
            .map_err(|_| CryptoError::CorruptedData)?;

        Ok(CryptoStore::new_with_key(
            key.try_into()
                .map_err(|_| SecureHandshakeError::InvalidKey)?,
        ))
    }

    /// Do server handshake async and returns CryptoStore on success
    pub async fn handshake_async<'a, S: AsyncRead + Unpin>(
        &'a mut self,
        stream: &'a mut S,
    ) -> Result<CryptoStore, SecureHandshakeError> {
        let mut handshake_head_buf = [0_u8; SECURE_HANDSHAKE_HEAD_SIZE];
        stream.read_exact(&mut handshake_head_buf).await?;

        let mut handshake = decode_handshake_head(&handshake_head_buf)?;
        stream.read_exact(&mut handshake.encrypted_key).await?;

        let key = self
            .key
            .decrypt(
                PaddingScheme::new_oaep::<sha1::Sha1>(),
                &handshake.encrypted_key,
            )
            .map_err(|_| CryptoError::CorruptedData)?;

        Ok(CryptoStore::new_with_key(
            key.try_into()
                .map_err(|_| SecureHandshakeError::InvalidKey)?,
        ))
    }
}
