/*
 * Created on Sun Jul 25 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

pub mod client;
pub mod server;

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, FutureExt, ready};
use rsa::{PaddingScheme, RsaPrivateKey, RsaPublicKey};

use self::client::to_handshake_packet;

use super::{
    crypto::{CryptoError, CryptoStore},
    stream::{SecureStream, SecureStreamAsync},
};
use crate::secure::{SecureHandshakeHeader, SECURE_HANDSHAKE_HEADER_SIZE};

use std::{
    future::Future,
    io::{self, Read, Write},
    pin::Pin,
    task::{Context, Poll},
};

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

/// Client side connection
pub struct SecureClientSession {
    key: RsaPublicKey,
}

impl SecureClientSession {
    pub fn new(key: RsaPublicKey) -> Self {
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
}

/// Async version of SecureClientSession
#[derive(Debug)]
pub struct SecureClientSessionAsync {
    key: RsaPublicKey,
}

impl SecureClientSessionAsync {
    pub fn new(key: RsaPublicKey) -> Self {
        Self { key }
    }

    /// Do client handshake
    pub fn handshake<'a, S: AsyncWrite + Unpin>(
        &'a self,
        secure_stream: &'a mut SecureStreamAsync<S>,
    ) -> WriteSecureHandshakeFuture<'a, S> {
        WriteSecureHandshakeFuture {
            key: &self.key,
            secure_stream,
        }
    }
}

#[derive(Debug)]
pub struct WriteSecureHandshakeFuture<'a, S> {
    key: &'a RsaPublicKey,
    secure_stream: &'a mut SecureStreamAsync<S>,
}

impl<S: AsyncWrite + Unpin> Future for WriteSecureHandshakeFuture<'_, S> {
    type Output = Result<(), SecureHandshakeError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let packet = to_handshake_packet(self.secure_stream.crypto(), self.key)?;

        ready!(self.secure_stream.write_all(&packet).poll_unpin(cx))?;

        Poll::Ready(Ok(()))
    }
}

/// Server side connection
#[derive(Debug)]
pub struct SecureServerSession {
    key: RsaPrivateKey,
    current_header: Option<SecureHandshakeHeader>,
}

impl SecureServerSession {
    pub fn new(key: RsaPrivateKey) -> Self {
        Self {
            key,
            current_header: None,
        }
    }

    /// Do server handshake and returns CryptoStore on success
    pub fn handshake<S: Read>(
        &mut self,
        stream: &mut S,
    ) -> Result<CryptoStore, SecureHandshakeError> {
        let handshake_header = match self.current_header.take() {
            Some(header) => header,
            None => {
                let mut handshake_header_buf = [0_u8; SECURE_HANDSHAKE_HEADER_SIZE];
                stream.read_exact(&mut handshake_header_buf)?;

                bincode::deserialize::<SecureHandshakeHeader>(&handshake_header_buf)?
            }
        };

        let mut encrypted_key = vec![0_u8; handshake_header.encrypted_key_len as usize];
        if let Err(err) = stream.read_exact(&mut encrypted_key) {
            self.current_header = Some(handshake_header);

            return Err(SecureHandshakeError::from(err));
        }

        let key = [0_u8; 16];
        self.key
            .decrypt(PaddingScheme::new_oaep::<sha1::Sha1>(), &encrypted_key)
            .map_err(|_| CryptoError::CorruptedData)?;

        Ok(CryptoStore::new_with_key(key))
    }
}

/// Async version of [SecureServerSession]
#[derive(Debug)]
pub struct SecureServerSessionAsync {
    key: RsaPrivateKey,
}

impl SecureServerSessionAsync {
    pub fn new(key: RsaPrivateKey) -> Self {
        Self { key }
    }

    /// Do server handshake and returns CryptoStore on success
    pub fn handshake<'a, S: AsyncRead + Unpin>(
        &'a self,
        secure_stream: &'a mut SecureStreamAsync<S>,
    ) -> ReadSecureHandshakeFuture<'a, S> {
        ReadSecureHandshakeFuture {
            key: &self.key,
            secure_stream,
        }
    }
}

#[derive(Debug)]
pub struct ReadSecureHandshakeFuture<'a, S> {
    key: &'a RsaPrivateKey,
    secure_stream: &'a mut SecureStreamAsync<S>,
}

impl<S: AsyncRead + Unpin> Future for ReadSecureHandshakeFuture<'_, S> {
    type Output = Result<CryptoStore, SecureHandshakeError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let handshake_header = {
            let mut handshake_header_buf = [0_u8; SECURE_HANDSHAKE_HEADER_SIZE];
            ready!(self.secure_stream.read_exact(&mut handshake_header_buf).poll_unpin(cx))?;

            bincode::deserialize::<SecureHandshakeHeader>(&handshake_header_buf)?
        };

        let mut encrypted_key = vec![0_u8; handshake_header.encrypted_key_len as usize];
        ready!(self.secure_stream.read_exact(&mut encrypted_key).poll_unpin(cx))?;

        let key = [0_u8; 16];
        self.key
            .decrypt(PaddingScheme::new_oaep::<sha1::Sha1>(), &encrypted_key)
            .map_err(|_| CryptoError::CorruptedData)?;

        Poll::Ready(Ok(CryptoStore::new_with_key(key)))
    }
}
