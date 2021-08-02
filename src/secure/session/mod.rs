/*
 * Created on Sun Jul 25 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

pub mod client;
pub mod server;

use futures::{ready, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, FutureExt};
use rsa::{PaddingScheme, RsaPrivateKey, RsaPublicKey};

use self::{client::to_handshake_packet, server::decode_handshake_head};

use super::{
    crypto::{CryptoError, CryptoStore},
    stream::SecureStream,
    SecureHandshake,
};
use crate::secure::SECURE_HANDSHAKE_HEAD_SIZE;

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

    /// Do client handshake async
    pub fn handshake_async<'a, S: AsyncWrite + Unpin>(
        &self,
        secure_stream: &'a mut SecureStream<S>,
    ) -> WriteSecureHandshakeFuture<'a, S> {
        let handshake_packet = to_handshake_packet(secure_stream.crypto(), &self.key);

        WriteSecureHandshakeFuture {
            handshake_packet: Some(handshake_packet),
            stream: secure_stream.stream_mut(),
        }
    }
}

#[derive(Debug)]
pub struct WriteSecureHandshakeFuture<'a, S> {
    stream: &'a mut S,
    handshake_packet: Option<Result<Vec<u8>, SecureHandshakeError>>,
}

impl<S: AsyncWrite + Unpin> Future for WriteSecureHandshakeFuture<'_, S> {
    type Output = Result<(), SecureHandshakeError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        match self.handshake_packet.take() {
            Some(handshake_packet) => {
                let handshake_packet = handshake_packet?;

                match self.stream.write_all(&handshake_packet).poll_unpin(cx) {
                    Poll::Ready(res) => {
                        res?;

                        Poll::Ready(Ok(()))
                    }

                    Poll::Pending => {
                        self.handshake_packet = Some(Ok(handshake_packet));

                        Poll::Pending
                    }
                }
            }

            None => Poll::Pending,
        }
    }
}

/// Server side connection
#[derive(Debug)]
pub struct SecureServerSession {
    key: RsaPrivateKey,
    current_handshake: Option<SecureHandshake>,
}

impl SecureServerSession {
    pub fn new(key: RsaPrivateKey) -> Self {
        Self {
            key,
            current_handshake: None,
        }
    }

    /// Do server handshake and returns CryptoStore on success
    pub fn handshake<S: Read>(
        &mut self,
        stream: &mut S,
    ) -> Result<CryptoStore, SecureHandshakeError> {
        let mut handshake = match self.current_handshake.take() {
            Some(header) => header,
            None => {
                let mut handshake_head_buf = [0_u8; SECURE_HANDSHAKE_HEAD_SIZE];
                stream.read_exact(&mut handshake_head_buf)?;

                decode_handshake_head(&handshake_head_buf)?
            }
        };

        if let Err(err) = stream.read_exact(&mut handshake.encrypted_key) {
            self.current_handshake = Some(handshake);

            return Err(SecureHandshakeError::from(err));
        }

        let key = [0_u8; 16];
        self.key
            .decrypt(
                PaddingScheme::new_oaep::<sha1::Sha1>(),
                &handshake.encrypted_key,
            )
            .map_err(|_| CryptoError::CorruptedData)?;

        Ok(CryptoStore::new_with_key(key))
    }

    /// Do server handshake async and returns CryptoStore on success
    pub fn handshake_async<'a, S: AsyncRead + Unpin>(
        &'a mut self,
        stream: &'a mut S,
    ) -> ReadSecureHandshakeFuture<'a, S> {
        ReadSecureHandshakeFuture {
            session: self,
            stream,
        }
    }
}

#[derive(Debug)]
pub struct ReadSecureHandshakeFuture<'a, S> {
    session: &'a mut SecureServerSession,
    stream: &'a mut S,
}

impl<S: AsyncRead + Unpin> Future for ReadSecureHandshakeFuture<'_, S> {
    type Output = Result<CryptoStore, SecureHandshakeError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let mut handshake = match self.session.current_handshake.take() {
            Some(handshake) => handshake,
            None => {
                let mut handshake_head_buf = [0_u8; SECURE_HANDSHAKE_HEAD_SIZE];
                ready!(self
                    .stream
                    .read_exact(&mut handshake_head_buf)
                    .poll_unpin(cx))?;

                decode_handshake_head(&handshake_head_buf)?
            }
        };

        match self
            .stream
            .read_exact(&mut handshake.encrypted_key)
            .poll_unpin(cx)
        {
            Poll::Ready(res) => {
                res?;

                let key = [0_u8; 16];
                self.session
                    .key
                    .decrypt(
                        PaddingScheme::new_oaep::<sha1::Sha1>(),
                        &handshake.encrypted_key,
                    )
                    .map_err(|_| CryptoError::CorruptedData)?;

                Poll::Ready(Ok(CryptoStore::new_with_key(key)))
            }

            Poll::Pending => {
                self.session.current_handshake = Some(handshake);

                Poll::Pending
            }
        }
    }
}
