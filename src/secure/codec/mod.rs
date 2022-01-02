/*
 * Created on Mon Jan 03 2022
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

pub mod decode;
pub mod encode;

use std::io::{self, Write, Read};

use futures::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};

use self::{encode::to_encrypted_packet, decode::decode_secure_head};

use super::{crypto::{CryptoStore, CryptoError}, SECURE_HEAD_SIZE, SecurePacket};

#[derive(Debug)]
pub enum SecureError {
    Bincode(bincode::Error),
    Io(io::Error),
    Crypto(CryptoError),
}

impl From<bincode::Error> for SecureError {
    fn from(err: bincode::Error) -> Self {
        Self::Bincode(err)
    }
}

impl From<io::Error> for SecureError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<CryptoError> for SecureError {
    fn from(err: CryptoError) -> Self {
        Self::Crypto(err)
    }
}

#[derive(Debug)]
pub struct SecureCodec<S> {
    crypto: CryptoStore,
    stream: S,
}

impl<S> SecureCodec<S> {
    pub const fn new(crypto: CryptoStore, stream: S) -> Self {
        Self { crypto, stream }
    }

    pub fn crypto(&self) -> &CryptoStore {
        &self.crypto
    }
    
    pub fn stream(&self) -> &S {
        &self.stream
    }

    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    pub fn into_inner(self) -> (CryptoStore, S) {
        (self.crypto, self.stream)
    }
}

impl<S: Read> SecureCodec<S> {
    /// Read one encrypted packet
    pub fn read_packet(&mut self) -> Result<SecurePacket, SecureError> {
        let mut head_buf = [0_u8; SECURE_HEAD_SIZE];
        self.stream.read_exact(&mut head_buf)?;

        let mut packet = decode_secure_head(&head_buf)?;
        self.stream.read_exact(&mut packet.data)?;

        let data = self.crypto.decrypt_aes(&packet.data, &packet.header.iv)?;

        Ok(SecurePacket {
            header: packet.header,
            data,
        })
    }
}

impl<S: Write> SecureCodec<S> {
    /// Write one secure packet.
    /// Returns size of packet written.
    pub fn write_data(&mut self, buf: &[u8]) -> Result<usize, SecureError> {
        let encrypted = to_encrypted_packet(&self.crypto, buf)?;

        self.stream.write_all(&encrypted)?;

        Ok(encrypted.len())
    }
}

impl<S: AsyncRead + Unpin> SecureCodec<S> {
    /// Read one encrypted packet
    pub async fn read_packet_async(&mut self) -> Result<SecurePacket, SecureError> {
        let mut head_buf = [0_u8; SECURE_HEAD_SIZE];
        self.stream.read_exact(&mut head_buf).await?;

        let mut packet = decode_secure_head(&head_buf)?;
        self.stream.read_exact(&mut packet.data).await?;

        let data = self.crypto.decrypt_aes(&packet.data, &packet.header.iv)?;

        Ok(SecurePacket {
            header: packet.header,
            data,
        })
    }
}

impl<S: AsyncWrite + Unpin> SecureCodec<S> {
    /// Write one secure packet.
    /// Returns size of packet written.
    pub async fn write_data_async(&mut self, buf: &[u8]) -> Result<usize, SecureError> {
        let encrypted = to_encrypted_packet(&self.crypto, buf)?;

        self.stream.write_all(&encrypted).await?;

        Ok(encrypted.len())
    }
}