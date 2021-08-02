/*
 * Created on Sun Nov 29 2020
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

pub mod decode;
pub mod encode;

use std::{
    io::{self, Read, Write},
    pin::Pin,
    task::{Context, Poll},
};

use futures::{ready, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, FutureExt};

use crate::{
    secure::{stream::decode::decode_secure_head, SecurePacket},
    vec_buf::VecBuf,
};

use self::encode::to_encrypted_packet;

use super::{
    crypto::{CryptoError, CryptoStore},
    SECURE_HEAD_SIZE,
};

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

/// Common secure layer used in client and server
#[derive(Debug)]
pub struct SecureStream<S> {
    crypto: CryptoStore,
    stream: S,
    current_packet: Option<SecurePacket>,
    read_buf: VecBuf,
}

impl<S> SecureStream<S> {
    pub fn new(crypto: CryptoStore, stream: S) -> Self {
        Self {
            crypto,
            stream,
            current_packet: None,
            read_buf: VecBuf::new(),
        }
    }

    pub fn stream(&self) -> &S {
        &self.stream
    }

    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    pub fn crypto(&self) -> &CryptoStore {
        &self.crypto
    }

    pub fn unwrap(self) -> (CryptoStore, S) {
        (self.crypto, self.stream)
    }
}

impl<S: Read> SecureStream<S> {
    /// Read one encrypted packet
    pub fn read_packet(&mut self) -> Result<SecurePacket, SecureError> {
        let mut packet = match self.current_packet.take() {
            Some(packet) => packet,
            None => {
                let mut head_buf = [0_u8; SECURE_HEAD_SIZE];
                self.stream.read_exact(&mut head_buf)?;

                decode_secure_head(&head_buf)?
            }
        };

        if let Err(err) = self.stream.read_exact(&mut packet.data) {
            self.current_packet = Some(packet);
            return Err(SecureError::from(err));
        }

        let data = self.crypto.decrypt_aes(&packet.data, &packet.header.iv)?;

        Ok(SecurePacket {
            header: packet.header,
            data,
        })
    }
}

impl<S: Write> SecureStream<S> {
    /// Write data.
    /// Returns size of packet written
    pub fn write_data(&mut self, buf: &[u8]) -> Result<usize, SecureError> {
        let encrypted = to_encrypted_packet(&self.crypto, buf)?;

        self.stream.write_all(&encrypted)?;

        Ok(encrypted.len())
    }
}

impl<S: Read> Read for SecureStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.read_buf.is_empty() {
            let chunk = self.read_packet().map_err(io_error_map)?;

            self.read_buf.push(chunk.data);
        }

        self.read_buf.read(buf)
    }
}

impl<S: Write> Write for SecureStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_data(buf).map_err(io_error_map)?;

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl<S: AsyncRead + Unpin> SecureStream<S> {
    /// Read one encrypted packet async
    pub async fn read_packet_async(&mut self) -> Result<SecurePacket, SecureError> {
        let mut packet = match self.current_packet.take() {
            Some(packet) => packet,
            None => {
                let mut head_buf = [0_u8; SECURE_HEAD_SIZE];
                self.stream.read_exact(&mut head_buf).await?;

                decode_secure_head(&head_buf)?
            }
        };

        if let Err(err) = self.stream.read_exact(&mut packet.data).await {
            self.current_packet = Some(packet);
            return Err(SecureError::from(err));
        }

        let data = self.crypto.decrypt_aes(&packet.data, &packet.header.iv)?;

        Ok(SecurePacket {
            header: packet.header,
            data,
        })
    }
}

impl<S: AsyncWrite + Unpin> SecureStream<S> {
    /// Write data async.
    /// Returns size of packet written
    pub async fn write_data_async(&mut self, buf: &[u8]) -> Result<usize, SecureError> {
        let encrypted = to_encrypted_packet(&self.crypto, buf)?;

        self.stream.write_all(&encrypted).await?;

        Ok(encrypted.len())
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for SecureStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if self.read_buf.is_empty() {
            let chunk = ready!(Box::pin(self.read_packet_async())
                .poll_unpin(cx)
                .map_err(io_error_map)?);

            self.read_buf.push(chunk.data);
        }

        Poll::Ready(self.read_buf.read(buf))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SecureStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(Box::pin(self.write_data_async(&buf))
            .poll_unpin(cx)
            .map_err(io_error_map))?;

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_close(cx)
    }
}

fn io_error_map(err: SecureError) -> io::Error {
    match err {
        SecureError::Io(err) => err,

        _ => io::Error::new(io::ErrorKind::InvalidData, "Invalid encryption data"),
    }
}
