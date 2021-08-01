/*
 * Created on Sun Nov 29 2020
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

pub mod decode;
pub mod encode;

use std::{
    future::Future,
    io::{self, Read, Write},
    pin::Pin,
    task::{Context, Poll},
};

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, FutureExt, ready};

use crate::{
    secure::{stream::decode::decode_secure_head, SecurePacket},
    vec_buf::VecBuf,
};

use self::encode::to_encrypted_packet;

use super::{
    crypto::{CryptoError, CryptoStore},
    SecureHeader, SECURE_HEADER_SIZE,
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
    current_header: Option<(u32, SecureHeader)>,
    read_buf: VecBuf,
}

impl<S> SecureStream<S> {
    pub fn new(crypto: CryptoStore, stream: S) -> Self {
        Self {
            crypto,
            stream,
            current_header: None,
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
        let (data_size, header) = match self.current_header.take() {
            Some(header) => header,
            None => {
                let mut header_buf = [0_u8; SECURE_HEADER_SIZE + 4];
                self.stream.read_exact(&mut header_buf)?;

                decode_secure_head(&header_buf)?
            }
        };

        let mut encrypted_buf = vec![0_u8; (data_size - 16) as usize];
        if let Err(err) = self.stream.read_exact(&mut encrypted_buf) {
            self.current_header = Some((data_size, header));
            return Err(SecureError::from(err));
        }

        let data = self.crypto.decrypt_aes(&encrypted_buf, &header.iv)?;

        Ok(SecurePacket { header, data })
    }
}

impl<S: Write> SecureStream<S> {
    /// Write data.
    /// Returns size of packet written
    pub fn write_data(&mut self, buf: &[u8]) -> Result<usize, SecureError> {
        let encrypted = to_encrypted_packet(&self.crypto, buf)?;

        self.stream
            .write_all(&encrypted)?;

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

/// Async version of [SecureStream].
#[derive(Debug)]
pub struct SecureStreamAsync<S> {
    crypto: CryptoStore,
    stream: S,
    read_buf: VecBuf,
}

impl<S> SecureStreamAsync<S> {
    pub fn new(crypto: CryptoStore, stream: S) -> Self {
        Self {
            crypto,
            stream,
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

impl<S: AsyncRead + Unpin> SecureStreamAsync<S> {
    /// Read one encrypted packet
    pub fn read_packet<'a>(&'a mut self) -> ReadSecurePacketFuture<'a, S> {
        ReadSecurePacketFuture {
            crypto: &self.crypto,
            stream: &mut self.stream,
        }
    }
}

impl<S: AsyncWrite + Unpin> SecureStreamAsync<S> {
    /// Write data.
    /// Returns size of packet written
    pub fn write_data<'a>(&'a mut self, buf: &'a [u8]) -> WriteSecurePacketFuture<'a, S> {
        WriteSecurePacketFuture {
            crypto: &self.crypto,
            stream: &mut self.stream,
            buf
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for SecureStreamAsync<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if self.read_buf.is_empty() {
            let chunk = ready!(self.read_packet().poll_unpin(cx).map_err(io_error_map)?);

            self.read_buf.push(chunk.data);
        }

        Poll::Ready(self.read_buf.read(buf))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SecureStreamAsync<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.write_data(&buf)
            .poll_unpin(cx)
            .map_err(io_error_map)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_close(cx)
    }
}

#[derive(Debug)]
pub struct ReadSecurePacketFuture<'a, S> {
    crypto: &'a CryptoStore,
    stream: &'a mut S,
}

impl<S: AsyncRead + Unpin> Future for ReadSecurePacketFuture<'_, S> {
    type Output = Result<SecurePacket, SecureError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let (data_size, header) = {
            let mut header_buf = [0_u8; SECURE_HEADER_SIZE + 4];
            ready!(self.stream.read_exact(&mut header_buf).poll_unpin(cx))?;

            decode_secure_head(&header_buf)?
        };

        let mut encrypted_buf = vec![0_u8; (data_size - 16) as usize];
        ready!(self.stream.read_exact(&mut encrypted_buf).poll_unpin(cx))?;

        let data = self.crypto.decrypt_aes(&encrypted_buf, &header.iv)?;

        Poll::Ready(Ok(SecurePacket { header, data }))
    }
}

#[derive(Debug)]
pub struct WriteSecurePacketFuture<'a, S> {
    crypto: &'a CryptoStore,
    stream: &'a mut S,
    buf: &'a [u8],
}

impl<S: AsyncWrite + Unpin> Future for WriteSecurePacketFuture<'_, S> {
    type Output = Result<usize, SecureError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let encrypted = to_encrypted_packet(self.crypto, self.buf)?;

        ready!(self.stream.write_all(&encrypted).poll_unpin(cx))?;

        Poll::Ready(Ok(encrypted.len()))
    }
}

fn io_error_map(err: SecureError) -> io::Error {
    match err {
        SecureError::Io(err) => err,

        _ => io::Error::new(io::ErrorKind::InvalidData, "Invalid encryption data"),
    }
}
