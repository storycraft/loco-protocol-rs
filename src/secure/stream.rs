/*
 * Created on Sun Nov 29 2020
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::{
    io::{self, Read, Write},
    pin::Pin,
    task::{Context, Poll},
};

use futures::{ready, AsyncRead, AsyncWrite, FutureExt};

use crate::vec_buf::VecBuf;

use super::{
    codec::{SecureCodec, SecureError},
    crypto::CryptoStore,
};

/// Secure layer used in client and server
#[derive(Debug)]
pub struct SecureStream<S> {
    codec: SecureCodec<S>,
    read_buf: VecBuf,
}

impl<S> SecureStream<S> {
    pub fn new(crypto: CryptoStore, stream: S) -> Self {
        Self {
            codec: SecureCodec::new(crypto, stream),
            read_buf: VecBuf::new(),
        }
    }

    pub fn stream(&self) -> &S {
        self.codec.stream()
    }

    pub fn stream_mut(&mut self) -> &mut S {
        self.codec.stream_mut()
    }

    pub fn crypto(&self) -> &CryptoStore {
        self.codec.crypto()
    }

    pub fn into_inner(self) -> (CryptoStore, S) {
        self.codec.into_inner()
    }
}

impl<S: Read> Read for SecureStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.read_buf.is_empty() {
            let chunk = self.codec.read_packet().map_err(io_error_map)?;

            self.read_buf.push(chunk.data);
        }

        self.read_buf.read(buf)
    }
}

impl<S: Write> Write for SecureStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.codec.write_data(buf).map_err(io_error_map)?;

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.codec.stream_mut().flush()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for SecureStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if self.read_buf.is_empty() {
            let chunk = ready!(Box::pin(self.codec.read_packet_async())
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
        ready!(Box::pin(self.codec.write_data_async(&buf))
            .poll_unpin(cx)
            .map_err(io_error_map))?;

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(self.codec.stream_mut()).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(self.codec.stream_mut()).poll_close(cx)
    }
}

fn io_error_map(err: SecureError) -> io::Error {
    match err {
        SecureError::Io(err) => err,

        _ => io::Error::new(io::ErrorKind::InvalidData, "Invalid encryption data"),
    }
}
