/*
 * Created on Sun Nov 29 2020
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::{
    io::{self, Cursor, Read, Write},
    pin::Pin,
    task::{Context, Poll}, collections::VecDeque,
};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use futures::{ready, AsyncRead, AsyncWrite};

use super::{
    crypto::{CryptoError, CryptoStore},
    SecureHeader, SECURE_HEAD_SIZE, SECURE_HEADER_SIZE,
};

/// Secure layer used in client and server
#[derive(Debug)]
pub struct SecureStream<S> {
    crypto: CryptoStore,
    stream: S,

    current_read: Option<ReadStreamState>,
    current_write: Option<WriteStreamState>,

    read_buf: VecDeque<u8>,
}

impl<S> SecureStream<S> {
    pub fn new(crypto: CryptoStore, stream: S) -> Self {
        Self {
            crypto,
            stream,
            current_read: None,
            current_write: None,
            read_buf: VecDeque::new(),
        }
    }

    pub const fn stream(&self) -> &S {
        &self.stream
    }

    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    pub fn crypto(&self) -> &CryptoStore {
        &self.crypto
    }

    pub fn into_inner(self) -> (CryptoStore, S) {
        (self.crypto, self.stream)
    }
}

impl<S: Read> Read for SecureStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.read_buf.is_empty() {
            let chunk = self.read_packet().map_err(io_error_map)?;

            self.read_buf.extend(chunk);
        }

        self.read_buf.read(buf)
    }
}

impl<S: Read> SecureStream<S> {
    fn read_packet(&mut self) -> Result<Vec<u8>, SecureError> {
        if self.current_read.is_none() {
            self.current_read = Some(ReadStreamState::Head(0, [0; SECURE_HEAD_SIZE]));
        }

        let current_read = self.current_read.as_mut().unwrap();
        if let ReadStreamState::Head(read, buf) = current_read {
            while *read != buf.len() {
                *read += self.stream.read(&mut buf[*read..])?;
            }

            let data_size = (&buf[..4]).read_u32::<LittleEndian>()? as usize - SECURE_HEADER_SIZE;
            let header = bincode::deserialize::<SecureHeader>(&buf[4..])?;

            *current_read = ReadStreamState::Data(header, 0, vec![0; data_size]);
        }

        if let ReadStreamState::Data(header, read, buf) = current_read {
            while *read != buf.len() {
                *read += self.stream.read(&mut buf[*read..])?;
            }

            let decrypted_data = self.crypto.decrypt_aes(buf, &header.iv)?;

            self.current_read = None;
            return Ok(decrypted_data);
        }

        unreachable!()
    }
}

impl<S: Write> Write for SecureStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_packet(buf).map_err(io_error_map)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl<S: Write> SecureStream<S> {
    fn write_packet(&mut self, buf: &[u8]) -> Result<usize, SecureError> {
        if self.current_write.is_none() {
            let head = [0; SECURE_HEAD_SIZE];
            let mut cursor = Cursor::new(head);

            cursor.write_u32::<LittleEndian>((buf.len() + 16) as u32)?;

            let mut iv = [0; 16];
            self.crypto.gen_random(&mut iv);
            bincode::serialize_into(&mut cursor, &SecureHeader { iv })?;

            let encrypted_data = self.crypto.encrypt_aes(buf, &iv)?;

            self.current_write = Some(WriteStreamState::Head(
                0,
                cursor.into_inner(),
                encrypted_data,
            ));
        }

        let current_write = self.current_write.as_mut().unwrap();
        if let WriteStreamState::Head(written, buf, encrypted_data) = current_write {
            while *written != buf.len() {
                *written += self.stream.write(&buf[*written..])?;
            }

            *current_write = WriteStreamState::Data(0, std::mem::take(encrypted_data));
        }

        if let WriteStreamState::Data(written, data) = current_write {
            while *written != data.len() {
                *written += self.stream.write(&mut data[*written..])?;
            }

            self.current_write = None;
            return Ok(buf.len());
        }

        unreachable!()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for SecureStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if self.read_buf.is_empty() {
            let chunk = ready!(self.as_mut().poll_read_packet(cx)).map_err(io_error_map)?;

            self.read_buf.extend(chunk);
        }

        Poll::Ready(self.read_buf.read(buf))
    }
}

impl<S: AsyncRead + Unpin> SecureStream<S> {
    fn poll_read_packet(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Vec<u8>, SecureError>> {
        if self.current_read.is_none() {
            self.current_read = Some(ReadStreamState::Head(0, [0; SECURE_HEAD_SIZE]));
        }

        let current_read = self.current_read.as_mut().unwrap();
        if let ReadStreamState::Head(read, buf) = current_read {
            while *read != buf.len() {
                *read += ready!(Pin::new(&mut self.stream).poll_read(cx, &mut buf[*read..]))?;
            }

            let data_size = (&buf[..4]).read_u32::<LittleEndian>()? as usize - SECURE_HEADER_SIZE;
            let header = bincode::deserialize::<SecureHeader>(&buf[4..])?;

            *current_read = ReadStreamState::Data(header, 0, vec![0; data_size]);
        }

        if let ReadStreamState::Data(header, read, buf) = current_read {
            while *read != buf.len() {
                *read += ready!(Pin::new(&mut self.stream).poll_read(cx, &mut buf[*read..]))?;
            }

            let decrypted_data = self.crypto.decrypt_aes(buf, &header.iv)?;

            self.current_read = None;
            return Poll::Ready(Ok(decrypted_data));
        }

        unreachable!()
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SecureStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(ready!(self.as_mut().poll_write_packet(cx, buf)).map_err(io_error_map))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_close(cx)
    }
}

impl<S: AsyncWrite + Unpin> SecureStream<S> {
    fn poll_write_packet(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, SecureError>> {
        if self.current_write.is_none() {
            let head = [0; SECURE_HEAD_SIZE];
            let mut cursor = Cursor::new(head);

            cursor.write_u32::<LittleEndian>((buf.len() + 16) as u32)?;

            let mut iv = [0; 16];
            self.crypto.gen_random(&mut iv);
            bincode::serialize_into(&mut cursor, &SecureHeader { iv })?;

            let encrypted_data = self.crypto.encrypt_aes(buf, &iv)?;

            self.current_write = Some(WriteStreamState::Head(
                0,
                cursor.into_inner(),
                encrypted_data,
            ));
        }

        let current_write = self.current_write.as_mut().unwrap();
        if let WriteStreamState::Head(written, buf, encrypted_data) = current_write {
            while *written != buf.len() {
                *written += ready!(Pin::new(&mut self.stream).poll_write(cx, &buf[*written..]))?;
            }

            *current_write = WriteStreamState::Data(0, std::mem::take(encrypted_data));
        }

        if let WriteStreamState::Data(written, data) = current_write {
            while *written != data.len() {
                *written +=
                    ready!(Pin::new(&mut self.stream).poll_write(cx, &mut data[*written..]))?;
            }

            self.current_write = None;
            return Poll::Ready(Ok(buf.len()));
        }

        unreachable!()
    }
}

#[derive(Debug)]
enum SecureError {
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
enum ReadStreamState {
    Head(usize, [u8; SECURE_HEAD_SIZE]),
    Data(SecureHeader, usize, Vec<u8>),
}

#[derive(Debug)]
enum WriteStreamState {
    Head(usize, [u8; SECURE_HEAD_SIZE], Vec<u8>),
    Data(usize, Vec<u8>),
}

fn io_error_map(err: SecureError) -> io::Error {
    match err {
        SecureError::Io(err) => err,

        _ => io::Error::new(io::ErrorKind::InvalidData, "Invalid encryption data"),
    }
}
