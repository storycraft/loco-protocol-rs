/*
 * Created on Sat Jul 24 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::{
    collections::VecDeque,
    io::{self, Cursor, Read, Write},
};

use super::{crypto::CryptoStore, layer::{SecureLayer, SecureLayerError}};

pub struct SecureStream<S> {
    layer: SecureLayer<S>,
    buf: VecDeque<u8>,
}

impl<S> SecureStream<S> {
    pub fn new(crypto: CryptoStore, stream: S) -> Self {
        SecureLayer::new(crypto, stream).into()
    }

    pub fn stream(&self) -> &S {
        self.layer.stream()
    }

    pub fn stream_mut(&mut self) -> &mut S {
        self.layer.stream_mut()
    }

    pub fn crypto(&self) -> &CryptoStore {
        &self.layer.crypto()
    }

    pub fn unwrap(self) -> (CryptoStore, S) {
        self.layer.unwrap()
    }
}

impl<S: Read> Read for SecureStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.buf.len() > 0 {
            let len = buf.len().min(self.buf.len());

            let mut buf_cursor = Cursor::new(buf);
            self.buf.drain(..len).for_each(|b| {
                buf_cursor.write(&[b]).unwrap();
            });

            Ok(len)
        } else {
            let read = self.layer.read().map_err(io_error_map)?;

            let copied = io::copy(&mut Cursor::new(&read), &mut Cursor::new(buf))?;

            self.buf
                .extend(read.into_iter().skip(copied as usize));

            Ok(copied as usize)
        }
    }
}

impl<S: Write> Write for SecureStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.layer.write(buf).map_err(io_error_map)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.layer.stream_mut().flush()
    }
}

impl<S> From<SecureLayer<S>> for SecureStream<S> {
    fn from(layer: SecureLayer<S>) -> Self {
        Self {
            layer,
            buf: VecDeque::new(),
        }
    }
}

fn io_error_map(err: SecureLayerError) -> io::Error {
    match err {
        SecureLayerError::Io(err) => err,

        _ => io::Error::new(io::ErrorKind::InvalidData, "Failed to write encrypted data"),
    }
}
