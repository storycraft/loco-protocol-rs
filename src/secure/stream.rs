/*
 * Created on Sat Jul 24 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::io::{self, Read, Write};

use crate::vec_buf::VecBuf;

use super::{
    crypto::CryptoStore,
    layer::{SecureLayer, SecureLayerError},
};

#[derive(Debug)]
pub struct SecureStream<S> {
    layer: SecureLayer<S>,
    read_buf: VecBuf,
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
        let chunk = self.layer.read().map_err(io_error_map)?;

        self.read_buf.push(chunk);

        self.read_buf.read(buf)
    }
}

impl<S: Write> Write for SecureStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.layer.write(buf).map_err(io_error_map)?;

        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.layer.stream_mut().flush()
    }
}

impl<S> From<SecureLayer<S>> for SecureStream<S> {
    fn from(layer: SecureLayer<S>) -> Self {
        Self {
            layer,
            read_buf: VecBuf::new(),
        }
    }
}

fn io_error_map(err: SecureLayerError) -> io::Error {
    match err {
        SecureLayerError::Io(err) => err,

        _ => io::Error::new(io::ErrorKind::InvalidData, "Invalid encryption data"),
    }
}
