/*
 * Created on Sat Jul 24 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::io::{self, Read, Write};

use super::{
    crypto::CryptoStore,
    layer::{SecureLayer, SecureLayerError},
};

pub struct SecureStream<S> {
    layer: SecureLayer<S>,
    read_buf: Vec<u8>,
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
        if self.read_buf.len() < buf.len() {
            let read = self.layer.read().map_err(io_error_map)?;

            if read.len() >= buf.len() {
                let len = buf.len();
                buf.copy_from_slice(&read[..len]);
                if read.len() > buf.len() {
                    self.read_buf.extend_from_slice(&read[len..]);
                }

                return Ok(len);
            }

            while self.read_buf.len() < buf.len() {
                let read = self.layer.read().map_err(io_error_map)?;

                self.read_buf.extend_from_slice(&read);
            }
        }

        let len = buf.len().min(self.read_buf.len());

        buf.copy_from_slice(&self.read_buf[..len]);
        self.read_buf.drain(..len);

        Ok(len)
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
            read_buf: Vec::new(),
        }
    }
}

fn io_error_map(err: SecureLayerError) -> io::Error {
    match err {
        SecureLayerError::Io(err) => err,

        _ => io::Error::new(io::ErrorKind::InvalidData, "Invalid encryption data"),
    }
}
