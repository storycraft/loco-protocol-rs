/*
 * Created on Sun Nov 29 2020
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::io::{self, Read, Write};

use super::{
    crypto::{CryptoError, CryptoStore},
    SecureHeader, SECURE_HEADER_SIZE,
};

#[derive(Debug)]
pub enum SecureLayerError {
    Bincode(bincode::Error),
    Io(io::Error),
    Crypto(CryptoError),
}

impl From<bincode::Error> for SecureLayerError {
    fn from(err: bincode::Error) -> Self {
        Self::Bincode(err)
    }
}

impl From<io::Error> for SecureLayerError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<CryptoError> for SecureLayerError {
    fn from(err: CryptoError) -> Self {
        Self::Crypto(err)
    }
}

/// Common secure layer used in client and server
pub struct SecureLayer<S> {
    crypto: CryptoStore,
    stream: S,
}

impl<S> SecureLayer<S> {
    pub fn new(crypto: CryptoStore, stream: S) -> Self {
        Self { crypto, stream }
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

impl<S: Read> SecureLayer<S> {
    /// Read one encrypted packet
    pub fn read(&mut self) -> Result<Vec<u8>, SecureLayerError> {
        let mut header_buf = [0_u8; SECURE_HEADER_SIZE as usize];

        self.stream.read_exact(&mut header_buf)?;
        let header = bincode::deserialize::<SecureHeader>(&header_buf)?;

        let mut encrypted_buf = vec![0_u8; (header.data_size - 16) as usize];
        self.stream.read_exact(&mut encrypted_buf)?;

        let data = self.crypto.decrypt_aes(&encrypted_buf, &header.iv)?;

        Ok(data)
    }
}

impl<S: Write> SecureLayer<S> {
    /// Write one encrypted packet.
    /// Returns size of buffer written
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, SecureLayerError> {
        let mut iv = [0_u8; 16];
        CryptoStore::gen_random(&mut iv);

        let data_buf = self.crypto.encrypt_aes(&buf, &iv)?;

        let secure_header = SecureHeader {
            data_size: (data_buf.len() + iv.len()) as u32,
            iv,
        };

        self.stream
            .write_all(&bincode::serialize(&secure_header)?)
            .and(self.stream.write_all(&data_buf))?;

        Ok(data_buf.len())
    }
}
