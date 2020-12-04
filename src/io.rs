/*
 * Created on Sun Nov 29 2020
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::{io::Cursor, io::{self, Read, Write}};

use openssl::{pkey::{HasPrivate, HasPublic}, rsa::Rsa};

use crate::{secure::CryptoStore, secure::{EncryptType, KeyEncryptType, LocoCrypto, SecureDataRead, SecureDataWrite, SecureHandshakeRead, SecureHandshakeWrite, SecureHeader, SecureHeaderRead, SecureHeaderWrite}};

/// Common secure layer used in client and server
pub struct SecureStream<S: Read + Write> {

    crypto: CryptoStore,
    stream: S,

    current: Option<SecureHeader>,
    read_buffer: Vec<u8>,
    decrypted_buffer: Vec<u8>

}

impl<S: Read + Write> SecureStream<S> {

    pub fn new(crypto: CryptoStore, stream: S) -> Self {
        Self {
            crypto,
            stream,

            current: None,
            read_buffer: Vec::new(),
            decrypted_buffer: Vec::new()
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

    pub fn crypto_mut(&mut self) -> &mut CryptoStore {
        &mut self.crypto
    }

    fn try_read_decrypted(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.decrypted_buffer.len() > 0 && buf.len() > 0 {
            let size = buf.len().min(self.decrypted_buffer.len());

            buf[..size].copy_from_slice(&self.decrypted_buffer.drain(..size).collect::<Vec<u8>>());

            Ok(size)
        } else {
            Ok(0)
        }
    }

    fn try_decrypt_encrypted(&mut self) -> io::Result<()> {
        if self.current.is_none() {
            if self.read_buffer.len() >= 20 {
                let mut cursor = Cursor::new(self.read_buffer.drain(..20).collect::<Vec<u8>>());
                let res = cursor.read_secure_header()?;

                self.current = Some(res);
            } else {
                return Ok(());
            }
        }

        let current = self.current.as_ref().unwrap();

        let data_size = current.data_size as usize - 16;

        if self.read_buffer.len() >= data_size {
            let mut data_cursor = Cursor::new(self.read_buffer.drain(..data_size).collect::<Vec<u8>>());

            let mut data = data_cursor.decrypt_data(&self.crypto, &current)?;

            self.decrypted_buffer.append(&mut data);

            self.current = None;
        }

        Ok(())
    }

}

impl<S: Read + Write> Read for SecureStream<S> {
    
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.try_decrypt_encrypted().and(self.try_read_decrypted(buf)) {
            Ok(size) if size > 0 => Ok(size),

            Ok(_) => {
                let mut stream_buf = [0_u8; 2048];

                let read = self.stream.read(&mut stream_buf)?;
                
                self.read_buffer.extend_from_slice(&mut stream_buf[..read]);

                self.try_decrypt_encrypted().and(self.try_read_decrypted(buf))
            },

            Err(err) => Err(err)
        }
    }

}

impl<S: Read + Write> Write for SecureStream<S> {

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut encrypted_buf = Cursor::new(Vec::<u8>::new());

        let iv = CryptoStore::random_iv();

        let data_size = encrypted_buf.encrypt_data(&self.crypto, &iv, buf)? as u32;

        let secure_header = SecureHeader {
            data_size: data_size + iv.len() as u32,
            iv
        };

        self.stream.write_encrypt_header(secure_header)?;

        let data = encrypted_buf.into_inner();

        self.stream.write_all(&data)?;

        Ok(data.len())
    }
}

/// Secure layer implemention for client
pub struct SecureClientStream<S: Read + Write, K: HasPublic> {

    inner: SecureStream<S>,
    
    key: Rsa<K>,
    handshaked: bool,

}

impl<S: Read + Write, K: HasPublic> SecureClientStream<S, K> {

    pub fn new(crypto: CryptoStore, key: Rsa<K>, stream: S) -> Self {
        Self {
            inner: SecureStream::new(crypto, stream),
            key,
            handshaked: false
        }
    }

    pub fn stream(&self) -> &S {
        self.inner.stream()
    }

    pub fn stream_mut(&mut self) -> &mut S {
        self.inner.stream_mut()
    }
    
    pub fn crypto(&self) -> &CryptoStore {
        self.inner.crypto()
    }

    pub fn crypto_mut(&mut self) -> &mut CryptoStore {
        self.inner.crypto_mut()
    }

    pub fn handshaked(&self) -> bool {
        self.handshaked
    }

}

impl<S: Read + Write, K: HasPublic> Read for SecureClientStream<S, K> {
    
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }

}

impl<S: Read + Write, K: HasPublic> Write for SecureClientStream<S, K> {

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !self.handshaked {
            self.inner.stream.write_handshake(&mut self.inner.crypto, KeyEncryptType::RsaOaepSha1Mgf1Sha1, EncryptType::AesCfb128, &self.key)?;
    
            self.handshaked = true;
        }

        self.inner.write(buf)
    }
}

/// Secure layer implemention for server
pub struct SecureServerStream<S: Read + Write, K: HasPrivate> {

    inner: SecureStream<S>,
    key: Rsa<K>,

    handshaked: bool,
    handshake: Box<Option<(usize, [u8; 268])>>

}

impl<S: Read + Write, K: HasPrivate> SecureServerStream<S, K> {

    pub fn new(crypto: CryptoStore, key: Rsa<K>, stream: S) -> Self {
        Self {
            inner: SecureStream::new(crypto, stream),
            key,
            handshaked: false,
            handshake: Box::new(None)
        }
    }

    pub fn stream(&self) -> &S {
        self.inner.stream()
    }

    pub fn stream_mut(&mut self) -> &mut S {
        self.inner.stream_mut()
    }
    
    pub fn crypto(&self) -> &CryptoStore {
        self.inner.crypto()
    }

    pub fn crypto_mut(&mut self) -> &mut CryptoStore {
        self.inner.crypto_mut()
    }

    pub fn handshaked(&self) -> bool {
        self.handshaked
    }

}

impl<S: Read + Write, K: HasPrivate> Read for SecureServerStream<S, K> {
    
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.handshaked {
            let (mut handshake_read, mut handshake_buf) = self.handshake.unwrap_or((0, [0_u8; 268]));

            handshake_read += self.inner.stream.read(&mut handshake_buf[handshake_read..])?;

            if handshake_read >= handshake_buf.len() {
                let mut cursor = Cursor::new(handshake_buf.to_vec());

                let header = cursor.read_handshake_header()?;

                cursor.read_handshake_key(&header, &mut self.inner.crypto, &self.key)?;

                self.handshake = Box::new(None);
                self.handshaked = true;
            } else {
                return Ok(0);
            }
        }

        self.inner.read(buf)
    }

}

impl<S: Read + Write, K: HasPrivate> Write for SecureServerStream<S, K> {

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
}