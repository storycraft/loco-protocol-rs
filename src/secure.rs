/*
 * Created on Sat Nov 28 2020
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::{io::{Cursor, Read, Write}, mem};
use openssl::{error::ErrorStack, pkey::{HasPrivate, HasPublic}, rand, rsa::Rsa};
use serde::{Serialize, Deserialize};

use crate::command::{Command, Error, ReadCommand, WriteCommand};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SecureHeader {

    pub data_size: u32,
    pub iv: [u8; 16]

}

#[derive(Debug)]
pub struct SecureCommand {

    pub header: SecureHeader,
    pub command: Command

}

#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct SecureHandshakeHeader {

    pub encrypted_key_len: u32,
    pub key_encrypt_type: u32,
    pub encrypt_type: u32

}

#[repr(u32)]
#[derive(Debug, Serialize, Deserialize, Copy, Clone)]
pub enum EncryptType {

    AesCfb128 = 2

}

#[repr(u32)]
#[derive(Debug, Serialize, Deserialize, Copy, Clone)]
pub enum KeyEncryptType {

    RsaOaepSha1Mgf1Sha1 = 12

}

#[derive(Debug)]
pub enum CryptoError {

    Fail(ErrorStack),
    Invalid

}

impl From<ErrorStack> for CryptoError {
    fn from(err: ErrorStack) -> Self {
        CryptoError::Fail(err)
    }
}

pub trait LocoCrypto {

    fn encrypt_key<K: HasPublic>(&self, key: &Rsa<K>) -> Result<Vec<u8>, CryptoError>;
    fn apply_encrypted_key<K: HasPrivate>(&mut self, encrypted_aes_key: &[u8], key: &Rsa<K>) -> Result<(), CryptoError>;

    fn encrypt_aes(&self, data: &[u8], iv: &[u8; 16]) -> Result<Vec<u8>, CryptoError>;

    fn decrypt_aes(&self, data: &[u8], iv: &[u8; 16]) -> Result<Vec<u8>, CryptoError>;

    fn random_iv() -> [u8; 16] {
        let mut iv = [0_u8; 16];

        rand::rand_bytes(&mut iv).expect("This shouldn't happen!");

        iv
    }

}

/// Stores aes key used on SecureClientStream
pub struct CryptoStore {

    aes_key: [u8; 16]

}

impl CryptoStore {

    pub fn new() -> Result<Self, CryptoError> {
        let mut aes_key = [0_u8; 16];

        rand::rand_bytes(&mut aes_key)?;

        Ok(Self::new_with_key(aes_key))
    }

    pub fn new_with_key(aes_key: [u8; 16]) -> Self {
        Self {
            aes_key
        }
    }

}

impl LocoCrypto for CryptoStore {

    fn encrypt_key<K: HasPublic>(&self, key: &Rsa<K>) -> Result<Vec<u8>, CryptoError> {
        let mut out = vec![0_u8; 256];

        key.public_encrypt(&self.aes_key, &mut out, openssl::rsa::Padding::PKCS1_OAEP)?;

        Ok(out)
    }

    fn apply_encrypted_key<K: HasPrivate>(&mut self, encrypted_aes_key: &[u8], key: &Rsa<K>) -> Result<(), CryptoError> {
        let mut aes_key = vec![0_u8; 256];

        let size = key.private_decrypt(&encrypted_aes_key, &mut aes_key, openssl::rsa::Padding::PKCS1_OAEP)?;

        if size != 16 {
            return Err(CryptoError::Invalid);
        }

        self.aes_key.copy_from_slice(&aes_key[..16]);

        Ok(())
    }

    fn encrypt_aes(&self, data: &[u8], iv: &[u8; 16]) -> Result<Vec<u8>, CryptoError> {
        let cipher = openssl::symm::Cipher::aes_128_cfb128();

        Ok(openssl::symm::encrypt(cipher, &self.aes_key, Some(iv), data)?)
    }

    fn decrypt_aes(&self, data: &[u8], iv: &[u8; 16]) -> Result<Vec<u8>, CryptoError> {
        let cipher = openssl::symm::Cipher::aes_128_cfb128();

        Ok(openssl::symm::decrypt(cipher, &self.aes_key, Some(iv), data)?)
    }

}

pub trait SecureHeaderRead {

    fn read_secure_header(&mut self) -> Result<SecureHeader, Error>;

}

impl<T: Read> SecureHeaderRead for T {

    fn read_secure_header(&mut self) -> Result<SecureHeader, Error> {
        let mut buf = [0_u8; mem::size_of::<SecureHeader>()];

        self.read_exact(&mut buf)?;

        Ok(bincode::deserialize::<SecureHeader>(&buf)?)
    }

}

pub trait SecureDataRead {

    fn decrypt_data(&mut self, crypto: &impl LocoCrypto, header: &SecureHeader) -> Result<Vec<u8>, Error>;

}

impl<T: Read + ReadCommand> SecureDataRead for T {

    fn decrypt_data(&mut self, crypto: &impl LocoCrypto, header: &SecureHeader) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0_u8; header.data_size as usize - 16];

        self.read_exact(&mut buf)?;
        
        Ok(crypto.decrypt_aes(&buf, &header.iv)?)
    }
}

pub trait SecureCommandRead {

    fn read_secure_command(&mut self, crypto: &impl LocoCrypto) -> Result<SecureCommand, Error>;

}

impl<T: SecureDataRead + SecureHeaderRead> SecureCommandRead for T {

    fn read_secure_command(&mut self, crypto: &impl LocoCrypto) -> Result<SecureCommand, Error> {
        let header = self.read_secure_header()?;

        let readed = self.decrypt_data(crypto, &header)?;

        let mut cursor = Cursor::new(readed);

        let command = cursor.read_command()?;

        Ok(SecureCommand { header, command })
    }

}

pub trait SecureHeaderWrite {

    fn write_encrypt_header(&mut self, header: SecureHeader) -> Result<usize, Error>;

}

pub trait SecureHandshakeRead {
    
    /// Read secure handshake header.
    fn read_handshake_header(&mut self) -> Result<SecureHandshakeHeader, Error>;

    /// Read secure handshake key and update crypto.
    fn read_handshake_key<K: HasPrivate>(&mut self, header: &SecureHandshakeHeader, crypto: &mut impl LocoCrypto, key: &Rsa<K>) -> Result<(), Error>;

    fn read_handshake<K: HasPrivate>(&mut self, crypto: &mut impl LocoCrypto, key: &Rsa<K>) -> Result<SecureHandshakeHeader, Error> {
        let header = self.read_handshake_header()?;

        self.read_handshake_key(&header, crypto, key)?;

        Ok(header)
    }

}

impl<T: Read> SecureHandshakeRead for T {

    fn read_handshake_header(&mut self) -> Result<SecureHandshakeHeader, Error> {
        let mut handshake_header = vec![0_u8; 12];

        self.read_exact(&mut handshake_header)?;

        Ok(bincode::deserialize::<SecureHandshakeHeader>(&handshake_header)?)
    }
    
    fn read_handshake_key<K: HasPrivate>(&mut self, header: &SecureHandshakeHeader, crypto: &mut impl LocoCrypto, key: &Rsa<K>) -> Result<(), Error> {
        let mut encrypted_key = vec![0_u8; header.encrypted_key_len as usize];
        self.read_exact(&mut encrypted_key)?;

        crypto.apply_encrypted_key(&encrypted_key, key)?;

        Ok(())
    }

}

pub trait SecureHandshakeWrite {
    
    /// Write secure handshake data.
    /// Returns written size.
    fn write_handshake<K: HasPublic>(&mut self, crypto: &impl LocoCrypto, key_encrypt_type: KeyEncryptType, encrypt_type: EncryptType, key: &Rsa<K>) -> Result<usize, Error>;

}

impl<T: Write> SecureHandshakeWrite for T {
    
    fn write_handshake<K: HasPublic>(&mut self, crypto: &impl LocoCrypto, key_encrypt_type: KeyEncryptType, encrypt_type: EncryptType, key: &Rsa<K>) -> Result<usize, Error> {
        let mut encrypted = crypto.encrypt_key(&key)?;

        let handshake_header = SecureHandshakeHeader {
            encrypted_key_len: encrypted.len() as u32,
            key_encrypt_type: key_encrypt_type as u32,
            encrypt_type: encrypt_type as u32
        };

        let data = bincode::serialize(&handshake_header)?;

        self.write_all(&data).and(self.write_all(&mut encrypted))?;

        Ok(data.len() + encrypted.len())
    }

}

impl<T: Write> SecureHeaderWrite for T {

    fn write_encrypt_header(&mut self, header: SecureHeader) -> Result<usize, Error> {
        let buf = bincode::serialize(&header)?;

        self.write_all(&buf)?;

        Ok(buf.len())
    }

}

pub trait SecureDataWrite {

    fn encrypt_data(&mut self, crypto: &impl LocoCrypto, iv: &[u8; 16], data: &[u8]) -> Result<usize, Error>;

}

impl<T: Write> SecureDataWrite for T {

    fn encrypt_data(&mut self, crypto: &impl LocoCrypto, iv: &[u8; 16], data: &[u8]) -> Result<usize, Error> {
        let encrypted = crypto.encrypt_aes(data, &iv)?;

        self.write_all(&encrypted)?;

        Ok(encrypted.len())
    }

}

pub trait SecureCommandWrite {

    fn write_encrypt_command(&mut self, crypto: &impl LocoCrypto, command: SecureCommand) -> Result<(), Error>;

}

impl<T: Write + WriteCommand> SecureCommandWrite for T {

    fn write_encrypt_command(&mut self, crypto: &impl LocoCrypto, command: SecureCommand) -> Result<(), Error> {
        let iv = command.header.iv;

        self.write_encrypt_header(command.header)?;

        let mut buf_cursor = Cursor::new(Vec::new());

        buf_cursor.write_commmand(command.command)?;

        self.encrypt_data(crypto, &iv, &buf_cursor.into_inner())?;

        Ok(())
    }

}