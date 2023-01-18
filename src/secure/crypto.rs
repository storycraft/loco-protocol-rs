/*
 * Created on Sat Jul 24 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::{error::Error, fmt::Display};

use libaes::Cipher;
use rand::{thread_rng, RngCore};
use rsa::{Oaep, PublicKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha1::Sha1;

#[repr(u32)]
#[derive(Debug, Serialize, Deserialize, Copy, Clone)]
pub enum EncryptType {
    AesCfb128 = 2,
}

#[repr(u32)]
#[derive(Debug, Serialize, Deserialize, Copy, Clone)]
pub enum KeyEncryptType {
    RsaOaepSha1Mgf1Sha1Old = 12,
    RsaOaepSha1Mgf1Sha1 = 15,
}

#[derive(Debug)]
pub enum CryptoError {
    CorruptedData,
}

impl Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Corrupted data")
    }
}

impl Error for CryptoError {}

/// AES Crypto implementation using aes
#[derive(Debug, Clone)]
pub struct CryptoStore {
    aes_key: [u8; 16],
}

impl CryptoStore {
    /// Create new crypto using cryptographically secure random key
    pub fn new() -> Self {
        let mut aes_key = [0_u8; 16];
        let mut rng = thread_rng();

        rng.fill_bytes(&mut aes_key);

        Self { aes_key }
    }

    /// Create new crypto store using given AES key
    pub fn new_with_key(aes_key: [u8; 16]) -> Self {
        Self { aes_key }
    }

    pub fn encrypt_aes(&self, data: &[u8], iv: &[u8; 16]) -> Result<Vec<u8>, CryptoError> {
        let cipher = Cipher::new_128(&self.aes_key);

        Ok(cipher.cfb128_encrypt(iv, data))
    }

    pub fn decrypt_aes(&self, data: &[u8], iv: &[u8; 16]) -> Result<Vec<u8>, CryptoError> {
        let cipher = Cipher::new_128(&self.aes_key);

        Ok(cipher.cfb128_decrypt(iv, data))
    }

    /// Encrypt AES key using RSA public key
    pub fn encrypt_key(&self, key: &RsaPublicKey) -> Result<Vec<u8>, CryptoError> {
        Ok(key
            .encrypt(&mut thread_rng(), Oaep::new_with_mgf_hash::<Sha1, Sha1>(), &self.aes_key)
            .unwrap())
    }

    pub fn gen_random(&self, data: &mut [u8]) {
        thread_rng().fill_bytes(data);
    }
}
