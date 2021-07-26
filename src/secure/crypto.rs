/*
 * Created on Sat Jul 24 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use libaes::Cipher;
use rand::{RngCore, rngs};
use rsa::{PaddingScheme, PublicKey, RSAPublicKey};
use serde::{Deserialize, Serialize};

#[repr(u32)]
#[derive(Debug, Serialize, Deserialize, Copy, Clone)]
pub enum EncryptType {
    AesCfb128 = 2,
}

#[repr(u32)]
#[derive(Debug, Serialize, Deserialize, Copy, Clone)]
pub enum KeyEncryptType {
    RsaOaepSha1Mgf1Sha1 = 12,
}

#[derive(Debug)]
pub enum CryptoError {
    CorruptedData
}

/// AES Crypto implementation using aes
pub struct CryptoStore {
    aes_key: [u8; 16],
}

impl CryptoStore {
    /// Create new crypto using cryptographically secure random key
    pub fn new() -> Self {
        let mut aes_key = [0_u8; 16];
        Self::gen_random(&mut aes_key);

        Self::new_with_key(aes_key)
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
    pub fn encrypt_key(&self, key: &RSAPublicKey) -> Result<Vec<u8>, CryptoError> {
        Ok(key.encrypt(&mut rngs::OsRng, PaddingScheme::new_oaep::<sha1::Sha1>(), &self.aes_key).unwrap())
    }

    /// Generate cryptographically secure random
    pub fn gen_random(data: &mut [u8]) {
        rngs::OsRng.fill_bytes(data)
    }
}