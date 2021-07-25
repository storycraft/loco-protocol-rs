/*
 * Created on Sat Jul 24 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use aes::Aes128;
use block_modes::{BlockMode, Cfb, block_padding::Pkcs7};

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
        let cipher = self.create_aes_cipher(iv);

        Ok(cipher.encrypt_vec(data))
    }

    pub fn decrypt_aes(&self, data: &[u8], iv: &[u8; 16]) -> Result<Vec<u8>, CryptoError> {
        let cipher = self.create_aes_cipher(iv);

        cipher.decrypt_vec(data).map_err(|_| CryptoError::CorruptedData)
    }

    /// Encrypt AES key using RSA public key
    pub fn encrypt_key(&self, key: &RSAPublicKey) -> Result<Vec<u8>, CryptoError> {
        Ok(key.encrypt(&mut rngs::OsRng, PaddingScheme::new_oaep::<sha1::Sha1>(), &self.aes_key).unwrap())
    }

    fn create_aes_cipher(&self, iv: &[u8; 16]) -> Cfb<Aes128, Pkcs7> {
        Cfb::<Aes128, Pkcs7>::new_from_slices(&self.aes_key, iv).unwrap()
    }

    /// Generate cryptographically secure random
    pub fn gen_random(data: &mut [u8]) {
        rngs::OsRng.fill_bytes(data)
    }
}
