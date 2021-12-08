/*
 * Created on Sat Jul 24 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::cell::RefCell;

use libaes::Cipher;
use rand::{rngs, RngCore, prelude::ThreadRng};
use rsa::{PaddingScheme, PublicKey, RsaPublicKey};
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
    CorruptedData,
}

/// AES Crypto implementation using aes
#[derive(Debug)]
pub struct CryptoStore {
    aes_key: [u8; 16],
    rng: RefCell<ThreadRng>
}

impl CryptoStore {
    /// Create new crypto using cryptographically secure random key
    pub fn new() -> Self {
        let mut aes_key = [0_u8; 16];
        let mut rng = rngs::ThreadRng::default();

        rng.fill_bytes(&mut aes_key);

        Self { aes_key, rng: RefCell::new(rng) }
    }

    /// Create new crypto store using given AES key
    pub fn new_with_key(aes_key: [u8; 16]) -> Self {
        Self { aes_key, rng: RefCell::new(rngs::ThreadRng::default()) }
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
            .encrypt(
                (&mut self.rng.borrow_mut()) as &mut ThreadRng,
                PaddingScheme::new_oaep::<sha1::Sha1>(),
                &self.aes_key,
            )
            .unwrap())
    }

    pub fn gen_random(&self, data: &mut [u8]) {
        self.rng.borrow_mut().fill_bytes(data);
    }
}
