/*
 * Created on Sun Sep 10 2023
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

pub use rsa;

use alloc::{boxed::Box, collections::VecDeque, vec::Vec};
use core::mem;

use aes::cipher::{AsyncStreamCipher, Key, KeyIvInit};
use arrayvec::ArrayVec;
use rand::thread_rng;
use rsa::{Oaep, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha1::Sha1;

use super::SecurePacket;

type Aes128CfbEnc = cfb_mode::Encryptor<aes::Aes128>;
type Aes128CfbDec = cfb_mode::Decryptor<aes::Aes128>;

#[derive(Debug)]
/// IO-free client secure layer
pub struct LocoClientSecureLayer {
    key: Key<aes::Aes128>,

    read_state: ReadState,

    encrypt_buffer: Vec<u8>,

    /// Read buffer for layer
    pub read_buffer: VecDeque<u8>,

    /// Write buffer for layer
    pub write_buffer: VecDeque<u8>,
}

impl LocoClientSecureLayer {
    /// Create new [`LocoClientSecureLayer`] with given encrypt key
    pub fn new(encrypt_key: [u8; 16]) -> Self {
        Self {
            key: encrypt_key.into(),

            read_state: ReadState::Pending,

            encrypt_buffer: Vec::new(),

            read_buffer: VecDeque::new(),
            write_buffer: VecDeque::new(),
        }
    }

    pub const fn read_state(&self) -> &ReadState {
        &self.read_state
    }

    /// Write handshake packet to [`LocoClientSecureLayer::write_buffer`] using given public key
    pub fn handshake(&mut self, key: &RsaPublicKey) {
        #[derive(Serialize)]
        struct RawHandshakeHeader {
            encrypted_key_size: u32,
            key_type: u32,
            encrypt_type: u32,
        }

        let encrypted_key = key
            .encrypt(
                &mut thread_rng(),
                Oaep::new_with_mgf_hash::<Sha1, Sha1>(),
                self.key.as_slice(),
            )
            .unwrap();

        bincode::serialize_into(
            &mut self.write_buffer,
            &RawHandshakeHeader {
                encrypted_key_size: encrypted_key.len() as u32,
                key_type: 15,    // RSA OAEP SHA1 MGF1 SHA1
                encrypt_type: 2, // AES_CFB128 NOPADDING
            },
        )
        .unwrap();

        self.write_buffer.extend(encrypted_key);
    }

    /// Try to read single [`SecurePacket`] from [`LocoClientSecureLayer::read_buffer`]
    pub fn read(&mut self) -> Option<SecurePacket<Box<[u8]>>> {
        loop {
            match mem::replace(&mut self.read_state, ReadState::Corrupted) {
                ReadState::Pending => {
                    if self.read_buffer.len() < 20 {
                        self.read_state = ReadState::Pending;
                        return None;
                    }

                    let raw_header = {
                        let buf = self.read_buffer.drain(..20).collect::<ArrayVec<u8, 20>>();

                        bincode::deserialize::<RawHeader>(&buf).unwrap()
                    };

                    self.read_state = ReadState::Header(raw_header);
                }

                ReadState::Header(raw_header) => {
                    let size = raw_header.size as usize - 16;

                    if self.read_buffer.len() < size {
                        self.read_state = ReadState::Header(raw_header);
                        return None;
                    }

                    let mut data = self.read_buffer.drain(..size).collect::<Box<[u8]>>();
                    Aes128CfbDec::new(&self.key, &raw_header.iv.into()).decrypt(&mut data);

                    self.read_state = ReadState::Pending;
                    return Some(SecurePacket {
                        iv: raw_header.iv,
                        data,
                    });
                }

                ReadState::Corrupted => unreachable!(),
            }
        }
    }

    /// Write single [`SecurePacket`] to [`LocoClientSecureLayer::write_buffer`]
    pub fn send(&mut self, packet: SecurePacket<impl AsRef<[u8]>>) {
        let encrypted_data = {
            let data = packet.data.as_ref();

            self.encrypt_buffer.extend(data);
            Aes128CfbEnc::new(&self.key, &packet.iv.into()).encrypt(&mut self.encrypt_buffer);

            &mut self.encrypt_buffer
        };

        bincode::serialize_into(
            &mut self.write_buffer,
            &RawHeader {
                size: 16 + encrypted_data.len() as u32,
                iv: packet.iv,
            },
        )
        .unwrap();

        self.write_buffer.extend(encrypted_data.drain(..));
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RawHeader {
    /// Data size including iv
    pub size: u32,

    /// Encrypted data IV
    pub iv: [u8; 16],
}

#[derive(Debug, Clone, PartialEq)]
pub enum ReadState {
    /// Client is waiting for packet
    Pending,

    /// Client read packet header and waiting for more data
    Header(RawHeader),

    /// Client corrupted and cannot continue
    Corrupted,
}
