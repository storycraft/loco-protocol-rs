/*
 * Created on Sun Sep 10 2023
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use core::mem::swap;

use loco_protocol::secure::{client::LocoClientSecureLayer, SecurePacket};
use rand::RngCore;
use rsa::{RsaPrivateKey, RsaPublicKey};

#[test]
pub fn test_handshake() {
    let mut layer = LocoClientSecureLayer::new([0_u8; 16]);

    let priv_key =
        RsaPrivateKey::new(&mut rand::thread_rng(), 2048).expect("failed to generate a key");
    let pub_key = RsaPublicKey::from(&priv_key);

    layer.handshake(&pub_key);

    assert_eq!(layer.write_buffer.len(), 12 + 256);
}

#[test]
pub fn read_write_test() {
    let key = {
        let mut arr = [0_u8; 16];
        rand::thread_rng().fill_bytes(&mut arr);

        arr
    };

    let mut layer = LocoClientSecureLayer::new(key);

    let packet = SecurePacket {
        iv: [0_u8; 16],
        data: Box::new([0_u8, 1, 2]) as Box<[u8]>,
    };

    layer.send(packet.clone());

    swap(&mut layer.read_buffer, &mut layer.write_buffer);

    assert_eq!(layer.read(), Some(packet));
}
