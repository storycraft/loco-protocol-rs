/*
 * Created on Sun Jul 25 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::io::Cursor;

use loco_protocol::secure::{
    crypto::CryptoStore,
    session::{SecureClientSession, SecureServerSession, SecureSession},
};
use rand::rngs::OsRng;
use rsa::{RSAPrivateKey, RSAPublicKey};

#[test]
pub fn handshake() {
    let private_key = RSAPrivateKey::new(&mut OsRng, 1024).expect("failed to generate a key");
    let public_key = RSAPublicKey::from(&private_key);

    let mut local = Vec::<u8>::new();

    let client_session = SecureClientSession::new(public_key, CryptoStore::new(), &mut local);

    client_session.handshake().expect("Client handshake failed");

    let server_session = SecureServerSession::new(private_key, Cursor::new(&mut local));

    server_session.handshake().expect("Server handshake failed");
}
