/*
 * Created on Sun Jul 25 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::io::Cursor;

use futures::executor::block_on;
use loco_protocol::secure::{crypto::CryptoStore, session::{SecureClientSession, SecureServerSession}, stream::SecureStream};
use rand::rngs::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey};

#[test]
pub fn handshake() {
    let private_key = RsaPrivateKey::new(&mut OsRng, 1024).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);

    let mut local = Vec::<u8>::new();
    let mut stream = SecureStream::new(CryptoStore::new(), &mut local);

    let client_session = SecureClientSession::new(public_key);

    client_session.handshake(&mut stream).expect("Client handshake failed");

    let server_session = SecureServerSession::new(private_key);

    server_session.handshake(&mut Cursor::new(&mut local)).expect("Server handshake failed");
}

#[test]
pub fn handshake_async() {
    let private_key = RsaPrivateKey::new(&mut OsRng, 1024).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);

    block_on(async move {
        let mut local = Vec::<u8>::new();
        let mut stream = SecureStream::new(CryptoStore::new(), &mut local);
        
        let client_session = SecureClientSession::new(public_key);

        client_session.handshake_async(&mut stream).await.expect("Client handshake failed");
    
        let server_session = SecureServerSession::new(private_key);
    
        server_session.handshake_async(&mut futures::io::Cursor::new(&mut local)).await.expect("Server handshake failed");
    });
}
