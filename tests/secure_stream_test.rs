/*
 * Created on Sun Jul 25 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::io::{Cursor, Read, Write};

use futures::{executor::block_on, AsyncReadExt, AsyncWriteExt};
use loco_protocol::secure::{crypto::CryptoStore, stream::SecureStream};

#[test]
pub fn secure_stream_read_write() {
    let mut local = Vec::<u8>::new();

    let crypto = CryptoStore::new();
    let mut stream = SecureStream::new(crypto, Cursor::new(&mut local));

    let test_data = vec![1_u8, 2, 3, 4];

    stream
        .write(&test_data)
        .expect("Data writing must not fail");

    // Reset read/write position
    stream.stream_mut().set_position(0);

    let mut data = vec![0_u8; 4];

    stream.read(&mut data).expect("Data reading must not fail");

    assert_eq!(test_data, data);
}

#[test]
pub fn secure_stream_read_write_async() {
    let mut local = Vec::<u8>::new();

    let crypto = CryptoStore::new();
    let mut stream = SecureStream::new(crypto, futures::io::Cursor::new(&mut local));

    block_on(async move {
        let test_data = vec![1_u8, 2, 3, 4];

        stream
            .write(&test_data)
            .await
            .expect("Data writing must not fail");

        // Reset read/write position
        stream.stream_mut().set_position(0);

        let mut data = vec![0_u8; 4];

        stream
            .read(&mut data)
            .await
            .expect("Data reading must not fail");

        assert_eq!(test_data, data);
    });
}
