/*
 * Created on Sun Jul 25 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::io::Cursor;

use loco_protocol::secure::{
    crypto::CryptoStore,
    stream::SecureStream,
};

#[test]
pub fn secure_layer_read_write() {
    let mut local = Vec::<u8>::new();

    let crypto = CryptoStore::new();
    let mut stream = SecureStream::new(crypto, Cursor::new(&mut local));

    let test_data1 = vec![1_u8, 2, 3, 4];
    let test_data2 = vec![1_u8, 2, 3, 4];

    stream
        .write_data(&test_data1)
        .expect("Data writing must not fail");
    stream
        .write_data(&test_data2)
        .expect("Data writing must not fail");

    // Reset read/write position
    stream.stream_mut().set_position(0);

    let packet1 = stream.read_packet().expect("Data reading must not fail");
    assert_eq!(packet1.data, test_data1);

    let packet2 = stream.read_packet().expect("Data reading must not fail");
    assert_eq!(packet2.data, test_data2);
}
