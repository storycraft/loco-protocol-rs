/*
 * Created on Sun Jul 25 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::io::Cursor;

use loco_protocol::secure::{
    crypto::CryptoStore,
    layer::SecureLayer,
};

#[test]
pub fn secure_layer_read_write() {
    let mut local = Vec::<u8>::new();

    let crypto = CryptoStore::new();
    let mut layer = SecureLayer::new(crypto, Cursor::new(&mut local));

    let test_data1 = vec![1_u8, 2, 3, 4];
    let test_data2 = vec![1_u8, 2, 3, 4];

    layer
        .write(&test_data1)
        .expect("Data writing must not fail");
    layer
        .write(&test_data2)
        .expect("Data writing must not fail");

    // Reset read/write position
    layer.stream_mut().set_position(0);

    let data1 = layer.read().expect("Data reading must not fail");
    assert_eq!(data1, test_data1);

    let data2 = layer.read().expect("Data reading must not fail");
    assert_eq!(data2, test_data2);
}
