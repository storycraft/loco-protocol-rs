/*
 * Created on Sun Jul 25 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::io::Cursor;

use loco_protocol::command::{codec::CommandCodec, Command, Header};

#[test]
pub fn codec_read_write() {
    let mut local = Vec::<u8>::new();

    let test_command1 = Command {
        header: Header {
            id: 0,
            data_type: 0,
            status: 0,
            method: Header::to_method(&"TEST1"),
        },
        data: vec![0_u8; 4],
    };

    let test_command2 = Command {
        header: Header {
            id: 0,
            data_type: 0,
            status: 0,
            method: Header::to_method(&"TEST2"),
        },
        data: vec![8_u8; 4],
    };

    let mut write_codec = CommandCodec::new(&mut local);

    write_codec
        .write(&test_command1)
        .expect("Command write must not fail");

    write_codec
        .write(&test_command2)
        .expect("Command write must not fail");

    let mut read_codec = CommandCodec::new(Cursor::new(&mut local));

    let (_, command1) = read_codec.read().expect("Command read must not fail");
    assert_eq!(command1, test_command1);

    let (_, command2) = read_codec.read().expect("Command read must not fail");
    assert_eq!(command2, test_command2);
}
