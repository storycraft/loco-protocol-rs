/*
 * Created on Sun Sep 10 2023
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::mem::swap;

use loco_protocol::command::{
    client::{LocoSink, LocoStream},
    Command, Header, Method,
};

#[test]
pub fn read_write_test() {
    let mut sink = LocoSink::new();

    let command = Command {
        header: Header {
            id: 0,
            status: 1,
            method: Method::new("TEST").unwrap(),
            data_type: 2,
        },
        data: Box::new([1_u8, 2, 3]) as Box<[u8]>,
    };

    sink.send(command.clone());

    let mut stream = LocoStream::new();

    swap(&mut stream.read_buffer, &mut sink.write_buffer);

    assert_eq!(stream.read(), Some(command));
}
