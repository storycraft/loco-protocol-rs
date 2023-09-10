/*
 * Created on Sun Sep 10 2023
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::mem::swap;

use loco_protocol::command::{client::LocoClient, Command, Header, Method};

#[test]
pub fn read_write_test() {
    let mut client = LocoClient::new();

    let command = Command {
        header: Header {
            id: 0,
            status: 1,
            method: Method::new("TEST").unwrap(),
            data_type: 2,
        },
        data: Box::new([1_u8, 2, 3]) as Box<[u8]>,
    };

    client.send(command.clone());

    swap(&mut client.read_buffer, &mut client.write_buffer);

    assert_eq!(client.read(), Some(command));
}
