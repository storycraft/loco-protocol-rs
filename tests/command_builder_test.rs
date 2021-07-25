/*
 * Created on Sun Jul 25 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use loco_protocol::command::{builder::CommandBuilder, Command, Header};

#[test]
pub fn command_builder() {
    let builder = CommandBuilder::new(0, &"TEST");

    let test_command = Command {
        header: Header {
            id: 0,
            data_type: 0,
            status: 0,
            method: Header::to_method(&"TEST"),
        },
        data: vec![0_u8; 4],
    };

    let command = builder.build(0, vec![0_u8; 4]);

    assert_eq!(test_command, command)
}
