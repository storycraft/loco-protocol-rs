/*
 * Created on Mon Nov 30 2020
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use super::{Command, Header};

/// Command build helper
#[derive(Debug)]
pub struct CommandBuilder<'a> {
    id: i32,
    method: &'a str,

    status: i16,
}

impl<'a> CommandBuilder<'a> {
    pub fn new(id: i32, method: &'a str) -> Self {
        Self {
            id,
            method,
            status: 0,
        }
    }

    pub fn id(&self) -> i32 {
        self.id
    }

    pub fn status(&self) -> i16 {
        self.status
    }

    pub fn set_status(mut self, status: i16) -> Self {
        self.status = status;

        self
    }

    pub fn build(self, data_type: i8, data: Vec<u8>) -> Command {
        let header = Header {
            id: self.id,
            status: self.status,
            method: Header::to_method(self.method),
            data_type,
        };

        Command { header, data }
    }
}
