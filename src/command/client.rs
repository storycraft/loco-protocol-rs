/*
 * Created on Sat Sep 09 2023
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::{collections::VecDeque, io::Write};

use arrayvec::ArrayVec;
use serde::{Deserialize, Serialize};

use crate::command::Header;

use super::Command;

#[derive(Debug)]
#[non_exhaustive]
/// IO-free loco protocol client
pub struct LocoClient {
    /// Read buffer for client
    pub read_buffer: VecDeque<u8>,

    /// Write buffer for client
    pub write_buffer: VecDeque<u8>,
}

impl LocoClient {
    /// Create new [`LocoClient`]
    pub const fn new() -> Self {
        Self {
            read_buffer: VecDeque::new(),
            write_buffer: VecDeque::new(),
        }
    }

    /// Try reading single [`Command`] from [`LocoClient::read_buffer`]
    pub fn read(&mut self) -> Option<Command<Box<[u8]>>> {
        if self.read_buffer.len() < 22 {
            return None;
        }

        let raw_header = {
            let buf = self
                .read_buffer
                .iter()
                .take(22)
                .copied()
                .collect::<ArrayVec<u8, 22>>();

            bincode::deserialize::<RawHeader>(&buf).unwrap()
        };

        if self.read_buffer.len() < 22 + raw_header.data_size as usize {
            return None;
        }

        let data = self
            .read_buffer
            .drain(..22 + raw_header.data_size as usize)
            .skip(22)
            .collect::<Box<[u8]>>();

        Some(Command {
            header: raw_header.header,
            data,
        })
    }

    /// Write single [`Command`] to [`LocoClient::write_buffer`]
    pub fn send(&mut self, command: Command<impl AsRef<[u8]>>) {
        let data = command.data.as_ref();

        bincode::serialize_into(
            &mut self.write_buffer,
            &RawHeader {
                header: command.header,
                data_size: data.len() as u32,
            },
        )
        .unwrap();

        self.write_buffer.write_all(data).unwrap();
    }
}

impl Default for LocoClient {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize, Deserialize)]
struct RawHeader {
    header: Header,
    data_size: u32,
}
