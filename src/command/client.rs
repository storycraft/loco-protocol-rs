/*
 * Created on Sat Sep 09 2023
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use alloc::{boxed::Box, collections::VecDeque};
use core::mem;

use arrayvec::ArrayVec;
use serde::{Deserialize, Serialize};

use crate::command::Header;

use super::Command;

#[derive(Debug)]
#[non_exhaustive]
/// IO-free loco protocol sink
pub struct LocoSink {
    /// Write buffer for sink
    pub write_buffer: VecDeque<u8>,
}

impl LocoSink {
    /// Create new [`LocoSink`]
    pub const fn new() -> Self {
        Self {
            write_buffer: VecDeque::new(),
        }
    }

    /// Write single [`Command`] to [`LocoSink::write_buffer`]
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

        self.write_buffer.extend(data);
    }
}

impl Default for LocoSink {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
/// IO-free loco protocol stream
pub struct LocoStream {
    state: StreamState,

    /// Read buffer for stream
    pub read_buffer: VecDeque<u8>,
}

impl LocoStream {
    /// Create new [`LocoStream`]
    pub const fn new() -> Self {
        Self {
            state: StreamState::Pending,
            read_buffer: VecDeque::new(),
        }
    }

    pub const fn state(&self) -> &StreamState {
        &self.state
    }

    /// Try reading single [`Command`] from [`LocoClient::read_buffer`]
    pub fn read(&mut self) -> Option<Command<Box<[u8]>>> {
        loop {
            match mem::replace(&mut self.state, StreamState::Corrupted) {
                StreamState::Pending => {
                    if self.read_buffer.len() < 22 {
                        self.state = StreamState::Pending;
                        return None;
                    }

                    let raw_header = {
                        let buf = self.read_buffer.drain(..22).collect::<ArrayVec<u8, 22>>();

                        bincode::deserialize::<RawHeader>(&buf).unwrap()
                    };

                    self.state = StreamState::Header(raw_header);
                }

                StreamState::Header(raw_header) => {
                    if self.read_buffer.len() < raw_header.data_size as usize {
                        self.state = StreamState::Header(raw_header);
                        return None;
                    }

                    let data = self
                        .read_buffer
                        .drain(..raw_header.data_size as usize)
                        .collect::<Box<[u8]>>();

                    self.state = StreamState::Pending;
                    return Some(Command {
                        header: raw_header.header,
                        data,
                    });
                }

                StreamState::Corrupted => unreachable!(),
            }
        }
    }
}

impl Default for LocoStream {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum StreamState {
    /// Stream is waiting for packet
    Pending,

    /// Stream read header and wait for data
    Header(RawHeader),

    /// Client corrupted and cannot continue
    Corrupted,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RawHeader {
    /// Packet header
    pub header: Header,

    /// Data size
    pub data_size: u32,
}
