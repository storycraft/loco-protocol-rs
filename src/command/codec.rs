/*
 * Created on Sat Jul 24 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::io::{self, Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use crate::command::HEADER_SIZE;

use super::Command;

#[derive(Debug)]
pub enum StreamError {
    Bincode(bincode::Error),
    Io(io::Error),
}

impl From<bincode::Error> for StreamError {
    fn from(err: bincode::Error) -> Self {
        Self::Bincode(err)
    }
}

impl From<io::Error> for StreamError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

/// Provide Command read / write operation to stream.
pub struct CommandCodec<S> {
    stream: S,
}

impl<S> CommandCodec<S> {
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    pub fn stream(&self) -> &S {
        &self.stream
    }

    pub fn unwrap(self) -> S {
        self.stream
    }
}

impl<S: Write> CommandCodec<S> {
    /// Write command to stream
    pub fn write(&mut self, command: &Command) -> Result<usize, StreamError> {
        let header = bincode::serialize(&command.header)?;

        let mut buf = Vec::<u8>::with_capacity((HEADER_SIZE + 4) as usize);

        buf.write_all(&header)
            .and(buf.write_u32::<LittleEndian>(command.data.len() as u32))
            .and(buf.write_all(&command.data))?;

        self.stream.write_all(&buf)?;

        Ok(command.data.len() + 22)
    }
}

impl<S: Read> CommandCodec<S> {
    /// Read one command from stream.
    /// Returns tuple with read size and Command.
    pub fn read(&mut self) -> Result<(u32, Command), StreamError> {
        let mut header_buf = [0u8; HEADER_SIZE as usize];

        self.stream.read_exact(&mut header_buf)?;

        let header = bincode::deserialize(&header_buf)?;

        let data_size = self.stream.read_u32::<LittleEndian>()?;

        let mut data = vec![0_u8; data_size as usize];
        self.stream.read_exact(&mut data)?;

        Ok((HEADER_SIZE + 4 + data_size as u32, Command { header, data }))
    }
}
