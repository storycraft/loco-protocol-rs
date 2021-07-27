/*
 * Created on Sat Jul 24 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::io::{self, Cursor, Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use crate::command::HEADER_SIZE;

use super::{Command, Header};

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
    current_header: Option<(Header, u32)>,
}

impl<S> CommandCodec<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            current_header: None,
        }
    }

    pub fn stream(&self) -> &S {
        &self.stream
    }

    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    pub fn unwrap(self) -> S {
        self.stream
    }
}

impl<S: Write> CommandCodec<S> {
    /// Write command to stream
    pub fn write(&mut self, command: &Command) -> Result<usize, StreamError> {
        let header = bincode::serialize(&command.header)?;

        self.stream
            .write_all(&header)
            .and(
                self.stream
                    .write_u32::<LittleEndian>(command.data.len() as u32),
            )
            .and(self.stream.write_all(&command.data))?;

        Ok(command.data.len() + 22)
    }
}

impl<S: Read> CommandCodec<S> {
    /// Read one command from stream.
    /// Returns tuple with read size and Command.
    pub fn read(&mut self) -> Result<(u32, Command), StreamError> {
        let (header, data_size) = match self.current_header.take() {
            Some(tup) => tup,
            None => {
                let mut buf = [0u8; HEADER_SIZE + 4];

                self.stream.read_exact(&mut buf)?;

                let header = bincode::deserialize::<Header>(&buf[..HEADER_SIZE])?;
                let data_size = Cursor::new(&buf[HEADER_SIZE..]).read_u32::<LittleEndian>()?;

                (header, data_size)
            }
        };

        let mut data = vec![0_u8; data_size as usize];
        if let Err(err) = self.stream.read_exact(&mut data) {
            self.current_header = Some((header, data_size));

            return Err(StreamError::from(err));
        }

        Ok((
            HEADER_SIZE as u32 + 4 + data_size as u32,
            Command { header, data },
        ))
    }
}
