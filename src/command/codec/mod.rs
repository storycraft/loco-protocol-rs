/*
 * Created on Sat Jul 24 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

pub mod decode;
pub mod encode;

use std::io::{self, Read, Write};

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::command::codec::decode::decode_head;

use self::encode::encode_head;

use super::{Command, HEAD_SIZE};

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
/// The Stream can be non blocking, therefore the codec holds the state.
#[derive(Debug)]
pub struct CommandCodec<S> {
    stream: S,
    current_command: Option<Command>,
}

impl<S> CommandCodec<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            current_command: None,
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
        let head = encode_head(&command)?;

        self.stream.write_all(&head)?;
        self.stream.write_all(&command.data)?;

        Ok(command.data.len() + HEAD_SIZE)
    }
}

impl<S: Read> CommandCodec<S> {
    /// Read one command from stream.
    /// Returns tuple with read size and Command.
    pub fn read(&mut self) -> Result<(usize, Command), StreamError> {
        let mut command = match self.current_command.take() {
            Some(tup) => tup,
            None => {
                let mut buf = [0u8; HEAD_SIZE];

                self.stream.read_exact(&mut buf)?;

                decode_head(&buf)?
            }
        };

        if let Err(err) = self.stream.read_exact(&mut command.data) {
            self.current_command = Some(command);

            return Err(StreamError::from(err));
        }

        Ok((HEAD_SIZE + command.data.len(), command))
    }
}

impl<S: AsyncRead + Unpin> CommandCodec<S> {
    /// Read one command from stream async.
    /// Returns tuple with read size and Command.
    pub async fn read_async(&mut self) -> Result<(usize, Command), StreamError> {
        let mut command = match self.current_command.take() {
            Some(tup) => tup,
            None => {
                let mut buf = [0u8; HEAD_SIZE];

                self.stream.read_exact(&mut buf).await?;

                decode_head(&buf)?
            }
        };

        if let Err(err) = self.stream.read_exact(&mut command.data).await {
            self.current_command = Some(command);

            return Err(StreamError::from(err));
        }

        Ok((HEAD_SIZE + command.data.len(), command))
    }
}

impl<S: AsyncWrite + Unpin> CommandCodec<S> {
    /// Write command to stream async
    pub async fn write_async(&mut self, command: &Command) -> Result<usize, StreamError> {
        let head = encode_head(&command)?;

        self.stream.write_all(&head).await?;
        self.stream.write_all(&command.data).await?;

        Ok(command.data.len() + HEAD_SIZE)
    }
}
