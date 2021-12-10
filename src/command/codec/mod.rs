/*
 * Created on Sat Jul 24 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

pub mod decode;
pub mod encode;

use std::{
    error::Error,
    fmt::Display,
    io::{self, Read, Write},
};

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

impl Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamError::Bincode(err) => err.fmt(f),
            StreamError::Io(err) => err.fmt(f),
        }
    }
}

impl Error for StreamError {}

/// Provide Command read / write operation to stream
#[derive(Debug)]
pub struct CommandCodec<S> {
    stream: S,
}

impl<S> CommandCodec<S> {
    pub const fn new(stream: S) -> Self {
        Self { stream }
    }

    pub const fn stream(&self) -> &S {
        &self.stream
    }

    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    pub fn into_inner(self) -> S {
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
        let mut buf = [0u8; HEAD_SIZE];
        self.stream.read_exact(&mut buf)?;

        let mut command = decode_head(&buf)?;
        self.stream.read_exact(&mut command.data)?;

        Ok((HEAD_SIZE + command.data.len(), command))
    }
}

impl<S: AsyncRead + Unpin> CommandCodec<S> {
    /// Read one command from stream async.
    /// Returns tuple with read size and Command.
    pub async fn read_async(&mut self) -> Result<(usize, Command), StreamError> {
        let mut buf = [0u8; HEAD_SIZE];

        self.stream.read_exact(&mut buf).await?;

        let mut command = decode_head(&buf)?;
        self.stream.read_exact(&mut command.data).await?;

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
