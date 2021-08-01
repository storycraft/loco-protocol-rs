/*
 * Created on Sat Jul 24 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

pub mod decode;
pub mod encode;

use std::{
    future::Future,
    io::{self, Read, Write},
    pin::Pin,
    task::{Context, Poll},
};

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, FutureExt, ready};

use crate::command::{codec::decode::decode_head, HEADER_SIZE};

use self::encode::encode_head;

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
/// The Stream can be non blocking, therefore the codec holds the state.
#[derive(Debug)]
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
        let head = encode_head(&command)?;

        self.stream.write_all(&head)?;
        self.stream.write_all(&command.data)?;

        Ok(command.data.len() + HEADER_SIZE + 4)
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

                decode_head(&buf)?
            }
        };

        let mut data = vec![0_u8; data_size as usize];
        if let Err(err) = self.stream.read_exact(&mut data) {
            self.current_header = Some((header, data_size));

            return Err(StreamError::from(err));
        }

        Ok((HEADER_SIZE as u32 + 4 + data_size, Command { header, data }))
    }
}

/// Async version of [CommandCodec].
/// Unlike sync version, Async version does not hold state.
#[derive(Debug)]
pub struct CommandCodecAsync<S> {
    stream: S,
}

impl<S> CommandCodecAsync<S> {
    pub fn new(stream: S) -> Self {
        Self { stream }
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

impl<S: AsyncRead + Unpin> CommandCodecAsync<S> {
    /// Read one command from stream.
    /// Returns tuple with read size and Command.
    pub fn read(&mut self) -> ReadCommandFuture<S> {
        ReadCommandFuture {
            stream: &mut self.stream,
        }
    }
}

impl<S: AsyncWrite + Unpin> CommandCodecAsync<S> {
    /// Write command to stream
    pub fn write<'a>(&'a mut self, command: &'a Command) -> WriteCommandFuture<'a, S> {
        WriteCommandFuture {
            stream: &mut self.stream,
            command,
        }
    }
}

#[derive(Debug)]
pub struct ReadCommandFuture<'a, S> {
    stream: &'a mut S,
}

impl<S: AsyncRead + Unpin> Future for ReadCommandFuture<'_, S> {
    type Output = Result<(u32, Command), StreamError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let (header, data_size) = {
            let mut buf = [0u8; HEADER_SIZE + 4];

            ready!(self.stream.read_exact(&mut buf).poll_unpin(cx))?;

            decode_head(&buf)?
        };

        let mut data = vec![0_u8; data_size as usize];
        ready!(self.stream.read_exact(&mut data).poll_unpin(cx))?;

        Poll::Ready(Ok((
            HEADER_SIZE as u32 + 4 + data_size,
            Command { header, data },
        )))
    }
}

#[derive(Debug)]
pub struct WriteCommandFuture<'a, S> {
    stream: &'a mut S,
    command: &'a Command,
}

impl<S: AsyncWrite + Unpin> Future for WriteCommandFuture<'_, S> {
    type Output = Result<usize, StreamError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let head = encode_head(self.command)?;
        let data = &self.command.data;

        ready!(self.stream.write_all(&head).poll_unpin(cx))?;
        ready!(self.stream.write_all(&data).poll_unpin(cx))?;

        Poll::Ready(Ok(self.command.data.len() + HEADER_SIZE + 4))
    }
}
