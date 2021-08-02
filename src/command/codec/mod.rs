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

use futures::{ready, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, FutureExt};

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
    pub fn read_async(&mut self) -> ReadCommandFuture<S> {
        ReadCommandFuture { codec: self }
    }
}

impl<S: AsyncWrite + Unpin> CommandCodec<S> {
    /// Write command to stream async
    pub fn write_async(&mut self, command: &Command) -> WriteCommandFuture<S> {
        let data = encode_head(&command).map(|mut buf| {
            buf.append(&mut command.data.clone());
            buf
        });

        WriteCommandFuture {
            stream: &mut self.stream,
            data: Some(data),
        }
    }
}

#[derive(Debug)]
pub struct ReadCommandFuture<'a, S> {
    codec: &'a mut CommandCodec<S>,
}

impl<S: AsyncRead + Unpin> Future for ReadCommandFuture<'_, S> {
    type Output = Result<(usize, Command), StreamError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let None = &self.codec.current_command {
            self.codec.current_command = Some({
                let mut buf = [0u8; HEAD_SIZE];

                ready!(self.codec.stream.read_exact(&mut buf).poll_unpin(cx))?;

                decode_head(&buf)?
            });
        }

        if let Some(mut command) = self.codec.current_command.take() {
            match self
                .codec
                .stream
                .read_exact(&mut command.data)
                .poll_unpin(cx)
            {
                Poll::Ready(res) => {
                    res?;

                    Poll::Ready(Ok((HEAD_SIZE + command.data.len(), command)))
                }
                Poll::Pending => {
                    self.codec.current_command = Some(command);

                    Poll::Pending
                }
            }
        } else {
            Poll::Pending
        }
    }
}

#[derive(Debug)]
pub struct WriteCommandFuture<'a, S> {
    stream: &'a mut S,
    data: Option<Result<Vec<u8>, bincode::Error>>,
}

impl<S: AsyncWrite + Unpin> Future for WriteCommandFuture<'_, S> {
    type Output = Result<usize, StreamError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.data.take() {
            Some(data) => {
                let data = data?;

                match self.stream.write_all(&data).poll_unpin(cx) {
                    Poll::Ready(res) => {
                        res?;
                        Poll::Ready(Ok(data.len()))
                    }

                    Poll::Pending => {
                        self.data = Some(Ok(data));

                        Poll::Pending
                    }
                }
            }
            None => Poll::Pending,
        }
    }
}
