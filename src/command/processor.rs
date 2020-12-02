/*
 * Created on Mon Nov 30 2020
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::io::{Cursor, Read, Write};

use super::{Command, Error, Header, ReadHeader, WriteCommand};

/// Like BufReader and BufWriter, provide optimized Command read/write operation to stream.
pub struct CommandProcessor<S: Read + Write> {
    
    stream: S,

    current: Option<Header>,
    read_buffer: Vec<u8>
    
}

impl<S: Read + Write> CommandProcessor<S> {

    pub fn new(stream: S) -> Self {
        Self {
            stream,
            current: None,
            read_buffer: Vec::new()
        }
    }

    pub fn stream(&self) -> &S {
        &self.stream
    }

    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    pub fn current_header(&self) -> Option<Header> {
        self.current.clone()
    }

    /// Consume this CommandProcessor and unwrap stream
    pub fn into_inner(self) -> S {
        self.stream
    }

    fn try_read_command(&mut self) -> Result<Option<Command>, Error> {
        if self.current.is_none() {
            if self.read_buffer.len() >= 22 {
                let mut cursor = Cursor::new(self.read_buffer.drain(..22).collect::<Vec<u8>>());
                let header = cursor.read_header()?;

                self.current = Some(header);
            } else {
                return Ok(None);
            }
        }

        let current = self.current.as_ref().unwrap();
        let command_size = current.data_size as usize;

        if self.read_buffer.len() >= command_size {
            let command = Command {
                header: self.current.unwrap(),
                data: self.read_buffer.drain(..command_size).collect::<Vec<u8>>()
            };

            self.current = None;

            Ok(Some(command))
        } else {
            Ok(None)
        }
    }

    /// Try to read one command
    pub fn read_commmand(&mut self) -> Result<Option<Command>, Error> {
        match self.try_read_command() {
            Ok(readed) => {
                match readed {
                    Some(command) => Ok(Some(command)),
                    None => {
                        let mut buf = [0_u8; 2048];

                        let readed = self.stream.read(&mut buf)?;
                
                        self.read_buffer.extend_from_slice(&mut buf[..readed]);

                        self.try_read_command()
                    }
                }
            },
            Err(err) => Err(err)
        }
    }

    /// Read all command
    pub fn read_all_command(&mut self) -> Result<Vec<Command>, Error> {
        let mut store = Vec::<Command>::new();

        loop {
            match self.read_commmand() {

                Ok(readed) => {
                    match readed {
                        Some(command) => {
                            store.push(command);
                        },

                        None => return Ok(store)
                    };
                }
    
                Err(err) => return Err(err)
            }
        }
    }

    /// Write command to stream.
    pub fn write_commmand(&mut self, command: Command) -> Result<usize, Error> {
        let mut cursor = Cursor::new(vec![0_u8; command.header.data_size as usize + 22]);
                
        let written = cursor.write_commmand(command)?;

        self.stream.write_all(&cursor.into_inner())?;

        Ok(written)
    }

    // Write all command to stream
    pub fn write_all_command(&mut self, list: Vec<Command>) -> Result<usize, Error> {
        let mut size = 0_usize;
        let mut written = 0_usize;

        for command in list.iter() {
            size += command.header.data_size as usize + 22;
        }

        let mut cursor = Cursor::new(vec![0_u8; size]);

        for command in list.into_iter() {
            written += cursor.write_commmand(command)?;
        }

        self.stream.write_all(&cursor.into_inner())?;

        Ok(written)
    }

}
