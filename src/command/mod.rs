/*
 * Created on Sat Nov 28 2020
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

pub mod builder;

pub mod processor;

use crate::secure::CryptoError;

use std::{fmt::Display, string::FromUtf8Error, io::{self, Read, Write}, str::Utf8Error};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug)]
pub struct Header {

    pub id: i32,
    pub status: i16,
    pub name: [u8; 11],
    pub data_type: i8,
    pub data_size: i32

}

impl Header {

    /// Extract String from name field
    pub fn name(&self) -> Result<String, FromUtf8Error> {
        let size = self.name.iter().position(|&c| c == b'\0').unwrap_or(11);

        String::from_utf8(self.name[..size].into())
    }

    /// set name field from str. Will be sliced to 11 bytes max.
    pub fn set_name(&mut self, name: &str) {
        self.name = Self::to_name(name);
    }

    pub fn to_name(name: &str) -> [u8; 11] {
        let bytes = name.as_bytes();
        let mut name = [0_u8; 11];

        name[..bytes.len().min(11)].copy_from_slice(bytes);

        name
    }

}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Command {

    pub header: Header,
    pub data: Vec<u8>,

}

pub trait CommandData: Sized {

    fn method(&self) -> &'static str;

    fn encode(&self) -> Result<Vec<u8>, Error>;
    fn decode(data: &Vec<u8>) -> Result<Self, Error>;

}

#[derive(Debug)]
pub enum Error {

    Io(io::Error),
    Marshal(bincode::Error),
    Decode(String),
    Encode(String),
    Crypto(CryptoError)

}

impl Display for Error {

    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }

}

impl std::error::Error for Error {
    
}

impl From<io::Error> for Error {

    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }

}

impl From<bincode::Error> for Error {

    fn from(err: bincode::Error) -> Self {
        Error::Marshal(err)
    }

}

impl From<CryptoError> for Error {

    fn from(err: CryptoError) -> Self {
        Error::Crypto(err)
    }

}

impl From<Utf8Error> for Error {

    fn from(err: Utf8Error) -> Self {
        Error::Decode(err.to_string()).into()
    }

}

impl From<Error> for io::Error {

    fn from(err: Error) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, format!("Command Error: {:?}", err))
    }

}

pub trait ReadHeader {

    fn read_header(&mut self) -> Result<Header, Error>;

}

impl<T: Read> ReadHeader for T {

    fn read_header(&mut self) -> Result<Header, Error> {
        let mut buf = [0_u8; 22];

        self.read_exact(&mut buf)?;
        let header = bincode::deserialize::<Header>(&buf)?;

        Ok(header)
    }

}

pub trait WriteHeader {

    fn write_header(&mut self, header: Header) -> Result<usize, Error>;

}

impl<T: Write> WriteHeader for T {
    
    fn write_header(&mut self, header: Header) -> Result<usize, Error> {
        let buf = bincode::serialize(&header)?;

        self.write_all(&buf)?;

        Ok(buf.len())
    }

}


pub trait ReadCommand {

    fn read_command(&mut self) -> Result<Command, Error>;

}

impl<T: ReadHeader + Read> ReadCommand for T {

    fn read_command(&mut self) -> Result<Command, Error> {
        let header_read = self.read_header();
        if header_read.is_err() {
            return Err(header_read.err().unwrap());
        }
        let header = header_read.ok().unwrap();

        let mut data_buf = Vec::with_capacity(header.data_size as usize);

        let read = self.read_exact(&mut data_buf);
        if read.is_err() {
            return Err(read.err().unwrap().into());
        }

        Ok(Command {
            header,
            data: data_buf
        })
    }

}

pub trait WriteCommand {

    fn write_command(&mut self, command: Command) -> Result<usize, Error>;

}

impl<T: Write + WriteHeader> WriteCommand for T {

    fn write_command(&mut self, command: Command) -> Result<usize, Error> {
        let header_written = self.write_header(command.header)?;
        
        self.write_all(&command.data)?;

        Ok(header_written + command.data.len())
    }

}