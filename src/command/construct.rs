/*
 * Created on Mon Nov 30 2020
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::marker::PhantomData;

use super::{Command, CommandData, Header};

/// Command encoder that can be used on Construct or encoding
pub trait Encode<C: CommandData> {

    fn encode(method: &str, data: &C) -> Result<Vec<u8>, super::Error>;

}

/// Command decoder that can be used on DeConstruct or decoding
pub trait Decode<C: CommandData> {

    fn decode(method: &str, data: &Vec<u8>) -> Result<C, super::Error>;

}

/// Construct struct used to create Command struct from CommandData
pub struct Construct<C: CommandData, E: Encode<C>> {

    id: i32,
    status: i16,
    data_type: i8,
    data: C,

    phantom: PhantomData<E>

}

impl<C: CommandData, E: Encode<C>> Construct<C, E> {

    pub fn new(id: i32, data: C) -> Self {
        Self {
            id,
            status: 0,
            data_type: 0,
            data,
            phantom: Default::default()
        }
    }

    pub fn id(&self) -> i32 {
        self.id
    }

    pub fn status(&self) -> i16 {
        self.status
    }

    pub fn data_type(&self) -> i8 {
        self.data_type
    }
 
    pub fn data(&self) -> &C {
        &self.data
    }

    pub fn set_id(mut self, id: i32) -> Self {
        self.id = id;

        self
    }

    pub fn set_status(mut self, status: i16) -> Self {
        self.status = status;

        self
    }

    pub fn set_data_type(mut self, data_type: i8) -> Self {
        self.data_type = data_type;

        self
    }

    pub fn set_data(mut self, data: C) -> Self {
        self.data = data;

        self
    }

    pub fn encode(self) -> Result<Command, super::Error> {
        let data_name = &self.data.method();
        let data = E::encode(data_name, &self.data)?;

        let mut name = [0_u8; 11];
        let bytes = data_name.as_bytes();
        let len = bytes.len().min(11);

        name[..len].copy_from_slice(&bytes[..len]);
        
        let header = Header {
            id: self.id,
            status: 0,
            name,
            data_type: 0,
            data_size: data.len() as i32
        };

        Ok(Command {
            header,
            data
        })
    }

}

pub struct DeConstruct;

impl DeConstruct {

    pub fn decode<C: CommandData, D: Decode<C>>(command: Command) -> Result<C, super::Error> {
        D::decode(std::str::from_utf8(&command.header.name)?, &command.data)
    }

}