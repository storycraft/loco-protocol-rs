/*
 * Created on Mon Nov 30 2020
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use super::{Command, CommandData, Header};

/// Builder struct used to create Command struct from CommandData
pub struct Builder<C: CommandData> {

    id: i32,
    status: i16,
    data_type: i8,
    data: C,

}

impl<C: CommandData> Builder<C> {

    pub fn new(id: i32, data: C) -> Self {
        Self {
            id,
            status: 0,
            data_type: 0,
            data
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
        let data = C::encode(&self.data)?;

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