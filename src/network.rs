/*
 * Created on Sat Nov 28 2020
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::{collections::HashMap, io::{self, Read, Write}, sync::mpsc::Receiver, sync::mpsc::SendError, sync::mpsc::{Sender, channel}};

use crate::command::{self, Command, processor::CommandProcessor};

#[derive(Debug)]
pub enum Error {

    Command(command::Error),
    Channel,
    Socket(io::Error)

}

impl From<command::Error> for Error {

    fn from(err: command::Error) -> Self {
        Error::Command(err)
    }

}

impl From<io::Error> for Error {

    fn from(err: io::Error) -> Self {
        Error::Socket(err)
    }

}

impl<A> From<SendError<A>> for Error {

    fn from(_: SendError<A>) -> Self {
        Error::Channel
    }

}

/// ConnectionChannel holds Sender and Receiver crossed with another ConnectionChannel pair.
/// Usually considered as user side and server side pair.
pub struct ConnectionChannel {

    id: u32,

    sender: Sender<Command>,
    receiver: Receiver<Command>,

}

impl ConnectionChannel {

    pub fn new_pair(id: u32) -> (ConnectionChannel, ConnectionChannel) {
        let user = channel::<Command>();
        let socket = channel::<Command>();

        (
            ConnectionChannel {
                id,
                sender: user.0,
                receiver: socket.1,
            },
            ConnectionChannel {
                id,
                sender: socket.0,
                receiver: user.1
            }
        )
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn sender(&self) -> &Sender<Command> {
        &self.sender
    }

    pub fn receiver(&self) -> &Receiver<Command> {
        &self.receiver
    }

}

/// ChannelConnection wrap command stream and process it.
/// The response command will only send to sender channel.
/// If response command doesn't have sender, It will treat as broadcast command and will be sent to every channel attached.
pub struct ChannelConnection<A: Read + Write> {

    processor: CommandProcessor<A>,

    next_channel_id: u32,
    channel_map: HashMap<u32, ConnectionChannel>,

    command_channel: HashMap<i32, u32>

}

impl<A: Read + Write> ChannelConnection<A> {

    pub fn new(processor: CommandProcessor<A>) -> Self {
        Self {
            processor,
            next_channel_id: 0,
            channel_map: HashMap::new(),
            command_channel: HashMap::new()
        }
    }

    pub fn processor(&self) -> &CommandProcessor<A> {
        &self.processor
    }

    pub fn channel_map(&self) -> &HashMap<u32, ConnectionChannel> {
        &self.channel_map
    }

    /// Attach channel between instance.
    /// The returned ConnectionChannel struct is user side Channel.
    pub fn create_channel(&mut self) -> ConnectionChannel {
        let (user_channel, socket_channel) = ConnectionChannel::new_pair(self.next_channel_id);
        self.next_channel_id += 1;

        self.channel_map.insert(user_channel.id(), socket_channel);

        user_channel
    }

    pub fn detach_channel(&mut self, channel: ConnectionChannel) -> (ConnectionChannel, Option<ConnectionChannel>) {
        let id = channel.id();
        (channel, self.channel_map.remove(&id))
    }

    pub fn process(&mut self) -> Result<(), Error> {
        for channel in self.channel_map.values() {
            for command in channel.receiver().try_iter() {
                self.command_channel.insert(command.header.id, channel.id());

                self.processor.write_commmand(command)?;
            }
        }

        let command = self.processor.read_commmand()?;

        match command {

            Some(command) => {
                match self.command_channel.remove(&command.header.id) {

                    Some(channel_id) => {
                        match self.channel_map.get(&channel_id) {
    
                            Some(channel) => {
                                channel.sender.send(command)?;
                            }
    
                            None => {}
                        }
                    }
    
                    None => {
                        for channel in self.channel_map.values() {
                            channel.sender().send(command.clone())?;
                        }
                    }
                }
            }

            None => {}
        }

        Ok(())
    }

}

pub type ResponseHandler = fn(Command, Command);

pub trait ChannelHandler {

    fn send_command(&mut self, command: Command, response_handler: ResponseHandler) -> Result<(), SendError<Command>>;

    fn handle(&mut self);

}

trait Handler<'a> {}
impl<'a, T: ?Sized> Handler<'a> for T {}

pub struct MappedHandler {

    pub channel: ConnectionChannel,
    command_map: HashMap<i32, (Command, ResponseHandler)>

}

impl MappedHandler {

    pub fn new(channel: ConnectionChannel) -> Self {
        Self {
            channel,
            command_map: HashMap::new()
        }
    }

}

impl ChannelHandler for MappedHandler {

    fn send_command(&mut self, command: Command, response_handler: ResponseHandler) -> Result<(), SendError<Command>> {
        self.command_map.insert(command.header.id, (command.clone(), response_handler));

        self.channel.sender().send(command)
    }

    fn handle(&mut self) {
        let iter = self.channel.receiver().try_iter();

        for response in iter {
            let id = response.header.id;

            match self.command_map.remove(&id) {

                Some(request_set) => {
                    let response_handler = request_set.1;

                    response_handler(response, request_set.0);
                }

                None => {}
            };
        }
    }
}