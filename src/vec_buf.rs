/*
 * Created on Tue Jul 27 2021
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

use std::{collections::VecDeque, io::{Cursor, Read, Write}};

/// Store buffers read
#[derive(Debug)]
pub struct VecBuf {
    
    deque: VecDeque<Vec<u8>>

}

impl VecBuf {

    pub fn new() -> Self {
        Self {
            deque: VecDeque::new()
        }
    }

    /// Push chunk
    pub fn push(&mut self, chunk: Vec<u8>) {
        self.deque.push_back(chunk)
    }

}

impl Read for VecBuf {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = buf.len();
        let mut cursor = Cursor::new(buf);

        while (cursor.position() as usize) < len {
            match self.deque.pop_front() {
                Some(chunk) => {
                    if chunk.len() + (cursor.position() as usize) <= len {
                        cursor.write_all(&chunk)?;
                    } else {
                        let left = len - cursor.position() as usize;
                        cursor.write_all(&chunk[..left])?;
                        self.deque.push_front(chunk[left..].to_vec());

                        break;
                    }
                }
                _ => break,
            }
        }

        Ok(cursor.position() as usize)
    }
}
