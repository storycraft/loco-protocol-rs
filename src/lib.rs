/*
 * Created on Sat Nov 28 2020
 *
 * Copyright (c) storycraft. Licensed under the MIT Licence.
 */

//! # `loco-protocol`: Rust Loco protocol implementation
//! This crate provides low brick for building client on it
//!
//! ## Specification
#![doc = include_str!("../specification.md")]
#![no_std]
extern crate alloc;

// Loco protocol implementation
pub mod command;

/// Secure loyer implementation
pub mod secure;
