//! Shared protocol and cryptography for e2e-chat-rs.

#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

pub mod crypto;
pub mod event;
pub mod nonce;
pub mod service;
pub mod types;

pub const PROTOCOL_VERSION: u16 = 1;
