//! Shared protocol and cryptography for e2e-chat-rs.

pub mod crypto;
pub mod event;
pub mod nonce;
pub mod types;

pub const PROTOCOL_VERSION: u16 = 1;
