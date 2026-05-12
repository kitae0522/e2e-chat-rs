//! Tiny CLI client support for encrypted chat sessions.

#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

pub mod session;
