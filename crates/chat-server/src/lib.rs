//! Event-driven relay server for encrypted chat envelopes.

#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

pub mod router;
pub mod ws;
