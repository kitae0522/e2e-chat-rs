use thiserror::Error;

use crate::event::WireEvent;
use crate::types::ClientId;

pub trait MessageRouter {
    fn connect(&mut self, client_id: ClientId) -> Result<(), RouterError>;

    fn disconnect(&mut self, client_id: &ClientId) -> Result<(), RouterError>;

    fn route(&mut self, connection_id: &ClientId, event: WireEvent) -> Result<(), RouterError>;

    fn drain_outbox(&mut self, client_id: &ClientId) -> Vec<WireEvent>;
}

pub trait EventHook {
    fn on_connect(&mut self, _client_id: &ClientId) {}

    fn on_disconnect(&mut self, _client_id: &ClientId) {}

    fn on_route_accepted(&mut self, _connection_id: &ClientId, _event: &WireEvent) {}

    fn on_route_rejected(
        &mut self,
        _connection_id: &ClientId,
        _event: &WireEvent,
        _error: &RouterError,
    ) {
    }
}

pub trait AuthProvider {
    /// Decides whether a client may register under this identity.
    /// Called once after ClientHello and before any routing happens.
    fn authorize_connect(&mut self, _client_id: &ClientId) -> Result<(), AuthError> {
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NoopAuthProvider;

impl AuthProvider for NoopAuthProvider {}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AuthError {
    #[error("client connect was denied")]
    ConnectDenied,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NoopEventHook;

impl EventHook for NoopEventHook {}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RouterError {
    #[error("client is already connected")]
    ClientAlreadyConnected,
    #[error("client is not connected")]
    ClientNotConnected,
    #[error("event sender does not match the connection")]
    SenderMismatch,
    #[error("recipient is not connected")]
    UnknownRecipient,
    #[error("event type is not routable")]
    UnsupportedEvent,
}
