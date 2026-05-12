use thiserror::Error;

use crate::event::WireEvent;
use crate::types::ClientId;

pub trait MessageRouter {
    fn connect(&mut self, client_id: ClientId) -> Result<(), RouterError>;

    fn disconnect(&mut self, client_id: &ClientId) -> Result<(), RouterError>;

    fn route(&mut self, connection_id: &ClientId, event: WireEvent) -> Result<(), RouterError>;

    fn drain_outbox(&mut self, client_id: &ClientId) -> Vec<WireEvent>;
}

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
