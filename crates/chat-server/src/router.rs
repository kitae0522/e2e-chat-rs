use std::collections::{HashMap, VecDeque};

use chat_core::event::WireEvent;
use chat_core::types::ClientId;

#[derive(Debug, Default)]
pub struct InMemoryRouter {
    outboxes: HashMap<ClientId, VecDeque<WireEvent>>,
}

impl InMemoryRouter {
    pub fn connect(&mut self, client_id: ClientId) -> Result<(), RouterError> {
        if self.outboxes.contains_key(&client_id) {
            return Err(RouterError::ClientAlreadyConnected);
        }

        self.outboxes.insert(client_id, VecDeque::new());
        Ok(())
    }

    pub fn disconnect(&mut self, client_id: &ClientId) -> Result<(), RouterError> {
        if self.outboxes.remove(client_id).is_some() {
            Ok(())
        } else {
            Err(RouterError::ClientNotConnected)
        }
    }

    pub fn route(&mut self, connection_id: &ClientId, event: WireEvent) -> Result<(), RouterError> {
        if !self.outboxes.contains_key(connection_id) {
            return Err(RouterError::ClientNotConnected);
        }

        let recipient = recipient_for(connection_id, &event)?;
        let Some(outbox) = self.outboxes.get_mut(&recipient) else {
            return Err(RouterError::UnknownRecipient);
        };

        outbox.push_back(event);
        Ok(())
    }

    pub fn drain_outbox(&mut self, client_id: &ClientId) -> Vec<WireEvent> {
        if let Some(outbox) = self.outboxes.get_mut(client_id) {
            outbox.drain(..).collect()
        } else {
            Vec::new()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouterError {
    ClientAlreadyConnected,
    ClientNotConnected,
    SenderMismatch,
    UnknownRecipient,
    UnsupportedEvent,
}

fn recipient_for(connection_id: &ClientId, event: &WireEvent) -> Result<ClientId, RouterError> {
    match event {
        WireEvent::PeerKey { from, to, .. } => {
            if from != connection_id {
                return Err(RouterError::SenderMismatch);
            }

            Ok(to.clone())
        }
        WireEvent::EncryptedMessage(envelope) => {
            if &envelope.sender != connection_id {
                return Err(RouterError::SenderMismatch);
            }

            Ok(envelope.recipient.clone())
        }
        WireEvent::ClientHello { .. } | WireEvent::Ack { .. } | WireEvent::Error { .. } => {
            Err(RouterError::UnsupportedEvent)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chat_core::event::{EncryptedEnvelope, WireEvent};
    use chat_core::types::{Ciphertext, ClientId, MessageId, NonceBytes, PublicKeyBytes};

    #[test]
    fn routes_peer_key_to_recipient_outbox() {
        let mut router = InMemoryRouter::default();
        let alice = ClientId::parse("alice").expect("alice");
        let bob = ClientId::parse("bob").expect("bob");

        router.connect(alice.clone()).expect("connect alice");
        router.connect(bob.clone()).expect("connect bob");
        router
            .route(
                &alice,
                WireEvent::PeerKey {
                    from: alice.clone(),
                    to: bob.clone(),
                    public_key: PublicKeyBytes::from_array([1; 32]),
                },
            )
            .expect("route peer key");

        assert_eq!(router.drain_outbox(&bob).len(), 1);
    }

    #[test]
    fn routes_encrypted_message_to_recipient_outbox() {
        let mut router = InMemoryRouter::default();
        let alice = ClientId::parse("alice").expect("alice");
        let bob = ClientId::parse("bob").expect("bob");

        router.connect(alice.clone()).expect("connect alice");
        router.connect(bob.clone()).expect("connect bob");
        router
            .route(
                &alice,
                WireEvent::EncryptedMessage(EncryptedEnvelope {
                    sender: alice.clone(),
                    recipient: bob.clone(),
                    message_id: MessageId::new(),
                    nonce: NonceBytes::from_array([7; 24]),
                    ciphertext: Ciphertext::from_bytes(vec![1, 2, 3]),
                }),
            )
            .expect("route encrypted message");

        let outbox = router.drain_outbox(&bob);

        assert_eq!(outbox.len(), 1);
        assert!(matches!(outbox[0], WireEvent::EncryptedMessage(_)));
    }

    #[test]
    fn rejects_forged_sender() {
        let mut router = InMemoryRouter::default();
        let alice = ClientId::parse("alice").expect("alice");
        let mallory = ClientId::parse("mallory").expect("mallory");
        let bob = ClientId::parse("bob").expect("bob");

        router.connect(alice.clone()).expect("connect alice");
        router.connect(bob.clone()).expect("connect bob");

        let err = router
            .route(
                &alice,
                WireEvent::PeerKey {
                    from: mallory,
                    to: bob,
                    public_key: PublicKeyBytes::from_array([2; 32]),
                },
            )
            .expect_err("forged sender must fail");

        assert_eq!(err, RouterError::SenderMismatch);
    }

    #[test]
    fn rejects_unknown_recipient() {
        let mut router = InMemoryRouter::default();
        let alice = ClientId::parse("alice").expect("alice");
        let bob = ClientId::parse("bob").expect("bob");

        router.connect(alice.clone()).expect("connect alice");

        let err = router
            .route(
                &alice,
                WireEvent::PeerKey {
                    from: alice.clone(),
                    to: bob,
                    public_key: PublicKeyBytes::from_array([3; 32]),
                },
            )
            .expect_err("unknown recipient must fail");

        assert_eq!(err, RouterError::UnknownRecipient);
    }
}
