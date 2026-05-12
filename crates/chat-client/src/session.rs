use chat_core::crypto::{CryptoError, CryptoSession, KeyPair};
use chat_core::event::WireEvent;
use chat_core::types::{ClientId, MessageId};

pub struct ClientSession {
    local_id: ClientId,
    peer_id: ClientId,
    keypair: KeyPair,
    crypto_session: Option<CryptoSession>,
}

impl ClientSession {
    pub fn new(local_id: ClientId, peer_id: ClientId) -> Self {
        Self {
            local_id,
            peer_id,
            keypair: KeyPair::generate(),
            crypto_session: None,
        }
    }

    pub fn client_hello(&self) -> WireEvent {
        WireEvent::ClientHello {
            client_id: self.local_id.clone(),
            public_key: self.keypair.public_key(),
        }
    }

    pub fn peer_key_event(&self) -> WireEvent {
        WireEvent::PeerKey {
            from: self.local_id.clone(),
            to: self.peer_id.clone(),
            public_key: self.keypair.public_key(),
        }
    }

    pub fn is_ready(&self) -> bool {
        self.crypto_session.is_some()
    }

    pub fn handle_event(&mut self, event: WireEvent) -> Result<Option<String>, ClientSessionError> {
        match event {
            WireEvent::PeerKey {
                from,
                to,
                public_key,
            } => {
                if from != self.peer_id || to != self.local_id {
                    return Err(ClientSessionError::UnexpectedPeerKey);
                }

                self.crypto_session = Some(CryptoSession::new(
                    &self.keypair,
                    public_key,
                    self.local_id.clone(),
                    self.peer_id.clone(),
                ));
                Ok(None)
            }
            WireEvent::EncryptedMessage(envelope) => {
                let session = self
                    .crypto_session
                    .as_mut()
                    .ok_or(ClientSessionError::MissingPeerKey)?;
                let plaintext = session.decrypt(&envelope)?;
                let message =
                    String::from_utf8(plaintext).map_err(|_| ClientSessionError::InvalidUtf8)?;

                Ok(Some(message))
            }
            WireEvent::ClientHello { .. } | WireEvent::Ack { .. } | WireEvent::Error { .. } => {
                Ok(None)
            }
        }
    }

    pub fn encrypt_line(&mut self, line: &str) -> Result<WireEvent, ClientSessionError> {
        let session = self
            .crypto_session
            .as_mut()
            .ok_or(ClientSessionError::MissingPeerKey)?;
        let envelope = session.encrypt(MessageId::new(), line.as_bytes())?;

        Ok(WireEvent::EncryptedMessage(envelope))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientSessionError {
    MissingPeerKey,
    UnexpectedPeerKey,
    InvalidUtf8,
    Crypto(CryptoError),
}

impl From<CryptoError> for ClientSessionError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chat_core::event::WireEvent;
    use chat_core::types::ClientId;

    #[test]
    fn builds_hello_and_peer_key_without_plaintext() {
        let session = ClientSession::new(
            ClientId::parse("alice").expect("alice"),
            ClientId::parse("bob").expect("bob"),
        );

        let hello = session.client_hello();
        let peer_key = session.peer_key_event();

        assert!(matches!(hello, WireEvent::ClientHello { .. }));
        assert!(matches!(peer_key, WireEvent::PeerKey { .. }));
    }

    #[test]
    fn encrypts_and_decrypts_line_after_peer_key_exchange() {
        let mut alice = ClientSession::new(
            ClientId::parse("alice").expect("alice"),
            ClientId::parse("bob").expect("bob"),
        );
        let mut bob = ClientSession::new(
            ClientId::parse("bob").expect("bob"),
            ClientId::parse("alice").expect("alice"),
        );

        bob.handle_event(alice.peer_key_event()).expect("alice key");
        alice.handle_event(bob.peer_key_event()).expect("bob key");

        let event = alice.encrypt_line("hello bob").expect("encrypt");
        let decrypted = bob.handle_event(event).expect("decrypt").expect("message");

        assert_eq!(decrypted, "hello bob");
    }

    #[test]
    fn reports_ready_after_peer_key_exchange() {
        let mut alice = ClientSession::new(
            ClientId::parse("alice").expect("alice"),
            ClientId::parse("bob").expect("bob"),
        );
        let bob = ClientSession::new(
            ClientId::parse("bob").expect("bob"),
            ClientId::parse("alice").expect("alice"),
        );

        assert!(!alice.is_ready());

        alice.handle_event(bob.peer_key_event()).expect("bob key");

        assert!(alice.is_ready());
    }
}
