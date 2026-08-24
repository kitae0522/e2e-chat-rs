use chat_core::crypto::{CryptoError, CryptoSession, KeyPair, fingerprint};
use chat_core::event::{SessionPayload, WireEvent};
use chat_core::types::{ClientId, PublicKeyBytes};

/// Display-worthy result of an inbound wire event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundEvent {
    Chat(String),
    RekeyCompleted { epoch: u32 },
}

/// What the session produced while processing one inbound wire event.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct InboundOutcome {
    pub event: Option<InboundEvent>,
    /// Outbound event generated in response (e.g. rekey response).
    pub reply_event: Option<WireEvent>,
}

pub struct ClientSession {
    local_id: ClientId,
    peer_id: ClientId,
    keypair: KeyPair,
    peer_public_key: Option<PublicKeyBytes>,
    crypto_session: Option<CryptoSession>,
    expected_peer_fingerprint: Option<String>,
}

impl ClientSession {
    pub fn new(local_id: ClientId, peer_id: ClientId) -> Self {
        Self {
            local_id,
            peer_id,
            keypair: KeyPair::generate(),
            peer_public_key: None,
            crypto_session: None,
            expected_peer_fingerprint: None,
        }
    }

    /// Pins the expected peer fingerprint (hex, case/whitespace tolerant).
    /// Inbound PeerKey events whose fingerprint differs are rejected.
    pub fn expect_peer_fingerprint(&mut self, fingerprint: String) {
        self.expected_peer_fingerprint = Some(fingerprint.trim().to_lowercase());
    }

    /// Fingerprint of the accepted peer key, for out-of-band verification.
    pub fn peer_fingerprint(&self) -> Option<String> {
        self.peer_public_key.as_ref().map(fingerprint)
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

    pub fn handle_event(&mut self, event: WireEvent) -> Result<InboundOutcome, ClientSessionError> {
        match event {
            WireEvent::PeerKey {
                from,
                to,
                public_key,
            } => {
                if from != self.peer_id || to != self.local_id {
                    return Err(ClientSessionError::UnexpectedPeerKey);
                }
                if let Some(peer_public_key) = self.peer_public_key {
                    if peer_public_key == public_key {
                        return Ok(InboundOutcome::default());
                    }

                    return Err(ClientSessionError::UnexpectedPeerKey);
                }

                if let Some(expected) = &self.expected_peer_fingerprint
                    && fingerprint(&public_key) != *expected
                {
                    return Err(ClientSessionError::PeerKeyFingerprintMismatch);
                }
                self.peer_public_key = Some(public_key);
                self.crypto_session = Some(CryptoSession::new(
                    &self.keypair,
                    public_key,
                    self.local_id.clone(),
                    self.peer_id.clone(),
                ));
                Ok(InboundOutcome::default())
            }
            WireEvent::EncryptedMessage(envelope) => self.handle_encrypted_message(envelope),
            WireEvent::ClientHello { .. } | WireEvent::Ack { .. } | WireEvent::Error { .. } => {
                Ok(InboundOutcome::default())
            }
        }
    }

    pub fn encrypt_line(&mut self, line: &str) -> Result<WireEvent, ClientSessionError> {
        self.encrypt_payload(SessionPayload::Chat {
            text: line.to_owned(),
        })
    }

    /// Starts a rekey handshake and returns the request envelope to send.
    pub fn start_rekey(&mut self) -> Result<WireEvent, ClientSessionError> {
        let payload = self
            .crypto_session
            .as_mut()
            .ok_or(ClientSessionError::MissingPeerKey)?
            .start_rekey()?;

        self.encrypt_payload(payload)
    }

    fn encrypt_payload(
        &mut self,
        payload: SessionPayload,
    ) -> Result<WireEvent, ClientSessionError> {
        let session = self
            .crypto_session
            .as_mut()
            .ok_or(ClientSessionError::MissingPeerKey)?;
        let envelope = session.encrypt_payload(&payload)?;

        Ok(WireEvent::EncryptedMessage(envelope))
    }

    fn handle_encrypted_message(
        &mut self,
        envelope: chat_core::event::EncryptedEnvelope,
    ) -> Result<InboundOutcome, ClientSessionError> {
        let session = self
            .crypto_session
            .as_mut()
            .ok_or(ClientSessionError::MissingPeerKey)?;
        let payload = session.decrypt_payload(&envelope)?;

        match payload {
            SessionPayload::Chat { text } => Ok(InboundOutcome {
                event: Some(InboundEvent::Chat(text)),
                reply_event: None,
            }),
            SessionPayload::RekeyRequest {
                rekey_id,
                ephemeral_public_key,
            } => {
                // 요청자를 대신해 자동으로 응답한다 (세션 키 보유자만 가능).
                let reply = session.handle_session_payload(SessionPayload::RekeyRequest {
                    rekey_id,
                    ephemeral_public_key,
                })?;
                let reply = reply.expect("rekey request yields a response");
                // 응답을 이전 epoch로 만든 뒤 전환을 확정한다.
                // (reply_event는 즉시 발송되므로 여기서 커밋하는 것이 순서상 안전하다.)
                let reply_envelope = session.encrypt_payload(&reply)?;
                session.commit_staged_rekey()?;

                Ok(InboundOutcome {
                    event: None,
                    reply_event: Some(WireEvent::EncryptedMessage(reply_envelope)),
                })
            }
            SessionPayload::RekeyResponse {
                rekey_id,
                ephemeral_public_key,
            } => {
                session.handle_session_payload(SessionPayload::RekeyResponse {
                    rekey_id,
                    ephemeral_public_key,
                })?;

                Ok(InboundOutcome {
                    event: Some(InboundEvent::RekeyCompleted {
                        epoch: session.epoch(),
                    }),
                    reply_event: None,
                })
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientSessionError {
    MissingPeerKey,
    UnexpectedPeerKey,
    PeerKeyFingerprintMismatch,
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
        let outcome = bob.handle_event(event).expect("decrypt");
        assert_eq!(outcome.reply_event, None);

        assert_eq!(
            outcome.event,
            Some(InboundEvent::Chat("hello bob".to_owned()))
        );
    }

    #[test]
    fn completes_rekey_handshake_from_inbound_request_and_replies() {
        // 인바운드 재키 요청에는 자동 응답하고, 양쪽이 새 epoch로 수렴해야 한다.
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

        let request_envelope = alice.start_rekey().expect("start rekey");

        let outcome = bob.handle_event(request_envelope).expect("handle request");
        let reply_envelope = outcome
            .reply_event
            .expect("responder replies automatically");
        assert_eq!(outcome.event, None);

        let outcome = alice.handle_event(reply_envelope).expect("complete rekey");

        assert_eq!(
            outcome.event,
            Some(InboundEvent::RekeyCompleted { epoch: 1 })
        );

        // 재키 이후에도 채팅이 동작한다.
        let event = alice.encrypt_line("fresh keys").expect("encrypt");
        let outcome = bob.handle_event(event).expect("decrypt after rekey");

        assert_eq!(
            outcome.event,
            Some(InboundEvent::Chat("fresh keys".to_owned()))
        );
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

    #[test]
    fn accepts_peer_key_matching_expected_fingerprint() {
        let mut alice = ClientSession::new(
            ClientId::parse("alice").expect("alice"),
            ClientId::parse("bob").expect("bob"),
        );
        let bob = ClientSession::new(
            ClientId::parse("bob").expect("bob"),
            ClientId::parse("alice").expect("alice"),
        );
        let bob_peer_key = bob.peer_key_event();
        let pinned = fingerprint(&match bob_peer_key {
            WireEvent::PeerKey { public_key, .. } => public_key,
            other => panic!("expected peer key event, got {other:?}"),
        });
        alice.expect_peer_fingerprint(pinned);

        alice.handle_event(bob_peer_key).expect("matching peer key");

        assert!(alice.is_ready());
    }

    #[test]
    fn rejects_mismatched_fingerprint_and_stays_unready() {
        // MITM이 키를 바꿔치기해도 기대 지문과 다르면 세션이 열리지 않아야 한다.
        let mut alice = ClientSession::new(
            ClientId::parse("alice").expect("alice"),
            ClientId::parse("bob").expect("bob"),
        );
        let mallory = ClientSession::new(
            ClientId::parse("bob").expect("bob"),
            ClientId::parse("alice").expect("alice"),
        );
        alice.expect_peer_fingerprint(fingerprint(&PublicKeyBytes::from_array([9; 32])));

        let mallory_event = mallory.peer_key_event();
        assert_eq!(
            alice.handle_event(mallory_event),
            Err(ClientSessionError::PeerKeyFingerprintMismatch)
        );
        assert!(!alice.is_ready());
        assert!(alice.encrypt_line("hello").is_err());
    }

    #[test]
    fn reports_received_peer_fingerprint_for_display() {
        let mut alice = ClientSession::new(
            ClientId::parse("alice").expect("alice"),
            ClientId::parse("bob").expect("bob"),
        );
        let bob = ClientSession::new(
            ClientId::parse("bob").expect("bob"),
            ClientId::parse("alice").expect("alice"),
        );

        assert!(alice.peer_fingerprint().is_none());

        let bob_event = bob.peer_key_event();
        let expected = fingerprint(&match bob_event {
            WireEvent::PeerKey { public_key, .. } => public_key,
            other => panic!("expected peer key event, got {other:?}"),
        });
        alice.handle_event(bob_event).expect("peer key");

        assert_eq!(alice.peer_fingerprint(), Some(expected));
    }

    #[test]
    fn keeps_replay_protection_after_duplicate_peer_key() {
        let mut alice = ClientSession::new(
            ClientId::parse("alice").expect("alice"),
            ClientId::parse("bob").expect("bob"),
        );
        let mut bob = ClientSession::new(
            ClientId::parse("bob").expect("bob"),
            ClientId::parse("alice").expect("alice"),
        );
        let alice_key = alice.peer_key_event();

        bob.handle_event(alice_key.clone()).expect("alice key");
        alice.handle_event(bob.peer_key_event()).expect("bob key");
        let event = alice.encrypt_line("hello bob").expect("encrypt");
        bob.handle_event(event.clone()).expect("first decrypt");

        bob.handle_event(alice_key).expect("duplicate peer key");

        assert_eq!(
            bob.handle_event(event),
            Err(ClientSessionError::Crypto(CryptoError::DuplicateNonce))
        );
    }

    #[test]
    fn rejects_changed_peer_key_after_session_ready() {
        let alice = ClientSession::new(
            ClientId::parse("alice").expect("alice"),
            ClientId::parse("bob").expect("bob"),
        );
        let mallory_as_alice = ClientSession::new(
            ClientId::parse("alice").expect("alice"),
            ClientId::parse("bob").expect("bob"),
        );
        let mut bob = ClientSession::new(
            ClientId::parse("bob").expect("bob"),
            ClientId::parse("alice").expect("alice"),
        );

        bob.handle_event(alice.peer_key_event()).expect("alice key");

        assert_eq!(
            bob.handle_event(mallory_as_alice.peer_key_event()),
            Err(ClientSessionError::UnexpectedPeerKey)
        );
    }
}
