use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::types::{Ciphertext, ClientId, MessageId, NonceBytes, PublicKeyBytes, RekeyId};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    pub sender: ClientId,
    pub recipient: ClientId,
    pub message_id: MessageId,
    /// Session key generation this envelope was encrypted under.
    /// Bound into the AEAD associated data; receivers accept the current
    /// and immediately previous epoch during a rekey transition.
    pub epoch: u32,
    pub nonce: NonceBytes,
    pub ciphertext: Ciphertext,
}

/// Machine-readable code carried by `WireEvent::Error`.
///
/// Known codes serialize as snake_case strings. Codes from newer peers that
/// this version does not know are preserved verbatim as [`RelayErrorCode::Other`]
/// so error events survive protocol evolution instead of failing to parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayErrorCode {
    SenderMismatch,
    UnknownRecipient,
    UnsupportedEvent,
    ClientNotConnected,
    ClientAlreadyConnected,
    ConnectDenied,
    Other(String),
}

impl RelayErrorCode {
    fn as_wire_str(&self) -> &str {
        match self {
            Self::SenderMismatch => "sender_mismatch",
            Self::UnknownRecipient => "unknown_recipient",
            Self::UnsupportedEvent => "unsupported_event",
            Self::ClientNotConnected => "client_not_connected",
            Self::ClientAlreadyConnected => "client_already_connected",
            Self::ConnectDenied => "connect_denied",
            Self::Other(raw) => raw,
        }
    }

    fn from_wire(raw: &str) -> Self {
        match raw {
            "sender_mismatch" => Self::SenderMismatch,
            "unknown_recipient" => Self::UnknownRecipient,
            "unsupported_event" => Self::UnsupportedEvent,
            "client_not_connected" => Self::ClientNotConnected,
            "client_already_connected" => Self::ClientAlreadyConnected,
            "connect_denied" => Self::ConnectDenied,
            other => Self::Other(other.to_owned()),
        }
    }
}

impl Serialize for RelayErrorCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_wire_str())
    }
}

impl<'de> Deserialize<'de> for RelayErrorCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;

        Ok(Self::from_wire(&raw))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WireEvent {
    ClientHello {
        client_id: ClientId,
        public_key: PublicKeyBytes,
    },
    PeerKey {
        from: ClientId,
        to: ClientId,
        public_key: PublicKeyBytes,
    },
    EncryptedMessage(EncryptedEnvelope),
    Ack {
        message_id: MessageId,
    },
    Error {
        code: RelayErrorCode,
        message: String,
    },
}

/// Decrypted payload of an `EncryptedEnvelope`.
///
/// Chat text and session control messages (rekey) share the same encrypted
/// channel so control messages inherit the session's authentication — a
/// network attacker cannot forge a rekey without the current session key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionPayload {
    Chat {
        text: String,
    },
    RekeyRequest {
        rekey_id: RekeyId,
        ephemeral_public_key: PublicKeyBytes,
    },
    RekeyResponse {
        rekey_id: RekeyId,
        ephemeral_public_key: PublicKeyBytes,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Ciphertext, ClientId, MessageId, NonceBytes, PublicKeyBytes, TypeError};

    #[test]
    fn roundtrips_session_payload_with_base64_rekey_id() {
        let payload = SessionPayload::RekeyRequest {
            rekey_id: RekeyId::generate(),
            ephemeral_public_key: PublicKeyBytes::from_array([3; 32]),
        };

        let encoded = serde_json::to_string(&payload).expect("serialize payload");
        let decoded: SessionPayload = serde_json::from_str(&encoded).expect("deserialize payload");

        assert_eq!(decoded, payload);
        assert!(!encoded.contains('['));
    }

    #[test]
    fn serializes_encrypted_message_without_plaintext_field() {
        let event = WireEvent::EncryptedMessage(EncryptedEnvelope {
            sender: ClientId::parse("alice").expect("valid sender"),
            recipient: ClientId::parse("bob").expect("valid recipient"),
            message_id: MessageId::new(),
            epoch: 0,
            nonce: NonceBytes::from_array([7; 24]),
            ciphertext: Ciphertext::from_bytes(vec![1, 2, 3, 4]),
        });

        let encoded = serde_json::to_string(&event).expect("serialize event");

        assert!(encoded.contains("\"type\":\"encrypted_message\""));
        assert!(!encoded.contains("plaintext"));
    }

    #[test]
    fn serializes_error_code_as_snake_case_contract() {
        let event = WireEvent::Error {
            code: RelayErrorCode::UnknownRecipient,
            message: "recipient is not connected".to_owned(),
        };

        let encoded = serde_json::to_string(&event).expect("serialize error event");

        assert!(encoded.contains("\"code\":\"unknown_recipient\""));
    }

    #[test]
    fn preserves_unknown_error_codes_from_newer_peers() {
        // 구버전 클라이언트도 새 코드를 받으면 이벤트를 유지해야 한다.
        let encoded = r#"{"type":"error","code":"rekey_required","message":"rekey"}"#;

        let event: WireEvent = serde_json::from_str(encoded).expect("deserialize error event");

        assert_eq!(
            event,
            WireEvent::Error {
                code: RelayErrorCode::Other("rekey_required".to_owned()),
                message: "rekey".to_owned(),
            }
        );
    }

    #[test]
    fn serializes_other_error_code_verbatim() {
        let event = WireEvent::Error {
            code: RelayErrorCode::Other("rekey_required".to_owned()),
            message: "rekey".to_owned(),
        };

        let encoded = serde_json::to_string(&event).expect("serialize error event");

        assert!(encoded.contains("\"code\":\"rekey_required\""));
    }

    #[test]
    fn rejects_blank_client_id() {
        let err = ClientId::parse(" ").expect_err("blank id must fail");

        assert_eq!(err, TypeError::ClientIdInvalidCharacter);
    }

    #[test]
    fn peer_key_event_binds_sender_and_recipient() {
        let event = WireEvent::PeerKey {
            from: ClientId::parse("alice").expect("valid sender"),
            to: ClientId::parse("bob").expect("valid recipient"),
            public_key: PublicKeyBytes::from_array([9; 32]),
        };

        let encoded = serde_json::to_string(&event).expect("serialize event");

        assert!(encoded.contains("\"from\":\"alice\""));
        assert!(encoded.contains("\"to\":\"bob\""));
    }
}
