use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Maximum byte length of a `ClientId` on the wire.
const CLIENT_ID_MAX_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TypeError {
    #[error("client id cannot be empty")]
    EmptyClientId,
    #[error("client id exceeds {CLIENT_ID_MAX_LEN} characters")]
    ClientIdTooLong,
    #[error("client id may only contain ASCII letters, digits, '-', '_', and '.'")]
    ClientIdInvalidCharacter,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ClientId(String);

impl ClientId {
    pub fn parse(value: impl Into<String>) -> Result<Self, TypeError> {
        // ClientId is a protocol-sensitive value: it routes envelopes and binds
        // AAD. Validation rejects rather than normalizes so the id on the wire
        // always matches the id every peer saw.
        let value = value.into();
        if value.is_empty() {
            return Err(TypeError::EmptyClientId);
        }
        if value.chars().count() > CLIENT_ID_MAX_LEN {
            return Err(TypeError::ClientIdTooLong);
        }
        if !value.chars().all(is_allowed_client_id_char) {
            return Err(TypeError::ClientIdInvalidCharacter);
        }

        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_allowed_client_id_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')
}

impl TryFrom<String> for ClientId {
    type Error = TypeError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<ClientId> for String {
    fn from(value: ClientId) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_alphanumeric_and_separator_ids() {
        for id in ["a", "alice", "user-1", "user_2", "user.3", "A1_b2.c3"] {
            ClientId::parse(id).unwrap_or_else(|e| panic!("{id} should be accepted: {e:?}"));
        }
    }

    #[test]
    fn rejects_empty_client_id() {
        assert_eq!(ClientId::parse(""), Err(TypeError::EmptyClientId));
    }

    #[test]
    fn rejects_ids_with_whitespace_instead_of_trimming() {
        // wire에 실리는 식별자는 자동 정규화하지 않고 거부한다.
        assert_eq!(
            ClientId::parse(" alice"),
            Err(TypeError::ClientIdInvalidCharacter)
        );
        assert_eq!(
            ClientId::parse("alice "),
            Err(TypeError::ClientIdInvalidCharacter)
        );
        assert_eq!(
            ClientId::parse("a lice"),
            Err(TypeError::ClientIdInvalidCharacter)
        );
    }

    #[test]
    fn rejects_control_and_non_ascii_characters() {
        assert_eq!(
            ClientId::parse("alice\n"),
            Err(TypeError::ClientIdInvalidCharacter)
        );
        assert_eq!(
            ClientId::parse("\u{7f}"),
            Err(TypeError::ClientIdInvalidCharacter)
        );
        assert_eq!(
            ClientId::parse("앨리스"),
            Err(TypeError::ClientIdInvalidCharacter)
        );
    }

    #[test]
    fn rejects_client_id_longer_than_limit() {
        let at_limit = "a".repeat(64);
        let over_limit = "a".repeat(65);

        ClientId::parse(at_limit).expect("64 chars should be accepted");

        assert_eq!(ClientId::parse(over_limit), Err(TypeError::ClientIdTooLong));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId(Uuid);

impl MessageId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for MessageId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyBytes([u8; 32]);

impl PublicKeyBytes {
    pub fn from_array(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_array(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NonceBytes([u8; 24]);

impl NonceBytes {
    pub fn from_array(bytes: [u8; 24]) -> Self {
        Self(bytes)
    }

    pub fn as_array(&self) -> &[u8; 24] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ciphertext(Vec<u8>);

impl Ciphertext {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
