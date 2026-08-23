use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use uuid::Uuid;

/// Wire policy for byte fields: base64 strings instead of JSON number arrays.
///
/// Number arrays cost ~2x the bytes and grow with every value; base64 keeps
/// the wire human-inspectable while halving encoded size.
fn serialize_bytes_as_base64<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&BASE64_STANDARD.encode(bytes))
}

fn deserialize_bytes_from_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    BASE64_STANDARD
        .decode(encoded.as_bytes())
        .map_err(serde::de::Error::custom)
}

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
    fn serializes_public_key_as_base64_string() {
        // byte 필드는 와이어 크기를 위해 base64 문자열로 직렬화된다.
        let key = PublicKeyBytes::from_array([7; 32]);

        let encoded = serde_json::to_string(&key).expect("serialize public key");

        assert_eq!(
            encoded,
            format!(
                "\"{}\"",
                base64::engine::general_purpose::STANDARD.encode([7; 32])
            )
        );
        assert!(!encoded.contains('['));
    }

    #[test]
    fn roundtrips_nonce_through_base64() {
        let nonce = NonceBytes::from_array([9; 24]);

        let encoded = serde_json::to_string(&nonce).expect("serialize nonce");
        let decoded: NonceBytes = serde_json::from_str(&encoded).expect("deserialize nonce");

        assert_eq!(decoded, nonce);
    }

    #[test]
    fn roundtrips_ciphertext_through_base64() {
        let ciphertext = Ciphertext::from_bytes(vec![1, 2, 3, 4, 5]);

        let encoded = serde_json::to_string(&ciphertext).expect("serialize ciphertext");
        let decoded: Ciphertext = serde_json::from_str(&encoded).expect("deserialize ciphertext");

        assert_eq!(decoded, ciphertext);
    }

    #[test]
    fn rejects_public_key_with_wrong_decoded_length() {
        let too_short = serde_json::to_string(&"AAAA").expect("encode short payload");

        let err =
            serde_json::from_str::<PublicKeyBytes>(&too_short).expect_err("wrong length must fail");

        assert!(err.to_string().contains("32 bytes"));
    }

    #[test]
    fn rejects_invalid_base64_payload() {
        let err = serde_json::from_str::<Ciphertext>("\"!!!not base64!!!\"")
            .expect_err("invalid base64 must fail");

        assert!(!err.to_string().is_empty());
    }

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKeyBytes([u8; 32]);

impl Serialize for PublicKeyBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_bytes_as_base64(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for PublicKeyBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = deserialize_bytes_from_base64(deserializer)?;
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("public key must decode to exactly 32 bytes"))?;

        Ok(Self(array))
    }
}

impl PublicKeyBytes {
    pub fn from_array(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_array(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NonceBytes([u8; 24]);

impl Serialize for NonceBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_bytes_as_base64(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for NonceBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = deserialize_bytes_from_base64(deserializer)?;
        let array: [u8; 24] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("nonce must decode to exactly 24 bytes"))?;

        Ok(Self(array))
    }
}

impl NonceBytes {
    pub fn from_array(bytes: [u8; 24]) -> Self {
        Self(bytes)
    }

    pub fn as_array(&self) -> &[u8; 24] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext(Vec<u8>);

impl Serialize for Ciphertext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_bytes_as_base64(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for Ciphertext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self(deserialize_bytes_from_base64(deserializer)?))
    }
}

impl Ciphertext {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
