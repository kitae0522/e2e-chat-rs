#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

use anyhow::{Context, Result, anyhow};
use chat_client::session::{ClientSession, ClientSessionError};
use chat_core::event::WireEvent;
use chat_core::types::ClientId;
use clap::Parser;
use futures::{Sink, SinkExt, StreamExt};
use tokio::io::{self, AsyncBufReadExt, BufReader};
use tokio::time::{self, Duration};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::warn;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Clone, PartialEq, Eq, Parser)]
#[command(name = "chat-client")]
struct Args {
    #[arg(long, default_value = "ws://127.0.0.1:3000/ws")]
    server: String,

    #[arg(long)]
    id: String,

    #[arg(long)]
    peer: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    run(Args::parse()).await
}

async fn run(args: Args) -> Result<()> {
    let local_id = ClientId::parse(args.id).context("parse local client id")?;
    let peer_id = ClientId::parse(args.peer).context("parse peer client id")?;
    let mut session = ClientSession::new(local_id, peer_id);

    let (socket, _) = connect_async(args.server.as_str())
        .await
        .with_context(|| format!("connect websocket {}", args.server))?;
    let (mut writer, mut reader) = socket.split();

    send_event(&mut writer, &session.client_hello()).await?;
    send_event(&mut writer, &session.peer_key_event()).await?;

    let stdin = BufReader::new(io::stdin());
    let mut lines = stdin.lines();
    let mut peer_key_retry = time::interval(Duration::from_secs(1));

    loop {
        tokio::select! {
            _ = peer_key_retry.tick() => {
                if should_retry_peer_key(session.is_ready()) {
                    send_event(&mut writer, &session.peer_key_event()).await?;
                }
            }
            line = lines.next_line() => {
                let Some(line) = line.context("read stdin line")? else {
                    break;
                };

                if line.is_empty() {
                    continue;
                }

                match session.encrypt_line(&line) {
                    Ok(event) => send_event(&mut writer, &event).await?,
                    Err(ClientSessionError::MissingPeerKey) => {
                        eprintln!("peer key not received yet");
                    }
                    Err(error) => {
                        return Err(anyhow!("encrypt outbound message: {error:?}"));
                    }
                }
            }
            message = reader.next() => {
                let Some(message) = message else {
                    break;
                };
                let message = message.context("read websocket message")?;

                match message {
                    Message::Text(payload) => {
                        let event = serde_json::from_str::<WireEvent>(payload.as_ref())
                            .context("decode websocket event")?;
                        let status = control_status(&event);
                        let reply_peer_key = needs_peer_key_reply(session.is_ready(), &event);

                        match session.handle_event(event) {
                            Ok(Some(plaintext)) => println!("{plaintext}"),
                            Ok(None) => {
                                if let Some(status) = status {
                                    eprintln!("{status}");
                                }
                            }
                            Err(error) => {
                                warn!(?error, "session rejected inbound event");
                                continue;
                            }
                        }

                        // 초기 PeerKey가 유실된 피어를 살리기 위해,
                        // 세션 ready로 전환되는 최초 수신에 자신의 키로 응답한다.
                        if reply_peer_key {
                            send_event(&mut writer, &session.peer_key_event()).await?;
                        }
                    }
                    Message::Close(_) => break,
                    Message::Binary(_) | Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
                }
            }
        }
    }

    Ok(())
}

async fn send_event<S>(sink: &mut S, event: &WireEvent) -> Result<()>
where
    S: Sink<Message> + Unpin,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let payload = serde_json::to_string(event).context("encode websocket event")?;
    sink.send(Message::Text(payload.into()))
        .await
        .context("send websocket event")?;
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

fn should_retry_peer_key(is_ready: bool) -> bool {
    !is_ready
}

fn needs_peer_key_reply(was_ready: bool, event: &WireEvent) -> bool {
    !was_ready && matches!(event, WireEvent::PeerKey { .. })
}

fn control_status(event: &WireEvent) -> Option<String> {
    match event {
        WireEvent::Ack { .. } => Some("message delivered to relay".to_owned()),
        WireEvent::Error { message, .. } => Some(format!("relay error: {message}")),
        WireEvent::ClientHello { .. }
        | WireEvent::PeerKey { .. }
        | WireEvent::EncryptedMessage(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_required_cli_args() {
        let args = Args::parse_from([
            "chat-client",
            "--server",
            "ws://127.0.0.1:3000/ws",
            "--id",
            "alice",
            "--peer",
            "bob",
        ]);

        assert_eq!(args.server, "ws://127.0.0.1:3000/ws");
        assert_eq!(args.id, "alice");
        assert_eq!(args.peer, "bob");
    }

    #[test]
    fn describes_ack_as_relay_delivery_status() {
        let status = control_status(&WireEvent::Ack {
            message_id: chat_core::types::MessageId::new(),
        });

        assert_eq!(status, Some("message delivered to relay".to_owned()));
    }

    #[test]
    fn retries_peer_key_only_while_session_is_not_ready() {
        // ready 후 재전송을 멈춰야 불필요한 트래픽이 사라진다.
        assert!(should_retry_peer_key(false));
        assert!(!should_retry_peer_key(true));
    }

    #[test]
    fn replies_with_own_peer_key_to_first_inbound_peer_key() {
        // 초기 PeerKey가 유실된 피어를 살리기 위해,
        // ready로 전환되는 최초 수신에만 자신의 키로 응답한다.
        let peer_key = WireEvent::PeerKey {
            from: ClientId::parse("bob").expect("bob"),
            to: ClientId::parse("alice").expect("alice"),
            public_key: chat_core::types::PublicKeyBytes::from_array([3; 32]),
        };
        let ack = WireEvent::Ack {
            message_id: chat_core::types::MessageId::new(),
        };

        assert!(needs_peer_key_reply(false, &peer_key));
        assert!(!needs_peer_key_reply(true, &peer_key));
        assert!(!needs_peer_key_reply(false, &ack));
    }

    #[test]
    fn describes_relay_error_status() {
        let status = control_status(&WireEvent::Error {
            code: chat_core::event::RelayErrorCode::UnknownRecipient,
            message: "event routing failed".to_owned(),
        });

        assert_eq!(status, Some("relay error: event routing failed".to_owned()));
    }

    #[test]
    fn describes_relay_error_with_unknown_code_from_newer_peer() {
        let status = control_status(&WireEvent::Error {
            code: chat_core::event::RelayErrorCode::Other("rekey_required".to_owned()),
            message: "rekey needed".to_owned(),
        });

        assert_eq!(status, Some("relay error: rekey needed".to_owned()));
    }
}
