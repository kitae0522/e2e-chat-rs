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
                send_event(&mut writer, &session.peer_key_event()).await?;
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

                        match session.handle_event(event) {
                            Ok(Some(plaintext)) => println!("{plaintext}"),
                            Ok(None) => {}
                            Err(error) => warn!(?error, "session rejected inbound event"),
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
}
