use std::time::Duration;

use chat_core::event::WireEvent;
use chat_core::types::{ClientId, PublicKeyBytes};
use futures::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

#[tokio::test]
async fn relays_peer_key_between_connected_clients() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move { chat_server::ws::serve(listener).await });

    let (mut alice, _) = connect_async(format!("ws://{addr}/ws")).await?;
    let (mut bob, _) = connect_async(format!("ws://{addr}/ws")).await?;
    let alice_id = ClientId::parse("alice")?;
    let bob_id = ClientId::parse("bob")?;

    alice
        .send(Message::Text(
            serde_json::to_string(&WireEvent::ClientHello {
                client_id: alice_id.clone(),
                public_key: PublicKeyBytes::from_array([1; 32]),
            })?
            .into(),
        ))
        .await?;
    bob.send(Message::Text(
        serde_json::to_string(&WireEvent::ClientHello {
            client_id: bob_id.clone(),
            public_key: PublicKeyBytes::from_array([2; 32]),
        })?
        .into(),
    ))
    .await?;

    tokio::time::sleep(Duration::from_millis(50)).await;

    alice
        .send(Message::Text(
            serde_json::to_string(&WireEvent::PeerKey {
                from: alice_id.clone(),
                to: bob_id.clone(),
                public_key: PublicKeyBytes::from_array([1; 32]),
            })?
            .into(),
        ))
        .await?;

    let received = tokio::time::timeout(Duration::from_secs(2), bob.next())
        .await?
        .transpose()?
        .expect("bob receives peer key");
    let received_text = received.into_text()?;
    let received_event: WireEvent = serde_json::from_str(received_text.as_ref())?;

    match received_event {
        WireEvent::PeerKey { from, to, .. } => {
            assert_eq!(from, alice_id);
            assert_eq!(to, bob_id);
        }
        other => panic!("expected peer key event, got {other:?}"),
    }

    server.abort();
    Ok(())
}
