use std::sync::{Arc, Mutex};
use std::time::Duration;

use chat_core::crypto::{CryptoSession, KeyPair};
use chat_core::event::WireEvent;
use chat_core::service::{EventHook, MessageRouter, RouterError};
use chat_core::types::{Ciphertext, ClientId, MessageId, NonceBytes, PublicKeyBytes};
use chat_server::ws::WsServer;
use futures::{Sink, SinkExt, Stream, StreamExt};
use tokio::net::TcpListener;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

#[tokio::test]
async fn relays_peer_key_between_connected_clients() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move { chat_server::ws::serve(listener).await });

    let (mut alice, _) = connect_async(format!("ws://{addr}/ws")).await?;
    let (mut bob, _) = connect_async(format!("ws://{addr}/ws")).await?;
    let alice_id = ClientId::parse("alice")?;
    let bob_id = ClientId::parse("bob")?;

    send_event(
        &mut alice,
        &WireEvent::ClientHello {
            client_id: alice_id.clone(),
            public_key: PublicKeyBytes::from_array([1; 32]),
        },
    )
    .await?;
    send_event(
        &mut bob,
        &WireEvent::ClientHello {
            client_id: bob_id.clone(),
            public_key: PublicKeyBytes::from_array([2; 32]),
        },
    )
    .await?;

    tokio::time::sleep(Duration::from_millis(50)).await;

    send_event(
        &mut alice,
        &WireEvent::PeerKey {
            from: alice_id.clone(),
            to: bob_id.clone(),
            public_key: PublicKeyBytes::from_array([1; 32]),
        },
    )
    .await?;

    let received_event = receive_event(&mut bob).await?;

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

#[tokio::test]
async fn relays_encrypted_message_and_ack_between_connected_clients() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move { chat_server::ws::serve(listener).await });

    let (mut alice, _) = connect_async(format!("ws://{addr}/ws")).await?;
    let (mut bob, _) = connect_async(format!("ws://{addr}/ws")).await?;
    let alice_id = ClientId::parse("alice")?;
    let bob_id = ClientId::parse("bob")?;
    let alice_keypair = KeyPair::generate();
    let bob_keypair = KeyPair::generate();

    send_event(
        &mut alice,
        &WireEvent::ClientHello {
            client_id: alice_id.clone(),
            public_key: alice_keypair.public_key(),
        },
    )
    .await?;
    send_event(
        &mut bob,
        &WireEvent::ClientHello {
            client_id: bob_id.clone(),
            public_key: bob_keypair.public_key(),
        },
    )
    .await?;

    tokio::time::sleep(Duration::from_millis(50)).await;

    send_event(
        &mut alice,
        &WireEvent::PeerKey {
            from: alice_id.clone(),
            to: bob_id.clone(),
            public_key: alice_keypair.public_key(),
        },
    )
    .await?;
    send_event(
        &mut bob,
        &WireEvent::PeerKey {
            from: bob_id.clone(),
            to: alice_id.clone(),
            public_key: bob_keypair.public_key(),
        },
    )
    .await?;

    assert!(matches!(
        receive_event(&mut bob).await?,
        WireEvent::PeerKey { .. }
    ));
    assert!(matches!(
        receive_event(&mut alice).await?,
        WireEvent::PeerKey { .. }
    ));

    let mut alice_session = CryptoSession::new(
        &alice_keypair,
        bob_keypair.public_key(),
        alice_id.clone(),
        bob_id.clone(),
    );
    let mut bob_session = CryptoSession::new(
        &bob_keypair,
        alice_keypair.public_key(),
        bob_id.clone(),
        alice_id,
    );
    let message_id = MessageId::new();
    let encrypted = alice_session.encrypt(message_id, b"hello bob")?;

    send_event(&mut alice, &WireEvent::EncryptedMessage(encrypted.clone())).await?;

    assert_eq!(
        receive_event(&mut alice).await?,
        WireEvent::Ack { message_id }
    );
    let received = receive_event(&mut bob).await?;
    let WireEvent::EncryptedMessage(envelope) = received else {
        panic!("expected encrypted message event, got {received:?}");
    };
    let plaintext = bob_session.decrypt(&envelope)?;

    assert_eq!(envelope, encrypted);
    assert_eq!(plaintext, b"hello bob");

    server.abort();
    Ok(())
}

#[tokio::test]
async fn serves_relay_through_default_builder() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move { WsServer::new(listener).run().await });

    let (mut alice, _) = connect_async(format!("ws://{addr}/ws")).await?;
    let (mut bob, _) = connect_async(format!("ws://{addr}/ws")).await?;
    let alice_id = ClientId::parse("alice")?;
    let bob_id = ClientId::parse("bob")?;

    send_event(
        &mut alice,
        &WireEvent::ClientHello {
            client_id: alice_id.clone(),
            public_key: PublicKeyBytes::from_array([1; 32]),
        },
    )
    .await?;
    send_event(
        &mut bob,
        &WireEvent::ClientHello {
            client_id: bob_id.clone(),
            public_key: PublicKeyBytes::from_array([2; 32]),
        },
    )
    .await?;

    tokio::time::sleep(Duration::from_millis(50)).await;

    send_event(
        &mut alice,
        &WireEvent::PeerKey {
            from: alice_id.clone(),
            to: bob_id.clone(),
            public_key: PublicKeyBytes::from_array([1; 32]),
        },
    )
    .await?;

    let received_event = receive_event(&mut bob).await?;

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

#[derive(Default, Clone)]
struct SharedHook {
    calls: Arc<Mutex<Vec<&'static str>>>,
}

impl EventHook for SharedHook {
    fn on_connect(&mut self, _client_id: &ClientId) {
        self.calls.lock().expect("record connect").push("connect");
    }

    fn on_disconnect(&mut self, _client_id: &ClientId) {
        self.calls
            .lock()
            .expect("record disconnect")
            .push("disconnect");
    }

    fn on_route_accepted(&mut self, _connection_id: &ClientId, _event: &WireEvent) {
        self.calls
            .lock()
            .expect("record route_accepted")
            .push("route_accepted");
    }
}

#[tokio::test]
async fn builder_injects_custom_hook_observing_lifecycle() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let hook = SharedHook::default();
    let server =
        tokio::spawn(async move { WsServer::new(listener).with_hook(hook.clone()).run().await });

    let (mut alice, _) = connect_async(format!("ws://{addr}/ws")).await?;
    send_event(
        &mut alice,
        &WireEvent::ClientHello {
            client_id: ClientId::parse("alice")?,
            public_key: PublicKeyBytes::from_array([1; 32]),
        },
    )
    .await?;
    tokio::time::sleep(Duration::from_millis(50)).await;

    send_event(
        &mut alice,
        &WireEvent::PeerKey {
            from: ClientId::parse("alice")?,
            to: ClientId::parse("bob")?,
            public_key: PublicKeyBytes::from_array([1; 32]),
        },
    )
    .await?;
    tokio::time::sleep(Duration::from_millis(50)).await;

    drop(alice);
    wait_for_calls(&hook, &["connect", "route_accepted", "disconnect"]).await;

    server.abort();
    Ok(())
}

struct RejectingRouter;

impl MessageRouter for RejectingRouter {
    fn connect(&mut self, _client_id: ClientId) -> Result<(), RouterError> {
        Ok(())
    }

    fn disconnect(&mut self, _client_id: &ClientId) -> Result<(), RouterError> {
        Ok(())
    }

    fn route(&mut self, _connection_id: &ClientId, _event: WireEvent) -> Result<(), RouterError> {
        Err(RouterError::UnsupportedEvent)
    }

    fn drain_outbox(&mut self, _client_id: &ClientId) -> Vec<WireEvent> {
        Vec::new()
    }
}

#[tokio::test]
async fn builder_injects_custom_router_and_reports_rejection() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        WsServer::new(listener)
            .with_router(RejectingRouter)
            .run()
            .await
    });

    let (mut alice, _) = connect_async(format!("ws://{addr}/ws")).await?;
    let alice_id = ClientId::parse("alice")?;
    let bob_id = ClientId::parse("bob")?;

    send_event(
        &mut alice,
        &WireEvent::ClientHello {
            client_id: alice_id.clone(),
            public_key: PublicKeyBytes::from_array([1; 32]),
        },
    )
    .await?;

    send_event(
        &mut alice,
        &WireEvent::EncryptedMessage(chat_core::event::EncryptedEnvelope {
            sender: alice_id,
            recipient: bob_id,
            message_id: MessageId::new(),
            nonce: NonceBytes::from_array([7; 24]),
            ciphertext: Ciphertext::from_bytes(vec![1, 2, 3]),
        }),
    )
    .await?;

    let received_event = receive_event(&mut alice).await?;

    assert!(matches!(received_event, WireEvent::Error { .. }));

    server.abort();
    Ok(())
}

async fn wait_for_calls(hook: &SharedHook, expected: &[&'static str]) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        {
            let calls = hook.calls.lock().expect("read calls");
            if calls.as_slice() == expected {
                return;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "hook calls did not match {expected:?} in time"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn send_event<S>(socket: &mut S, event: &WireEvent) -> anyhow::Result<()>
where
    S: Sink<Message> + Unpin,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    socket
        .send(Message::Text(serde_json::to_string(event)?.into()))
        .await?;
    Ok(())
}

async fn receive_event<S>(socket: &mut S) -> anyhow::Result<WireEvent>
where
    S: Stream<Item = Result<Message, WsError>> + Unpin,
{
    let received = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await?
        .transpose()?
        .expect("client receives event");
    let received_text = received.into_text()?;

    Ok(serde_json::from_str(received_text.as_ref())?)
}
