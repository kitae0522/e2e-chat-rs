use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use axum::Router;
use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::IntoResponse;
use axum::routing::get;
use chat_core::event::WireEvent;
use chat_core::types::ClientId;
use futures::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, mpsc};

use crate::router::{InMemoryRouter, RouterError};

#[derive(Clone, Default)]
struct ServerState {
    router: Arc<Mutex<InMemoryRouter>>,
    connections: Arc<Mutex<HashMap<ClientId, mpsc::UnboundedSender<WireEvent>>>>,
}

pub async fn serve(listener: TcpListener) -> anyhow::Result<()> {
    let state = ServerState::default();
    let app = Router::new()
        .route("/ws", get(ws_handler))
        .with_state(state);

    axum::serve(listener, app)
        .await
        .context("websocket server failed")
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<ServerState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: ServerState) {
    let (mut socket_sender, mut socket_receiver) = socket.split();
    let Some(client_id) = read_client_hello(&mut socket_receiver).await else {
        return;
    };

    let (event_sender, mut event_receiver) = mpsc::unbounded_channel();
    if register_client(&state, client_id.clone(), event_sender.clone())
        .await
        .is_err()
    {
        return;
    }

    let writer = tokio::spawn(async move {
        while let Some(event) = event_receiver.recv().await {
            let Ok(text) = serde_json::to_string(&event) else {
                continue;
            };

            if socket_sender
                .send(Message::Text(text.into()))
                .await
                .is_err()
            {
                break;
            }
        }
    });

    while let Some(message) = socket_receiver.next().await {
        let Ok(Message::Text(text)) = message else {
            continue;
        };
        let Ok(event) = serde_json::from_str::<WireEvent>(&text) else {
            continue;
        };

        if let Err(error) = route_and_flush(&state, &client_id, event.clone()).await
            && should_report_routing_error(&event, &error)
        {
            let _ = event_sender.send(WireEvent::Error {
                code: format!("{error:?}"),
                message: format!("routing failed: {error:?}"),
            });
        }
    }

    unregister_client(&state, &client_id).await;
    writer.abort();
}

async fn read_client_hello(
    socket_receiver: &mut futures::stream::SplitStream<WebSocket>,
) -> Option<ClientId> {
    while let Some(message) = socket_receiver.next().await {
        let Ok(Message::Text(text)) = message else {
            continue;
        };
        let Ok(WireEvent::ClientHello { client_id, .. }) = serde_json::from_str::<WireEvent>(&text)
        else {
            continue;
        };

        return Some(client_id);
    }

    None
}

async fn register_client(
    state: &ServerState,
    client_id: ClientId,
    sender: mpsc::UnboundedSender<WireEvent>,
) -> Result<(), ()> {
    if state
        .router
        .lock()
        .await
        .connect(client_id.clone())
        .is_err()
    {
        return Err(());
    }

    state.connections.lock().await.insert(client_id, sender);
    Ok(())
}

async fn unregister_client(state: &ServerState, client_id: &ClientId) {
    state.connections.lock().await.remove(client_id);
    let _ = state.router.lock().await.disconnect(client_id);
}

async fn route_and_flush(
    state: &ServerState,
    connection_id: &ClientId,
    event: WireEvent,
) -> Result<(), RouterError> {
    state.router.lock().await.route(connection_id, event)?;

    flush_outboxes(state).await;
    Ok(())
}

fn should_report_routing_error(event: &WireEvent, error: &RouterError) -> bool {
    !matches!(
        (event, error),
        (WireEvent::PeerKey { .. }, RouterError::UnknownRecipient)
    )
}

async fn flush_outboxes(state: &ServerState) {
    let senders = state.connections.lock().await.clone();
    let deliveries = {
        let mut router = state.router.lock().await;
        collect_outbox_deliveries(&mut router, &senders)
    };

    send_outbox_deliveries(deliveries);
}

struct OutboxDelivery {
    sender: mpsc::UnboundedSender<WireEvent>,
    events: Vec<WireEvent>,
}

fn collect_outbox_deliveries(
    router: &mut InMemoryRouter,
    senders: &HashMap<ClientId, mpsc::UnboundedSender<WireEvent>>,
) -> Vec<OutboxDelivery> {
    senders
        .iter()
        .filter_map(|(client_id, sender)| {
            let events = router.drain_outbox(client_id);
            if events.is_empty() {
                None
            } else {
                Some(OutboxDelivery {
                    sender: sender.clone(),
                    events,
                })
            }
        })
        .collect()
}

fn send_outbox_deliveries(deliveries: Vec<OutboxDelivery>) {
    for delivery in deliveries {
        for event in delivery.events {
            let _ = delivery.sender.send(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router::RouterError;
    use chat_core::event::EncryptedEnvelope;
    use chat_core::types::{Ciphertext, MessageId, NonceBytes, PublicKeyBytes};

    #[test]
    fn suppresses_unknown_recipient_error_for_peer_key_retry() {
        let event = WireEvent::PeerKey {
            from: ClientId::parse("alice").expect("alice"),
            to: ClientId::parse("bob").expect("bob"),
            public_key: PublicKeyBytes::from_array([1; 32]),
        };

        assert!(!should_report_routing_error(
            &event,
            &RouterError::UnknownRecipient
        ));
    }

    #[test]
    fn reports_unknown_recipient_error_for_encrypted_message() {
        let event = WireEvent::EncryptedMessage(EncryptedEnvelope {
            sender: ClientId::parse("alice").expect("alice"),
            recipient: ClientId::parse("bob").expect("bob"),
            message_id: MessageId::new(),
            nonce: NonceBytes::from_array([7; 24]),
            ciphertext: Ciphertext::from_bytes(vec![1, 2, 3]),
        });

        assert!(should_report_routing_error(
            &event,
            &RouterError::UnknownRecipient
        ));
    }

    #[test]
    fn collect_outbox_deliveries_drains_before_sending() {
        let mut router = InMemoryRouter::default();
        let alice = ClientId::parse("alice").expect("alice");
        let bob = ClientId::parse("bob").expect("bob");
        let message_id = MessageId::new();
        let envelope = EncryptedEnvelope {
            sender: alice.clone(),
            recipient: bob.clone(),
            message_id,
            nonce: NonceBytes::from_array([9; 24]),
            ciphertext: Ciphertext::from_bytes(vec![1, 2, 3]),
        };
        let (alice_sender, mut alice_receiver) = mpsc::unbounded_channel();
        let (bob_sender, mut bob_receiver) = mpsc::unbounded_channel();
        let senders = HashMap::from([(alice.clone(), alice_sender), (bob.clone(), bob_sender)]);

        router.connect(alice.clone()).expect("connect alice");
        router.connect(bob).expect("connect bob");
        router
            .route(&alice, WireEvent::EncryptedMessage(envelope.clone()))
            .expect("route encrypted message");

        let deliveries = collect_outbox_deliveries(&mut router, &senders);

        assert!(alice_receiver.try_recv().is_err());
        assert!(bob_receiver.try_recv().is_err());

        send_outbox_deliveries(deliveries);

        assert_eq!(
            alice_receiver.try_recv().expect("alice receives ack"),
            WireEvent::Ack { message_id }
        );
        assert_eq!(
            bob_receiver.try_recv().expect("bob receives message"),
            WireEvent::EncryptedMessage(envelope)
        );
    }
}
