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

use crate::router::InMemoryRouter;

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

        if let Err(error) = route_and_flush(&state, &client_id, event).await {
            let _ = event_sender.send(WireEvent::Error {
                code: format!("{error:?}"),
                message: "event routing failed".to_owned(),
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
) -> Result<(), ()> {
    state
        .router
        .lock()
        .await
        .route(connection_id, event)
        .map_err(|_| ())?;

    flush_outboxes(state).await;
    Ok(())
}

async fn flush_outboxes(state: &ServerState) {
    let client_ids: Vec<ClientId> = state.connections.lock().await.keys().cloned().collect();

    for client_id in client_ids {
        let events = state.router.lock().await.drain_outbox(&client_id);
        if events.is_empty() {
            continue;
        }

        let sender = state.connections.lock().await.get(&client_id).cloned();
        if let Some(sender) = sender {
            for event in events {
                let _ = sender.send(event);
            }
        }
    }
}
