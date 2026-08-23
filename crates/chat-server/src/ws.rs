use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use axum::Router as AxumRouter;
use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::IntoResponse;
use axum::routing::get;
use chat_core::event::WireEvent;
use chat_core::service::{
    AuthError, AuthProvider, EventHook, MessageRouter, NoopAuthProvider, NoopEventHook, RouterError,
};
use chat_core::types::ClientId;
use futures::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, mpsc};

use crate::router::InMemoryRouter;

struct ServerState<R, H, A> {
    router: Arc<Mutex<R>>,
    hook: Arc<Mutex<H>>,
    auth: Arc<Mutex<A>>,
    connections: Arc<Mutex<HashMap<ClientId, mpsc::UnboundedSender<WireEvent>>>>,
}

impl<R, H, A> ServerState<R, H, A> {
    fn new(router: R, hook: H, auth: A) -> Self {
        Self {
            router: Arc::new(Mutex::new(router)),
            hook: Arc::new(Mutex::new(hook)),
            auth: Arc::new(Mutex::new(auth)),
            connections: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<R, H, A> Clone for ServerState<R, H, A> {
    fn clone(&self) -> Self {
        Self {
            router: Arc::clone(&self.router),
            hook: Arc::clone(&self.hook),
            auth: Arc::clone(&self.auth),
            connections: Arc::clone(&self.connections),
        }
    }
}

pub async fn serve(listener: TcpListener) -> anyhow::Result<()> {
    WsServer::new(listener).run().await
}

pub async fn serve_with_router<R>(listener: TcpListener, router: R) -> anyhow::Result<()>
where
    R: MessageRouter + Send + 'static,
{
    WsServer::new(listener).with_router(router).run().await
}

pub async fn serve_with_router_and_hook<R, H>(
    listener: TcpListener,
    router: R,
    hook: H,
) -> anyhow::Result<()>
where
    R: MessageRouter + Send + 'static,
    H: EventHook + Send + 'static,
{
    WsServer::new(listener)
        .with_router(router)
        .with_hook(hook)
        .run()
        .await
}

/// Builder for the WebSocket relay server.
///
/// Defaults to [`InMemoryRouter`], [`NoopEventHook`], and [`NoopAuthProvider`];
/// extension points such as routers, hooks, auth providers, and future storage
/// boundaries are injected by chaining `with_*` methods instead of growing
/// `serve*` function signatures.
pub struct WsServer<R = InMemoryRouter, H = NoopEventHook, A = NoopAuthProvider> {
    listener: TcpListener,
    router: R,
    hook: H,
    auth: A,
}

impl WsServer {
    pub fn new(listener: TcpListener) -> Self {
        Self {
            listener,
            router: InMemoryRouter::default(),
            hook: NoopEventHook,
            auth: NoopAuthProvider,
        }
    }
}

impl<R, H, A> WsServer<R, H, A> {
    pub fn with_router<R2>(self, router: R2) -> WsServer<R2, H, A>
    where
        R2: MessageRouter,
    {
        WsServer {
            listener: self.listener,
            router,
            hook: self.hook,
            auth: self.auth,
        }
    }

    pub fn with_hook<H2>(self, hook: H2) -> WsServer<R, H2, A>
    where
        H2: EventHook,
    {
        WsServer {
            listener: self.listener,
            router: self.router,
            hook,
            auth: self.auth,
        }
    }

    pub fn with_auth_provider<A2>(self, auth: A2) -> WsServer<R, H, A2>
    where
        A2: AuthProvider,
    {
        WsServer {
            listener: self.listener,
            router: self.router,
            hook: self.hook,
            auth,
        }
    }

    pub async fn run(self) -> anyhow::Result<()>
    where
        R: MessageRouter + Send + 'static,
        H: EventHook + Send + 'static,
        A: AuthProvider + Send + 'static,
    {
        let state = ServerState::new(self.router, self.hook, self.auth);
        let app = AxumRouter::new()
            .route("/ws", get(ws_handler))
            .with_state(state);

        axum::serve(self.listener, app)
            .await
            .context("websocket server failed")
    }
}

async fn ws_handler<R, H, A>(
    ws: WebSocketUpgrade,
    State(state): State<ServerState<R, H, A>>,
) -> impl IntoResponse
where
    R: MessageRouter + Send + 'static,
    H: EventHook + Send + 'static,
    A: AuthProvider + Send + 'static,
{
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket<R, H, A>(socket: WebSocket, state: ServerState<R, H, A>)
where
    R: MessageRouter + Send + 'static,
    H: EventHook + Send + 'static,
    A: AuthProvider + Send + 'static,
{
    let (mut socket_sender, mut socket_receiver) = socket.split();
    let Some(client_id) = read_client_hello(&mut socket_receiver).await else {
        return;
    };

    if let Err(error) = state.auth.lock().await.authorize_connect(&client_id) {
        reject_connection(&mut socket_sender, &error).await;
        return;
    }

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

/// Sends an Error wire event for denied connections before closing the socket.
async fn reject_connection(
    socket_sender: &mut futures::stream::SplitSink<WebSocket, Message>,
    error: &AuthError,
) {
    let rejection = WireEvent::Error {
        code: format!("{error:?}"),
        message: format!("connect rejected: {error}"),
    };
    if let Ok(text) = serde_json::to_string(&rejection) {
        let _ = socket_sender.send(Message::Text(text.into())).await;
    }
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

async fn register_client<R, H, A>(
    state: &ServerState<R, H, A>,
    client_id: ClientId,
    sender: mpsc::UnboundedSender<WireEvent>,
) -> Result<(), ()>
where
    R: MessageRouter,
    H: EventHook,
{
    if state
        .router
        .lock()
        .await
        .connect(client_id.clone())
        .is_err()
    {
        return Err(());
    }

    state
        .connections
        .lock()
        .await
        .insert(client_id.clone(), sender);
    state.hook.lock().await.on_connect(&client_id);
    Ok(())
}

async fn unregister_client<R, H, A>(state: &ServerState<R, H, A>, client_id: &ClientId)
where
    R: MessageRouter,
    H: EventHook,
{
    state.connections.lock().await.remove(client_id);
    if state.router.lock().await.disconnect(client_id).is_ok() {
        state.hook.lock().await.on_disconnect(client_id);
    }
}

async fn route_and_flush<R, H, A>(
    state: &ServerState<R, H, A>,
    connection_id: &ClientId,
    event: WireEvent,
) -> Result<(), RouterError>
where
    R: MessageRouter,
    H: EventHook,
{
    let route_result = {
        state
            .router
            .lock()
            .await
            .route(connection_id, event.clone())
    };

    match route_result {
        Ok(()) => {
            state
                .hook
                .lock()
                .await
                .on_route_accepted(connection_id, &event);
        }
        Err(error) => {
            state
                .hook
                .lock()
                .await
                .on_route_rejected(connection_id, &event, &error);
            return Err(error);
        }
    }

    let targets = delivery_targets(connection_id, &event);
    flush_outboxes(state, &targets).await;
    Ok(())
}

fn should_report_routing_error(event: &WireEvent, error: &RouterError) -> bool {
    !matches!(
        (event, error),
        (WireEvent::PeerKey { .. }, RouterError::UnknownRecipient)
    )
}

fn delivery_targets(connection_id: &ClientId, event: &WireEvent) -> Vec<ClientId> {
    match event {
        WireEvent::PeerKey { to, .. } => vec![to.clone()],
        WireEvent::EncryptedMessage(envelope) => {
            vec![envelope.recipient.clone(), connection_id.clone()]
        }
        WireEvent::ClientHello { .. } | WireEvent::Ack { .. } | WireEvent::Error { .. } => {
            Vec::new()
        }
    }
}

async fn flush_outboxes<R, H, A>(state: &ServerState<R, H, A>, targets: &[ClientId])
where
    R: MessageRouter,
    H: EventHook,
{
    let mut deliveries = Vec::new();
    {
        let mut router = state.router.lock().await;
        let connections = state.connections.lock().await;
        for client_id in targets {
            let Some(sender) = connections.get(client_id) else {
                continue;
            };
            let events = router.drain_outbox(client_id);
            if !events.is_empty() {
                deliveries.push(OutboxDelivery {
                    sender: sender.clone(),
                    events,
                });
            }
        }
    }

    send_outbox_deliveries(deliveries);
}

struct OutboxDelivery {
    sender: mpsc::UnboundedSender<WireEvent>,
    events: Vec<WireEvent>,
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
    use chat_core::event::EncryptedEnvelope;
    use chat_core::types::{Ciphertext, MessageId, NonceBytes, PublicKeyBytes};
    use std::sync::Mutex as StdMutex;

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

    #[tokio::test]
    async fn route_and_flush_accepts_message_router_implementation() {
        struct RejectingRouter;

        impl MessageRouter for RejectingRouter {
            fn connect(&mut self, _client_id: ClientId) -> Result<(), RouterError> {
                Ok(())
            }

            fn disconnect(&mut self, _client_id: &ClientId) -> Result<(), RouterError> {
                Ok(())
            }

            fn route(
                &mut self,
                _connection_id: &ClientId,
                _event: WireEvent,
            ) -> Result<(), RouterError> {
                Err(RouterError::UnsupportedEvent)
            }

            fn drain_outbox(&mut self, _client_id: &ClientId) -> Vec<WireEvent> {
                Vec::new()
            }
        }

        let state = ServerState::new(RejectingRouter, NoopEventHook, NoopAuthProvider);
        let alice = ClientId::parse("alice").expect("alice");
        let bob = ClientId::parse("bob").expect("bob");
        let event = WireEvent::PeerKey {
            from: alice.clone(),
            to: bob,
            public_key: PublicKeyBytes::from_array([4; 32]),
        };

        let err = route_and_flush(&state, &alice, event)
            .await
            .expect_err("custom router should reject the event");

        assert_eq!(err, RouterError::UnsupportedEvent);
    }

    #[test]
    fn delivery_targets_cover_recipient_and_ack_sender() {
        let alice = ClientId::parse("alice").expect("alice");
        let bob = ClientId::parse("bob").expect("bob");

        let peer_key_targets = delivery_targets(
            &alice,
            &WireEvent::PeerKey {
                from: alice.clone(),
                to: bob.clone(),
                public_key: PublicKeyBytes::from_array([4; 32]),
            },
        );

        assert_eq!(peer_key_targets, vec![bob.clone()]);

        let message_targets = delivery_targets(
            &alice,
            &WireEvent::EncryptedMessage(EncryptedEnvelope {
                sender: alice.clone(),
                recipient: bob.clone(),
                message_id: MessageId::new(),
                nonce: NonceBytes::from_array([7; 24]),
                ciphertext: Ciphertext::from_bytes(vec![1, 2, 3]),
            }),
        );

        // 수신자와 Ack를 받는 발신자 모두 대상이다.
        assert_eq!(message_targets, vec![bob, alice]);
    }

    #[tokio::test]
    async fn flush_outboxes_drains_only_target_clients() {
        let state = ServerState::new(InMemoryRouter::default(), NoopEventHook, NoopAuthProvider);
        let alice = ClientId::parse("alice").expect("alice");
        let bob = ClientId::parse("bob").expect("bob");
        let carol = ClientId::parse("carol").expect("carol");
        let (alice_sender, mut alice_receiver) = mpsc::unbounded_channel();
        let (bob_sender, mut bob_receiver) = mpsc::unbounded_channel();
        let (carol_sender, mut carol_receiver) = mpsc::unbounded_channel();

        register_client(&state, alice.clone(), alice_sender)
            .await
            .expect("register alice");
        register_client(&state, bob.clone(), bob_sender)
            .await
            .expect("register bob");
        register_client(&state, carol.clone(), carol_sender)
            .await
            .expect("register carol");

        // carol의 outbox를 flush 대상 외부에서 미리 적재한다.
        // (alice→carol 메시지는 carol의 outbox에만 이벤트를 남긴다.)
        state
            .router
            .lock()
            .await
            .route(
                &alice,
                WireEvent::EncryptedMessage(EncryptedEnvelope {
                    sender: alice.clone(),
                    recipient: carol.clone(),
                    message_id: MessageId::new(),
                    nonce: NonceBytes::from_array([1; 24]),
                    ciphertext: Ciphertext::from_bytes(vec![9, 9, 9]),
                }),
            )
            .expect("seed carol outbox");

        let event = WireEvent::PeerKey {
            from: alice.clone(),
            to: bob.clone(),
            public_key: PublicKeyBytes::from_array([4; 32]),
        };

        state
            .router
            .lock()
            .await
            .route(&alice, event.clone())
            .expect("route peer key");
        let targets = delivery_targets(&alice, &event);

        flush_outboxes(&state, &targets).await;

        assert!(matches!(
            bob_receiver.try_recv().expect("bob receives peer key"),
            WireEvent::PeerKey { .. }
        ));
        // 대상 외 클라이언트의 outbox는 건드리지 않는다.
        assert!(alice_receiver.try_recv().is_err());
        assert!(carol_receiver.try_recv().is_err());
        let mut router = state.router.lock().await;

        assert_eq!(router.drain_outbox(&carol).len(), 1);
    }

    #[derive(Debug, Default, PartialEq, Eq)]
    struct RecordingHook {
        calls: Vec<&'static str>,
    }

    impl EventHook for RecordingHook {
        fn on_connect(&mut self, _client_id: &ClientId) {
            self.calls.push("connect");
        }

        fn on_disconnect(&mut self, _client_id: &ClientId) {
            self.calls.push("disconnect");
        }

        fn on_route_accepted(&mut self, _connection_id: &ClientId, _event: &WireEvent) {
            self.calls.push("route_accepted");
        }

        fn on_route_rejected(
            &mut self,
            _connection_id: &ClientId,
            _event: &WireEvent,
            _error: &RouterError,
        ) {
            self.calls.push("route_rejected");
        }
    }

    #[tokio::test]
    async fn event_hook_observes_connection_lifecycle() {
        let state = ServerState::new(
            InMemoryRouter::default(),
            RecordingHook::default(),
            NoopAuthProvider,
        );
        let alice = ClientId::parse("alice").expect("alice");
        let (sender, _receiver) = mpsc::unbounded_channel();

        register_client(&state, alice.clone(), sender)
            .await
            .expect("register alice");
        unregister_client(&state, &alice).await;

        let hook = state.hook.lock().await;

        assert_eq!(hook.calls, vec!["connect", "disconnect"]);
    }

    #[tokio::test]
    async fn event_hook_observes_route_success_and_error() {
        let state = ServerState::new(
            InMemoryRouter::default(),
            RecordingHook::default(),
            NoopAuthProvider,
        );
        let alice = ClientId::parse("alice").expect("alice");
        let bob = ClientId::parse("bob").expect("bob");
        let mallory = ClientId::parse("mallory").expect("mallory");
        let (alice_sender, _alice_receiver) = mpsc::unbounded_channel();
        let (bob_sender, _bob_receiver) = mpsc::unbounded_channel();

        register_client(&state, alice.clone(), alice_sender)
            .await
            .expect("register alice");
        register_client(&state, bob.clone(), bob_sender)
            .await
            .expect("register bob");

        route_and_flush(
            &state,
            &alice,
            WireEvent::PeerKey {
                from: alice.clone(),
                to: bob.clone(),
                public_key: PublicKeyBytes::from_array([4; 32]),
            },
        )
        .await
        .expect("route peer key");

        let err = route_and_flush(
            &state,
            &alice,
            WireEvent::PeerKey {
                from: mallory,
                to: bob,
                public_key: PublicKeyBytes::from_array([5; 32]),
            },
        )
        .await
        .expect_err("forged route should fail");

        let hook = state.hook.lock().await;

        assert_eq!(err, RouterError::SenderMismatch);
        assert_eq!(
            hook.calls,
            vec!["connect", "connect", "route_accepted", "route_rejected"]
        );
    }

    #[tokio::test]
    async fn event_hook_runs_after_router_lock_is_released() {
        struct RouterLockProbeHook {
            router: Arc<Mutex<InMemoryRouter>>,
            observations: Arc<StdMutex<Vec<bool>>>,
        }

        impl EventHook for RouterLockProbeHook {
            fn on_route_accepted(&mut self, _connection_id: &ClientId, _event: &WireEvent) {
                self.observations
                    .lock()
                    .expect("record observations")
                    .push(self.router.try_lock().is_ok());
            }
        }

        let router = Arc::new(Mutex::new(InMemoryRouter::default()));
        let observations = Arc::new(StdMutex::new(Vec::new()));
        let state = ServerState {
            router: Arc::clone(&router),
            hook: Arc::new(Mutex::new(RouterLockProbeHook {
                router,
                observations: Arc::clone(&observations),
            })),
            auth: Arc::new(Mutex::new(NoopAuthProvider)),
            connections: Arc::new(Mutex::new(HashMap::new())),
        };
        let alice = ClientId::parse("alice").expect("alice");
        let bob = ClientId::parse("bob").expect("bob");
        let (alice_sender, _alice_receiver) = mpsc::unbounded_channel();
        let (bob_sender, _bob_receiver) = mpsc::unbounded_channel();

        register_client(&state, alice.clone(), alice_sender)
            .await
            .expect("register alice");
        register_client(&state, bob.clone(), bob_sender)
            .await
            .expect("register bob");

        route_and_flush(
            &state,
            &alice,
            WireEvent::PeerKey {
                from: alice.clone(),
                to: bob,
                public_key: PublicKeyBytes::from_array([6; 32]),
            },
        )
        .await
        .expect("route peer key");

        let observations = observations.lock().expect("read observations");

        assert_eq!(*observations, vec![true]);
    }
}
