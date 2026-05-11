use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let addr = std::env::var("CHAT_SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".to_owned());
    let listener = TcpListener::bind(&addr).await?;

    tracing::info!(%addr, "chat server listening");
    chat_server::ws::serve(listener).await
}
