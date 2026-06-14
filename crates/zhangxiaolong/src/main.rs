use std::sync::Arc;

use log::info;
use mmtls::MmtlsServer;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let port: u16 = std::env::var("MMTLS_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);

    let addr = format!("0.0.0.0:{port}");
    let listener = TcpListener::bind(&addr).await.expect("bind TCP listener");
    info!("zhangxiaolong listening on {addr}");

    let server = Arc::new(MmtlsServer::new());

    loop {
        let (conn, peer) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                log::error!("accept failed: {e}");
                continue;
            }
        };
        info!("accepted connection from {peer}");

        let srv = server.clone();
        tokio::spawn(async move {
            if let Err(e) = srv.handle_http_connection(conn).await {
                log::warn!("connection from {peer} failed: {e}");
            }
        });
    }
}
