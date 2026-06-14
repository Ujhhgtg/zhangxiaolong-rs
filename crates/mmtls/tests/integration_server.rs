use mmtls::*;
use std::sync::Arc;
use tokio::net::TcpListener;

/// Helper: spawn a server that accepts `n` raw TCP connections, handling each with `handle_raw_connection`.
async fn spawn_raw_server(server: Arc<MmtlsServer>, n: usize) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        for _ in 0..n {
            let (conn, _) = listener.accept().await.expect("accept");
            let s = server.clone();
            tokio::spawn(async move {
                if let Err(e) = s.handle_raw_connection(conn).await {
                    eprintln!("Raw server error: {e}");
                }
            });
        }
    });
    addr
}

/// Helper: spawn a server that accepts `n` HTTP connections, handling each with `handle_http_connection`.
async fn spawn_http_server(server: Arc<MmtlsServer>, n: usize) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        for _ in 0..n {
            let (conn, _) = listener.accept().await.expect("accept");
            let s = server.clone();
            tokio::spawn(async move {
                if let Err(e) = s.handle_http_connection(conn).await {
                    eprintln!("HTTP server error: {e}");
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn test_local_ecdhe_raw_handshake() {
    let server = Arc::new(MmtlsServer::new());
    let addr = spawn_raw_server(server, 1).await;

    let mut client = MmtlsClient::new();
    client.verify_ecdsa = false;
    client
        .handshake(&format!("127.0.0.1:{}", addr.port()))
        .await
        .expect("1-RTT ECDHE handshake");
    eprintln!("Local ECDHE raw handshake success");
    client.noop().await.expect("send noop");
    eprintln!("Local ECDHE raw noop success");
}

#[tokio::test]
async fn test_local_ecdhe_short_link_handshake() {
    let server = Arc::new(MmtlsServer::new());
    let addr = spawn_http_server(server, 1).await;
    let host = format!("127.0.0.1:{}", addr.port());

    let mut client = MmtlsClientShort::new();
    client.verify_ecdsa = false;
    client
        .handshake(&host)
        .await
        .expect("Short-link ECDHE handshake");
    eprintln!("Local ECDHE short-link handshake success");

    let session = client.session.as_ref().expect("Session should not be nil");
    assert!(
        !session.psk_access.is_empty(),
        "pskAccess should not be nil"
    );
    assert!(
        !session.psk_refresh.is_empty(),
        "pskRefresh should not be nil"
    );
    assert!(
        !session.tk.tickets.is_empty(),
        "tickets should not be empty"
    );
    eprintln!("Session has {} tickets", session.tk.tickets.len());
}

#[tokio::test]
async fn test_local_psk_0rtt_request() {
    let server = Arc::new(MmtlsServer::new());
    // Need 2 connections: first for ECDHE handshake, second for PSK 0-RTT
    let addr = spawn_http_server(server, 2).await;
    let host = format!("127.0.0.1:{}", addr.port());

    let mut client = MmtlsClientShort::new();
    client.verify_ecdsa = false;

    // First: ECDHE handshake to get session
    client.handshake(&host).await.expect("ECDHE handshake");
    eprintln!("PSK test: ECDHE handshake success");

    // Second: PSK 0-RTT request
    let resp_body = client
        .request(&host, "/test/path", b"hello")
        .await
        .expect("0-RTT PSK request");
    eprintln!("PSK test: 0-RTT request success");

    // The response should be parseable as HTTP
    parse_http_response_from_byte(&resp_body).expect("parse response body");
    eprintln!("PSK test: parse response body success");
}
