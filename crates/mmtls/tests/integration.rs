use mmtls::*;

#[tokio::test]
// #[ignore = "requires network"]
async fn test_1rtt_ecdhe_handshake() {
    let mut client = MmtlsClient::default();
    client.verify_ecdsa = false;
    client
        .handshake("szlong.weixin.qq.com:8080")
        .await
        .expect("1-RTT ECDHE handshake");
    eprintln!("1-RTT ECDHE handshake success");
    client.noop().await.expect("send noop");
    eprintln!("1-RTT ECDHE send noop success");
}

#[tokio::test]
#[ignore = "requires network"]
async fn test_1rtt_psk_handshake() {
    let session = Session::load("../gommtls/session_long").await.ok();
    let mut client = MmtlsClient::default();
    client.session = session;
    client
        .handshake("szlong.weixin.qq.com:8080")
        .await
        .expect("1-RTT PSK handshake");
    eprintln!("1-RTT PSK handshake success");
    client.noop().await.expect("send noop");
    eprintln!("1-RTT PSK send noop success");
}

#[tokio::test]
// #[ignore = "requires network"]
async fn test_short_link_ecdhe_handshake() {
    let mut client = MmtlsClientShort::default();
    client.verify_ecdsa = false;
    client
        .handshake("dns.weixin.qq.com.cn")
        .await
        .expect("Short-link ECDHE handshake");
    eprintln!("Short-link ECDHE handshake success");
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
// #[ignore = "requires network"]
async fn test_short_link_auto_handshake() {
    let mut client = MmtlsClientShort::default();
    client.verify_ecdsa = false;
    let resp_body = client
        .request(
            "dns.weixin.qq.com.cn",
            "/cgi-bin/micromsg-bin/newgetdns",
            &[],
        )
        .await
        .expect("auto-handshake + request");
    eprintln!("Short-link auto-handshake + request success");
    parse_http_response_from_byte(&resp_body).expect("parse response body");
    eprintln!("Parse response body success");
}

#[tokio::test]
// #[ignore = "requires network"]
async fn test_short_link_handshake_then_request() {
    let mut client = MmtlsClientShort::default();
    client.verify_ecdsa = false;
    client
        .handshake("dns.weixin.qq.com.cn")
        .await
        .expect("ECDHE handshake");
    eprintln!("Short-link ECDHE handshake success");
    let resp_body = client
        .request(
            "dns.weixin.qq.com.cn",
            "/cgi-bin/micromsg-bin/newgetdns",
            &[],
        )
        .await
        .expect("0-RTT request");
    eprintln!("Short-link 0-RTT request success");
    parse_http_response_from_byte(&resp_body).expect("parse response body");
    eprintln!("Parse response body success");
}

#[tokio::test]
// #[ignore = "requires network"]
async fn test_short_link_session_persistence() {
    let session_path = "../session_short";
    let mut client1 = MmtlsClientShort::default();
    client1.verify_ecdsa = false;
    client1
        .handshake("dns.weixin.qq.com.cn")
        .await
        .expect("ECDHE handshake");
    eprintln!("Short-link ECDHE handshake success");
    if let Some(ref session) = client1.session {
        session.save(session_path).await.expect("save session");
    }
    eprintln!("Session saved");

    let mut client2 = MmtlsClientShort::default();
    client2.session = Some(Session::load(session_path).await.expect("load session"));
    eprintln!("Session loaded");

    let resp_body = client2
        .request(
            "dns.weixin.qq.com.cn",
            "/cgi-bin/micromsg-bin/newgetdns",
            &[],
        )
        .await
        .expect("0-RTT request with loaded session");
    eprintln!("Short-link 0-RTT request with loaded session success");
    parse_http_response_from_byte(&resp_body).expect("parse response body");
    eprintln!("Parse response body success");
}

// #[tokio::test]
// #[ignore = "requires network"]
// async fn test_0rtt_psk_send_data() {
//     let session = Session::load("../session_short")
//         .await
//         .expect("load session");
//     let mut client = MmtlsClientShort::default();
//     client.session = Some(session);
//     let resp_body = client
//         .request(
//             "dns.weixin.qq.com.cn",
//             "/cgi-bin/micromsg-bin/newgetdns",
//             &[],
//         )
//         .await
//         .expect("0-RTT PSK request");
//     eprintln!("mmtls short client 0rtt psk send request success");
//     parse_http_response_from_byte(&resp_body).expect("parse request body");
//     eprintln!("mmtls short client 0rtt psk parse response body success");
// }
