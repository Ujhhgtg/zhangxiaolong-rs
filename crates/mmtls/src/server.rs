use crate::client_finish::ClientFinish;
use crate::client_hello::{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, read_client_hello};
use crate::consts::{PROTOCOL_VERSION, TLS_PSK_WITH_AES_128_GCM_SHA256};
use crate::crypto::{
    build_hkdf_info, compute_ephemeral_secret, compute_hmac, compute_traffic_key_n, hkdf_expand,
    sign_ecdsa,
};
use crate::record::{
    create_abort_record, create_handshake_record, create_raw_data_record, read_record, read_sync,
};
use crate::server_finish::ServerFinish;
use crate::server_hello::ServerHello;
use crate::session_ticket::{NewSessionTicket, SessionTicket};
use crate::signature::Signature;
use crate::util::{get_random, read_u16_len_data};
use crate::{MmtlsError, Result, TrafficKeyPair};
use p256::elliptic_curve::Generate;
use p256::{PublicKey, SecretKey};
use sha2::Digest;
use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Mutex;

/// Stored session for PSK reuse
struct ServerSession {
    psk_access: Vec<u8>, // 32 bytes
    #[allow(dead_code)]
    psk_refresh: Vec<u8>, // 32 bytes
}

pub struct MmtlsServer {
    ecdh_secret: SecretKey,
    ecdh_public: PublicKey,
    sign_secret: SecretKey,
    sessions: Arc<Mutex<HashMap<Vec<u8>, ServerSession>>>,
}

impl MmtlsServer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Handle a raw TCP connection (long-link, like MmtlsClient).
    /// Completes ECDHE handshake and one noop exchange.
    pub async fn handle_raw_connection(&self, mut conn: TcpStream) -> Result<()> {
        let (com_key, hasher, server_seq, client_seq) =
            self.handle_ecdhe_handshake(&mut conn).await?;
        self.handle_noop_exchange(&mut conn, &com_key, &hasher, server_seq, client_seq)
            .await?;
        Ok(())
    }

    /// Handle an HTTP-wrapped connection (short-link, like MmtlsClientShort).
    pub async fn handle_http_connection(&self, mut conn: TcpStream) -> Result<()> {
        let body = parse_http_request_body(&mut conn).await?;
        let mut reader = Cursor::new(body);

        // Read first record to determine if ECDHE or PSK
        let first_record = read_sync(&mut reader)?;

        // Look at the ClientHello to check cipher suites
        let ch = read_client_hello(&first_record.data)?;

        if ch.cipher_suites.contains(&TLS_PSK_WITH_AES_128_GCM_SHA256) {
            self.handle_psk_short_link(&ch, &first_record.data, &mut reader, &mut conn)
                .await
        } else {
            self.handle_ecdhe_short_link(&ch, &first_record.data, &mut conn)
                .await
        }
    }

    // ── ECDHE handshake (shared by raw and HTTP short-link) ──────────────

    async fn handle_ecdhe_handshake(
        &self,
        conn: &mut TcpStream,
    ) -> Result<(Vec<u8>, sha2::Sha256, u32, u32)> {
        let mut hasher = sha2::Sha256::new();
        let mut server_seq: u32 = 0;
        let mut client_seq: u32 = 0;

        // 1. Read ClientHello
        let ch_record = read_record(conn).await?;
        hasher.update(&ch_record.data);
        server_seq += 1; // server's receive counter
        let ch = read_client_hello(&ch_record.data)?;

        let cli_ecdh_pub = PublicKey::from_sec1_bytes(
            ch.extensions
                .get(&TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
                .and_then(|keys| keys.first())
                .ok_or_else(|| MmtlsError::Protocol("missing ECDHE key".into()))?,
        )
        .map_err(|e| MmtlsError::Parse(format!("invalid client ECDH key: {e}")))?;

        // 2. Compute shared secret
        let com_key = compute_ephemeral_secret(&cli_ecdh_pub, &self.ecdh_secret);

        // 3. Build and send ServerHello
        let sh = ServerHello {
            protocol_version: PROTOCOL_VERSION,
            cipher_suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            public_key: self.ecdh_public,
            random: get_random(32),
        };
        let sh_data = sh.serialize();
        hasher.update(&sh_data);
        let sh_record = create_handshake_record(sh_data);
        conn.write_all(&sh_record.serialize()).await?;
        client_seq += 1; // plain record counts toward seq

        // 4. Derive handshake traffic keys
        let traffic_key = compute_traffic_key_n(
            &com_key,
            &build_hkdf_info("handshake key expansion", Some(&hasher)),
            56,
        )?;

        // 5. Build and send Signature (encrypted as server)
        let handshake_hash_for_sig = hasher.clone().finalize();
        let sig = sign_ecdsa(&handshake_hash_for_sig, &self.sign_secret);
        let sig_msg = Signature {
            sig_type: 0x01,
            ecdsa_signature: sig,
        };
        let sig_data = sig_msg.serialize();
        hasher.update(&sig_data); // update AFTER signing, BEFORE encrypting
        let mut sig_record = create_handshake_record(sig_data);
        sig_record.encrypt_as_server(&traffic_key, client_seq)?;
        client_seq += 1;
        conn.write_all(&sig_record.serialize()).await?;

        // 6. Build NewSessionTicket
        let psk_access = hkdf_expand(&com_key, "PSK_ACCESS", Some(&hasher))?;
        let psk_refresh = hkdf_expand(&com_key, "PSK_REFRESH", Some(&hasher))?;
        let ticket_id = get_random(16);
        let ticket = SessionTicket {
            ticket_type: 0x01,
            ticket_lifetime: 7200,
            ticket_age_add: get_random(4),
            reversed: 0,
            nonce: get_random(8),
            ticket: ticket_id.clone(),
        };
        let nst = NewSessionTicket {
            reversed: 0x04,
            count: 1,
            tickets: vec![ticket],
        };
        let nst_data = nst
            .serialize()
            .map_err(|e| MmtlsError::Protocol(format!("nst serialize: {e}")))?;
        hasher.update(&nst_data);
        let mut nst_record = create_handshake_record(nst_data);
        nst_record.encrypt_as_server(&traffic_key, client_seq)?;
        client_seq += 1;
        conn.write_all(&nst_record.serialize()).await?;

        // Store session
        self.sessions.lock().await.insert(
            ticket_id,
            ServerSession {
                psk_access,
                psk_refresh,
            },
        );

        // 7. Build and send ServerFinish
        let sf_key = hkdf_expand(&com_key, "server finished", None)?;
        let sf_hmac = compute_hmac(&sf_key, &hasher.clone().finalize());
        let sf = ServerFinish {
            reversed: 0x04,
            data: sf_hmac,
        };
        let sf_data = sf.serialize();
        let mut sf_record = create_handshake_record(sf_data);
        sf_record.encrypt_as_server(&traffic_key, client_seq)?;
        conn.write_all(&sf_record.serialize()).await?;
        client_seq += 1;

        // 8. Read ClientFinish
        let mut cf_record = read_record(conn).await?;
        cf_record.decrypt_as_server(&traffic_key, server_seq)?;
        server_seq += 1;

        // Parse ClientFinish
        let cf = parse_client_finish(&cf_record.data)?;

        // Verify ClientFinish HMAC
        let cf_key = hkdf_expand(&com_key, "client finished", None)?;
        let expected_cf = compute_hmac(&cf_key, &hasher.clone().finalize());
        if cf.data != expected_cf {
            return Err(MmtlsError::Protocol(
                "ClientFinish verification failed".into(),
            ));
        }

        log::info!("ECDHE handshake complete");
        Ok((com_key, hasher, server_seq, client_seq))
    }

    /// Handle a single noop exchange after ECDHE handshake.
    async fn handle_noop_exchange(
        &self,
        conn: &mut TcpStream,
        com_key: &[u8],
        hasher: &sha2::Sha256,
        server_seq: u32,
        client_seq: u32,
    ) -> Result<()> {
        use crate::consts::{TCP_NOOP_REQUEST, TCP_NOOP_RESPONSE};
        use crate::record::create_data_record;

        let expanded_secret = {
            use hkdf::Hkdf;
            let hk = Hkdf::<sha2::Sha256>::from_prk(com_key)
                .map_err(|_| MmtlsError::Crypto("hkdf from_prk failed".into()))?;
            let mut okm = [0u8; 32];
            hk.expand(&build_hkdf_info("expanded secret", Some(hasher)), &mut okm)
                .map_err(|_| MmtlsError::Crypto("hkdf expand failed".into()))?;
            okm.to_vec()
        };

        let app_key = compute_traffic_key_n(
            &expanded_secret,
            &build_hkdf_info("application data key expansion", Some(hasher)),
            56,
        )?;

        // Read noop request from client
        let mut noop_req = read_record(conn).await?;
        noop_req.decrypt_as_server(&app_key, server_seq)?;

        // Parse DataRecord to verify
        let mut r = Cursor::new(&noop_req.data[..]);
        let mut pack_len_buf = [0u8; 4];
        r.read_exact(&mut pack_len_buf)?;
        let _pack_len = u32::from_be_bytes(pack_len_buf);
        let mut flag_buf = [0u8; 4];
        r.read_exact(&mut flag_buf)?;
        let mut data_type_buf = [0u8; 4];
        r.read_exact(&mut data_type_buf)?;
        let data_type = u32::from_be_bytes(data_type_buf);
        if data_type != TCP_NOOP_REQUEST {
            return Err(MmtlsError::Protocol("expected noop request".into()));
        }

        // Send noop response
        let mut noop_resp = create_data_record(TCP_NOOP_RESPONSE, 0xFFFFFFFF, vec![]);
        noop_resp.encrypt_as_server(&app_key, client_seq)?;
        conn.write_all(&noop_resp.serialize()).await?;

        log::info!("Noop exchange complete");
        Ok(())
    }

    async fn handle_ecdhe_short_link(
        &self,
        _ch: &crate::client_hello::ClientHello,
        _ch_data: &[u8],
        conn: &mut TcpStream,
    ) -> Result<()> {
        // For ECDHE short-link, the client sends only 1 handshake record with ClientHello.
        // We need to build the full 4-record response.
        // Re-implement the handshake building the response in-memory, then send as HTTP.

        let mut hasher = sha2::Sha256::new();
        let mut client_seq: u32 = 0;

        // We already consumed the ClientHello record bytes; hash them
        hasher.update(_ch_data);
        let ch = _ch;

        let cli_ecdh_pub = PublicKey::from_sec1_bytes(
            ch.extensions
                .get(&TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
                .and_then(|keys| keys.first())
                .ok_or_else(|| MmtlsError::Protocol("missing ECDHE key".into()))?,
        )
        .map_err(|e| MmtlsError::Parse(format!("invalid client ECDH key: {e}")))?;

        let com_key = compute_ephemeral_secret(&cli_ecdh_pub, &self.ecdh_secret);

        let mut response_tls = Vec::new();

        // ServerHello
        let sh = ServerHello {
            protocol_version: PROTOCOL_VERSION,
            cipher_suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            public_key: self.ecdh_public,
            random: get_random(32),
        };
        let sh_data = sh.serialize();
        hasher.update(&sh_data);
        response_tls.extend_from_slice(&create_handshake_record(sh_data).serialize());
        client_seq += 1; // plain record counts toward seq

        // Handshake traffic keys
        let traffic_key = compute_traffic_key_n(
            &com_key,
            &build_hkdf_info("handshake key expansion", Some(&hasher)),
            56,
        )?;

        // Signature
        let handshake_hash_for_sig = hasher.clone().finalize();
        let sig = sign_ecdsa(&handshake_hash_for_sig, &self.sign_secret);
        let sig_msg = Signature {
            sig_type: 0x01,
            ecdsa_signature: sig,
        };
        let sig_data = sig_msg.serialize();
        hasher.update(&sig_data);
        let mut sig_record = create_handshake_record(sig_data);
        sig_record.encrypt_as_server(&traffic_key, client_seq)?;
        client_seq += 1;
        response_tls.extend_from_slice(&sig_record.serialize());

        // NewSessionTicket
        let psk_access = hkdf_expand(&com_key, "PSK_ACCESS", Some(&hasher))?;
        let psk_refresh = hkdf_expand(&com_key, "PSK_REFRESH", Some(&hasher))?;
        let ticket_id = get_random(16);
        let ticket = SessionTicket {
            ticket_type: 0x01,
            ticket_lifetime: 7200,
            ticket_age_add: get_random(4),
            reversed: 0,
            nonce: get_random(8),
            ticket: ticket_id.clone(),
        };
        let nst = NewSessionTicket {
            reversed: 0x04,
            count: 1,
            tickets: vec![ticket],
        };
        let nst_data = nst
            .serialize()
            .map_err(|e| MmtlsError::Protocol(format!("nst serialize: {e}")))?;
        hasher.update(&nst_data);
        let mut nst_record = create_handshake_record(nst_data);
        nst_record.encrypt_as_server(&traffic_key, client_seq)?;
        client_seq += 1;
        response_tls.extend_from_slice(&nst_record.serialize());

        self.sessions.lock().await.insert(
            ticket_id,
            ServerSession {
                psk_access,
                psk_refresh,
            },
        );

        // ServerFinish
        let sf_key = hkdf_expand(&com_key, "server finished", None)?;
        let sf_hmac = compute_hmac(&sf_key, &hasher.clone().finalize());
        let sf = ServerFinish {
            reversed: 0x04,
            data: sf_hmac,
        };
        let sf_data = sf.serialize();
        let mut sf_record = create_handshake_record(sf_data);
        sf_record.encrypt_as_server(&traffic_key, client_seq)?;
        response_tls.extend_from_slice(&sf_record.serialize());

        let http_response = build_http_response(&response_tls);
        conn.write_all(&http_response).await?;

        log::info!("Short-link ECDHE handshake complete");
        Ok(())
    }

    // ── PSK 0-RTT short-link ─────────────────────────────────────────────

    async fn handle_psk_short_link(
        &self,
        ch: &crate::client_hello::ClientHello,
        ch_data: &[u8],
        reader: &mut Cursor<Vec<u8>>,
        conn: &mut TcpStream,
    ) -> Result<()> {
        let mut hasher = sha2::Sha256::new();
        let mut client_seq: u32 = 0;

        // Hash the ClientHello (system record 0x19)
        hasher.update(ch_data);
        client_seq += 1;

        // Extract ticket from PSK extension
        let tickets = ch
            .extensions
            .get(&TLS_PSK_WITH_AES_128_GCM_SHA256)
            .ok_or_else(|| MmtlsError::Protocol("missing PSK extension".into()))?;
        let ticket_data = tickets
            .first()
            .ok_or_else(|| MmtlsError::Protocol("empty PSK ticket list".into()))?;

        let session_ticket = crate::session_ticket::read_session_ticket(ticket_data)?;
        let ticket_key = session_ticket.ticket.clone();

        let psk_access = {
            let sessions = self.sessions.lock().await;
            sessions
                .get(&ticket_key)
                .map(|s| s.psk_access.clone())
                .ok_or_else(|| MmtlsError::Protocol("unknown PSK session".into()))?
        };

        // Derive early data key
        let early_data_key = compute_traffic_key_n(
            &psk_access,
            &build_hkdf_info("early data key expansion", Some(&hasher)),
            28,
        )?;

        // Read and decrypt extensions record (system record 0x19)
        let mut ext_record = read_sync(reader)?;
        ext_record.decrypt_as_server(&early_data_key, client_seq)?;
        hasher.update(&ext_record.data);
        client_seq += 1;

        // Read and decrypt request data record (0x17)
        let mut data_record = read_sync(reader)?;
        data_record.decrypt_as_server(&early_data_key, client_seq)?;
        client_seq += 1;
        let request_data = data_record.data.clone();

        // Parse request: gen_data_part format
        // [4B total length] [2B path len] [path] [2B host len] [host] [4B req len] [req]
        let (path, host, req_body) = parse_data_part(&request_data)?;
        let _ = (&path, &host); // debug path logged inside parse_data_part

        // Read and decrypt abort record (0x15)
        let mut abort_record = read_sync(reader)?;
        abort_record.decrypt_as_server(&early_data_key, client_seq)?;
        // client_seq advanced but will be reset for response


        // Build response — simple HTTP response so client can parse_http_response_from_byte it
        let resp_payload = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
            req_body.len(),
            String::from_utf8_lossy(&req_body)
        );
        let resp_bytes = resp_payload.into_bytes();

        let mut response_tls = Vec::new();
        let mut server_seq: u32 = 0;

        // ServerHello (PSK cipher suite) — MUST hash before deriving app_key
        let sh = ServerHello {
            protocol_version: PROTOCOL_VERSION,
            cipher_suite: TLS_PSK_WITH_AES_128_GCM_SHA256,
            public_key: self.ecdh_public,
            random: get_random(32),
        };
        let sh_data = sh.serialize();
        hasher.update(&sh_data);
        let sh_record = create_handshake_record(sh_data);
        response_tls.extend_from_slice(&sh_record.serialize());
        server_seq += 1; // plain record counts toward seq

        // Derive app key from psk_access + handshake hash (includes ServerHello now)
        // Client uses n=28 with client_key→server_key, client_nonce→server_nonce
        let traffic_key = compute_traffic_key_n(
            &psk_access,
            &build_hkdf_info("handshake key expansion", Some(&hasher)),
            28,
        )?;
        let app_key = TrafficKeyPair {
            client_key: Vec::new(),
            server_key: traffic_key.client_key,
            client_nonce: Vec::new(),
            server_nonce: traffic_key.client_nonce,
        };

        // ServerFinish
        let sf_key = hkdf_expand(&psk_access, "server finished", None)?;
        let sf_hmac = compute_hmac(&sf_key, &hasher.clone().finalize());
        let sf = ServerFinish {
            reversed: 0x04,
            data: sf_hmac,
        };
        let sf_data = sf.serialize();
        let mut sf_record = create_handshake_record(sf_data);
        sf_record.encrypt_as_server(&app_key, server_seq)?;
        server_seq += 1;
        response_tls.extend_from_slice(&sf_record.serialize());

        // Data record
        let mut data_record = create_raw_data_record(resp_bytes);
        data_record.encrypt_as_server(&app_key, server_seq)?;
        server_seq += 1;
        response_tls.extend_from_slice(&data_record.serialize());

        // Abort record
        let abort_part = vec![0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x01];
        let mut abort_record = create_abort_record(abort_part);
        abort_record.encrypt_as_server(&app_key, server_seq)?;
        response_tls.extend_from_slice(&abort_record.serialize());

        let http_response = build_http_response(&response_tls);
        conn.write_all(&http_response).await?;

        log::info!("PSK 0-RTT request complete");
        Ok(())
    }
}

impl Default for MmtlsServer {
    fn default() -> Self {
        let ecdh_secret = SecretKey::generate();
        let sign_secret = SecretKey::generate();
        let ecdh_public = ecdh_secret.public_key();
        Self {
            ecdh_secret,
            ecdh_public,
            sign_secret,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

// ── ClientFinish parsing ─────────────────────────────────────────────────

fn parse_client_finish(buf: &[u8]) -> Result<ClientFinish> {
    let mut r = Cursor::new(buf);
    // skip total length (4B)
    let mut _len_buf = [0u8; 4];
    r.read_exact(&mut _len_buf)?;

    let mut reversed_buf = [0u8; 1];
    r.read_exact(&mut reversed_buf)?;
    let reversed = reversed_buf[0];

    let mut data_len_buf = [0u8; 2];
    r.read_exact(&mut data_len_buf)?;
    let data_len = u16::from_be_bytes(data_len_buf);

    let mut data = vec![0u8; data_len as usize];
    r.read_exact(&mut data)?;

    Ok(ClientFinish { reversed, data })
}

// ── HTTP helpers ─────────────────────────────────────────────────────────

async fn parse_http_request_body(conn: &mut TcpStream) -> Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];

    loop {
        let n = conn.read(&mut chunk).await?;
        if n == 0 {
            return Err(MmtlsError::Parse("incomplete HTTP request".into()));
        }
        buf.extend_from_slice(&chunk[..n]);
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut req = httparse::Request::new(&mut headers);
        match req.parse(&buf) {
            Ok(httparse::Status::Complete(header_len)) => {
                let body_so_far = buf.len() - header_len;
                let content_length = req
                    .headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case("content-length"))
                    .and_then(|h| std::str::from_utf8(h.value).ok())
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(body_so_far);
                let mut remaining = content_length.saturating_sub(body_so_far);
                while remaining > 0 {
                    let n = conn.read(&mut chunk).await?;
                    if n == 0 {
                        return Err(MmtlsError::Parse("incomplete HTTP request body".into()));
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    remaining = remaining.saturating_sub(n);
                }
                return Ok(buf[header_len..].to_vec());
            }
            Ok(httparse::Status::Partial) => continue,
            Err(e) => return Err(MmtlsError::Parse(format!("http parse: {e}"))),
        }
    }
}

fn build_http_response(tls_payload: &[u8]) -> Vec<u8> {
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: Keep-Alive\r\n\r\n",
        tls_payload.len()
    );
    let mut response = header.into_bytes();
    response.extend_from_slice(tls_payload);
    response
}

// ── Data part parsing / building ─────────────────────────────────────────

/// Parse gen_data_part format: path, host, request body.
fn parse_data_part(data: &[u8]) -> Result<(String, String, Vec<u8>)> {
    let mut r = Cursor::new(data);

    // skip total length (4B)
    let mut total_len_buf = [0u8; 4];
    r.read_exact(&mut total_len_buf)?;

    let path = String::from_utf8(read_u16_len_data(&mut r)?)
        .map_err(|e| MmtlsError::Parse(format!("invalid path utf8: {e}")))?;
    let host = String::from_utf8(read_u16_len_data(&mut r)?)
        .map_err(|e| MmtlsError::Parse(format!("invalid host utf8: {e}")))?;

    log::info!("<-- {} {} ({} bytes)", host, path, r.get_ref().len() - r.position() as usize);

    // req body
    let mut req_len_buf = [0u8; 4];
    r.read_exact(&mut req_len_buf)?;
    let req_len = u32::from_be_bytes(req_len_buf) as usize;
    let mut req = vec![0u8; req_len];
    if req_len > 0 {
        r.read_exact(&mut req)?;
    }

    Ok((path, host, req))
}
