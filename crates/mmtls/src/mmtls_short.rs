use crate::client_hello::{new_ecdhe_hello, new_psk_zero_hello};
use crate::crypto::{
    build_hkdf_info, compute_ephemeral_secret, compute_hmac, compute_traffic_key_n,
    generate_key_pairs, verify_ecdsa_signature,
};
use crate::record::{
    MmtlsRecord, create_abort_record, create_handshake_record, create_raw_data_record,
    create_system_record,
};
use crate::server_finish::read_server_finish;
use crate::server_hello::read_server_hello;
use crate::session_ticket::read_new_session_ticket;
use crate::signature::read_signature;
use crate::util::{get_random, write_u16_len_data, write_u32_len_data};
use crate::{MmtlsError, Result, Session, TrafficKeyPair};
use sha2::Digest;
use std::io::{Cursor, Read};
use std::sync::atomic::AtomicI32;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

pub struct MmtlsClientShort {
    conn: Option<TcpStream>,
    status: AtomicI32,
    public_ecdh: Option<p256::SecretKey>,
    verify_ecdh: Option<p256::SecretKey>,
    server_ecdh: Option<p256::PublicKey>,
    packet_reader: Option<Cursor<Vec<u8>>>,
    handshake_hasher: sha2::Sha256,
    server_seq_num: u32,
    client_seq_num: u32,
    pub session: Option<Session>,
    pub verify_ecdsa: bool,
}

pub fn new_mmtls_client_short() -> MmtlsClientShort {
    MmtlsClientShort::default()
}

impl MmtlsClientShort {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn handshake(&mut self, host: &str) -> Result<()> {
        if self.handshake_complete() {
            return Ok(());
        }
        self.reset();
        let (pub_key, verify) = generate_key_pairs()?;
        self.public_ecdh = Some(pub_key);
        self.verify_ecdh = Some(verify);

        let ch = new_ecdhe_hello(
            &self.public_ecdh.as_ref().unwrap().public_key(),
            &self.verify_ecdh.as_ref().unwrap().public_key(),
        );
        let hello_part = ch.serialize();
        self.handshake_hasher.update(&hello_part);

        let hello_record = create_handshake_record(hello_part);
        let tls_payload = hello_record.serialize();
        self.client_seq_num += 1;

        let header = build_request_header(host, tls_payload.len())?;
        let http_packet = [header, tls_payload].concat();
        let addr = format!("{host}:80");
        let mut conn = TcpStream::connect(&addr).await?;
        conn.write_all(&http_packet).await?;

        let response = parse_response(&mut conn).await?;
        log::debug!(
            "Handshake response({}):\n{}",
            response.len(),
            hex::encode(&response)
        );
        self.packet_reader = Some(Cursor::new(response));

        // ServerHello
        let server_hello_record = read_sync(self.packet_reader.as_mut().unwrap())?;
        self.handshake_hasher.update(&server_hello_record.data);
        self.server_seq_num += 1;
        let sh = read_server_hello(&server_hello_record.data)?;
        self.server_ecdh = Some(sh.public_key);

        let com_key = compute_ephemeral_secret(
            self.server_ecdh.as_ref().unwrap(),
            self.public_ecdh.as_ref().unwrap(),
        );
        let traffic_key = compute_traffic_key_n(
            &com_key,
            &build_hkdf_info("handshake key expansion", Some(&self.handshake_hasher)),
            56,
        )?;

        // Signature
        let mut sig_record = read_sync(self.packet_reader.as_mut().unwrap())?;
        sig_record.decrypt(&traffic_key, self.server_seq_num)?;
        let sig = read_signature(&sig_record.data)?;
        if self.verify_ecdsa
            && !verify_ecdsa_signature(
                &self.handshake_hasher.clone().finalize(),
                &sig.ecdsa_signature,
            )
        {
            return Err(MmtlsError::Protocol("verify ECDSA signature failed".into()));
        }
        self.handshake_hasher.update(&sig_record.data);
        self.server_seq_num += 1;

        // NewSessionTicket
        let mut ticket_record = read_sync(self.packet_reader.as_mut().unwrap())?;
        ticket_record.decrypt(&traffic_key, self.server_seq_num)?;
        let tickets = read_new_session_ticket(&ticket_record.data)?;

        let psk_access = hkdf_expand(
            com_key.as_slice(),
            "PSK_ACCESS",
            Some(&self.handshake_hasher),
        )?;
        let psk_refresh = hkdf_expand(
            com_key.as_slice(),
            "PSK_REFRESH",
            Some(&self.handshake_hasher),
        )?;
        log::debug!("Short PSK_ACCESS:\n{}", hex::encode(&psk_access));
        log::debug!("Short PSK_REFRESH:\n{}", hex::encode(&psk_refresh));

        self.session = Some(Session {
            tk: tickets,
            psk_access,
            psk_refresh,
            app_key: None,
        });
        self.handshake_hasher.update(&ticket_record.data);
        self.server_seq_num += 1;

        // ServerFinish
        let mut sf_record = read_sync(self.packet_reader.as_mut().unwrap())?;
        sf_record.decrypt(&traffic_key, self.server_seq_num)?;
        let sf = read_server_finish(&sf_record.data)?;
        let sf_key = hkdf_expand(com_key.as_slice(), "server finished", None)?;
        let security_param = compute_hmac(&sf_key, &self.handshake_hasher.clone().finalize());
        if sf.data != security_param {
            return Err(MmtlsError::Protocol(
                "ServerFinish verification failed".into(),
            ));
        }
        self.server_seq_num += 1;
        self.status.store(1, std::sync::atomic::Ordering::SeqCst);
        log::info!("Short-link ECDHE handshake complete");
        Ok(())
    }

    pub async fn request(&mut self, host: &str, path: &str, req: &[u8]) -> Result<Vec<u8>> {
        if self.session.is_none()
            || self
                .session
                .as_ref()
                .is_none_or(|s| s.tk.tickets.is_empty() || s.psk_access.is_empty())
        {
            self.handshake(host).await?;
        }

        log::info!("0-RTT PSK request");
        let addr = format!("{host}:80");
        let mut conn = TcpStream::connect(&addr).await?;
        self.handshake_hasher = sha2::Sha256::new();
        self.client_seq_num = 0;
        self.server_seq_num = 0;

        let http_packet = self.pack_http(host, path, req)?;
        conn.write_all(&http_packet).await?;
        let response = parse_response(&mut conn).await?;
        log::debug!("Receive response:\n{}", hex::encode(&response));
        self.packet_reader = Some(Cursor::new(response));

        // ServerHello
        let hello_record = read_sync(self.packet_reader.as_mut().unwrap())?;
        self.handshake_hasher.update(&hello_record.data);
        self.server_seq_num += 1;

        let session_psk = self.session.as_ref().unwrap().psk_access.clone();
        // Derive server-side key (server_key+server_nonce) for decrypting responses
        use hkdf::Hkdf;
        let hk = Hkdf::<sha2::Sha256>::from_prk(&session_psk)
            .map_err(|_| MmtlsError::Crypto("hkdf from_prk failed".into()))?;
        let mut okm = [0u8; 28];
        hk.expand(
            &build_hkdf_info("handshake key expansion", Some(&self.handshake_hasher)),
            &mut okm,
        )
        .map_err(|_| MmtlsError::Crypto("hkdf expand failed".into()))?;
        let traffic_key = TrafficKeyPair {
            client_key: Vec::new(),
            server_key: okm[..16].to_vec(),
            client_nonce: Vec::new(),
            server_nonce: okm[16..].to_vec(),
        };
        if let Some(session) = &mut self.session {
            session.app_key = Some(traffic_key);
        }

        // ServerFinish
        let mut sf_record = read_sync(self.packet_reader.as_mut().unwrap())?;
        sf_record.decrypt(
            self.session.as_ref().unwrap().app_key.as_ref().unwrap(),
            self.server_seq_num,
        )?;
        self.server_seq_num += 1;

        // Data record
        let mut data_record = read_sync(self.packet_reader.as_mut().unwrap())?;
        data_record.decrypt(
            self.session.as_ref().unwrap().app_key.as_ref().unwrap(),
            self.server_seq_num,
        )?;
        self.server_seq_num += 1;
        let data = data_record.data.clone();

        // Abort
        let mut abort_record = read_sync(self.packet_reader.as_mut().unwrap())?;
        abort_record.decrypt(
            self.session.as_ref().unwrap().app_key.as_ref().unwrap(),
            self.server_seq_num,
        )?;
        self.server_seq_num += 1;

        Ok(data)
    }

    pub async fn close(&mut self) -> Result<()> {
        self.conn = None;
        Ok(())
    }

    fn handshake_complete(&self) -> bool {
        self.status.load(std::sync::atomic::Ordering::SeqCst) == 1
    }

    fn reset(&mut self) {
        self.handshake_hasher = sha2::Sha256::new();
        self.client_seq_num = 0;
        self.server_seq_num = 0;
    }

    fn pack_http(&mut self, host: &str, path: &str, req: &[u8]) -> Result<Vec<u8>> {
        let mut tls_payload = Vec::new();
        let dat_part = gen_data_part(host, path, req)?;

        let session = self
            .session
            .as_ref()
            .ok_or_else(|| MmtlsError::Protocol("no session for pack_http".into()))?;
        let hello = new_psk_zero_hello(&session.tk.tickets[0]);
        let hello_part = hello.serialize();

        self.handshake_hasher.update(&hello_part);
        let early_key = &self.early_data_key(&session.psk_access, &self.handshake_hasher)?;

        tls_payload.extend_from_slice(&create_system_record(hello_part).serialize());

        self.client_seq_num += 1; // seq 1: first encrypted record

        // Extensions
        let mut extensions_part = vec![
            0x00, 0x00, 0x00, 0x10, 0x08, 0x00, 0x00, 0x00, 0x0b, 0x01, 0x00, 0x00, 0x00, 0x06,
            0x00, 0x12,
        ];
        extensions_part.extend_from_slice(&[0u8; 4]);
        let ts = hello.timestamp;
        let ts_bytes = ts.to_be_bytes();
        let pos = extensions_part.len() - 4;
        extensions_part[pos..pos + 4].copy_from_slice(&ts_bytes);

        self.handshake_hasher.update(&extensions_part);
        let mut extensions_record = create_system_record(extensions_part);
        extensions_record.encrypt(early_key, self.client_seq_num)?;
        tls_payload.extend_from_slice(&extensions_record.serialize());
        self.client_seq_num += 1;

        // Request
        let mut request_record = create_raw_data_record(dat_part);
        request_record.encrypt(early_key, self.client_seq_num)?;
        tls_payload.extend_from_slice(&request_record.serialize());
        self.client_seq_num += 1;

        // Abort
        let abort_part = vec![0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x01];
        let mut abort_record = create_abort_record(abort_part);
        abort_record.encrypt(early_key, self.client_seq_num)?;
        tls_payload.extend_from_slice(&abort_record.serialize());
        self.client_seq_num += 1;

        let header = build_request_header(host, tls_payload.len())?;
        Ok([header, tls_payload].concat())
    }

    fn early_data_key(
        &self,
        psk_access: &[u8],
        handshake_hasher: &sha2::Sha256,
    ) -> Result<TrafficKeyPair> {
        compute_traffic_key_n(
            psk_access,
            &build_hkdf_info("early data key expansion", Some(handshake_hasher)),
            28,
        )
    }
}

impl Default for MmtlsClientShort {
    fn default() -> Self {
        Self {
            conn: None,
            status: AtomicI32::new(0),
            public_ecdh: None,
            verify_ecdh: None,
            server_ecdh: None,
            verify_ecdsa: true,
            packet_reader: None,
            handshake_hasher: sha2::Sha256::new(),
            server_seq_num: 0,
            client_seq_num: 0,
            session: None,
        }
    }
}

fn hkdf_expand(com_key: &[u8], info: &str, hasher: Option<&sha2::Sha256>) -> Result<Vec<u8>> {
    use hkdf::Hkdf;
    let hk = Hkdf::<sha2::Sha256>::from_prk(com_key)
        .map_err(|_| MmtlsError::Crypto("hkdf from_prk failed".into()))?;
    let mut okm = [0u8; 32];
    hk.expand(&build_hkdf_info(info, hasher), &mut okm)
        .map_err(|_| MmtlsError::Crypto("hkdf expand failed".into()))?;
    Ok(okm.to_vec())
}

fn gen_data_part(host: &str, path: &str, req: &[u8]) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    write_u16_len_data(&mut buf, path.as_bytes())?;
    write_u16_len_data(&mut buf, host.as_bytes())?;
    write_u32_len_data(&mut buf, req)?;
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&(buf.len() as u32).to_be_bytes());
    pkt.extend_from_slice(&buf);
    Ok(pkt)
}

fn build_request_header(host: &str, length: usize) -> Result<Vec<u8>> {
    let rand_name: String = get_random(4).iter().map(|b| format!("{b:02x}")).collect();
    let header = format!(
        "POST /mmtls/{rand_name} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Accept: */*\r\n\
         Cache-Control: no-cache\r\n\
         Connection: Keep-Alive\r\n\
         Content-Type: application/octet-stream\r\n\
         Content-Length: {length}\r\n\
         Upgrade: mmtls\r\n\
         User-Agent: MicroMessenger Client\r\n\
         \r\n"
    );
    Ok(header.into_bytes())
}

async fn parse_response(conn: &mut TcpStream) -> Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];

    loop {
        let n = conn.read(&mut chunk).await?;
        if n == 0 {
            return Err(MmtlsError::Parse("incomplete HTTP response".into()));
        }
        buf.extend_from_slice(&chunk[..n]);
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut resp = httparse::Response::new(&mut headers);
        match resp.parse(&buf) {
            Ok(httparse::Status::Complete(header_len)) => {
                let body_so_far = buf.len() - header_len;
                let content_length = resp
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
                        return Err(MmtlsError::Parse("incomplete HTTP response body".into()));
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

fn read_sync(r: &mut Cursor<Vec<u8>>) -> Result<MmtlsRecord> {
    let mut header = [0u8; 5];
    r.read_exact(&mut header)?;
    let record_type = header[0];
    let version = u16::from_be_bytes([header[1], header[2]]);
    let length = u16::from_be_bytes([header[3], header[4]]);
    let mut data = vec![0u8; length as usize];
    r.read_exact(&mut data)?;
    Ok(MmtlsRecord {
        record_type,
        version,
        length,
        data,
    })
}
