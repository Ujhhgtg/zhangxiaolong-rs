use crate::client_finish::new_client_finish;
use crate::client_hello::{ClientHello, new_ecdhe_hello, new_psk_one_hello};
use crate::consts::{TCP_NOOP_REQUEST, TCP_NOOP_RESPONSE};
use crate::crypto::{
    build_hkdf_info, compute_ephemeral_secret, compute_hmac, compute_traffic_key_n,
    generate_key_pairs, verify_ecdsa_signature,
};
use crate::record::{MmtlsRecord, create_data_record, create_handshake_record, read_record};
use crate::server_finish::read_server_finish;
use crate::server_hello::{ServerHello, read_server_hello};
use crate::session_ticket::read_new_session_ticket;
use crate::signature::read_signature;
use crate::{MmtlsError, Result, Session, TrafficKeyPair};
use sha2::Digest;
use std::io::Cursor;
use std::sync::atomic::AtomicI32;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

pub struct MmtlsClient {
    conn: Option<TcpStream>,
    status: AtomicI32,
    public_ecdh: Option<p256::SecretKey>,
    verify_ecdh: Option<p256::SecretKey>,
    server_ecdh: Option<p256::PublicKey>,
    handshake_hasher: sha2::Sha256,
    server_seq_num: u32,
    client_seq_num: u32,
    pub session: Option<Session>,
    pub verify_ecdsa: bool,
}

pub fn new_mmtls_client() -> MmtlsClient {
    MmtlsClient::default()
}

impl MmtlsClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn handshake(&mut self, host: &str) -> Result<()> {
        if self.conn.is_none() {
            let conn = TcpStream::connect(host).await?;
            self.conn = Some(conn);
        }

        if self.handshake_complete() {
            return Ok(());
        }

        self.reset();

        let (pub_key, verify) = generate_key_pairs()?;
        eprintln!("CLIENT_PK: {}", hex::encode(pub_key.public_key().to_sec1_bytes()));
        self.public_ecdh = Some(pub_key);
        self.verify_ecdh = Some(verify);

        let ch = match &self.session {
            Some(s) if s.tk.tickets.len() > 1 => {
                log::info!("1-RTT PSK handshake");
                new_psk_one_hello(
                    &self.public_ecdh.as_ref().unwrap().public_key(),
                    &self.verify_ecdh.as_ref().unwrap().public_key(),
                    &s.tk.tickets[1],
                )
            }
            _ => {
                log::info!("1-RTT ECDHE handshake");
                new_ecdhe_hello(
                    &self.public_ecdh.as_ref().unwrap().public_key(),
                    &self.verify_ecdh.as_ref().unwrap().public_key(),
                )
            }
        };
        self.send_client_hello(&ch).await?;

        let server_hello = self.read_server_hello_msg().await?;
        self.server_ecdh = Some(server_hello.public_key);

        let com_key = compute_ephemeral_secret(
            self.server_ecdh.as_ref().unwrap(),
            self.public_ecdh.as_ref().unwrap(),
        );

        let traffic_key = compute_traffic_key_n(
            &com_key,
            &build_hkdf_info("handshake key expansion", Some(&self.handshake_hasher)),
            56,
        )?;

        self.read_signature_msg(&traffic_key).await?;
        self.read_new_session_ticket_msg(&com_key, &traffic_key)
            .await?;
        self.read_server_finish_msg(&com_key, &traffic_key).await?;
        self.send_client_finish_msg(&com_key, &traffic_key).await?;

        let expanded_secret = {
            use hkdf::Hkdf;
            let hk = Hkdf::<sha2::Sha256>::from_prk(&com_key)
                .map_err(|_| MmtlsError::Crypto("hkdf from_prk failed".into()))?;
            let mut okm = [0u8; 32];
            hk.expand(
                &build_hkdf_info("expanded secret", Some(&self.handshake_hasher)),
                &mut okm,
            )
            .map_err(|_| MmtlsError::Crypto("hkdf expand failed".into()))?;
            okm.to_vec()
        };

        let app_key = compute_traffic_key_n(
            &expanded_secret,
            &build_hkdf_info(
                "application data key expansion",
                Some(&self.handshake_hasher),
            ),
            56,
        )?;

        if let Some(session) = &mut self.session {
            session.app_key = Some(app_key);
        }

        self.status.store(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    pub async fn noop(&mut self) -> Result<()> {
        self.send_noop().await?;
        self.read_noop().await?;
        Ok(())
    }

    pub async fn close(&mut self) -> Result<()> {
        log::debug!("Close connection...");
        self.conn = None;
        Ok(())
    }

    fn reset(&mut self) {
        self.handshake_hasher = sha2::Sha256::new();
        self.client_seq_num = 0;
        self.server_seq_num = 0;
    }

    fn handshake_complete(&self) -> bool {
        self.status.load(std::sync::atomic::Ordering::SeqCst) == 1
    }

    async fn send_client_hello(&mut self, hello: &ClientHello) -> Result<()> {
        let data = hello.serialize();
        self.handshake_hasher.update(&data);

        let packet = create_handshake_record(data).serialize();
        log::debug!(
            "Send ClientHello packet({}):\n{}",
            packet.len(),
            hex::encode(&packet)
        );

        if let Some(conn) = &mut self.conn {
            conn.write_all(&packet).await?;
        }
        self.client_seq_num += 1;
        Ok(())
    }

    async fn read_server_hello_msg(&mut self) -> Result<ServerHello> {
        let record = self.read_record().await?;
        self.handshake_hasher.update(&record.data);
        self.server_seq_num += 1;
        read_server_hello(&record.data)
    }

    async fn read_signature_msg(&mut self, traffic_key: &TrafficKeyPair) -> Result<()> {
        let mut record = self.read_record().await?;
        record.decrypt(traffic_key, self.server_seq_num)?;

        let sig = read_signature(&record.data)?;

        if self.verify_ecdsa
            && !verify_ecdsa_signature(
                &self.handshake_hasher.clone().finalize(),
                &sig.ecdsa_signature,
            )
        {
            return Err(MmtlsError::Protocol("verify signature failed".into()));
        }

        self.handshake_hasher.update(&record.data);
        self.server_seq_num += 1;
        Ok(())
    }

    async fn read_new_session_ticket_msg(
        &mut self,
        com_key: &[u8],
        traffic_key: &TrafficKeyPair,
    ) -> Result<()> {
        let mut record = self.read_record().await?;
        record.decrypt(traffic_key, self.server_seq_num)?;

        let tickets = read_new_session_ticket(&record.data)?;

        let psk_access = {
            use hkdf::Hkdf;
            let hk = Hkdf::<sha2::Sha256>::from_prk(com_key)
                .map_err(|_| MmtlsError::Crypto("hkdf from_prk failed".into()))?;
            let mut okm = [0u8; 32];
            hk.expand(
                &build_hkdf_info("PSK_ACCESS", Some(&self.handshake_hasher)),
                &mut okm,
            )
            .map_err(|_| MmtlsError::Crypto("hkdf expand failed".into()))?;
            okm.to_vec()
        };

        let psk_refresh = {
            use hkdf::Hkdf;
            let hk = Hkdf::<sha2::Sha256>::from_prk(com_key)
                .map_err(|_| MmtlsError::Crypto("hkdf from_prk failed".into()))?;
            let mut okm = [0u8; 32];
            hk.expand(
                &build_hkdf_info("PSK_REFRESH", Some(&self.handshake_hasher)),
                &mut okm,
            )
            .map_err(|_| MmtlsError::Crypto("hkdf expand failed".into()))?;
            okm.to_vec()
        };

        log::debug!("PSK_ACCESS:\n{}", hex::encode(&psk_access));
        log::debug!("PSK_REFRESH:\n{}", hex::encode(&psk_refresh));

        self.session = Some(Session {
            tk: tickets,
            psk_access,
            psk_refresh,
            app_key: None,
        });

        self.handshake_hasher.update(&record.data);
        self.server_seq_num += 1;
        Ok(())
    }

    async fn read_server_finish_msg(
        &mut self,
        com_key: &[u8],
        traffic_key: &TrafficKeyPair,
    ) -> Result<()> {
        let mut record = self.read_record().await?;
        record.decrypt(traffic_key, self.server_seq_num)?;

        let sf = read_server_finish(&record.data)?;

        let sf_key = {
            use hkdf::Hkdf;
            let hk = Hkdf::<sha2::Sha256>::from_prk(com_key)
                .map_err(|_| MmtlsError::Crypto("hkdf from_prk failed".into()))?;
            let mut okm = [0u8; 32];
            hk.expand(&build_hkdf_info("server finished", None), &mut okm)
                .map_err(|_| MmtlsError::Crypto("hkdf expand failed".into()))?;
            okm.to_vec()
        };

        let security_param = compute_hmac(&sf_key, &self.handshake_hasher.clone().finalize());

        if sf.data != security_param {
            return Err(MmtlsError::Protocol("security key not compare".into()));
        }

        self.server_seq_num += 1;
        Ok(())
    }

    async fn send_client_finish_msg(
        &mut self,
        com_key: &[u8],
        traffic_key: &TrafficKeyPair,
    ) -> Result<()> {
        let cli_key = {
            use hkdf::Hkdf;
            let hk = Hkdf::<sha2::Sha256>::from_prk(com_key)
                .map_err(|_| MmtlsError::Crypto("hkdf from_prk failed".into()))?;
            let mut okm = [0u8; 32];
            hk.expand(&build_hkdf_info("client finished", None), &mut okm)
                .map_err(|_| MmtlsError::Crypto("hkdf expand failed".into()))?;
            okm.to_vec()
        };

        let hmac_val = compute_hmac(&cli_key, &self.handshake_hasher.clone().finalize());
        let cf = new_client_finish(hmac_val);

        let mut cf_record = create_handshake_record(cf.serialize());
        cf_record.encrypt(traffic_key, self.client_seq_num)?;

        let packet = cf_record.serialize();
        log::debug!(
            "Send ClientFinish packet({}):\n{}",
            packet.len(),
            hex::encode(&packet)
        );

        if let Some(conn) = &mut self.conn {
            conn.write_all(&packet).await?;
        }
        self.client_seq_num += 1;
        Ok(())
    }

    async fn send_noop(&mut self) -> Result<()> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| MmtlsError::Protocol("no session for noop".into()))?;
        let app_key = session
            .app_key
            .as_ref()
            .ok_or_else(|| MmtlsError::Protocol("no app key for noop".into()))?;

        let mut noop = create_data_record(TCP_NOOP_REQUEST, 0xFFFFFFFF, vec![]);
        noop.encrypt(app_key, self.client_seq_num)?;

        let packet = noop.serialize();
        log::debug!(
            "Send Noop packet({}):\n{}",
            packet.len(),
            hex::encode(&packet)
        );

        if let Some(conn) = &mut self.conn {
            conn.write_all(&packet).await?;
        }
        self.client_seq_num += 1;
        Ok(())
    }

    async fn read_noop(&mut self) -> Result<()> {
        let app_key = self
            .session
            .as_ref()
            .and_then(|s| s.app_key.as_ref())
            .cloned()
            .ok_or_else(|| MmtlsError::Protocol("no app key for noop read".into()))?;

        let mut record = self.read_record().await?;
        record.decrypt(&app_key, self.server_seq_num)?;

        let mut r = Cursor::new(&record.data[..]);

        let mut pack_len_buf = [0u8; 4];
        use std::io::Read;
        r.read_exact(&mut pack_len_buf)?;
        let pack_len = u32::from_be_bytes(pack_len_buf);

        if pack_len != 16 {
            return Err(MmtlsError::Protocol(
                "noop response packet length invalid".into(),
            ));
        }

        // skip flag (4B)
        let mut flag_buf = [0u8; 4];
        r.read_exact(&mut flag_buf)?;

        let mut data_type_buf = [0u8; 4];
        r.read_exact(&mut data_type_buf)?;
        let data_type = u32::from_be_bytes(data_type_buf);

        if TCP_NOOP_RESPONSE != data_type {
            return Err(MmtlsError::Protocol(
                "noop response packet type mismatch".into(),
            ));
        }

        self.server_seq_num += 1;
        Ok(())
    }

    async fn read_record(&mut self) -> Result<MmtlsRecord> {
        let conn = self
            .conn
            .as_mut()
            .ok_or_else(|| MmtlsError::Protocol("no connection".into()))?;
        read_record(conn).await
    }
}

impl Default for MmtlsClient {
    fn default() -> Self {
        Self {
            conn: None,
            status: AtomicI32::new(0),
            public_ecdh: None,
            verify_ecdh: None,
            server_ecdh: None,
            handshake_hasher: sha2::Sha256::new(),
            server_seq_num: 0,
            client_seq_num: 0,
            session: None,
            verify_ecdsa: true,
        }
    }
}
