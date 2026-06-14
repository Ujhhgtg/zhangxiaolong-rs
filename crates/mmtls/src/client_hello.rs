use crate::consts::{PROTOCOL_VERSION, TLS_PSK_WITH_AES_128_GCM_SHA256};
use crate::session_ticket::SessionTicket;
use p256::PublicKey;
use std::collections::HashMap;
use std::io::Cursor;

// TLS cipher suite constants (from Go's crypto/tls)
pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: u16 = 0xC02B;

pub struct ClientHello {
    pub protocol_version: u16,
    pub cipher_suites: Vec<u16>,
    pub random: Vec<u8>,
    pub timestamp: u32,
    pub extensions: HashMap<u16, Vec<Vec<u8>>>,
}

pub fn new_ecdhe_hello(cli_pub_key: &PublicKey, cli_ver_key: &PublicKey) -> ClientHello {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;

    let mut extensions = HashMap::new();
    let cli_pub_key_bytes = cli_pub_key.to_sec1_bytes().to_vec();
    let verify_key_bytes = cli_ver_key.to_sec1_bytes().to_vec();
    extensions.insert(
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        vec![cli_pub_key_bytes, verify_key_bytes],
    );

    ClientHello {
        protocol_version: PROTOCOL_VERSION,
        timestamp,
        random: crate::util::get_random(32),
        cipher_suites: vec![TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256],
        extensions,
    }
}

pub fn new_psk_one_hello(
    cli_pub_key: &PublicKey,
    cli_ver_key: &PublicKey,
    ticket: &SessionTicket,
) -> ClientHello {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;

    let mut t = ticket.clone();
    t.ticket_age_add = Vec::new();
    let ticket_data = t.serialize().expect("serialize session ticket");

    let mut extensions = HashMap::new();
    extensions.insert(TLS_PSK_WITH_AES_128_GCM_SHA256, vec![ticket_data]);

    let cli_pub_key_bytes = cli_pub_key.to_sec1_bytes().to_vec();
    let verify_key_bytes = cli_ver_key.to_sec1_bytes().to_vec();
    extensions.insert(
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        vec![cli_pub_key_bytes, verify_key_bytes],
    );

    ClientHello {
        protocol_version: PROTOCOL_VERSION,
        timestamp,
        random: crate::util::get_random(32),
        cipher_suites: vec![
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            TLS_PSK_WITH_AES_128_GCM_SHA256,
        ],
        extensions,
    }
}

pub fn new_psk_zero_hello(ticket: &SessionTicket) -> ClientHello {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;

    let mut t = ticket.clone();
    t.ticket_age_add = Vec::new();
    let ticket_data = t.serialize().expect("serialize session ticket");

    let mut extensions = HashMap::new();
    extensions.insert(TLS_PSK_WITH_AES_128_GCM_SHA256, vec![ticket_data]);

    ClientHello {
        protocol_version: PROTOCOL_VERSION,
        timestamp,
        random: crate::util::get_random(32),
        cipher_suites: vec![TLS_PSK_WITH_AES_128_GCM_SHA256],
        extensions,
    }
}

impl ClientHello {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::with_capacity(512);

        // total length placeholder
        buf.extend_from_slice(&[0u8; 4]);
        // flag
        buf.push(0x01);

        // protocol version (2B LE)
        let ver_bytes = self.protocol_version.to_le_bytes();
        buf.extend_from_slice(&[0u8; 2]);
        let len = buf.len();
        buf[len - 2..len].copy_from_slice(&ver_bytes);

        // cipher suites
        buf.push(self.cipher_suites.len() as u8);
        for &cs in &self.cipher_suites {
            buf.extend_from_slice(&[0u8; 2]);
            let len = buf.len();
            buf[len - 2..len].copy_from_slice(&cs.to_be_bytes());
        }

        // random
        buf.extend_from_slice(&self.random);

        // timestamp (4B BE)
        buf.extend_from_slice(&[0u8; 4]);
        let len = buf.len();
        buf[len - 4..len].copy_from_slice(&self.timestamp.to_be_bytes());

        // Extensions
        let cipher_pos = buf.len();
        buf.extend_from_slice(&[0u8; 4]); // extensions total length placeholder
        buf.push(self.cipher_suites.len() as u8);

        // Iterate in reverse to match Go's loop order
        for i in (0..self.cipher_suites.len()).rev() {
            let cipher = self.cipher_suites[i];
            if cipher == TLS_PSK_WITH_AES_128_GCM_SHA256 {
                let psk_pos = buf.len();
                buf.extend_from_slice(&[0u8; 4]); // psk ext length placeholder
                buf.extend_from_slice(&[0x00, 0x0F]); // PSK marker
                buf.push(0x01); // ticket count

                let key_pos = buf.len();
                buf.extend_from_slice(&[0u8; 4]); // ticket length placeholder
                let tickets = self.extensions.get(&cipher).expect("PSK extension data");
                buf.extend_from_slice(&tickets[0]);

                let psk_end = buf.len();
                buf[key_pos..key_pos + 4]
                    .copy_from_slice(&((psk_end - key_pos - 4) as u32).to_be_bytes());
                buf[psk_pos..psk_pos + 4]
                    .copy_from_slice(&((psk_end - psk_pos - 4) as u32).to_be_bytes());
            } else if cipher == TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 {
                let ecdsa_pos = buf.len();
                buf.extend_from_slice(&[0u8; 4]); // ecdsa ext length placeholder
                buf.extend_from_slice(&[0x00, 0x10]); // ECDHE marker
                let keys = self.extensions.get(&cipher).expect("ECDHE extension data");
                buf.push(keys.len() as u8);

                let mut key_flag: u32 = 5;
                for key_data in keys {
                    let key_pos = buf.len();
                    buf.extend_from_slice(&[0u8; 4]); // key length placeholder

                    buf.extend_from_slice(&[0u8; 4]);
                    let len = buf.len();
                    buf[len - 4..len].copy_from_slice(&key_flag.to_be_bytes());
                    key_flag += 1;

                    buf.extend_from_slice(&[0u8; 2]);
                    let len = buf.len();
                    buf[len - 2..len].copy_from_slice(&(key_data.len() as u16).to_be_bytes());

                    buf.extend_from_slice(key_data);

                    let key_end = buf.len();
                    buf[key_pos..key_pos + 4]
                        .copy_from_slice(&((key_end - key_pos - 4) as u32).to_be_bytes());
                }

                // trailing magic
                buf.extend_from_slice(&[
                    0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04,
                ]);

                let ecdsa_end = buf.len();
                buf[ecdsa_pos..ecdsa_pos + 4]
                    .copy_from_slice(&((ecdsa_end - ecdsa_pos - 4) as u32).to_be_bytes());
            }
        }

        // fix cipher length
        let cipher_end = buf.len();
        buf[cipher_pos..cipher_pos + 4]
            .copy_from_slice(&((cipher_end - cipher_pos - 4) as u32).to_be_bytes());

        // fix total length
        let total_len = buf.len() - 4;
        buf[0..4].copy_from_slice(&(total_len as u32).to_be_bytes());

        buf
    }
}

pub fn read_client_hello(buf: &[u8]) -> crate::Result<ClientHello> {
    let mut r = Cursor::new(buf);
    use std::io::Read;

    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let _total_len = u32::from_be_bytes(len_buf);

    // flag
    let mut flag_buf = [0u8; 1];
    r.read_exact(&mut flag_buf)?;

    // protocol version (LE)
    let mut ver_buf = [0u8; 2];
    r.read_exact(&mut ver_buf)?;
    let protocol_version = u16::from_le_bytes(ver_buf);

    // cipher suites
    let mut cs_count_buf = [0u8; 1];
    r.read_exact(&mut cs_count_buf)?;
    let cs_count = cs_count_buf[0];
    let mut cipher_suites = Vec::with_capacity(cs_count as usize);
    for _ in 0..cs_count {
        let mut cs_buf = [0u8; 2];
        r.read_exact(&mut cs_buf)?;
        cipher_suites.push(u16::from_be_bytes(cs_buf));
    }

    // random (32B)
    let mut random_buf = [0u8; 32];
    r.read_exact(&mut random_buf)?;
    let random = random_buf.to_vec();

    // timestamp (4B BE)
    let mut ts_buf = [0u8; 4];
    r.read_exact(&mut ts_buf)?;
    let timestamp = u32::from_be_bytes(ts_buf);

    // extensions
    let mut ext_len_buf = [0u8; 4];
    r.read_exact(&mut ext_len_buf)?;
    let _ext_total_len = u32::from_be_bytes(ext_len_buf);

    let mut ext_count_buf = [0u8; 1];
    r.read_exact(&mut ext_count_buf)?;
    let ext_count = ext_count_buf[0];

    let mut extensions: HashMap<u16, Vec<Vec<u8>>> = HashMap::new();

    for _ in 0..ext_count {
        let mut item_len_buf = [0u8; 4];
        r.read_exact(&mut item_len_buf)?;
        let ext_item_len = u32::from_be_bytes(item_len_buf) as usize;
        let ext_start = r.position() as usize;

        let mut ext_type_buf = [0u8; 2];
        r.read_exact(&mut ext_type_buf)?;
        let ext_type = u16::from_be_bytes(ext_type_buf);

        match ext_type {
            0x000F => {
                // PSK extension
                let mut tc_buf = [0u8; 1];
                r.read_exact(&mut tc_buf)?;
                let tc = tc_buf[0];
                let mut tickets = Vec::with_capacity(tc as usize);
                for _ in 0..tc {
                    let mut tl_buf = [0u8; 4];
                    r.read_exact(&mut tl_buf)?;
                    let tl = u32::from_be_bytes(tl_buf) as usize;
                    let mut td = vec![0u8; tl];
                    r.read_exact(&mut td)?;
                    tickets.push(td);
                }
                extensions.insert(TLS_PSK_WITH_AES_128_GCM_SHA256, tickets);
            }
            0x0010 => {
                // ECDHE extension
                let mut kc_buf = [0u8; 1];
                r.read_exact(&mut kc_buf)?;
                let kc = kc_buf[0];
                let mut keys = Vec::with_capacity(kc as usize);
                for _ in 0..kc {
                    // key entry length (4B)
                    let mut kel_buf = [0u8; 4];
                    r.read_exact(&mut kel_buf)?;
                    // key flag (4B)
                    let mut kf_buf = [0u8; 4];
                    r.read_exact(&mut kf_buf)?;
                    // key data length (2B)
                    let mut kdl_buf = [0u8; 2];
                    r.read_exact(&mut kdl_buf)?;
                    let kdl = u16::from_be_bytes(kdl_buf) as usize;
                    let mut kd = vec![0u8; kdl];
                    r.read_exact(&mut kd)?;
                    keys.push(kd);
                }
                extensions.insert(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, keys);
                // consume trailing magic (13 bytes)
                let consumed = r.position() as usize - ext_start;
                let remaining = ext_item_len.saturating_sub(2).saturating_sub(consumed);
                if remaining > 0 {
                    let mut _magic = vec![0u8; remaining];
                    r.read_exact(&mut _magic)?;
                }
            }
            _ => {
                // unknown extension, skip remaining bytes
                let consumed = r.position() as usize - ext_start;
                let remaining = ext_item_len.saturating_sub(2).saturating_sub(consumed);
                if remaining > 0 {
                    let mut _skip = vec![0u8; remaining];
                    r.read_exact(&mut _skip)?;
                }
            }
        }
    }

    Ok(ClientHello {
        protocol_version,
        cipher_suites,
        random,
        timestamp,
        extensions,
    })
}
