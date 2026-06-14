use crate::util::xor_nonce;
use crate::{Result, TrafficKeyPair};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use tokio::io::{AsyncRead, AsyncReadExt};

pub struct DataRecord {
    pub data_type: u32,
    pub cmd_id: u32,
    pub data: Vec<u8>,
}

impl DataRecord {
    pub fn serialize(&self) -> Vec<u8> {
        let length = self.data.len() + 16;
        let mut buf = Vec::with_capacity(length);
        buf.extend_from_slice(&(length as u32).to_be_bytes());
        buf.extend_from_slice(&[0u8; 4]); // flags
        buf.extend_from_slice(&self.data_type.to_be_bytes());
        buf.extend_from_slice(&self.cmd_id.to_be_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }
}

#[derive(Debug, Clone)]
pub struct MmtlsRecord {
    pub record_type: u8,
    pub version: u16,
    pub length: u16,
    pub data: Vec<u8>,
}

impl MmtlsRecord {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(5 + self.data.len());
        buf.push(self.record_type);
        buf.extend_from_slice(&self.version.to_be_bytes());
        buf.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }

    pub fn encrypt(&mut self, keys: &TrafficKeyPair, client_seq_num: u32) -> Result<()> {
        let mut nonce_bytes = keys.client_nonce.clone();
        xor_nonce(&mut nonce_bytes, client_seq_num);

        let cipher = Aes128Gcm::new_from_slice(&keys.client_key)
            .map_err(|_| crate::MmtlsError::Crypto("invalid key for encrypt".into()))?;
        let nonce = Nonce::try_from(&nonce_bytes)
            .map_err(|_| crate::MmtlsError::Crypto("invalid nonce bytes".into()))?;

        let ciphertext = cipher
            .encrypt(&nonce, self.data.as_ref())
            .map_err(|_| crate::MmtlsError::Crypto("encryption failed".into()))?;

        // Prepend nonce to ciphertext (matching Go: nonce || ciphertext+tag)
        let mut out = nonce_bytes;
        out.extend_from_slice(&ciphertext);
        self.data = out;
        Ok(())
    }

    pub fn decrypt(&mut self, keys: &TrafficKeyPair, server_seq_num: u32) -> Result<()> {
        if self.data.len() < 28 {
            return Err(crate::MmtlsError::Parse(
                "data too short for decrypt".into(),
            ));
        }
        let recv_nonce = self.data[..12].to_vec();
        let ciphertext = &self.data[12..];

        let mut nonce_bytes = keys.server_nonce.clone();
        xor_nonce(&mut nonce_bytes, server_seq_num);

        if recv_nonce != nonce_bytes {
            return Err(crate::MmtlsError::Crypto(
                "nonce mismatch in decrypt".into(),
            ));
        }

        let cipher = Aes128Gcm::new_from_slice(&keys.server_key)
            .map_err(|_| crate::MmtlsError::Crypto("invalid key for decrypt".into()))?;
        let nonce = Nonce::try_from(&nonce_bytes)
            .map_err(|_| crate::MmtlsError::Crypto("invalid nonce bytes".into()))?;

        let plaintext = cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| crate::MmtlsError::Crypto("decryption failed".into()))?;

        self.data = plaintext;
        Ok(())
    }
}

pub fn create_abort_record(data: Vec<u8>) -> MmtlsRecord {
    create_record(crate::MAGIC_ABORT, data)
}

pub fn create_handshake_record(data: Vec<u8>) -> MmtlsRecord {
    create_record(crate::MAGIC_HANDSHAKE, data)
}

pub fn create_data_record(data_type: u32, seq: u32, data: Vec<u8>) -> MmtlsRecord {
    let dr = DataRecord {
        data_type,
        cmd_id: seq,
        data,
    };
    create_record(crate::MAGIC_RECORD, dr.serialize())
}

pub fn create_raw_data_record(data: Vec<u8>) -> MmtlsRecord {
    create_record(crate::MAGIC_RECORD, data)
}

pub fn create_system_record(data: Vec<u8>) -> MmtlsRecord {
    create_record(crate::MAGIC_SYSTEM, data)
}

pub fn create_record(record_type: u8, data: Vec<u8>) -> MmtlsRecord {
    MmtlsRecord {
        record_type,
        version: crate::PROTOCOL_VERSION,
        length: data.len() as u16,
        data,
    }
}

pub async fn read_record(r: &mut (impl AsyncRead + Unpin)) -> Result<MmtlsRecord> {
    let mut header = [0u8; 5];
    r.read_exact(&mut header).await?;

    let record_type = header[0];
    let version = u16::from_be_bytes([header[1], header[2]]);
    let length = u16::from_be_bytes([header[3], header[4]]);

    let mut data = vec![0u8; length as usize];
    r.read_exact(&mut data).await?;

    Ok(MmtlsRecord {
        record_type,
        version,
        length,
        data,
    })
}
