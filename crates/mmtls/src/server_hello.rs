use crate::{MmtlsError, Result};
use p256::PublicKey;
use std::io::Cursor;

pub struct ServerHello {
    pub protocol_version: u16,
    pub cipher_suite: u16,
    pub public_key: PublicKey,
    pub random: Vec<u8>,
}

impl ServerHello {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        use std::io::Write;
        // placeholder for total length
        buf.write_all(&[0u8; 4]).unwrap();
        buf.write_all(&[0x01]).unwrap(); // flag
        buf.write_all(&self.protocol_version.to_be_bytes()).unwrap();
        buf.write_all(&self.cipher_suite.to_be_bytes()).unwrap();
        // server random (32B)
        buf.write_all(&self.random).unwrap();
        // extensions
        let ext_pos = buf.len();
        buf.write_all(&[0u8; 4]).unwrap(); // ext total len placeholder
        buf.write_all(&[0x01]).unwrap(); // count = 1
        // ECDHE extension
        let ext_item_pos = buf.len();
        buf.write_all(&[0u8; 4]).unwrap(); // ext item len placeholder
        buf.write_all(&[0x00, 0x10]).unwrap(); // type = ECDHE
        buf.write_all(&[0x00, 0x00, 0x00, 0x01]).unwrap(); // array index = 1
        let key_bytes = self.public_key.to_sec1_bytes();
        buf.write_all(&(key_bytes.len() as u16).to_be_bytes())
            .unwrap();
        buf.write_all(&key_bytes).unwrap();
        // fix lengths
        let ext_item_end = buf.len();
        buf[ext_item_pos..ext_item_pos + 4]
            .copy_from_slice(&((ext_item_end - ext_item_pos - 4) as u32).to_be_bytes());
        buf[ext_pos..ext_pos + 4]
            .copy_from_slice(&((ext_item_end - ext_pos - 4) as u32).to_be_bytes());
        // fix total length
        let total_len = buf.len() - 4;
        buf[0..4].copy_from_slice(&(total_len as u32).to_be_bytes());
        buf
    }
}

pub fn read_server_hello(buf: &[u8]) -> Result<ServerHello> {
    let mut r = Cursor::new(buf);
    use std::io::Read;

    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let pack_len = u32::from_be_bytes(len_buf);

    if buf.len() != pack_len as usize + 4 {
        return Err(MmtlsError::Parse("server hello data corrupted".into()));
    }

    // flag
    let mut flag_buf = [0u8; 1];
    r.read_exact(&mut flag_buf)?;
    let _flag = flag_buf[0];

    let mut ver_buf = [0u8; 2];
    r.read_exact(&mut ver_buf)?;
    let protocol_version = u16::from_be_bytes(ver_buf);

    let mut cs_buf = [0u8; 2];
    r.read_exact(&mut cs_buf)?;
    let cipher_suite = u16::from_be_bytes(cs_buf);

    // server random (32B)
    let mut random_buf = [0u8; 32];
    r.read_exact(&mut random_buf)?;
    let random = random_buf.to_vec();

    // skip extensions package length (4B)
    let mut ext_pkg_buf = [0u8; 4];
    r.read_exact(&mut ext_pkg_buf)?;

    // skip extensions count (1B)
    let mut ext_count_buf = [0u8; 1];
    r.read_exact(&mut ext_count_buf)?;

    // skip extension package length (4B)
    let mut ext_item_buf = [0u8; 4];
    r.read_exact(&mut ext_item_buf)?;

    // skip extension type (2B)
    let mut ext_type_buf = [0u8; 2];
    r.read_exact(&mut ext_type_buf)?;

    // skip array index (4B)
    let mut array_idx_buf = [0u8; 4];
    r.read_exact(&mut array_idx_buf)?;

    let mut key_len_buf = [0u8; 2];
    r.read_exact(&mut key_len_buf)?;
    let key_len = u16::from_be_bytes(key_len_buf);

    let mut ec_point = vec![0u8; key_len as usize];
    r.read_exact(&mut ec_point)?;

    let public_key = PublicKey::from_sec1_bytes(&ec_point)
        .map_err(|e| MmtlsError::Parse(format!("invalid public key: {e}")))?;

    Ok(ServerHello {
        protocol_version,
        cipher_suite,
        public_key,
        random,
    })
}
