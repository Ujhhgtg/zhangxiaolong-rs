use crate::{MmtlsError, Result};
use p256::PublicKey;
use std::io::Cursor;

#[allow(unused)]
pub struct ServerHello {
    pub protocol_version: u16,
    pub cipher_suite: u16,
    pub public_key: PublicKey,
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

    // skip flag
    let mut flag_buf = [0u8; 1];
    r.read_exact(&mut flag_buf)?;
    let _flag = flag_buf[0];

    let mut ver_buf = [0u8; 2];
    r.read_exact(&mut ver_buf)?;
    let protocol_version = u16::from_be_bytes(ver_buf);

    let mut cs_buf = [0u8; 2];
    r.read_exact(&mut cs_buf)?;
    let cipher_suite = u16::from_be_bytes(cs_buf);

    // skip server random (32B)
    let mut random_buf = [0u8; 32];
    r.read_exact(&mut random_buf)?;

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
    })
}
