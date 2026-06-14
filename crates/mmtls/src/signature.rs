use crate::Result;
use std::io::Cursor;

pub struct Signature {
    pub sig_type: u8,
    pub ecdsa_signature: Vec<u8>,
}

pub fn read_signature(buf: &[u8]) -> Result<Signature> {
    let mut r = Cursor::new(buf);
    use std::io::Read;

    // skip total length (4B)
    let mut _len_buf = [0u8; 4];
    r.read_exact(&mut _len_buf)?;

    let mut type_buf = [0u8; 1];
    r.read_exact(&mut type_buf)?;
    let sig_type = type_buf[0];

    let mut sig_len_buf = [0u8; 2];
    r.read_exact(&mut sig_len_buf)?;
    let sig_len = u16::from_be_bytes(sig_len_buf);

    let mut sig_data = vec![0u8; sig_len as usize];
    r.read_exact(&mut sig_data)?;

    Ok(Signature {
        sig_type,
        ecdsa_signature: sig_data,
    })
}
