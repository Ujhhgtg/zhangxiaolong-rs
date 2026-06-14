use crate::Result;
use std::io::Cursor;

pub struct Signature {
    pub sig_type: u8,
    pub ecdsa_signature: Vec<u8>,
}

impl Signature {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(7 + self.ecdsa_signature.len());
        use std::io::Write;
        let total_len = (self.ecdsa_signature.len() + 3) as u32; // type(1) + len(2) + sig
        buf.write_all(&total_len.to_be_bytes()).unwrap();
        buf.write_all(&[self.sig_type]).unwrap();
        buf.write_all(&(self.ecdsa_signature.len() as u16).to_be_bytes())
            .unwrap();
        buf.write_all(&self.ecdsa_signature).unwrap();
        buf
    }
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
