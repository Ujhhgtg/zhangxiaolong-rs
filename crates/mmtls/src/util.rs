use crate::Result;
use rand::Rng;

pub fn get_random(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::rng().fill_bytes(&mut buf);
    buf
}

pub fn xor_nonce(nonce: &mut [u8], seq: u32) {
    let seq_bytes = seq.to_le_bytes();
    let len = nonce.len();
    for i in 0..4 {
        nonce[len - i - 1] ^= seq_bytes[i];
    }
}

pub fn read_u16_len_data(r: &mut dyn std::io::Read) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    r.read_exact(&mut len_buf)?;
    let length = u16::from_be_bytes(len_buf);
    if length > 0 {
        let mut buf = vec![0u8; length as usize];
        r.read_exact(&mut buf)?;
        Ok(buf)
    } else {
        Ok(Vec::new())
    }
}

pub fn write_u32_len_data(w: &mut dyn std::io::Write, d: &[u8]) -> Result<()> {
    w.write_all(&(d.len() as u32).to_be_bytes())?;
    if !d.is_empty() {
        w.write_all(d)?;
    }
    Ok(())
}

pub fn write_u16_len_data(w: &mut dyn std::io::Write, d: &[u8]) -> Result<()> {
    w.write_all(&(d.len() as u16).to_be_bytes())?;
    if !d.is_empty() {
        w.write_all(d)?;
    }
    Ok(())
}
