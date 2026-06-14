use crate::Result;
use std::io::Cursor;

pub struct ServerFinish {
    pub reversed: u8,
    pub data: Vec<u8>,
}

impl ServerFinish {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(7 + self.data.len());
        use std::io::Write;
        let total_len = (self.data.len() + 3) as u32; // reversed(1) + len(2) + data
        buf.write_all(&total_len.to_be_bytes()).unwrap();
        buf.write_all(&[self.reversed]).unwrap();
        buf.write_all(&(self.data.len() as u16).to_be_bytes())
            .unwrap();
        buf.write_all(&self.data).unwrap();
        buf
    }
}

pub fn read_server_finish(buf: &[u8]) -> Result<ServerFinish> {
    let mut r = Cursor::new(buf);
    use std::io::Read;

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

    Ok(ServerFinish { reversed, data })
}
