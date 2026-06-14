pub struct ClientFinish {
    pub reversed: u8,
    pub data: Vec<u8>,
}

pub fn new_client_finish(data: Vec<u8>) -> ClientFinish {
    ClientFinish {
        reversed: 0x14,
        data,
    }
}

impl ClientFinish {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.data.len() + 7);

        // total length: len(data) + 3
        let total_len = (self.data.len() + 3) as u32;
        buf.extend_from_slice(&total_len.to_be_bytes());

        buf.push(self.reversed);

        let data_len = self.data.len() as u16;
        buf.extend_from_slice(&data_len.to_be_bytes());

        buf.extend_from_slice(&self.data);

        buf
    }
}
