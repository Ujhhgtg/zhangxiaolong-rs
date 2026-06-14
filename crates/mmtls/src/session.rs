use crate::session_ticket::{NewSessionTicket, read_new_session_ticket};
use crate::util::{read_u16_len_data, write_u16_len_data};
use crate::{Result, TrafficKeyPair};
use std::io::Cursor;

pub struct Session {
    pub tk: NewSessionTicket,
    pub psk_access: Vec<u8>,
    pub psk_refresh: Vec<u8>,
    pub app_key: Option<TrafficKeyPair>,
}

impl Session {
    pub async fn save(&self, path: &str) -> Result<()> {
        let mut buf = Vec::new();
        write_u16_len_data(&mut buf, &self.psk_access)?;
        write_u16_len_data(&mut buf, &self.psk_refresh)?;
        let ticket_bytes = self.tk.serialize()?;
        buf.extend_from_slice(&ticket_bytes);

        tokio::fs::write(path, &buf).await?;
        Ok(())
    }

    pub async fn load(path: &str) -> Result<Self> {
        let data = tokio::fs::read(path).await?;
        let mut r = Cursor::new(&data[..]);

        let psk_access = read_u16_len_data(&mut r)?;
        let psk_refresh = read_u16_len_data(&mut r)?;

        let pos = r.position() as usize;
        let ticket_bytes = &data[pos..];
        let tk = read_new_session_ticket(ticket_bytes)?;

        Ok(Session {
            tk,
            psk_access,
            psk_refresh,
            app_key: None,
        })
    }
}
