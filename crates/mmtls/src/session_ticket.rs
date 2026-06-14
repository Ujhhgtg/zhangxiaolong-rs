use crate::Result;
use crate::util::{read_u16_len_data, write_u16_len_data, write_u32_len_data};
use std::io::Cursor;

#[derive(Clone)]
pub struct SessionTicket {
    pub ticket_type: u8,
    pub ticket_lifetime: u32,
    pub ticket_age_add: Vec<u8>,
    pub reversed: u32,
    pub nonce: Vec<u8>,
    pub ticket: Vec<u8>,
}

#[derive(Clone)]
pub struct NewSessionTicket {
    pub reversed: u8,
    pub count: u8,
    pub tickets: Vec<SessionTicket>,
}

pub fn read_new_session_ticket(buf: &[u8]) -> Result<NewSessionTicket> {
    let mut r = Cursor::new(buf);

    let mut len_buf = [0u8; 4];
    use std::io::Read;
    r.read_exact(&mut len_buf)?;
    let _length = u32::from_be_bytes(len_buf);

    let mut reversed_buf = [0u8; 1];
    r.read_exact(&mut reversed_buf)?;
    let reversed = reversed_buf[0];

    let mut count_buf = [0u8; 1];
    r.read_exact(&mut count_buf)?;
    let count = count_buf[0];

    let mut tickets = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let mut ticket_len_buf = [0u8; 4];
        r.read_exact(&mut ticket_len_buf)?;
        let ticket_len = u32::from_be_bytes(ticket_len_buf) as usize;
        let mut ticket_buf = vec![0u8; ticket_len];
        r.read_exact(&mut ticket_buf)?;
        let ticket = read_session_ticket(&ticket_buf)?;
        tickets.push(ticket);
    }

    Ok(NewSessionTicket {
        reversed,
        count,
        tickets,
    })
}

pub fn read_session_ticket(buf: &[u8]) -> Result<SessionTicket> {
    let mut r = Cursor::new(buf);
    use std::io::Read;

    let mut ticket_type_buf = [0u8; 1];
    r.read_exact(&mut ticket_type_buf)?;
    let ticket_type = ticket_type_buf[0];

    let mut lifetime_buf = [0u8; 4];
    r.read_exact(&mut lifetime_buf)?;
    let ticket_lifetime = u32::from_be_bytes(lifetime_buf);

    let ticket_age_add = read_u16_len_data(&mut r)?;

    let mut reversed_buf = [0u8; 4];
    r.read_exact(&mut reversed_buf)?;
    let reversed = u32::from_be_bytes(reversed_buf);

    let nonce = read_u16_len_data(&mut r)?;
    let ticket = read_u16_len_data(&mut r)?;

    Ok(SessionTicket {
        ticket_type,
        ticket_lifetime,
        ticket_age_add,
        reversed,
        nonce,
        ticket,
    })
}

impl SessionTicket {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        use std::io::Write;
        buf.write_all(&[self.ticket_type])?;
        buf.write_all(&self.ticket_lifetime.to_be_bytes())?;
        write_u16_len_data(&mut buf, &self.ticket_age_add)?;
        buf.write_all(&self.reversed.to_be_bytes())?;
        write_u16_len_data(&mut buf, &self.nonce)?;
        write_u16_len_data(&mut buf, &self.ticket)?;

        Ok(buf)
    }
}

impl NewSessionTicket {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        use std::io::Write;
        // placeholder for total length
        buf.write_all(&[0u8; 4])?;
        buf.write_all(&[0x04])?; // reversed
        buf.write_all(&[self.count])?;

        for ticket in &self.tickets {
            let ticket_bytes = ticket.serialize()?;
            write_u32_len_data(&mut buf, &ticket_bytes)?;
        }

        // fix total length
        let total_len = (buf.len() - 4) as u32;
        buf[0..4].copy_from_slice(&total_len.to_be_bytes());

        Ok(buf)
    }

    pub fn export(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        let ticket_data = self.tickets[0].serialize()?;
        write_u32_len_data(&mut buf, &ticket_data)?;
        Ok(buf)
    }
}
