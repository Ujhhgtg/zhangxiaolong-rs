use crate::Result;
use crate::record::MmtlsRecord;
use crate::consts::{MAGIC_HANDSHAKE, MAGIC_SYSTEM, MAGIC_RECORD, MAGIC_ABORT};
use crate::session_ticket::{read_new_session_ticket, read_session_ticket};
use crate::server_finish::read_server_finish;
use crate::signature::read_signature;
use std::io::{Cursor, Read};
use std::fmt::Write;

#[derive(Clone)]
pub struct ParsedField {
    pub name: String,
    pub value: String,
    pub raw: Vec<u8>,
    pub children: Vec<ParsedField>,
}

#[derive(Clone)]
pub struct ParsedRecord {
    pub index: usize,
    pub record_type: u8,
    pub version: u16,
    pub length: u16,
    pub fields: Vec<ParsedField>,
    pub raw: Vec<u8>,
}

const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: u16 = 0xC02B;

pub fn parse_records(data: &[u8]) -> Result<Vec<ParsedRecord>> {
    let mut remaining = data;
    let mut records = Vec::new();
    let mut idx = 0;

    while !remaining.is_empty() {
        let (rec, consumed) = match read_sync_record(remaining) {
            Ok(r) => r,
            Err(_) => break,
        };

        let mut parsed = ParsedRecord {
            index: idx,
            record_type: rec.record_type,
            version: rec.version,
            length: rec.length,
            raw: rec.data.clone(),
            fields: Vec::new(),
        };

        if (rec.record_type == MAGIC_HANDSHAKE || rec.record_type == MAGIC_SYSTEM)
            && rec.data.len() > 5
        {
            parsed.fields = parse_handshake_payload(&rec.data);
        } else if rec.record_type == MAGIC_RECORD {
            parsed.fields = parse_application_data(&rec.data);
        } else if rec.record_type == MAGIC_ABORT {
            parsed.fields = parse_abort_payload(&rec.data);
        } else if rec.record_type == MAGIC_SYSTEM {
            parsed.fields = encrypted_payload(&rec.data);
        } else {
            parsed.fields = vec![ParsedField {
                name: "Unknown".into(),
                value: format!("({} bytes)", rec.data.len()),
                raw: rec.data.clone(),
                children: vec![],
            }];
        }

        records.push(parsed);
        remaining = &remaining[consumed..];
        idx += 1;
    }

    Ok(records)
}

fn read_sync_record(data: &[u8]) -> Result<(MmtlsRecord, usize)> {
    if data.len() < 5 {
        return Err(crate::MmtlsError::Parse("too short".into()));
    }
    let record_type = data[0];
    let version = u16::from_be_bytes([data[1], data[2]]);
    let length = u16::from_be_bytes([data[3], data[4]]) as usize;
    let total = 5 + length;
    if data.len() < total {
        return Err(crate::MmtlsError::Parse("incomplete record".into()));
    }
    Ok((MmtlsRecord {
        record_type,
        version,
        length: length as u16,
        data: data[5..total].to_vec(),
    }, total))
}

fn parse_handshake_payload(data: &[u8]) -> Vec<ParsedField> {
    if data.len() < 5 { return encrypted_fallback(data); }
    let total_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let flag = data[4];
    if total_len as usize != data.len() - 4 { return encrypted_payload(data); }
    match flag {
        0x01 => parse_client_hello_fields(data),
        0x02 => parse_server_hello_fields(data),
        0x08 => parse_psk_extensions_fields(data),
        0x0F => parse_signature_fields(data),
        0x04 => parse_new_session_ticket_fields(data),
        0x14 => parse_server_finish_fields(data),
        _ => encrypted_payload(data),
    }
}

fn parse_client_hello_fields(data: &[u8]) -> Vec<ParsedField> {
    let mut fields = vec![ParsedField { name: "ClientHello".into(), value: String::new(), raw: data.to_vec(), children: vec![] }];
    let mut r = Cursor::new(data);

    let mut buf = [0u8; 4];
    if r.read_exact(&mut buf).is_err() { return encrypted_fallback(data); }
    let total_len = u32::from_be_bytes(buf);
    fields[0].children.push(ParsedField { name: "Total Length".into(), value: format!("{total_len}"), raw: vec![], children: vec![] });

    let mut b = [0u8; 1];
    if r.read_exact(&mut b).is_err() { return encrypted_fallback(data); }
    fields[0].children.push(ParsedField { name: "Flag".into(), value: format!("0x{:02X}", b[0]), raw: vec![], children: vec![] });

    let mut vb = [0u8; 2];
    if r.read_exact(&mut vb).is_err() { return encrypted_fallback(data); }
    let pv = u16::from_le_bytes(vb);
    fields[0].children.push(ParsedField { name: "Protocol Version".into(), value: format!("0x{pv:04X} (LE)"), raw: vec![], children: vec![] });

    if r.read_exact(&mut b).is_err() { return encrypted_fallback(data); }
    let cs_count = b[0];
    let mut csf = ParsedField { name: "Cipher Suites".into(), value: format!("({cs_count})"), raw: vec![], children: vec![] };
    let mut csb = [0u8; 2];
    for i in 0..cs_count {
        if r.read_exact(&mut csb).is_err() { break; }
        let cs = u16::from_be_bytes(csb);
        csf.children.push(ParsedField { name: format!("[{i}]"), value: format!("{} (0x{cs:04X})", cipher_suite_name(cs)), raw: vec![], children: vec![] });
    }
    fields[0].children.push(csf);

    let mut random = [0u8; 32];
    if r.read_exact(&mut random).is_err() { return encrypted_fallback(data); }
    fields[0].children.push(ParsedField { name: "Client Random".into(), value: format!("{} (32 bytes)", hex::encode(random)), raw: random.to_vec(), children: vec![] });

    let mut ts_buf = [0u8; 4];
    if r.read_exact(&mut ts_buf).is_err() { return encrypted_fallback(data); }
    let ts = u32::from_be_bytes(ts_buf);
    fields[0].children.push(ParsedField { name: "Timestamp".into(), value: format!("{ts} ({})", chrono_now(ts)), raw: vec![], children: vec![] });

    let mut el_buf = [0u8; 4];
    if r.read_exact(&mut el_buf).is_err() { return fields; }
    let ext_len = u32::from_be_bytes(el_buf);
    if r.read_exact(&mut b).is_err() { return fields; }
    let ext_count = b[0];

    let mut extf = ParsedField { name: "Extensions".into(), value: format!("({ext_count}), total {ext_len} bytes"), raw: vec![], children: vec![] };
    let rem = data.len() - r.position() as usize;
    let es = &data[data.len()-rem..];
    let mut er = Cursor::new(es);
    for _ in 0..ext_count {
        if let Some(e) = parse_extension(&mut er) { extf.children.push(e); }
    }
    fields[0].children.push(extf);
    fields
}

fn parse_extension(r: &mut Cursor<&[u8]>) -> Option<ParsedField> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf).ok()?;
    let ext_item_len = u32::from_be_bytes(buf);
    let mut mb = [0u8; 2];
    r.read_exact(&mut mb).ok()?;
    let marker = u16::from_be_bytes(mb);
    match marker {
        0x000F => Some(parse_psk_extension(r, ext_item_len)),
        0x0010 => Some(parse_ecdhe_extension(r, ext_item_len)),
        _ => {
            let rem = ext_item_len as usize - 2;
            let mut d = vec![0u8; rem];
            if rem > 0 { r.read_exact(&mut d).ok()?; }
            Some(ParsedField { name: format!("Unknown Extension (0x{marker:04X})"), value: format!("{rem} bytes"), raw: d, children: vec![] })
        }
    }
}

fn parse_psk_extension(r: &mut Cursor<&[u8]>, _: u32) -> ParsedField {
    let mut field = ParsedField { name: "PSK Extension".into(), value: String::new(), raw: vec![], children: vec![] };
    let mut b = [0u8; 1];
    if r.read_exact(&mut b).is_err() { return field; }
    let tc = b[0];
    field.value = format!("({tc} ticket(s))");
    for i in 0..tc {
        let mut lb = [0u8; 4];
        if r.read_exact(&mut lb).is_err() { break; }
        let tl = u32::from_be_bytes(lb);
        let mut td = vec![0u8; tl as usize];
        if r.read_exact(&mut td).is_err() { break; }
        let mut tf = ParsedField { name: format!("[{i}] Ticket"), value: format!("({tl} bytes)"), raw: td.clone(), children: vec![] };
        if let Ok(st) = read_session_ticket(&td) {
            tf.children.push(ParsedField { name: "Ticket Type".into(), value: format!("0x{:02X}", st.ticket_type), raw: vec![], children: vec![] });
            tf.children.push(ParsedField { name: "Lifetime".into(), value: format!("{} seconds", st.ticket_lifetime), raw: vec![], children: vec![] });
            tf.children.push(ParsedField { name: "Ticket Age Add".into(), value: format!("({} bytes)", st.ticket_age_add.len()), raw: st.ticket_age_add, children: vec![] });
            tf.children.push(ParsedField { name: "Reserved".into(), value: format!("0x{:08X}", st.reversed), raw: vec![], children: vec![] });
            tf.children.push(ParsedField { name: "Nonce".into(), value: format!("({} bytes): {}", st.nonce.len(), hex::encode(&st.nonce)), raw: st.nonce, children: vec![] });
            tf.children.push(ParsedField { name: "Ticket Data".into(), value: format!("({} bytes): {}", st.ticket.len(), truncate_hex(&st.ticket, 32)), raw: st.ticket, children: vec![] });
        }
        field.children.push(tf);
    }
    field
}

fn parse_ecdhe_extension(r: &mut Cursor<&[u8]>, _: u32) -> ParsedField {
    let mut field = ParsedField { name: "ECDHE Extension".into(), value: String::new(), raw: vec![], children: vec![] };
    let mut b = [0u8; 1];
    if r.read_exact(&mut b).is_err() { return field; }
    let kc = b[0];
    field.value = format!("({kc} key(s))");
    for i in 0..kc {
        let mut lb = [0u8; 4];
        if r.read_exact(&mut lb).is_err() { break; }
        r.read_exact(&mut lb).ok();
        let kf = u32::from_be_bytes(lb);
        let mut sb = [0u8; 2];
        if r.read_exact(&mut sb).is_err() { break; }
        let ks = u16::from_be_bytes(sb);
        let mut ep = vec![0u8; ks as usize];
        if r.read_exact(&mut ep).is_err() { break; }
        let mut ph = hex::encode(&ep);
        if ph.len() > 16 { ph = format!("{}...", &ph[..16]); }
        field.children.push(ParsedField { name: format!("[{i}]"), value: format!("Flag={kf}, EC Point ({ks} bytes): {ph}"), raw: ep, children: vec![] });
    }
    let mut magic = [0u8; 13];
    if let Ok(n) = r.read(&mut magic)
        && n > 0 { field.children.push(ParsedField { name: "Trailing Magic".into(), value: format!("{n} bytes"), raw: magic[..n].to_vec(), children: vec![] }); }
    field
}

fn parse_server_hello_fields(data: &[u8]) -> Vec<ParsedField> {
    let mut fields = vec![ParsedField { name: "ServerHello".into(), value: String::new(), raw: data.to_vec(), children: vec![] }];
    let mut r = Cursor::new(data);
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf).ok();
    let tl = u32::from_be_bytes(buf);
    fields[0].children.push(ParsedField { name: "Total Length".into(), value: format!("{tl}"), raw: vec![], children: vec![] });
    let mut b = [0u8; 1];
    r.read_exact(&mut b).ok();
    fields[0].children.push(ParsedField { name: "Flag".into(), value: format!("0x{:02X}", b[0]), raw: vec![], children: vec![] });
    let mut vb = [0u8; 2];
    if r.read_exact(&mut vb).is_err() { return encrypted_fallback(data); }
    fields[0].children.push(ParsedField { name: "Protocol Version".into(), value: format!("0x{:04X}", u16::from_be_bytes(vb)), raw: vec![], children: vec![] });
    if r.read_exact(&mut vb).is_err() { return encrypted_fallback(data); }
    let cs = u16::from_be_bytes(vb);
    fields[0].children.push(ParsedField { name: "Negotiated Cipher Suite".into(), value: format!("{} (0x{cs:04X})", cipher_suite_name(cs)), raw: vec![], children: vec![] });
    let mut sr = [0u8; 32];
    if r.read_exact(&mut sr).is_err() { return encrypted_fallback(data); }
    fields[0].children.push(ParsedField { name: "Server Random".into(), value: format!("{} (32 bytes)", hex::encode(sr)), raw: sr.to_vec(), children: vec![] });
    let mut el = [0u8; 4];
    if r.read_exact(&mut el).is_err() { return fields; }
    let ep = u32::from_be_bytes(el);
    if r.read_exact(&mut b).is_err() { return fields; }
    let ec = b[0];
    let mut ef = ParsedField { name: "Extensions".into(), value: format!("({ec}), total {ep} bytes"), raw: vec![], children: vec![] };
    let rem = data.len() - r.position() as usize;
    let es = &data[data.len()-rem..];
    let mut er = Cursor::new(es);
    for _ in 0..ec {
        if let Some(e) = parse_server_hello_extension(&mut er) { ef.children.push(e); }
    }
    fields[0].children.push(ef);
    fields
}

fn parse_server_hello_extension(r: &mut Cursor<&[u8]>) -> Option<ParsedField> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf).ok()?;
    let eil = u32::from_be_bytes(buf);
    let mut tb = [0u8; 2];
    r.read_exact(&mut tb).ok()?;
    let et = u16::from_be_bytes(tb);
    let mut field = ParsedField { name: format!("Extension (0x{et:04X})"), value: String::new(), raw: vec![], children: vec![] };
    r.read_exact(&mut buf).ok()?;
    let ai = u32::from_be_bytes(buf);
    let mut kb = [0u8; 2];
    r.read_exact(&mut kb).ok()?;
    let kl = u16::from_be_bytes(kb);
    let mut ep = vec![0u8; kl as usize];
    r.read_exact(&mut ep).ok()?;
    field.value = format!("Key Share ({kl} bytes)");
    field.children.push(ParsedField { name: "Array Index".into(), value: format!("{ai}"), raw: vec![], children: vec![] });
    field.children.push(ParsedField { name: "Server EC Public Key".into(), value: format!("({kl} bytes): {}", hex::encode(&ep)), raw: ep, children: vec![] });
    let consumed = 2 + 4 + 2 + kl as usize;
    let rem = eil as usize - consumed;
    if rem > 0 {
        let mut ex = vec![0u8; rem];
        r.read_exact(&mut ex).ok();
        field.children.push(ParsedField { name: "Extra Data".into(), value: format!("({rem} bytes): {}", hex::encode(&ex)), raw: ex, children: vec![] });
    }
    Some(field)
}

fn parse_signature_fields(data: &[u8]) -> Vec<ParsedField> {
    match read_signature(data) {
        Ok(sig) => vec![ParsedField { name: "Signature".into(), value: String::new(), raw: data.to_vec(), children: vec![
            ParsedField { name: "Type".into(), value: format!("0x{:02X}", sig.sig_type), raw: vec![], children: vec![] },
            ParsedField { name: "ECDSA Signature".into(), value: format!("({} bytes): {}", sig.ecdsa_signature.len(), truncate_hex(&sig.ecdsa_signature, 64)), raw: sig.ecdsa_signature, children: vec![] },
        ]}],
        Err(_) => encrypted_fallback(data),
    }
}

fn parse_new_session_ticket_fields(data: &[u8]) -> Vec<ParsedField> {
    match read_new_session_ticket(data) {
        Ok(nst) => {
            let mut field = ParsedField { name: "NewSessionTicket".into(), value: String::new(), raw: data.to_vec(), children: vec![
                ParsedField { name: "Reversed".into(), value: format!("0x{:02X}", nst.reversed), raw: vec![], children: vec![] },
                ParsedField { name: "Ticket Count".into(), value: format!("{}", nst.count), raw: vec![], children: vec![] },
            ]};
            for (i, t) in nst.tickets.iter().enumerate() {
                field.children.push(ParsedField { name: format!("[{i}] Ticket"), value: String::new(), raw: vec![], children: vec![
                    ParsedField { name: "Type".into(), value: format!("0x{:02X}", t.ticket_type), raw: vec![], children: vec![] },
                    ParsedField { name: "Lifetime".into(), value: format!("{} seconds", t.ticket_lifetime), raw: vec![], children: vec![] },
                    ParsedField { name: "Ticket Age Add".into(), value: format!("({} bytes)", t.ticket_age_add.len()), raw: t.ticket_age_add.clone(), children: vec![] },
                    ParsedField { name: "Reserved".into(), value: format!("0x{:08X}", t.reversed), raw: vec![], children: vec![] },
                    ParsedField { name: "Nonce".into(), value: format!("({} bytes): {}", t.nonce.len(), hex::encode(&t.nonce)), raw: t.nonce.clone(), children: vec![] },
                    ParsedField { name: "Ticket Data".into(), value: format!("({} bytes): {}", t.ticket.len(), truncate_hex(&t.ticket, 64)), raw: t.ticket.clone(), children: vec![] },
                ]});
            }
            vec![field]
        }
        Err(_) => encrypted_fallback(data),
    }
}

fn parse_server_finish_fields(data: &[u8]) -> Vec<ParsedField> {
    match read_server_finish(data) {
        Ok(sf) => vec![ParsedField { name: "ServerFinish".into(), value: String::new(), raw: data.to_vec(), children: vec![
            ParsedField { name: "Flag".into(), value: format!("0x{:02X}", sf.reversed), raw: vec![], children: vec![] },
            ParsedField { name: "Verify Data".into(), value: format!("({} bytes): {}", sf.data.len(), truncate_hex(&sf.data, 64)), raw: sf.data, children: vec![] },
        ]}],
        Err(_) => encrypted_fallback(data),
    }
}

fn parse_psk_extensions_fields(data: &[u8]) -> Vec<ParsedField> {
    let mut fields = vec![ParsedField { name: "PSK Extensions (0-RTT)".into(), value: String::new(), raw: data.to_vec(), children: vec![] }];
    let mut r = Cursor::new(data);
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf).ok();
    fields[0].children.push(ParsedField { name: "Total Length".into(), value: format!("{}", u32::from_be_bytes(buf)), raw: vec![], children: vec![] });
    let mut b = [0u8; 1];
    r.read_exact(&mut b).ok();
    fields[0].children.push(ParsedField { name: "Flag".into(), value: format!("0x{:02X}", b[0]), raw: vec![], children: vec![] });
    let rem = &data[5..];
    if rem.len() >= 15 {
        let mut rr = Cursor::new(rem);
        r.read_exact(&mut buf).ok(); // consume from r
        let ext_len = u32::from_be_bytes(buf);
        rr.read_exact(&mut buf).ok();
        rr.read_exact(&mut b).ok();
        rr.read_exact(&mut buf).ok();
        let _il = u32::from_be_bytes(buf);
        let mut mb = [0u8; 2];
        rr.read_exact(&mut mb).ok();
        let marker = u16::from_be_bytes(mb);
        rr.read_exact(&mut buf).ok();
        let ts = u32::from_be_bytes(buf);
        fields[0].children.push(ParsedField { name: "Extension Length".into(), value: format!("{ext_len}"), raw: vec![], children: vec![] });
        fields[0].children.push(ParsedField { name: "Extension Flag".into(), value: format!("0x{:02X}", b[0]), raw: vec![], children: vec![] });
        fields[0].children.push(ParsedField { name: "Inner Length".into(), value: format!("{}", r.position()), raw: vec![], children: vec![] });
        fields[0].children.push(ParsedField { name: "Marker".into(), value: format!("0x{marker:04X}"), raw: vec![], children: vec![] });
        if ts > 0 {
            fields[0].children.push(ParsedField { name: "Timestamp".into(), value: format!("{ts} ({})", chrono_now(ts)), raw: vec![], children: vec![] });
        } else {
            fields[0].children.push(ParsedField { name: "Timestamp".into(), value: "0 (not set)".into(), raw: vec![], children: vec![] });
        }
    } else {
        fields[0].children.push(ParsedField { name: "Raw Data".into(), value: truncate_hex(rem, 64), raw: rem.to_vec(), children: vec![] });
    }
    fields
}

fn parse_abort_payload(data: &[u8]) -> Vec<ParsedField> {
    if data.len() >= 5 {
        let tl = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if tl as usize == data.len() - 4 {
            return vec![ParsedField { name: "Abort (plaintext)".into(), value: String::new(), raw: data.to_vec(), children: vec![
                ParsedField { name: "Total Length".into(), value: format!("{tl}"), raw: vec![], children: vec![] },
                ParsedField { name: "Data".into(), value: truncate_hex(&data[4..], 32), raw: data[4..].to_vec(), children: vec![] },
            ]}];
        }
    }
    vec![ParsedField { name: "Abort (encrypted)".into(), value: format!("({} bytes)", data.len()), raw: data.to_vec(), children: vec![
        ParsedField { name: "Data".into(), value: truncate_hex(data, 80), raw: vec![], children: vec![] },
    ]}]
}

fn parse_application_data(data: &[u8]) -> Vec<ParsedField> {
    let mut field = ParsedField { name: "Application Data".into(), value: format!("({} bytes)", data.len()), raw: data.to_vec(), children: vec![] };
    if data.len() >= 16 {
        let mut r = Cursor::new(data);
        let mut buf = [0u8; 4];
        r.read_exact(&mut buf).ok();
        let il = u32::from_be_bytes(buf);
        r.read_exact(&mut buf).ok(); // pad
        r.read_exact(&mut buf).ok();
        let dt = u32::from_be_bytes(buf);
        r.read_exact(&mut buf).ok();
        let ci = u32::from_be_bytes(buf);
        if il == data.len() as u32 {
            field.children.push(ParsedField { name: "Inner Length".into(), value: format!("{il}"), raw: vec![], children: vec![] });
            field.children.push(ParsedField { name: "Data Type".into(), value: format!("0x{dt:08X}"), raw: vec![], children: vec![] });
            field.children.push(ParsedField { name: "Cmd ID".into(), value: format!("0x{ci:08X} ({ci})"), raw: vec![], children: vec![] });
            if data.len() > 16 {
                field.children.push(ParsedField { name: "Payload".into(), value: format!("({} bytes): {}", data[16..].len(), truncate_hex(&data[16..], 64)), raw: data[16..].to_vec(), children: vec![] });
            }
        }
    }
    vec![field]
}

fn truncate_hex(data: &[u8], max_hex_chars: usize) -> String {
    let s = hex::encode(data);
    if s.len() > max_hex_chars { format!("{}...", &s[..max_hex_chars]) } else { s }
}

fn encrypted_payload(data: &[u8]) -> Vec<ParsedField> {
    vec![ParsedField { name: "Encrypted Payload".into(), value: format!("({} bytes)", data.len()), raw: data.to_vec(), children: vec![
        ParsedField { name: "Data".into(), value: truncate_hex(data, 80), raw: vec![], children: vec![] },
    ]}]
}

fn encrypted_fallback(data: &[u8]) -> Vec<ParsedField> {
    vec![ParsedField { name: "Encrypted Payload".into(), value: format!("({} bytes): {}", data.len(), truncate_hex(data, 64)), raw: data.to_vec(), children: vec![] }]
}

fn cipher_suite_name(cs: u16) -> &'static str {
    match cs {
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        crate::consts::TLS_PSK_WITH_AES_128_GCM_SHA256 => "TLS_PSK_WITH_AES_128_GCM_SHA256",
        _ => "Unknown",
    }
}

pub fn record_type_name(rt: u8) -> &'static str {
    match rt {
        MAGIC_ABORT => "Abort",
        MAGIC_HANDSHAKE => "Handshake",
        MAGIC_RECORD => "Data",
        MAGIC_SYSTEM => "System",
        _ => "Unknown",
    }
}

pub fn format_records(records: &[ParsedRecord]) -> String {
    let mut sb = String::new();
    for (i, rec) in records.iter().enumerate() {
        if i > 0 { sb.push('\n'); }
        let _ = writeln!(sb, "Record #{} [{}] ({} bytes)", rec.index, record_type_name(rec.record_type), rec.length as usize + 5);
        let _ = writeln!(sb, "  Type: {} (0x{:02X})", record_type_name(rec.record_type), rec.record_type);
        let _ = writeln!(sb, "  Version: 0x{:04X}", rec.version);
        let _ = writeln!(sb, "  Length: {}", rec.length);
        for f in &rec.fields { format_field(&mut sb, f, 2); }
    }
    sb
}

fn format_field(sb: &mut String, f: &ParsedField, indent: usize) {
    let p = " ".repeat(indent);
    if f.value.is_empty() { let _ = writeln!(sb, "{p}{}", f.name); }
    else { let _ = writeln!(sb, "{p}{}: {}", f.name, f.value); }
    for c in &f.children { format_field(sb, c, indent + 2); }
}

pub fn clean_hex_string(s: &str) -> String {
    s.replace([' ', '\n', '\r', '\t', ':'], "").replace("0x", "").replace("0X", "")
}

fn chrono_now(ts: u32) -> String {
    use std::time::{UNIX_EPOCH, Duration};
    let d = UNIX_EPOCH + Duration::from_secs(ts as u64);
    let secs = d.duration_since(UNIX_EPOCH).unwrap().as_secs();
    let days = (secs / 86400) as i64;
    let time = secs % 86400;
    let h = time / 3600;
    let m = (time % 3600) / 60;
    let s = time % 60;
    let (y, mo, dy) = civil_from_days(days);
    format!("{y:04}-{mo:02}-{dy:02} {h:02}:{m:02}:{s:02} UTC")
}

fn civil_from_days(d: i64) -> (i64, u32, u32) {
    let d = d + 719468;
    let era = if d >= 0 { d } else { d - 146096 } / 146097;
    let doe = (d - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let yr = y + if mo <= 2 { 1 } else { 0 };
    (yr, mo, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    use crate::session_ticket::*;
    use std::collections::HashSet;

    #[test]
    fn test_parse_client_hello_ecdhe() {
        let (pub_key, ver_key) = crypto::generate_key_pairs().unwrap();
        let ch = client_hello::new_ecdhe_hello(&pub_key.public_key(), &ver_key.public_key());
        let payload = ch.serialize();
        let rec = record::create_handshake_record(payload);
        let data = rec.serialize();
        let records = parse_records(&data).unwrap();
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(r.record_type, MAGIC_HANDSHAKE);
        assert_eq!(r.version, PROTOCOL_VERSION);
        assert!(!r.fields.is_empty());
        assert_eq!(r.fields[0].name, "ClientHello");
        let mut found = HashSet::new();
        for c in &r.fields[0].children { found.insert(c.name.clone()); }
        for name in ["Flag", "Protocol Version", "Cipher Suites", "Client Random", "Timestamp", "Extensions"] {
            assert!(found.contains(name), "missing field: {name}");
        }
        eprintln!("\n{}", format_records(&records));
    }

    #[test]
    fn test_parse_client_hello_psk_zero() {
        let ticket = SessionTicket { ticket_type: 0x01, ticket_lifetime: 86400, ticket_age_add: vec![], reversed: 0x48, nonce: vec![0u8; 12], ticket: b"test-ticket-data-for-psk".to_vec() };
        let ch = client_hello::new_psk_zero_hello(&ticket);
        let rec = record::create_handshake_record(ch.serialize());
        let records = parse_records(&rec.serialize()).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].fields[0].name, "ClientHello");
        for c in &records[0].fields[0].children {
            if c.name == "Cipher Suites" { assert_eq!(c.children.len(), 1); }
        }
        eprintln!("\n{}", format_records(&records));
    }

    #[test]
    fn test_parse_multiple_records() {
        let (pk, vk) = crypto::generate_key_pairs().unwrap();
        let ch = client_hello::new_ecdhe_hello(&pk.public_key(), &vk.public_key());
        let mut data = record::create_handshake_record(ch.serialize()).serialize();
        data.extend_from_slice(&record::create_abort_record(vec![0x00]).serialize());
        data.extend_from_slice(&record::create_data_record(0x01, 0x01, b"hello".to_vec()).serialize());
        let records = parse_records(&data).unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].record_type, MAGIC_HANDSHAKE);
        assert_eq!(records[1].record_type, MAGIC_ABORT);
        assert_eq!(records[2].record_type, MAGIC_RECORD);
        eprintln!("\n{}", format_records(&records));
    }

    #[test]
    fn test_hex_cleaning() {
        for (i, e) in [("16 f1 04 00 05", "16f1040005"),("16:f1:04:00:05","16f1040005"),("0x160xf10x04","16f104"),("16F104\n0005","16F1040005"),("  16 f1 04  ","16f104"),("0X160XF1","16F1")] {
            assert_eq!(clean_hex_string(i), e, "input: {i:?}");
        }
    }

    #[test]
    fn test_parse_new_session_ticket() {
        let nst = NewSessionTicket { reversed: 0x04, count: 1, tickets: vec![SessionTicket { ticket_type: 0x01, ticket_lifetime: 3600, ticket_age_add: vec![0x01, 0x02], reversed: 0x48, nonce: vec![0u8; 12], ticket: b"ticket-data".to_vec() }] };
        let rec = record::create_handshake_record(nst.serialize().unwrap());
        let records = parse_records(&rec.serialize()).unwrap();
        assert_eq!(records[0].fields[0].name, "NewSessionTicket");
        eprintln!("\n{}", format_records(&records));
    }

    #[test]
    fn test_parse_signature() {
        let mut sd = vec![0x30, 0x44, 0x02, 0x20];
        sd.extend_from_slice(&vec![0u8; 60]);
        let mut buf = Vec::new();
        buf.extend_from_slice(&((1 + 2 + sd.len()) as u32).to_be_bytes());
        buf.push(0x0F);
        buf.extend_from_slice(&(sd.len() as u16).to_be_bytes());
        buf.extend_from_slice(&sd);
        let records = parse_records(&record::create_handshake_record(buf).serialize()).unwrap();
        assert_eq!(records[0].fields[0].name, "Signature");
        eprintln!("\n{}", format_records(&records));
    }

    #[test]
    fn test_parse_raw_hex() {
        let (pk, vk) = crypto::generate_key_pairs().unwrap();
        let ch = client_hello::new_ecdhe_hello(&pk.public_key(), &vk.public_key());
        let raw = record::create_handshake_record(ch.serialize()).serialize();
        let hs = hex::encode(&raw);
        let mut sp = String::new();
        for (i, c) in hs.as_bytes().chunks(2).enumerate() { if i > 0 { sp.push(' '); } sp.push_str(std::str::from_utf8(c).unwrap()); }
        let records = parse_records(&hex::decode(clean_hex_string(&sp)).unwrap()).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].fields[0].name, "ClientHello");
    }

    #[test]
    fn test_parse_psk_zero_flow() {
        let mut all = Vec::new();
        let t = SessionTicket { ticket_type: 0x01, ticket_lifetime: 86400, ticket_age_add: vec![], reversed: 0x48, nonce: vec![0x71,0xae,0xce,0xff,0xd8,0x3f,0x29,0x48,0x01,0x02,0x03,0x04], ticket: b"psk-access-ticket-data-here".to_vec() };
        all.extend_from_slice(&record::create_system_record(client_hello::new_psk_zero_hello(&t).serialize()).serialize());
        let mut ee = vec![0u8; 52]; ee[..8].copy_from_slice(&[0x47,0x4c,0x34,0x03,0x71,0x9e,0xaa,0xbb]); all.extend_from_slice(&record::create_system_record(ee).serialize());
        let mut ed = vec![0u8; 96]; ed[..8].copy_from_slice(&[0x98,0xcd,0x6e,0xa0,0x7c,0x6b,0x11,0x22]); all.extend_from_slice(&record::create_raw_data_record(ed).serialize());
        let mut ea = vec![0u8; 40]; ea[..8].copy_from_slice(&[0x8a,0xd1,0xc3,0x42,0x9a,0x30,0x55,0x66]); all.extend_from_slice(&record::create_abort_record(ea).serialize());
        let records = parse_records(&all).unwrap();
        assert_eq!(records.len(), 4);
        assert_eq!(records[0].record_type, MAGIC_SYSTEM); assert_eq!(records[0].fields[0].name, "ClientHello");
        assert_eq!(records[1].record_type, MAGIC_SYSTEM); assert_eq!(records[1].fields[0].name, "Encrypted Payload");
        assert_eq!(records[2].record_type, MAGIC_RECORD);
        assert_eq!(records[3].record_type, MAGIC_ABORT); assert_eq!(records[3].fields[0].name, "Abort (encrypted)");
        eprintln!("\n{}", format_records(&records));
    }

    #[test]
    fn test_parse_server_response() {
        let mut all = Vec::new();
        let mut sh = Vec::new();
        sh.extend_from_slice(&[0u8; 4]); sh.push(0x02); sh.extend_from_slice(&[0xF1, 0x04]); sh.extend_from_slice(&[0xC0, 0x2B]);
        sh.extend_from_slice(&[0x2b,0xa6,0x88,0x7e,0x61,0x5e,0x27,0xeb,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18]);
        let mut ep = vec![0u8; 65]; ep[0]=0x04; ep[1..8].copy_from_slice(&[0xfa,0xe3,0xdc,0x03,0x4a,0x21,0xd9]);
        let ei = (2+4+2+65) as u32; sh.extend_from_slice(&((4+ei) as u32).to_be_bytes()); sh.push(0x01); sh.extend_from_slice(&ei.to_be_bytes());
        sh.extend_from_slice(&[0x00,0x10]); sh.extend_from_slice(&[0u8;4]); sh.extend_from_slice(&65u16.to_be_bytes()); sh.extend_from_slice(&ep);
        let t = (sh.len()-4) as u32; sh[0..4].copy_from_slice(&t.to_be_bytes());
        all.extend_from_slice(&record::create_handshake_record(sh).serialize());
        let mut es = vec![0u8;80]; es[..8].copy_from_slice(&[0xb8,0x79,0xa1,0x60,0xbe,0x6c,0x3f,0x22]); all.extend_from_slice(&record::create_handshake_record(es).serialize());
        let mut et = vec![0u8;120]; et[..8].copy_from_slice(&[0x1a,0x6d,0xc9,0xdd,0x6e,0xf1,0x88,0x44]); all.extend_from_slice(&record::create_handshake_record(et).serialize());
        let mut ef = vec![0u8;48]; ef[..8].copy_from_slice(&[0xb8,0x79,0xa1,0x60,0xbe,0x6c,0x55,0x99]); all.extend_from_slice(&record::create_handshake_record(ef).serialize());
        let records = parse_records(&all).unwrap();
        assert_eq!(records.len(), 4);
        assert_eq!(records[0].fields[0].name, "ServerHello");
        for i in 1..=3 { assert_eq!(records[i].fields[0].name, "Encrypted Payload", "record {i}"); }
        eprintln!("\n{}", format_records(&records));
    }
}
