use crate::cli::OutputMode;
use crate::highlight;
use serde_json::{Map, Value};

/// Parse and print an HTTP response based on the requested parse mode.
pub fn print(data: &[u8], output: &OutputMode, pretty: bool) {
    match output {
        OutputMode::HexEncode => {
            println!("{}", hex::encode(data));
            return;
        }
        OutputMode::Raw => {
            use std::io::Write;
            let _ = std::io::stdout().write_all(data);
            return;
        }
        OutputMode::Proto => {
            // Extract body from HTTP framing, decode as protobuf, output JSON
            let body = match extract_http_body(data) {
                Ok(b) => b,
                Err(_) => {
                    // Try raw decode in case it's not HTTP-framed
                    match protobuf_decode(data) {
                        Ok(val) => {
                            println!("{}", serde_json::to_string_pretty(&val).unwrap_or_default());
                        }
                        Err(e) => eprintln!("failed to parse response: {e}"),
                    }
                    return;
                }
            };
            match protobuf_decode(&body) {
                Ok(val) => println!("{}", serde_json::to_string_pretty(&val).unwrap_or_default()),
                Err(e) => eprintln!("protobuf decode failed: {e}"),
            }
            return;
        }
        OutputMode::Http | OutputMode::Auto => {}
    }

    // HTTP display logic (OutputMode::Http or OutputMode::Auto with fallback)
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut headers);
    match resp.parse(data) {
        Ok(httparse::Status::Complete(header_len)) => {
            let status_line = format!(
                "HTTP/{} {} {}",
                resp.version.unwrap_or(0),
                resp.code.unwrap_or(0),
                resp.reason.unwrap_or("")
            );
            println!("{status_line}");
            for h in resp.headers.iter() {
                if let Ok(v) = std::str::from_utf8(h.value) {
                    println!("{}: {}", h.name, v);
                } else {
                    println!("{}: {:?}", h.name, h.value);
                }
            }
            println!();

            let body = &data[header_len..];
            let body = decompress_body(body, resp.headers);

            if matches!(output, OutputMode::Auto) {
                if let Ok(val) = protobuf_decode(&body) {
                    println!("{}", serde_json::to_string_pretty(&val).unwrap_or_default());
                    return;
                }
            }

            if let Ok(s) = std::str::from_utf8(&body) {
                let content_type = resp
                    .headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case("content-type"))
                    .and_then(|h| std::str::from_utf8(h.value).ok())
                    .unwrap_or("");
                let highlighted = highlight::by_content_type(s, content_type, pretty);
                print!("{highlighted}");
            } else {
                print!("{}", hex::encode(&body));
            }
            if body.last() != Some(&b'\n') {
                println!();
            }
        }
        Ok(httparse::Status::Partial) => {
            eprintln!("partial http response - printing raw bytes");
            println!("{}", hex::encode(data));
        }
        Err(e) => {
            eprintln!("failed to parse HTTP response: {e}");
            println!("{}", hex::encode(data));
        }
    }
}

/// Extract the HTTP body from a raw HTTP response.
fn extract_http_body(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut headers);
    match resp.parse(data) {
        Ok(httparse::Status::Complete(header_len)) => {
            let body = data[header_len..].to_vec();
            Ok(decompress_body(&body, resp.headers))
        }
        Ok(httparse::Status::Partial) => Err("partial HTTP response".to_string()),
        Err(e) => Err(format!("HTTP parse error: {e}")),
    }
}

/// Decompress `body` if the response has a Content-Encoding header.
fn decompress_body(body: &[u8], headers: &[httparse::Header<'_>]) -> Vec<u8> {
    let encoding = headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-encoding"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .unwrap_or("")
        .trim()
        .to_lowercase();

    match encoding.as_str() {
        "deflate" => {
            use std::io::Read;
            let mut decoder = flate2::read::ZlibDecoder::new(body);
            let mut out = Vec::new();
            if decoder.read_to_end(&mut out).is_err() {
                // Fall back to raw deflate
                let mut decoder = flate2::read::DeflateDecoder::new(body);
                out.clear();
                decoder.read_to_end(&mut out).unwrap_or_default();
            }
            out
        }
        "gzip" => {
            use std::io::Read;
            let mut decoder = flate2::read::GzDecoder::new(body);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out).unwrap_or_default();
            out
        }
        _ => body.to_vec(),
    }
}

/// Decode protobuf wire-format bytes into a JSON value.
///
/// Field numbers become string keys. Repeated fields become JSON arrays.
/// Length-delimited values: try sub-message decode; if that fails, try UTF-8 string;
/// otherwise base64-encode.
fn protobuf_decode(data: &[u8]) -> Result<Value, String> {
    let mut fields: Map<String, Value> = Map::new();
    let mut pos = 0;

    while pos < data.len() {
        let (tag, n) = read_varint(data, pos).map_err(|e| format!("tag: {e}"))?;
        pos = n;
        let field_number = tag >> 3;
        let wire_type = tag & 0x07;

        let (value, consumed) = match wire_type {
            0 => {
                let (v, n) = read_varint(data, pos)
                    .map_err(|e| format!("varint field {field_number}: {e}"))?;
                (Value::from(v), n)
            }
            1 => {
                if pos + 8 > data.len() {
                    return Err(format!("64-bit field {field_number}: unexpected EOF"));
                }
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&data[pos..pos + 8]);
                let v = u64::from_le_bytes(buf);
                (Value::from(v), pos + 8)
            }
            2 => {
                let (len, n) = read_varint(data, pos)
                    .map_err(|e| format!("length field {field_number}: {e}"))?;
                let len = len as usize;
                let start = n;
                let end = start + len;
                if end > data.len() {
                    return Err(format!(
                        "length-delimited field {field_number}: unexpected EOF"
                    ));
                }
                let raw = &data[start..end];
                let value = decode_length_delimited(raw);
                (value, end)
            }
            5 => {
                if pos + 4 > data.len() {
                    return Err(format!("32-bit field {field_number}: unexpected EOF"));
                }
                let mut buf = [0u8; 4];
                buf.copy_from_slice(&data[pos..pos + 4]);
                let v = u32::from_le_bytes(buf);
                (Value::from(v), pos + 4)
            }
            _ => {
                return Err(format!(
                    "unknown wire type {wire_type} for field {field_number}"
                ));
            }
        };

        let key = field_number.to_string();
        if let Some(existing) = fields.remove(&key) {
            let arr = match existing {
                Value::Array(mut a) => {
                    a.push(value);
                    a
                }
                _ => vec![existing, value],
            };
            fields.insert(key, Value::Array(arr));
        } else {
            fields.insert(key, value);
        }

        pos = consumed;
    }

    Ok(Value::Object(fields))
}

/// Decode a length-delimited protobuf value.
/// Try sub-message decode, then UTF-8 string, then base64.
fn decode_length_delimited(raw: &[u8]) -> Value {
    // Try sub-message decode
    if let Ok(child) = protobuf_decode(raw) {
        if !child.as_object().map_or(false, |m| m.is_empty()) {
            return child;
        }
    }
    // Try UTF-8 string
    if let Ok(s) = std::str::from_utf8(raw) {
        return Value::String(s.to_string());
    }
    // Fall back to base64
    Value::String(format!(
        "base64:{}",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, raw)
    ))
}

/// Read a protobuf base128 varint from `data` starting at `pos`.
/// Returns (value, new_position).
fn read_varint(data: &[u8], pos: usize) -> Result<(u64, usize), String> {
    let mut result: u64 = 0;
    let mut shift = 0;
    let mut p = pos;
    loop {
        if p >= data.len() {
            return Err("unexpected EOF reading varint".to_string());
        }
        let byte = data[p] as u64;
        p += 1;
        result |= (byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            return Ok((result, p));
        }
        shift += 7;
        if shift > 63 {
            return Err("varint too long".to_string());
        }
    }
}
