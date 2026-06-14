use serde_json::Value;

use crate::cli::Cli;

/// Resolve the request body from CLI flags.
/// Exactly 0 or 1 of --req-file, --req-proto-json-file, --req-proto-json may be provided.
pub async fn resolve_bytes(cli: &Cli) -> Result<Vec<u8>, String> {
    let present = [&cli.req_file, &cli.req_proto_json_file, &cli.req_proto_json]
        .iter()
        .filter(|o| o.is_some())
        .count();

    if present > 1 {
        return Err(
            "only one of --req-file, --req-proto-json-file, --req-proto-json may be provided"
                .to_string(),
        );
    }

    if let Some(path) = &cli.req_file {
        return tokio::fs::read(path)
            .await
            .map_err(|e| format!("error reading --req-file '{path}': {e}"));
    }

    if let Some(path) = &cli.req_proto_json_file {
        let content = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| format!("error reading --req-proto-json-file '{path}': {e}"))?;
        return json_to_protobuf(&content);
    }

    if let Some(json_str) = &cli.req_proto_json {
        return json_to_protobuf(json_str);
    }

    // None present → empty body
    Ok(Vec::new())
}

/// Convert a protobuf JSON representation (field numbers as keys) to protobuf wire format.
///
/// Expected shape: `{"1": "value", "2": 1234, "3": ["repeated", "fields"]}`
fn json_to_protobuf(json_str: &str) -> Result<Vec<u8>, String> {
    let value: Value =
        serde_json::from_str(json_str).map_err(|e| format!("invalid JSON: {e}"))?;

    let mut buf = Vec::new();
    encode_value(0, &value, &mut buf)?;
    Ok(buf)
}

/// Encode a single JSON value into `buf` as a protobuf field.
///
/// `field_num` is the protobuf field number (0 for top-level — no tag emitted).
fn encode_value(field_num: u32, value: &Value, buf: &mut Vec<u8>) -> Result<(), String> {
    match value {
        Value::Null => {}
        Value::Bool(b) => {
            write_tag(buf, field_num, 0);
            encode_varint(buf, if *b { 1 } else { 0 });
        }
        Value::Number(n) => {
            write_tag(buf, field_num, 0); // varint wire type
            if let Some(v) = n.as_i64() {
                encode_varint(buf, v as u64);
            } else if let Some(v) = n.as_u64() {
                encode_varint(buf, v);
            } else {
                return Err(format!("unsupported numeric value: {n}"));
            }
        }
        Value::String(s) => {
            write_tag(buf, field_num, 2); // length-delimited wire type
            encode_varint(buf, s.len() as u64);
            buf.extend_from_slice(s.as_bytes());
        }
        Value::Array(arr) => {
            for elem in arr {
                encode_value(field_num, elem, buf)?;
            }
        }
        Value::Object(map) => {
            // Encode as sub-message (length-delimited)
            let mut sub = Vec::new();
            for (key, val) in map {
                let sub_field: u32 = key
                    .parse()
                    .map_err(|_| format!("invalid protobuf field number: '{key}'"))?;
                encode_value(sub_field, val, &mut sub)?;
            }
            if field_num != 0 {
                write_tag(buf, field_num, 2);
                encode_varint(buf, sub.len() as u64);
            }
            buf.extend_from_slice(&sub);
        }
    }
    Ok(())
}

/// Write a protobuf wire-format tag: (field_number << 3) | wire_type.
fn write_tag(buf: &mut Vec<u8>, field_num: u32, wire_type: u32) {
    if field_num != 0 {
        encode_varint(buf, ((field_num << 3) | wire_type) as u64);
    }
}

/// Encode `value` as a base128 varint.
fn encode_varint(buf: &mut Vec<u8>, mut value: u64) {
    loop {
        if value < 0x80 {
            buf.push(value as u8);
            break;
        } else {
            buf.push((value as u8 & 0x7F) | 0x80);
            value >>= 7;
        }
    }
}
