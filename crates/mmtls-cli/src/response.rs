use crate::highlight;

/// Parse and print an HTTP response to stdout in human-readable format.
pub fn print(data: &[u8], pretty: bool) {
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
