use crate::{MmtlsError, Result};

/// Parse an HTTP response from bytes, logging headers and status.
/// Used only by integration tests to validate the response is parseable.
pub fn parse_http_response_from_byte(data: &[u8]) -> Result<()> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut headers);
    let status = resp
        .parse(data)
        .map_err(|e| MmtlsError::Parse(format!("http parse error: {e}")))?;

    match status {
        httparse::Status::Complete(_) => {
            log::info!(
                "HTTP {} {}",
                resp.code.unwrap_or(0),
                resp.reason.unwrap_or("")
            );
            for h in resp.headers.iter() {
                log::info!("  {}: {:?}", h.name, std::str::from_utf8(h.value).unwrap_or("?"));
            }

            // Body is after headers
            Ok(())
        }
        httparse::Status::Partial => Err(MmtlsError::Parse(
            "incomplete HTTP response".into(),
        )),
    }
}
