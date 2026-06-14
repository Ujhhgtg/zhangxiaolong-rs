// Re-export main types and functions
pub use consts::*;
pub use http_util::parse_http_response_from_byte;
pub use mmtls::{MmtlsClient, new_mmtls_client};
pub use mmtls_short::{MmtlsClientShort, new_mmtls_client_short};
pub use parser::{clean_hex_string, format_records, parse_records, record_type_name};
pub use record::*;
pub use session::Session;
pub use types::*;

// Error type
#[derive(Debug, thiserror::Error)]
pub enum MmtlsError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("protocol error: {0}")]
    Protocol(String),
}

/// Result alias with MmtlsError as the default error type.
pub type Result<T, E = MmtlsError> = std::result::Result<T, E>;

mod client_finish;
mod client_hello;
mod consts;
mod crypto;
mod http_util;
mod mmtls;
mod mmtls_short;
mod parser;
mod record;
mod server_finish;
mod server_hello;
mod session;
mod session_ticket;
mod signature;
mod types;
mod util;
