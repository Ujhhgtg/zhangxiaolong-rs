use clap::{
    Parser, ValueEnum,
    builder::{
        Styles,
        styling::{AnsiColor, Effects},
    },
};

#[derive(Parser)]
#[command(name = "mmtls-cli", version, about = "Send MMTLS requests",
    styles = Styles::styled()
        .header(AnsiColor::BrightGreen.on_default() | Effects::BOLD | Effects::UNDERLINE)
        .usage(AnsiColor::Cyan.on_default() | Effects::BOLD)
        .literal(AnsiColor::BrightCyan.on_default() | Effects::BOLD)
        .placeholder(AnsiColor::Cyan.on_default()))]
pub struct Cli {
    /// Connection mode: shortlink or longlink (only shortlink supported)
    #[arg(short, long, value_enum, default_value_t = LinkMode::Shortlink)]
    pub link_mode: LinkMode,

    /// MMTLS host (e.g. "dns.weixin.qq.com.cn" or "host:port")
    pub host: String,

    /// Request path (e.g. "/cgi-bin/micromsg-bin/newgetdns")
    pub path: String,

    /// File whose raw bytes become the request body
    #[arg(short = 'f', long)]
    pub req_file: Option<String>,

    /// JSON file path; converted to protobuf wire format as request body
    #[arg(long)]
    pub req_proto_json_file: Option<String>,

    /// Inline JSON string converted to protobuf wire format as request body (e.g. '{"1": "hello", "2": 42}')
    #[arg(long)]
    pub req_proto_json: Option<String>,

    /// Output mode: "hex-encode" = hex dump, "raw" = raw bytes,
    /// "http" = HTTP with highlighting, "proto" = decode body as protobuf JSON,
    /// "auto" = detect from content
    #[arg(long, default_value = "raw")]
    pub output: OutputMode,

    /// Enable syntax highlighting for human-readable output.
    /// Disable with --pretty-printing false, NO_COLOR env var, or piped output.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub pretty_printing: bool,
}

#[derive(Clone, ValueEnum)]
pub enum LinkMode {
    Shortlink,
    Longlink,
}

#[derive(Clone, ValueEnum)]
pub enum OutputMode {
    HexEncode,
    Raw,
    Http,
    Proto,
    Auto,
}
