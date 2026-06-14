mod cli;
mod highlight;
mod request;
mod response;

use clap::Parser;
use cli::LinkMode;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = cli::Cli::parse();

    match cli.link_mode {
        LinkMode::Shortlink => {
            let req_bytes = match request::resolve_bytes(&cli).await {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::FAILURE;
                }
            };

            let mut client = mmtls::new_mmtls_client_short();
            client.verify_ecdsa = false;

            match client.request(&cli.host, &cli.path, &req_bytes).await {
                Ok(resp) => {
                    if cli.parse_http {
                        response::print(&resp, cli.pretty_printing);
                    } else {
                        println!("{}", hex::encode(&resp));
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("mmtls request failed: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        LinkMode::Longlink => {
            eprintln!("longlink mode is not yet implemented");
            ExitCode::FAILURE
        }
    }
}
