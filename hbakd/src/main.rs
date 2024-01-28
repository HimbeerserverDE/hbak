use hbak_common::config::NodeConfig;
use hbak_common::conn::{AuthServ, DEFAULT_PORT};
use hbak_common::{LocalNodeError, NetworkError};

use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};

use clap::Parser;
use fork::{daemon, Fork};

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
/// Background process to serve push and pull requests.
struct Args {
    /// Stay attached to the terminal instead of daemonizing.
    debug: bool,
}

fn main() {
    let args = Args::parse();

    if args.debug {
        match serve() {
            Ok(_) => {}
            Err(e) => eprintln!("Error: {}", e),
        }
    } else if let Ok(Fork::Child) = daemon(false, false) {
        match serve() {
            Ok(_) => {}
            Err(e) => eprintln!("Error: {}", e),
        }
    }
}

fn serve() -> Result<(), LocalNodeError> {
    let node_config = NodeConfig::load()?;
    let bind_addr = node_config.bind_addr.unwrap_or(SocketAddr::new(
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        DEFAULT_PORT,
    ));

    let listener = TcpListener::bind(bind_addr)?;

    println!("[info] Listening on <{}>", bind_addr);

    for stream in listener.incoming() {
        let stream = stream?;
        let peer_addr = stream.peer_addr()?;

        match handle_client(stream, &node_config) {
            Ok(_) => {}
            Err(e) => eprintln!("[warn] <{}> Cannot handle client: {}", peer_addr, e),
        }
    }

    unreachable!()
}

fn handle_client(stream: TcpStream, node_config: &NodeConfig) -> Result<(), NetworkError> {
    let auth_serv = AuthServ::from(stream);
    let (stream_conn, remote_node_auth) = auth_serv.secure_stream(node_config.auth.clone())?;

    Ok(())
}
