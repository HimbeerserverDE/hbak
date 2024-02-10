use hbak_common::config::NodeConfig;
use hbak_common::conn::{AuthServ, DEFAULT_PORT};
use hbak_common::message::SyncInfo;
use hbak_common::proto::{LocalNode, Node, Snapshot};
use hbak_common::{LocalNodeError, NetworkError, RemoteError};

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::BufReader;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::thread;

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

        thread::spawn(move || match handle_client(stream) {
            Ok(_) => {}
            Err(e) => eprintln!("[warn] <{}> Cannot handle client: {}", peer_addr, e),
        });
    }

    unreachable!()
}

fn handle_client(stream: TcpStream) -> Result<(), NetworkError> {
    let node = LocalNode::new()?;

    let auth_serv = AuthServ::from(stream);
    let (stream_conn, remote_node_auth) = auth_serv.secure_stream(node.config().auth.clone())?;

    let mut local_sync_info = SyncInfo {
        volumes: HashMap::new(),
    };

    for volume in &remote_node_auth.push {
        let latest_snapshots = node.latest_snapshots(volume.clone())?;
        local_sync_info
            .volumes
            .insert(volume.clone(), latest_snapshots);
    }

    let (stream_conn, remote_sync_info) = stream_conn.meta_sync(local_sync_info)?;

    let mut tx = Vec::new();
    for (volume, latest_snapshots) in remote_sync_info.volumes.into_iter().filter(|(volume, _)| {
        remote_node_auth.pull.contains(volume) || volume.node_name() == remote_node_auth.node_name
    }) {
        let local_latest = node.latest_snapshots(volume.clone())?;

        // Full backup: Either restoring or remote is out of date.
        if volume.node_name() == remote_node_auth.node_name {
            let snapshot = node.latest_backup_full(volume.clone())?;
            let file = File::open(snapshot.backup_path())?;

            tx.push((BufReader::new(file), snapshot));
        } else if latest_snapshots.last_full <= local_latest.last_full {
            for snapshot in node.backup_full_after(volume.clone(), latest_snapshots.last_full)? {
                let file = File::open(snapshot.backup_path())?;
                tx.push((BufReader::new(file), snapshot));
            }
        }

        // Incremental backup: Either restoring or remote is out of date.
        let incr = if volume.node_name() == remote_node_auth.node_name {
            node.backup_incremental_after(volume, local_latest.last_full)?
        } else if latest_snapshots.last_incremental <= local_latest.last_incremental {
            node.backup_incremental_after(volume, latest_snapshots.last_incremental)?
        } else {
            Vec::default()
        };

        for snapshot in incr {
            let file = File::open(snapshot.backup_path())?;
            tx.push((BufReader::new(file), snapshot));
        }
    }

    let rx_setup = |snapshot: &Snapshot| {
        if !remote_node_auth
            .push
            .iter()
            .any(|volume| snapshot.is_of_volume(volume) && volume.node_name() != node.name())
        {
            return Err(RemoteError::AccessDenied);
        }

        if snapshot.backup_path().exists() {
            return Err(RemoteError::Immutable);
        }

        let file = File::create(snapshot.streaming_path()).map_err(|_| RemoteError::RxError)?;
        Ok(file)
    };

    let rx_finish = |snapshot: Snapshot| {
        fs::rename(snapshot.streaming_path(), snapshot.backup_path())
            .map_err(|_| RemoteError::RxError)
    };

    stream_conn.data_sync(tx, rx_setup, rx_finish)
}
