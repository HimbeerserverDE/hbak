use hbak_common::conn::{AuthServ, DEFAULT_PORT};
use hbak_common::message::SyncInfo;
use hbak_common::proto::{LocalNode, Mode, Node, Snapshot};
use hbak_common::{LocalNodeError, NetworkError, RemoteError};

use std::collections::HashMap;
use std::fs::{self, File};
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use clap::Parser;
use fork::{daemon, Fork};

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
/// Background process to serve push and pull requests.
struct Args {
    /// Stay attached to the terminal instead of daemonizing.
    #[arg(short, long)]
    debug: bool,
}

fn main() {
    let args = Args::parse();

    if args.debug {
        match serve() {
            Ok(_) => {}
            Err(e) => eprintln!("Error: {}", e),
        }
    } else {
        match daemon(false, false) {
            Ok(Fork::Parent(_)) => {}
            Ok(Fork::Child) => match serve() {
                Ok(_) => {}
                Err(e) => eprintln!("Error: {}", e),
            },
            Err(e) => eprintln!("Error: {}", io::Error::from_raw_os_error(e)),
        }
    }
}

fn serve() -> Result<(), LocalNodeError> {
    let local_node = Arc::new(LocalNode::new(Mode::Server)?);

    let bind_addr = local_node.config().bind_addr.unwrap_or(SocketAddr::new(
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        DEFAULT_PORT,
    ));

    let listener = TcpListener::bind(bind_addr)?;

    println!("[info] <{}> Listening", bind_addr);

    for stream in listener.incoming() {
        let stream = stream?;
        let peer_addr = stream.peer_addr()?;

        let local_node = Arc::clone(&local_node);
        thread::spawn(move || match handle_client(&local_node, stream) {
            Ok(_) => println!("[info] <{}> Disconnected", peer_addr),
            Err(e) => eprintln!("[warn] <{}> Cannot handle client: {}", peer_addr, e),
        });
    }

    unreachable!()
}

fn handle_client(local_node: &LocalNode, stream: TcpStream) -> Result<(), NetworkError> {
    let peer_addr = stream.peer_addr()?;

    let auth_serv = AuthServ::from(stream);
    let (stream_conn, remote_node_auth) =
        auth_serv.secure_stream(local_node.config().auth.clone())?;

    println!(
        "[info] <{}@{}> Authentication successful",
        remote_node_auth.node_name, peer_addr
    );

    let mut local_sync_info = SyncInfo {
        volumes: HashMap::new(),
    };

    for volume in &remote_node_auth.push {
        let latest_snapshots = local_node.latest_snapshots(volume.clone())?;
        local_sync_info
            .volumes
            .insert(volume.clone(), latest_snapshots);
    }

    let (stream_conn, remote_sync_info) = stream_conn.meta_sync(local_sync_info)?;

    let mut tx = Vec::new();
    for (volume, latest_snapshots) in remote_sync_info.volumes.into_iter().filter(|(volume, _)| {
        remote_node_auth.pull.contains(volume) || volume.node_name() == remote_node_auth.node_name
    }) {
        // Full backup: Either restoring or remote is out of date.
        if volume.node_name() == remote_node_auth.node_name {
            let snapshot = local_node.latest_backup_full(volume.clone())?;
            let r = local_node.export(&snapshot)?;

            tx.push((r, snapshot));
        } else {
            for snapshot in local_node.all_full_after(volume.clone(), latest_snapshots.last_full)? {
                let r = local_node.export(&snapshot)?;
                tx.push((r, snapshot));
            }
        }

        // Incremental backup: Either restoring or remote is out of date.
        let incr = if volume.node_name() == remote_node_auth.node_name {
            local_node.backup_incremental_after(
                volume.clone(),
                local_node.latest_backup_full(volume)?.taken(),
            )?
        } else {
            local_node.all_incremental_after(volume, latest_snapshots.last_incremental)?
        };

        for snapshot in incr {
            let r = local_node.export(&snapshot)?;
            tx.push((r, snapshot));
        }
    }

    for (_, snapshot) in &tx {
        println!(
            "[info] <{}@{}> Queueing {} for transmission",
            remote_node_auth.node_name, peer_addr, snapshot
        );
    }

    let rx_setup =
        |snapshot: &Snapshot| {
            if !remote_node_auth.push.iter().any(|volume| {
                snapshot.is_of_volume(volume) && volume.node_name() != local_node.name()
            }) {
                return Err(RemoteError::AccessDenied);
            }

            if snapshot.backup_path(Mode::Server).exists() {
                return Err(RemoteError::Immutable);
            }

            let file = File::create(snapshot.streaming_path(Mode::Server))
                .map_err(|_| RemoteError::RxError)?;

            println!(
                "[info] <{}@{}> Receiving {}",
                remote_node_auth.node_name, peer_addr, snapshot
            );

            Ok(file)
        };

    let rx_finish = |snapshot: Snapshot| {
        fs::rename(
            snapshot.streaming_path(Mode::Server),
            snapshot.backup_path(Mode::Server),
        )
        .map_err(|_| RemoteError::RxError)?;

        println!(
            "[info] <{}@{}> Received {}",
            remote_node_auth.node_name, peer_addr, snapshot
        );

        Ok(())
    };

    stream_conn.data_sync(tx, rx_setup, rx_finish)
}
