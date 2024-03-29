// hbakd is an hbak server providing clients with push and pull access.
// Copyright (C) 2024  Himbeer <himbeerserverde@gmail.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

mod error;
use error::*;

use hbak_common::conn::{AuthServ, DEFAULT_PORT, READ_TIMEOUT};
use hbak_common::message::SyncInfo;
use hbak_common::proto::{LocalNode, Mode, Node, Snapshot};
use hbak_common::stream::CHUNKSIZE;
use hbak_common::RemoteError;

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufWriter};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::{cmp, process, thread};

use clap::Parser;
use daemonizr::{Daemonizr, DaemonizrError, Stderr, Stdout};

const PWD: &str = "/";
const PIDFILE: &str = "/run/hbakd.pid";
const LOGFILE_STDOUT: &str = "/var/log/hbakd.out";
const LOGFILE_STDERR: &str = "/var/log/hbakd.err";

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

    if !args.debug {
        match Daemonizr::new()
            .work_dir(PathBuf::from(PWD))
            .expect("invalid workdir")
            .pidfile(PathBuf::from(PIDFILE))
            .stdout(Stdout::Redirect(PathBuf::from(LOGFILE_STDOUT)))
            .stderr(Stderr::Redirect(PathBuf::from(LOGFILE_STDERR)))
            .umask(0o027)
            .expect("invalid umask")
            .spawn()
        {
            Ok(_) => {}
            Err(DaemonizrError::AlreadyRunning) => {
                match Daemonizr::new()
                    .work_dir(PathBuf::from(PWD))
                    .unwrap()
                    .pidfile(PathBuf::from(PIDFILE))
                    .search()
                {
                    Ok(pid) => {
                        eprintln!("Another daemon with PID {} is already running", pid);
                        process::exit(1);
                    }
                    Err(e) => eprintln!("Daemonization PID search error: {}", e),
                }
            }
            Err(e) => {
                eprintln!("Daemonization error: {}", e);
                process::exit(1);
            }
        }
    }

    match serve() {
        Ok(_) => {}
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    }
}

fn serve() -> Result<()> {
    let should_exit = Arc::new(AtomicBool::new(false));
    let should_exit2 = Arc::clone(&should_exit);

    ctrlc::set_handler(move || {
        eprintln!("[info] Caught SIGINT, SIGTERM or SIGHUP, exiting");
        should_exit2.store(true, Ordering::SeqCst);
    })?;

    let client_threads = Arc::new(Mutex::new(0));

    let local_node = Arc::new(LocalNode::new(Mode::Server)?);

    let bind_addr = local_node.config().bind_addr.unwrap_or(SocketAddr::new(
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        DEFAULT_PORT,
    ));

    let listener = TcpListener::bind(bind_addr)?;

    listener.set_nonblocking(true)?;

    eprintln!("[info] <{}> Listening", bind_addr);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let peer_addr = stream.peer_addr()?;

                *client_threads.lock().unwrap() += 1;

                let local_node = Arc::clone(&local_node);
                let client_threads = Arc::clone(&client_threads);
                thread::spawn(move || {
                    match handle_client(&local_node, stream) {
                        Ok(_) => {
                            eprintln!("[info] <{}> Disconnected", peer_addr)
                        }
                        Err(e) => {
                            eprintln!("[warn] <{}> Cannot handle client: {}", peer_addr, e)
                        }
                    }

                    *client_threads.lock().unwrap() -= 1;
                });
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if should_exit.load(Ordering::SeqCst) {
                    break;
                } else {
                    thread::sleep(READ_TIMEOUT);
                }
            }
            Err(e) => return Err(e.into()),
        }
    }

    while *client_threads.lock().unwrap() > 0 {
        thread::sleep(READ_TIMEOUT);
    }

    Ok(())
}

fn handle_client(local_node: &LocalNode, stream: TcpStream) -> Result<()> {
    let peer_addr = stream.peer_addr()?;

    let auth_serv = AuthServ::from(stream);
    let (stream_conn, remote_node_auth) =
        auth_serv.secure_stream(local_node.config().auth.clone())?;

    eprintln!(
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

            if snapshot.taken() > latest_snapshots.last_full {
                let r = local_node.export(&snapshot)?;
                tx.push((r, snapshot));
            }
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
                cmp::max(
                    cmp::max(
                        latest_snapshots.last_full,
                        local_node.latest_backup_full(volume)?.taken(),
                    ),
                    latest_snapshots.last_incremental,
                ),
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
        eprintln!(
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

            eprintln!(
                "[info] <{}@{}> Receiving {}",
                remote_node_auth.node_name, peer_addr, snapshot
            );

            Ok(BufWriter::with_capacity(2 * CHUNKSIZE, file))
        };

    let rx_finish = |snapshot: Snapshot| {
        fs::rename(
            snapshot.streaming_path(Mode::Server),
            snapshot.backup_path(Mode::Server),
        )
        .map_err(|_| RemoteError::RxError)?;

        eprintln!(
            "[info] <{}@{}> Received {}",
            remote_node_auth.node_name, peer_addr, snapshot
        );

        Ok(())
    };

    stream_conn.data_sync(tx, rx_setup, rx_finish)?;

    Ok(())
}
