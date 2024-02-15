// hbak is a tool for distributed incremental btrfs snapshotting.
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

use hbak_common::config::{NodeConfig, RemoteNode, RemoteNodeAuth};
use hbak_common::conn::{AuthConn, DEFAULT_PORT};
use hbak_common::message::SyncInfo;
use hbak_common::proto::{LocalNode, Mode, Node, Snapshot, Volume};
use hbak_common::system;
use hbak_common::{LocalNodeError, RemoteError};

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Empty};
use std::net::SocketAddr;
use std::sync::Mutex;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Perform basic initialization of the local node.
    Init {
        /// Initialize the configuration file but not the btrfs subvolumes.
        #[arg(short, long)]
        config_only: bool,
        /// The device file the local btrfs file system is located at.
        device: String,
        /// The name to use for this node.
        node_name: String,
        /// The network address `hbakd` binds to. The default is `[::]:20406` (dual stack).
        bind_addr: Option<SocketAddr>,
    },
    /// Fully clean the local node of non-binary files with optional backup removal.
    Clean {
        /// Remove the btrfs subvolumes that contain the snapshots and backups.
        #[arg(short, long)]
        backups: bool,
    },
    /// Mark a subvolume as owned by the local node.
    Track {
        /// The name of the subvolume to mark as owned.
        subvol: String,
    },
    /// Remove the local node ownership mark from a subvolume.
    Untrack {
        /// The name of the subvolume to unmark as owned.
        subvol: String,
    },
    /// Add or modify a remote to push to or pull from.
    AddRemote {
        /// The network address and optional port of the remote node.
        address: String,
        /// The volumes to push to the remote node.
        #[arg(long)]
        push: Vec<String>,
        /// The volumes to pull from the remote node.
        /// Subvolumes owned by the local node are silently ignored.
        #[arg(long)]
        pull: Vec<String>,
    },
    /// Remove a remote without deleting anything.
    RmRemote {
        /// The network address and optional port of the node to forget.
        address: String,
    },
    /// Add or modify authentication and authorization information for a remote client.
    Grant {
        /// The name of the remote node to apply the information to.
        node_name: String,
        /// The volumes the remote node is allowed to push.
        /// Subvolumes owned by the local node are silently ignored.
        #[arg(long)]
        push: Vec<String>,
        /// The volumes the remote node is allowed to pull.
        #[arg(long)]
        pull: Vec<String>,
    },
    /// Modify permissions for a remote client without changing the passphrase.
    SetPerms {
        /// The name of the remote node to apply the information to.
        node_name: String,
        /// The volumes the remote node is allowed to push.
        /// Subvolumes owned by the local node are silently ignored.
        #[arg(long)]
        push: Vec<String>,
        /// The volumes the remote node is allowed to pull.
        #[arg(long)]
        pull: Vec<String>,
    },
    /// Revoke a remote client all access and delete local configuration about it.
    Revoke {
        /// The name of the remote node to remove from the security configuration.
        node_name: String,
    },
    /// Export a random verifier and key of the local encryption passphrase.
    ExportPass,
    /// Take a (local) snapshot of the specified subvolumes.
    Snapshot {
        /// Take incremental snapshots rather than full snapshots.
        #[arg(short, long)]
        incremental: bool,
        /// The subvolumes to limit snapshotting to.
        subvols: Vec<String>,
    },
    /// Synchronize snapshots with remote nodes.
    Synchronize {
        /// The volumes to limit pushing to.
        #[arg(long)]
        push: Vec<String>,
        /// The volumes to limit pulling to.
        #[arg(long)]
        pull: Vec<String>,
        /// The network addresses and optional ports of the nodes to limit synchronization to.
        remote_nodes: Vec<String>,
    },
    /// Restore the local node to the latest remote backup.
    Restore {
        /// Do not restore the latest snapshots to the subvolumes.
        #[arg(short = 'r', long)]
        no_restore: bool,
        /// Do not keep the fstab file from an existing subvolume.
        #[arg(short = 'f', long)]
        ignore_fstab: bool,
        /// The device file the local btrfs file system is located at.
        device: String,
        /// The name this node was previously known under.
        node_name: String,
        /// The network address and optional port of the node to download from.
        address: Option<String>,
        /// The subvolumes to recover.
        #[arg(short, long)]
        subvols: Vec<String>,
    },
}

fn logic() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init {
            config_only,
            device,
            node_name,
            bind_addr,
        } => {
            let passphrase = rpassword::prompt_password("Enter new encryption passphrase: ")?;
            system::init(config_only, device, bind_addr, node_name, passphrase)?;
        }
        Commands::Clean { backups } => {
            system::deinit(backups)?;
        }
        Commands::Track { subvol } => {
            let mut node_config = NodeConfig::load()?;

            node_config.subvols.retain(|item| *item != subvol);
            node_config.subvols.push(subvol);
            node_config.save()?;
        }
        Commands::Untrack { subvol } => {
            let mut node_config = NodeConfig::load()?;

            node_config.subvols.retain(|item| *item != subvol);
            node_config.save()?;
        }
        Commands::AddRemote {
            address,
            push,
            pull,
        } => {
            let mut node_config = NodeConfig::load()?;

            node_config.remotes.retain(|item| item.address != address);
            node_config.remotes.push(RemoteNode {
                address,
                push: Volume::try_from_bulk(push)?,
                pull: Volume::try_from_bulk(pull)?,
            });
            node_config.save()?;
        }
        Commands::RmRemote { address } => {
            let mut node_config = NodeConfig::load()?;

            node_config.remotes.retain(|item| item.address != address);
            node_config.save()?;
        }
        Commands::Grant {
            node_name,
            mut push,
            pull,
        } => {
            // Unmount the btrfs before potentially getting killed at prompts.
            {
                let local_node = LocalNode::new(Mode::Client)?;

                push.retain(|subvol| !local_node.owns_subvol(subvol));
            }

            println!("Use the passphrase export results from the remote node below.");
            let verifier_hex = rpassword::prompt_password("Enter verifier: ")?;
            let verifier = hex::decode(verifier_hex)?;
            let key_hex = rpassword::prompt_password("Enter key: ")?;
            let key = hex::decode(key_hex)?;

            let mut node_config = NodeConfig::load()?;

            node_config.auth.retain(|item| item.node_name != node_name);
            node_config.auth.push(RemoteNodeAuth {
                node_name,
                verifier,
                key,
                push: Volume::try_from_bulk(push)?,
                pull: Volume::try_from_bulk(pull)?,
            });
            node_config.save()?;
        }
        Commands::SetPerms {
            node_name,
            mut push,
            pull,
        } => {
            let local_node = LocalNode::new(Mode::Client)?;

            push.retain(|subvol| !local_node.owns_subvol(subvol));

            let mut node_config = NodeConfig::load()?;

            for item in &mut node_config.auth {
                if item.node_name == node_name {
                    item.push = Volume::try_from_bulk(push)?;
                    item.pull = Volume::try_from_bulk(pull)?;

                    break;
                }
            }

            node_config.save()?;
        }
        Commands::Revoke { node_name } => {
            let mut node_config = NodeConfig::load()?;

            node_config.auth.retain(|item| item.node_name != node_name);
            node_config.save()?;
        }
        Commands::ExportPass => {
            let node_config = NodeConfig::load()?;
            let (verifier, key) = system::hash_passphrase(node_config.passphrase)?;

            println!("Verifier: {}", hex::encode(verifier));
            println!("Key:      {}", hex::encode(key));
        }
        Commands::Snapshot {
            incremental,
            subvols,
        } => {
            let local_node = LocalNode::new(Mode::Client)?;

            let subvols = if subvols.is_empty() {
                &local_node.config().subvols
            } else {
                &subvols
            }
            .iter();

            for subvol in subvols {
                if !local_node.owns_subvol(subvol) {
                    return Err(LocalNodeError::ForeignSubvolume(subvol.clone()).into());
                }

                println!("Snapshotting {}...", subvol);
                local_node.snapshot_now(subvol.clone(), incremental)?;
            }
        }
        Commands::Synchronize {
            push,
            pull,
            remote_nodes,
        } => {
            let local_node = LocalNode::new(Mode::Client)?;

            for remote_node in local_node
                .config()
                .remotes
                .iter()
                .filter(|item| remote_nodes.is_empty() || remote_nodes.contains(&item.address))
            {
                println!("Synchronizing with {}...", remote_node.address);
                sync(&local_node, remote_node, &push, &pull)?;
            }
        }
        Commands::Restore {
            no_restore,
            ignore_fstab,
            device,
            node_name,
            address,
            subvols,
        } => {
            let passphrase = rpassword::prompt_password("Enter passphrase: ")?;

            let local_node = LocalNode::with_config(
                Mode::Client,
                NodeConfig {
                    device,
                    bind_addr: None,
                    node_name,
                    subvols,
                    passphrase,
                    remotes: Vec::default(),
                    auth: Vec::default(),
                },
            )?;

            if let Some(address) = &address {
                println!("Restoring from {}...", address);
            } else {
                println!("Restoring locally...");
            }

            restore(&local_node, address.as_deref(), no_restore, ignore_fstab)?;
        }
    }

    Ok(())
}

fn main() {
    match logic() {
        Ok(_) => {}
        Err(e) => eprintln!("Error: {}", e),
    }
}

fn sync(
    local_node: &LocalNode,
    remote_node: &RemoteNode,
    push: &[String],
    pull: &[String],
) -> Result<()> {
    let address = match remote_node.address.parse() {
        Ok(address) => address,
        Err(_) => SocketAddr::new(remote_node.address.parse()?, DEFAULT_PORT),
    };

    let auth_conn = AuthConn::new(&address)?;
    let stream_conn = auth_conn.secure_stream(
        local_node.name().to_string(),
        remote_node.address.to_string(),
        &local_node.config().passphrase,
    )?;

    println!("Authentication to {} successful", remote_node.address);

    let mut local_sync_info = SyncInfo {
        volumes: HashMap::new(),
    };

    for volume in remote_node
        .pull
        .iter()
        .filter(|volume| volume.node_name() != local_node.name())
        .filter(|volume| pull.is_empty() || pull.contains(&volume.to_string()))
    {
        let latest_snapshots = local_node.latest_snapshots(volume.clone())?;
        local_sync_info
            .volumes
            .insert(volume.clone(), latest_snapshots);
    }

    let (stream_conn, remote_sync_info) = stream_conn.meta_sync(local_sync_info)?;

    let mut tx = Vec::new();
    for (volume, latest_snapshots) in remote_sync_info
        .volumes
        .into_iter()
        .filter(|(volume, _)| remote_node.push.contains(volume))
        .filter(|(volume, _)| push.is_empty() || push.contains(&volume.to_string()))
    {
        // Full backup: Remote is out of date.
        for snapshot in local_node.all_full_after(volume.clone(), latest_snapshots.last_full)? {
            let r = local_node.export(&snapshot)?;
            tx.push((r, snapshot));
        }

        // Incremental backup: Remote is out of date.
        for snapshot in
            local_node.all_incremental_after(volume, latest_snapshots.last_incremental)?
        {
            let r = local_node.export(&snapshot)?;
            tx.push((r, snapshot));
        }
    }

    for (_, snapshot) in &tx {
        println!(
            "Queueing {} for transmission to {}",
            snapshot, remote_node.address
        );
    }

    let rx_setup =
        |snapshot: &Snapshot| {
            if !remote_node.pull.iter().any(|volume| {
                snapshot.is_of_volume(volume) && volume.node_name() != local_node.name()
            }) {
                return Err(RemoteError::AccessDenied);
            }

            if snapshot.backup_path(Mode::Client).exists() {
                return Err(RemoteError::Immutable);
            }

            let file = File::create(snapshot.streaming_path(Mode::Client))
                .map_err(|_| RemoteError::RxError)?;

            println!("Receiving {} from {}", snapshot, remote_node.address);

            Ok(file)
        };

    let rx_finish = |snapshot: Snapshot| {
        fs::rename(
            snapshot.streaming_path(Mode::Client),
            snapshot.backup_path(Mode::Client),
        )
        .map_err(|_| RemoteError::RxError)?;

        println!("Received {} from {}", snapshot, remote_node.address);

        Ok(())
    };

    stream_conn.data_sync(tx, rx_setup, rx_finish)?;

    Ok(())
}

fn restore(
    local_node: &LocalNode,
    address: Option<&str>,
    no_restore: bool,
    ignore_fstab: bool,
) -> Result<()> {
    // Synchronize with remote node if an address was passed in.
    if let Some(address) = address {
        let address = match address.parse() {
            Ok(address) => address,
            Err(_) => SocketAddr::new(address.parse()?, DEFAULT_PORT),
        };

        let auth_conn = AuthConn::new(&address)?;
        let stream_conn = auth_conn.secure_stream(
            local_node.name().to_string(),
            address.to_string(),
            &local_node.config().passphrase,
        )?;

        println!("Authentication to {} successful", address);

        let mut local_sync_info = SyncInfo {
            volumes: HashMap::new(),
        };

        for subvol in &local_node.config().subvols {
            let volume = Volume::new_local(local_node, subvol.to_string())?;
            local_sync_info
                .volumes
                .insert(volume.clone(), local_node.latest_snapshots(volume)?);
        }

        let (stream_conn, _) = stream_conn.meta_sync(local_sync_info)?;

        let children = Mutex::new(HashMap::new());

        let rx_setup = |snapshot: &Snapshot| {
            if !local_node.config().subvols.iter().any(|subvol| {
                snapshot.subvol() == subvol && snapshot.node_name() == local_node.name()
            }) {
                return Err(RemoteError::AccessDenied);
            }

            if snapshot.snapshot_path(Mode::Client).exists() {
                return Err(RemoteError::Immutable);
            }

            let (child, recovery_stream) =
                local_node.recover().map_err(|_| RemoteError::RxError)?;
            children.lock().unwrap().insert(snapshot.clone(), child);

            println!("Receiving {} from {}", snapshot, address);

            Ok(recovery_stream)
        };

        let rx_finish = |snapshot: Snapshot| {
            println!("Received {} from {}", snapshot, address);

            let mut child = children
                .lock()
                .unwrap()
                .remove(&snapshot)
                .ok_or(RemoteError::NotStreaming)?;

            if child.wait().map_err(|_| RemoteError::RxError)?.success() {
                Ok(())
            } else {
                Err(RemoteError::RxError)
            }
        };

        match stream_conn.data_sync(Vec::<(Empty, Snapshot)>::default(), rx_setup, rx_finish) {
            Ok(_) => {}
            Err(e) => {
                for (snapshot, child) in children.lock().unwrap().iter_mut() {
                    match child.kill() {
                        Ok(_) => {}
                        Err(e) => eprintln!("Cannot kill failed receiver for {}: {}", snapshot, e),
                    }
                }

                return Err(e.into());
            }
        }
    }

    if !no_restore {
        for subvol in &local_node.config().subvols {
            ensure_unmounted(subvol.clone())?;

            println!("Restoring subvolume {}", subvol);
            local_node.restore(subvol.clone(), ignore_fstab)?;
        }
    }

    Ok(())
}

fn ensure_unmounted(subvol: String) -> Result<()> {
    let file = File::open("/proc/self/mounts")?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line?;

        let mountpoint = line
            .split_whitespace()
            .nth(1)
            .ok_or(Error::NoMountpoint(line.clone()))?;

        if line.contains(&format!("subvol=/{}", subvol))
            && mountpoint != "/mnt/hbak"
            && mountpoint != "/mnt/hbakd"
        {
            return Err(Error::Mounted(subvol));
        }
    }

    Ok(())
}
