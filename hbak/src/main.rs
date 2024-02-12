mod error;
use error::*;

use hbak_common::config::{NodeConfig, RemoteNode, RemoteNodeAuth};
use hbak_common::conn::{AuthConn, DEFAULT_PORT};
use hbak_common::message::SyncInfo;
use hbak_common::proto::{LocalNode, Node, Snapshot, Volume};
use hbak_common::system;
use hbak_common::{LocalNodeError, RemoteError};

use std::collections::HashMap;
use std::fs::{self, File};
use std::net::SocketAddr;

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
        /// The network address and port of the remote node.
        address: String,
        /// The volumes to push to the remote node.
        push: Vec<String>,
        /// The volumes to pull from the remote node.
        /// Subvolumes owned by the local node are silently ignored.
        pull: Vec<String>,
    },
    /// Remove a remote without deleting anything.
    RmRemote {
        /// The network address and port of the node to forget.
        address: String,
    },
    /// Add or modify authentication and authorization information for a remote client.
    Grant {
        /// The name of the remote node to apply the information to.
        node_name: String,
        /// The volumes the remote node is allowed to push.
        /// Subvolumes owned by the local node are silently ignored.
        #[arg(long = "push")]
        push: Vec<String>,
        /// The volumes the remote node is allowed to pull.
        #[arg(long = "pull")]
        pull: Vec<String>,
    },
    /// Modify permissions for a remote client without changing the passphrase.
    SetPerms {
        /// The name of the remote node to apply the information to.
        node_name: String,
        /// The volumes the remote node is allowed to push.
        /// Subvolumes owned by the local node are silently ignored.
        #[arg(long = "push")]
        push: Vec<String>,
        /// The volumes the remote node is allowed to pull.
        #[arg(long = "pull")]
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
        #[arg(long = "push")]
        push: Vec<String>,
        /// The volumes to limit pulling to.
        #[arg(long = "pull")]
        pull: Vec<String>,
        /// The nodes to limit synchronization to.
        nodes: Vec<String>,
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
                let local_node = LocalNode::new()?;

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
            let local_node = LocalNode::new()?;

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
            let local_node = LocalNode::new()?;

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
        Commands::Synchronize { push, pull, nodes } => {
            let local_node = LocalNode::new()?;

            for node in local_node
                .config()
                .remotes
                .iter()
                .filter(|item| nodes.is_empty() || nodes.contains(&item.address))
            {
                println!("Synchronizing with {}...", node.address);
                sync(&local_node, node, &push, &pull)?;
            }
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

            if snapshot.backup_path().exists() {
                return Err(RemoteError::Immutable);
            }

            let file = File::create(snapshot.streaming_path()).map_err(|_| RemoteError::RxError)?;

            println!("Receiving {} from {}", snapshot, remote_node.address);

            Ok(file)
        };

    let rx_finish = |snapshot: Snapshot| {
        fs::rename(snapshot.streaming_path(), snapshot.backup_path())
            .map_err(|_| RemoteError::RxError)?;

        println!("Received {} from {}", snapshot, remote_node.address);

        Ok(())
    };

    stream_conn.data_sync(tx, rx_setup, rx_finish)?;

    Ok(())
}
