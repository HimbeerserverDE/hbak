mod error;
use error::*;

use hbak_common::config::{NodeConfig, RemoteNode, RemoteNodeAuth};
use hbak_common::proto::LocalNode;
use hbak_common::system;

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
    /// Add or modify a remote to push volumes to.
    AddPush {
        /// The network address and port of the node to push to.
        address: String,
        /// The volumes to push to the remote node.
        volumes: Vec<String>,
    },
    /// Remove a push remote without deleting anything.
    RmPush {
        /// The network address and port of the node to forget.
        address: String,
    },
    /// Add or modify a remote to pull volumes from.
    AddPull {
        /// The network address and port of the node to pull from.
        address: String,
        /// The volumes to pull from the remote node.
        /// Subvolumes owned by the local node are silently ignored.
        volumes: Vec<String>,
    },
    /// Remove a pull remote without deleting anything.
    RmPull {
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
        Commands::AddPush { address, volumes } => {
            let mut node_config = NodeConfig::load()?;

            node_config.push.retain(|item| item.address != address);
            node_config.push.push(RemoteNode { address, volumes });
            node_config.save()?;
        }
        Commands::RmPush { address } => {
            let mut node_config = NodeConfig::load()?;

            node_config.push.retain(|item| item.address != address);
            node_config.save()?;
        }
        Commands::AddPull {
            address,
            mut volumes,
        } => {
            let local_node = LocalNode::new()?;

            volumes.retain(|subvol| !local_node.owns_subvol(subvol));

            let mut node_config = NodeConfig::load()?;

            node_config.pull.retain(|item| item.address != address);
            node_config.pull.push(RemoteNode { address, volumes });
            node_config.save()?;
        }
        Commands::RmPull { address } => {
            let mut node_config = NodeConfig::load()?;

            node_config.pull.retain(|item| item.address != address);
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
                push,
                pull,
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
                    item.push = push;
                    item.pull = pull;

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
    }

    Ok(())
}

fn main() {
    match logic() {
        Ok(_) => {}
        Err(e) => eprintln!("Error: {}", e),
    }
}
