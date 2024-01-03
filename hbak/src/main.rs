use hbak_common::config::{NodeConfig, RemoteNode, RemoteNodeAuth};
use hbak_common::system;

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
        /// The device file the local btrfs file system is located at.
        device: String,
        /// The name to use for this node.
        node_name: String,
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
        /// Must not include subvolumes owned by the local node.
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
        /// Must not include subvolumes owned by the local node.
        push: Vec<String>,
        /// The volumes the remote node is allowed to pull.
        pull: Vec<String>,
    },
    /// Revoke a remote client all access and delete local configuration about it.
    Revoke {
        /// The name of the remote node to remove from the security configuration.
        node_name: String,
    },
}

fn main() -> Result<(), hbak_common::LocalNodeError> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { device, node_name } => {
            let passphrase = rpassword::prompt_password("Enter new encryption password: ")?;
            system::init(device, node_name, passphrase)?;
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
            let secret = rpassword::prompt_password("Enter shared secret: ")?;

            let mut node_config = NodeConfig::load()?;

            node_config.push.retain(|item| item.address != address);
            node_config.push.push(RemoteNode {
                address,
                secret,
                volumes,
            });
            node_config.save()?;
        }
        Commands::RmPush { address } => {
            let mut node_config = NodeConfig::load()?;

            node_config.push.retain(|item| item.address != address);
            node_config.save()?;
        }
        Commands::AddPull { address, volumes } => {
            let secret = rpassword::prompt_password("Enter shared secret: ")?;

            let mut node_config = NodeConfig::load()?;

            node_config.pull.retain(|item| item.address != address);
            node_config.pull.push(RemoteNode {
                address,
                secret,
                volumes,
            });
            node_config.save()?;
        }
        Commands::RmPull { address } => {
            let mut node_config = NodeConfig::load()?;

            node_config.pull.retain(|item| item.address != address);
            node_config.save()?;
        }
        Commands::Grant {
            node_name,
            push,
            pull,
        } => {
            let secret = rpassword::prompt_password("Enter shared secret: ")?;

            let mut node_config = NodeConfig::load()?;

            node_config.auth.retain(|item| item.node_name != node_name);
            node_config.auth.push(RemoteNodeAuth {
                node_name,
                secret,
                push,
                pull,
            });
            node_config.save()?;
        }
        Commands::Revoke { node_name } => {
            let mut node_config = NodeConfig::load()?;

            node_config.auth.retain(|item| item.node_name != node_name);
            node_config.save()?;
        }
    }

    Ok(())
}
