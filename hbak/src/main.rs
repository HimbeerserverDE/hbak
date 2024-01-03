use hbak_common::config::{NodeConfig, RemoteNode};
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
    /// Add or modify a remote to push subvolumes to.
    AddPush {
        /// The network address and port of the node to push to.
        address: String,
        /// The shared secret for mutual authentication.
        secret: String,
        /// The volumes to push to the remote node.
        volumes: Vec<String>,
    },
    /// Remove a push remote without deleting anything.
    RmPush {
        /// The network address and port of the node to forget.
        address: String,
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
        Commands::AddPush {
            address,
            secret,
            volumes,
        } => {
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
    }

    Ok(())
}
