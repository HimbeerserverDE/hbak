use hbak_common::config::NodeConfig;

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
        /// The encryption passphrase to use for owned subvolumes.
        passphrase: String,
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
}

fn main() -> Result<(), hbak_common::LocalNodeError> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init {
            device,
            node_name,
            passphrase,
        } => {
            hbak_common::system::init(device, node_name, passphrase)?;
        }
        Commands::Track { subvol } => {
            let mut node_config = NodeConfig::load()?;

            node_config.subvols.push(subvol);
            node_config.save()?;
        }
        Commands::Untrack { subvol } => {
            let mut node_config = NodeConfig::load()?;

            node_config.subvols.retain(|item| *item != subvol);
            node_config.save()?;
        }
    }

    Ok(())
}
