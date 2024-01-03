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
    }

    Ok(())
}
