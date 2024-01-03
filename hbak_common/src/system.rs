use crate::config::NodeConfig;
use crate::proto::{BACKUP_DIR, SNAPSHOT_DIR};
use crate::LocalNodeError;

use std::fs;
use std::path::Path;
use std::process::Command;

use sys_mount::{Mount, UnmountFlags};

pub const MOUNTPOINT: &str = "/mnt/hbak";

/// Initializes the configuration file and local btrfs subvolumes.
pub fn init(device: String, node_name: String, passphrase: String) -> Result<(), LocalNodeError> {
    if Path::new(NodeConfig::PATH).exists() {
        return Err(LocalNodeError::ConfigExists);
    }

    let node_config = NodeConfig {
        device,
        node_name,
        subvols: Vec::default(),
        passphrase,
        push: Vec::default(),
        pull: Vec::default(),
        auth: Vec::default(),
    };

    node_config.save()?;

    init_btrfs(&node_config.device)
}

fn init_btrfs(device: &str) -> Result<(), LocalNodeError> {
    fs::create_dir_all(MOUNTPOINT)?;

    let _btrfs = Mount::builder().data("compress=zstd").mount_autodrop(
        device,
        MOUNTPOINT,
        UnmountFlags::DETACH,
    )?;

    if !Command::new("btrfs")
        .arg("subvolume")
        .arg("create")
        .arg(SNAPSHOT_DIR)
        .spawn()?
        .wait()?
        .success()
    {
        return Err(LocalNodeError::BtrfsCmd);
    }

    if !Command::new("btrfs")
        .arg("subvolume")
        .arg("create")
        .arg(BACKUP_DIR)
        .spawn()?
        .wait()?
        .success()
    {
        return Err(LocalNodeError::BtrfsCmd);
    }

    Ok(())
}
