use crate::config::NodeConfig;
use crate::proto::{BACKUP_DIR, SNAPSHOT_DIR};
use crate::LocalNodeError;

use std::fs;
use std::path::Path;
use std::process::Command;

use argon2::Argon2;
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::Sha256;
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

/// Converts the provided passphrase into a hash
/// suitable for node authentication using a random verifier.
///
/// Returns the verifier and the HMAC hash in this order
pub fn hash_passphrase<P: AsRef<[u8]>>(
    passphrase: P,
) -> Result<(Vec<u8>, Vec<u8>), LocalNodeError> {
    let verifier: Vec<u8> = rand::thread_rng()
        .sample_iter(&rand::distributions::Standard)
        .take(32)
        .collect();

    let mut key_array = [0; 32];
    Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::default(),
        argon2::Params::new(524288, 10, 4, Some(32))?,
    )
    .hash_password_into(passphrase.as_ref(), &verifier, &mut key_array)?;

    let mut mac: Hmac<Sha256> =
        Hmac::new_from_slice(&key_array).expect("HMAC can take key of any size");
    mac.update(&verifier);
    let hmac = mac.finalize();

    Ok((verifier, hmac.into_bytes().to_vec()))
}
