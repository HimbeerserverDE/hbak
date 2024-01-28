use crate::config::NodeConfig;
use crate::proto::{BACKUP_DIR, SNAPSHOT_DIR};
use crate::LocalNodeError;

use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::process::Command;

use argon2::Argon2;
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::Sha256;
use sys_mount::{Mount, UnmountFlags};

pub const MOUNTPOINT: &str = "/mnt/hbak";

/// Initializes the configuration file and local btrfs subvolumes.
pub fn init(
    config_only: bool,
    device: String,
    bind_addr: Option<SocketAddr>,
    node_name: String,
    passphrase: String,
) -> Result<(), LocalNodeError> {
    if Path::new(NodeConfig::PATH).exists() {
        return Err(LocalNodeError::ConfigExists);
    }

    let node_config = NodeConfig {
        device,
        bind_addr,
        node_name,
        subvols: Vec::default(),
        passphrase,
        push: Vec::default(),
        pull: Vec::default(),
        auth: Vec::default(),
    };

    node_config.save()?;

    if !config_only {
        init_btrfs(&node_config.device)?;
    }

    Ok(())
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

/// Deinitializes the configuration file, optionally deleting the btrfs subvolumes.
pub fn deinit(remove_backups: bool) -> Result<(), LocalNodeError> {
    if !Path::new(NodeConfig::PATH).exists() {
        return Err(LocalNodeError::ConfigUninit);
    }

    if remove_backups {
        deinit_btrfs()?;
    }

    fs::remove_file(NodeConfig::PATH)?;

    Ok(())
}

fn deinit_btrfs() -> Result<(), LocalNodeError> {
    fs::create_dir_all(MOUNTPOINT)?;

    let node_config = NodeConfig::load()?;

    let _btrfs = Mount::builder().data("compress=zstd").mount_autodrop(
        node_config.device,
        MOUNTPOINT,
        UnmountFlags::DETACH,
    )?;

    if !Command::new("btrfs")
        .arg("subvolume")
        .arg("delete")
        .arg(BACKUP_DIR)
        .spawn()?
        .wait()?
        .success()
    {
        return Err(LocalNodeError::BtrfsCmd);
    }

    if !Command::new("btrfs")
        .arg("subvolume")
        .arg("delete")
        .arg(SNAPSHOT_DIR)
        .spawn()?
        .wait()?
        .success()
    {
        return Err(LocalNodeError::BtrfsCmd);
    }

    Ok(())
}

/// Provides a `Vec<u8>` of `n` random bytes. Uses the thread-local generator
/// of the `rand` crate.
pub fn random_bytes(n: usize) -> Vec<u8> {
    rand::thread_rng()
        .sample_iter(&rand::distributions::Standard)
        .take(n)
        .collect()
}

/// Performs an HMAC-SHA256 hash computation.
pub fn hash_hmac(secret: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac: Hmac<Sha256> =
        Hmac::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(data);
    let hmac = mac.finalize();

    hmac.into_bytes().to_vec()
}

/// Performs an Argon2id hash computation.
pub fn hash_argon2id<P: AsRef<[u8]>>(
    okm: &mut [u8],
    salt: &[u8],
    passphrase: P,
) -> Result<(), LocalNodeError> {
    Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::default(),
        argon2::Params::new(524288, 32, 128, Some(32))?,
    )
    .hash_password_into(passphrase.as_ref(), salt, okm)?;

    Ok(())
}

/// Converts the provided passphrase into a key
/// suitable for node authentication or encryption using a random verifier.
///
/// This function wraps the [`derive_key`] function.
///
/// Returns the verifier and the HMAC hash in this order.
pub fn hash_passphrase<P: AsRef<[u8]>>(
    passphrase: P,
) -> Result<(Vec<u8>, Vec<u8>), LocalNodeError> {
    let verifier = random_bytes(32);
    let key = derive_key(&verifier, passphrase)?;

    Ok((verifier, key))
}

/// Converts the provided verifier and passphrase into a key
/// for node authentication or encryption.
pub fn derive_key<P: AsRef<[u8]>>(
    verifier: &[u8],
    passphrase: P,
) -> Result<Vec<u8>, LocalNodeError> {
    let mut key_array = [0; 32];
    hash_argon2id(&mut key_array, verifier, passphrase)?;

    let key = hash_hmac(&key_array, verifier);
    Ok(key)
}
