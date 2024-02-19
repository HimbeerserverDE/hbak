// hbak_common is the main hbak library implementing the protocol shared logic.
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

use crate::config::NodeConfig;
use crate::proto::{BACKUP_DIR_C, SNAPSHOT_DIR_C};
use crate::LocalNodeError;

use std::fs;
use std::io::BufRead;
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Command, Stdio};

use argon2::Argon2;
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::Sha256;
use sys_mount::{Mount, UnmountFlags};

pub const MOUNTPOINTC: &str = "/mnt/hbak";
pub const MOUNTPOINTS: &str = "/mnt/hbakd";

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
        remotes: Vec::default(),
        auth: Vec::default(),
    };

    node_config.save()?;

    if !config_only {
        init_btrfs(&node_config.device)?;
    }

    Ok(())
}

fn init_btrfs(device: &str) -> Result<(), LocalNodeError> {
    fs::create_dir_all(MOUNTPOINTC)?;
    fs::create_dir_all(MOUNTPOINTS)?;

    let _btrfs = Mount::builder().data("compress=zstd").mount_autodrop(
        device,
        MOUNTPOINTC,
        UnmountFlags::DETACH,
    )?;

    if !Command::new("btrfs")
        .arg("subvolume")
        .arg("create")
        .arg(SNAPSHOT_DIR_C)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?
        .wait()?
        .success()
    {
        return Err(LocalNodeError::BtrfsCmd);
    }

    if !Command::new("btrfs")
        .arg("subvolume")
        .arg("create")
        .arg(BACKUP_DIR_C)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
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

    fs::remove_dir(MOUNTPOINTC)?;
    fs::remove_dir(MOUNTPOINTS)?;

    Ok(())
}

fn deinit_btrfs() -> Result<(), LocalNodeError> {
    fs::create_dir_all(MOUNTPOINTC)?;
    fs::create_dir_all(MOUNTPOINTS)?;

    let node_config = NodeConfig::load()?;

    let _btrfs = Mount::builder().data("compress=zstd").mount_autodrop(
        node_config.device,
        MOUNTPOINTC,
        UnmountFlags::DETACH,
    )?;

    if !Command::new("btrfs")
        .arg("subvolume")
        .arg("delete")
        .arg(BACKUP_DIR_C)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?
        .wait()?
        .success()
    {
        return Err(LocalNodeError::BtrfsCmd);
    }

    let output = Command::new("btrfs")
        .arg("subvolume")
        .arg("list")
        .arg("-o")
        .arg(SNAPSHOT_DIR_C)
        .stdin(Stdio::null())
        .output()?;
    if !output.status.success() {
        return Err(LocalNodeError::BtrfsCmd);
    }

    let subvols = output.stdout.lines().map(|line| match line {
        Ok(line) => Ok(Path::new(MOUNTPOINTC).join(
            line.split_whitespace()
                .next_back()
                .expect("String splitting yields at least one item"),
        )),
        Err(e) => Err(e),
    });

    for subvol in subvols {
        if !Command::new("btrfs")
            .arg("subvolume")
            .arg("delete")
            .arg(subvol?)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?
            .wait()?
            .success()
        {
            return Err(LocalNodeError::BtrfsCmd);
        }
    }

    if !Command::new("btrfs")
        .arg("subvolume")
        .arg("delete")
        .arg(SNAPSHOT_DIR_C)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
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
