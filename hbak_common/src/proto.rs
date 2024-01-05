use crate::config::NodeConfig;
use crate::stream::SnapshotStream;
use crate::system::MOUNTPOINT;
use crate::{LocalNodeError, SnapshotParseError, VolumeParseError};

use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::{ChildStdout, Command, Stdio};
use std::{fmt, fs};

use chacha20::XChaCha20;
use chacha20poly1305::aead::{consts::U19, stream::EncryptorBE32, AeadCore, OsRng};
use chacha20poly1305::{ChaChaPoly1305, Key};
use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sys_mount::{Mount, UnmountDrop, UnmountFlags};

pub const SNAPSHOT_DIR: &str = "/mnt/hbak/snapshots";
pub const BACKUP_DIR: &str = "/mnt/hbak/backups";

/// A `Snapshot` uniquely identifies a full or incremental btrfs snapshot
/// of a node via the node name, subvolume name and creation date.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    node_name: String,
    subvol: String,
    is_incremental: bool,
    taken: NaiveDateTime,
}

impl Snapshot {
    const TIMESTAMP_FMT: &str = "%Y%m%d%H%M%S";

    /// Returns the name of the node the `Snapshot` represents.
    pub fn node_name(&self) -> &str {
        &self.node_name
    }

    /// Returns the name of the subvolume the `Snapshot` represents.
    pub fn subvol(&self) -> &str {
        &self.subvol
    }

    /// Reports whether the `Snapshot` is incremental (is full otherwise).
    pub fn is_incremental(&self) -> bool {
        self.is_incremental
    }

    /// Returns the timestamp of when the `Snapshot` was taken.
    pub fn taken(&self) -> NaiveDateTime {
        self.taken
    }

    /// Converts the `Snapshot` to its local storage location,
    /// i.e. a member of the `/mnt/hbak/snapshots` directory
    /// of its node's own snapshots.
    pub fn snapshot_path(&self) -> PathBuf {
        let mut path_buf = PathBuf::new();

        path_buf.push(SNAPSHOT_DIR);
        path_buf.push(self.to_string());

        path_buf
    }

    /// Converts the `Snapshots` to its remote storage location,
    /// i.e. a member of the `/mnt/hbak/backups` directory
    /// where other nodes may store it.
    pub fn backup_path(&self) -> PathBuf {
        let mut path_buf = PathBuf::new();

        path_buf.push(BACKUP_DIR);
        path_buf.push(self.to_string());

        path_buf
    }
}

impl fmt::Display for Snapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}_{}_{}_{}",
            self.node_name(),
            self.subvol(),
            if self.is_incremental { "incr" } else { "full" },
            self.taken().format(Self::TIMESTAMP_FMT)
        )
    }
}

impl TryFrom<&str> for Snapshot {
    type Error = SnapshotParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut tokens = value.split('_');

        let node_name = tokens.next().ok_or(SnapshotParseError::MissingNodeName)?;
        let subvol = tokens.next().ok_or(SnapshotParseError::MissingSubvolume)?;
        let ty = tokens.next().ok_or(SnapshotParseError::MissingType)?;
        let taken = tokens.next().ok_or(SnapshotParseError::MissingTimeTaken)?;

        Ok(Self {
            node_name: node_name.to_string(),
            subvol: subvol.to_string(),
            is_incremental: match ty {
                "full" => false,
                "incr" => true,
                _ => return Err(SnapshotParseError::InvalidType(ty.to_string())),
            },
            taken: NaiveDateTime::parse_from_str(taken, Self::TIMESTAMP_FMT)?,
        })
    }
}

impl TryFrom<&Path> for Snapshot {
    type Error = SnapshotParseError;

    fn try_from(value: &Path) -> Result<Self, Self::Error> {
        Self::try_from(
            value
                .file_name()
                .ok_or(SnapshotParseError::NoFileName)?
                .to_str()
                .ok_or(SnapshotParseError::InvalidUnicode)?,
        )
    }
}

/// A `Volume` is a unique combination of btrfs subvolume and host name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Volume {
    node_name: String,
    subvol: String,
}

impl Volume {
    /// Constructs a new `Volume` using the local node name
    /// and the specified subvolume name.
    pub fn new_local(subvol: String) -> Result<Self, LocalNodeError> {
        let node = LocalNode::new()?;

        if node.owns_subvol(&subvol) {
            return Err(LocalNodeError::NoSuchSubvolume(subvol.clone()));
        }

        Ok(Self {
            node_name: node.name().to_string(),
            subvol,
        })
    }
}

impl fmt::Display for Volume {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}_{}", self.node_name, self.subvol)
    }
}

impl TryFrom<&str> for Volume {
    type Error = VolumeParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut tokens = value.split('_');

        let node_name = tokens.next().ok_or(VolumeParseError::MissingNodeName)?;
        let subvol = tokens.next().ok_or(VolumeParseError::MissingSubvolume)?;

        Ok(Self {
            node_name: node_name.to_string(),
            subvol: subvol.to_string(),
        })
    }
}

/// A `Node` is a member of a distributed backup network
/// that can run its own `Volumes` and store those of other `Node`s.
pub trait Node {
    /// Returns the name of the `Node`.
    fn name(&self) -> &str;
}

/// An `AnyNode` represents any machine, possibly the current one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnyNode {
    node_name: String,
}

impl Node for AnyNode {
    /// Returns the name of the `AnyNode`.
    fn name(&self) -> &str {
        &self.node_name
    }
}

impl fmt::Display for AnyNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl From<String> for AnyNode {
    fn from(node_name: String) -> Self {
        Self { node_name }
    }
}

/// A `LocalNode` represents the current machine.
pub struct LocalNode {
    config: NodeConfig,
    _btrfs: UnmountDrop<Mount>,
}

impl LocalNode {
    /// Returns a new `LocalNode` representing the local machine.
    pub fn new() -> Result<Self, LocalNodeError> {
        let config = NodeConfig::load()?;
        let device = config.device.clone();

        Ok(Self {
            config,
            _btrfs: Mount::builder().data("compress=zstd").mount_autodrop(
                device,
                MOUNTPOINT,
                UnmountFlags::DETACH,
            )?,
        })
    }

    /// Reports whether the `LocalNode` is the origin of the specified subvolume.
    pub fn owns_subvol(&self, subvol: &String) -> bool {
        self.config.subvols.contains(subvol)
    }

    /// Creates a new btrfs snapshot of the specified subvolume.
    pub fn snapshot_now(
        &self,
        subvol: String,
        is_incremental: bool,
    ) -> Result<Snapshot, LocalNodeError> {
        if !self.owns_subvol(&subvol) {
            return Err(LocalNodeError::ForeignSubvolume(subvol));
        }

        fs::create_dir_all(MOUNTPOINT)?;

        let src = Path::new(MOUNTPOINT).join(&subvol);
        let snapshot = Snapshot {
            node_name: self.name().to_string(),
            subvol,
            is_incremental,
            taken: Utc::now().naive_utc(),
        };
        let dst = snapshot.snapshot_path();

        if !Command::new("btrfs")
            .arg("subvolume")
            .arg("snapshot")
            .arg("-r")
            .arg(src)
            .arg(dst)
            .spawn()?
            .wait()?
            .success()
        {
            return Err(LocalNodeError::BtrfsCmd);
        }

        Ok(snapshot)
    }

    /// Returns all snapshots of the specified subvolume of this node.
    pub fn all_snapshots(&self, subvol: String) -> Result<Vec<Snapshot>, LocalNodeError> {
        if !self.owns_subvol(&subvol) {
            return Err(LocalNodeError::ForeignSubvolume(subvol));
        }

        let snapshots = fs::read_dir(SNAPSHOT_DIR)?;
        let mut all_snapshots = Vec::new();
        for snapshot in snapshots {
            all_snapshots.push(Snapshot::try_from(&*snapshot?.path())?);
        }

        Ok(all_snapshots)
    }

    /// Returns the latest full snapshot of the specified subvolume of this node.
    pub fn latest_snapshot_full(&self, subvol: String) -> Result<Snapshot, LocalNodeError> {
        self.all_snapshots(subvol.clone())?
            .into_iter()
            .filter(|snapshot| !snapshot.is_incremental())
            .max_by_key(|snapshot| snapshot.taken())
            .ok_or(LocalNodeError::NoFullSnapshot(subvol))
    }

    /// Returns a new [`crate::stream::SnapshotStream`]
    /// wrapping the latest full snapshot of the specified subvolume.
    pub fn export_full(
        &self,
        subvol: String,
    ) -> Result<SnapshotStream<BufReader<ChildStdout>>, LocalNodeError> {
        let src = self.latest_snapshot_full(subvol)?.snapshot_path();
        let cmd = Command::new("btrfs")
            .arg("send")
            .arg("--compressed-data")
            .arg(src)
            .stdout(Stdio::piped())
            .spawn()?;

        let nonce = ChaChaPoly1305::<XChaCha20, U19>::generate_nonce(&mut OsRng);
        let key_array = pbkdf2::pbkdf2_hmac_array::<Sha256, 32>(
            self.config.passphrase.as_bytes(),
            &nonce,
            600000,
        );
        let key = Key::from_slice(&key_array);

        Ok(SnapshotStream::new(
            BufReader::new(cmd.stdout.ok_or(LocalNodeError::NoBtrfsOutput)?),
            EncryptorBE32::new(key, &nonce),
            nonce.to_vec(),
        ))
    }
}

impl Node for LocalNode {
    /// Returns the name of the `LocalNode`.
    fn name(&self) -> &str {
        &self.config.node_name
    }
}

impl fmt::Display for LocalNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl PartialEq for LocalNode {
    fn eq(&self, other: &Self) -> bool {
        self.config.node_name == other.config.node_name
    }
}

impl Eq for LocalNode {}
