use crate::config::NodeConfig;
use crate::stream::{RecoveryStream, SnapshotStream};
use crate::system::MOUNTPOINT;
use crate::{LocalNodeError, SnapshotParseError, VolumeParseError};

use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::process::{ChildStdout, Command, Stdio};
use std::{fmt, fs};

use chrono::prelude::*;
use serde::{Deserialize, Serialize};
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

/// Describes what the last known timestamps of full and incremental snapshots
/// of a [`Volume`] are.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LatestSnapshots {
    /// Timestamp of the last full snapshot.
    pub last_full: NaiveDateTime,
    /// Timestamp of the last incremental snapshot.
    pub last_incremental: NaiveDateTime,
}

/// A `Volume` is a unique combination of btrfs subvolume and host name.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
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

        fs::create_dir_all(MOUNTPOINT)?;

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

    /// Reports whether the `LocalNode` is the origin of the specified `Snapshot`
    /// by verifying the node name.
    pub fn owns_backup(&self, backup: &Snapshot) -> bool {
        backup.node_name() == self.config.node_name
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

        let src = Path::new(MOUNTPOINT).join(&subvol);
        let snapshot = Snapshot {
            node_name: self.name().to_string(),
            subvol,
            is_incremental,
            taken: Utc::now().naive_utc(),
        };
        let dst = snapshot.snapshot_path();

        if dst.exists() {
            return Err(LocalNodeError::SnapshotExists(snapshot));
        }

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

        SnapshotStream::new(
            BufReader::new(cmd.stdout.ok_or(LocalNodeError::NoBtrfsOutput)?),
            &self.config.passphrase,
        )
    }

    /// Writes the provided [`crate::stream::SnapshotStream`]
    /// to the specified local backup.
    pub fn backup<B: BufRead>(
        &self,
        stream: SnapshotStream<B>,
        snapshot: &Snapshot,
    ) -> Result<(), LocalNodeError> {
        let dst = snapshot.backup_path();
        let mut file = BufWriter::new(File::create(dst)?);

        stream.write_to(&mut file)?;
        Ok(())
    }

    /// Returns all backups of the specified subvolume
    /// that have been synchronized to this node.
    pub fn all_backups(&self, subvol: String) -> Result<Vec<Snapshot>, LocalNodeError> {
        if !self.owns_subvol(&subvol) {
            return Err(LocalNodeError::ForeignSubvolume(subvol));
        }

        let backups = fs::read_dir(BACKUP_DIR)?;
        let mut all_backups = Vec::new();
        for backup in backups {
            all_backups.push(Snapshot::try_from(&*backup?.path())?);
        }

        Ok(all_backups)
    }

    /// Returns the latest full backup of the specified subvolume of this node.
    pub fn latest_backup_full(&self, subvol: String) -> Result<Snapshot, LocalNodeError> {
        self.all_backups(subvol.clone())?
            .into_iter()
            .filter(|backup| self.owns_backup(backup) && !backup.is_incremental())
            .max_by_key(|backup| backup.taken())
            .ok_or(LocalNodeError::NoFullBackup(subvol))
    }

    /// Returns a new [`crate::stream::RecoveryStream`]
    /// wrapping the latest full backup of the specified subvolume.
    pub fn import_full(
        &self,
        subvol: String,
    ) -> Result<RecoveryStream<BufReader<File>>, LocalNodeError> {
        let backup = self.latest_backup_full(subvol)?;
        if backup.snapshot_path().exists() {
            return Err(LocalNodeError::SnapshotNotGone(backup));
        }

        let src = backup.backup_path();
        let file = BufReader::new(File::open(src)?);

        RecoveryStream::new(file, &self.config.passphrase)
    }

    /// Writes the provided [`crate::stream::RecoveryStream`]
    /// to the correct local snapshot.
    pub fn recover<B: BufRead>(&self, stream: RecoveryStream<B>) -> Result<(), LocalNodeError> {
        let dst = SNAPSHOT_DIR;
        let mut cmd = Command::new("btrfs")
            .arg("receive")
            .arg(dst)
            .stdin(Stdio::piped())
            .spawn()?;

        if let Err(e) = stream.write_to(cmd.stdin.as_mut().ok_or(LocalNodeError::NoBtrfsInput)?) {
            cmd.kill()?;
            return Err(e);
        }
        cmd.stdin = None; // Make sure `btrfs receive` doesn't deadlock.

        if cmd.wait()?.success() {
            Ok(())
        } else {
            Err(LocalNodeError::BtrfsCmd)
        }
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
