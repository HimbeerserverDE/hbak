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
use crate::stream::{RecoveryStream, SnapshotStream, CHUNKSIZE};
use crate::system::{MOUNTPOINTC, MOUNTPOINTS};
use crate::{LocalNodeError, SnapshotParseError, VolumeParseError};

use std::cmp::Ordering;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::{fmt, fs};

use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use sys_mount::{Mount, UnmountDrop, UnmountFlags};

pub const SNAPSHOT_DIR_C: &str = "/mnt/hbak/snapshots";
pub const SNAPSHOT_DIR_S: &str = "/mnt/hbakd/snapshots";
pub const BACKUP_DIR_C: &str = "/mnt/hbak/backups";
pub const BACKUP_DIR_S: &str = "/mnt/hbakd/backups";

/// A `Snapshot` uniquely identifies a full or incremental btrfs snapshot
/// of a node via the node name, subvolume name and creation date.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    node_name: String,
    subvol: String,
    is_incremental: bool,
    taken: NaiveDateTime,
}

impl Snapshot {
    const TIMESTAMP_FMT: &'static str = "%Y%m%d%H%M%S";

    /// Returns the name of the node the `Snapshot` represents.
    pub fn node_name(&self) -> &str {
        &self.node_name
    }

    /// Returns the name of the subvolume the `Snapshot` represents.
    pub fn subvol(&self) -> &str {
        &self.subvol
    }

    /// Returns the [`Volume`] the `Snapshot` represents.
    pub fn volume(&self) -> Volume {
        Volume {
            node_name: self.node_name.clone(),
            subvol: self.subvol.clone(),
        }
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
    pub fn snapshot_path(&self, mode: Mode) -> PathBuf {
        let mut path_buf = PathBuf::new();

        path_buf.push(mode.snapshot_dir());
        path_buf.push(self.to_string());

        path_buf
    }

    /// Converts the `Snapshot` to its remote storage location,
    /// i.e. a member of the `/mnt/hbak/backups` directory
    /// where other nodes may store it.
    pub fn backup_path(&self, mode: Mode) -> PathBuf {
        let mut path_buf = PathBuf::new();

        path_buf.push(mode.backup_dir());
        path_buf.push(self.to_string());

        path_buf
    }

    /// Converts the `Snapshot` to its temporary remote storage location,
    /// i.e. a member of the `/mnt/hbak/backups` directory
    /// where other nodes may store it until the transmission is complete.
    ///
    /// It is suffixed with the `.part` file extension and won't be treated
    /// as a backup by methods like [`LocalNode::all_backups`].
    /// This behavior allows partial or failed transmissions to be retried
    /// and is used to prevent (malicious) overwriting of existing snapshots
    /// that have fully been written.
    pub fn streaming_path(&self, mode: Mode) -> PathBuf {
        let mut path_buf = PathBuf::new();

        path_buf.push(mode.backup_dir());
        path_buf.push(format!("{self}.part"));

        path_buf
    }

    /// Reports whether this `Snapshot` is a snapshot of the specified [`Volume`].
    pub fn is_of_volume(&self, volume: &Volume) -> bool {
        self.node_name() == volume.node_name() && self.subvol() == volume.subvol()
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

impl LatestSnapshots {
    /// Returns a `LatestSnapshots` that signifies that no snapshots exist.
    /// Only useful when restoring.
    pub fn none() -> Self {
        Self {
            last_full: NaiveDateTime::MIN,
            last_incremental: NaiveDateTime::MIN,
        }
    }
}

/// A `Volume` is a unique combination of btrfs subvolume and host name.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct Volume {
    node_name: String,
    subvol: String,
}

impl Volume {
    /// Constructs a new `Volume` using the name of the provided [`LocalNode`]
    /// and the specified subvolume name.
    pub fn new_local(local_node: &LocalNode, subvol: String) -> Result<Self, LocalNodeError> {
        if !local_node.owns_subvol(&subvol) {
            return Err(LocalNodeError::ForeignSubvolume(subvol.clone()));
        }

        Ok(Self {
            node_name: local_node.name().to_string(),
            subvol,
        })
    }

    /// Returns the name of the node owning this `Volume`.
    pub fn node_name(&self) -> &str {
        &self.node_name
    }

    /// Returns the name of the subvolume this `Volume` represents.
    pub fn subvol(&self) -> &str {
        &self.subvol
    }

    /// Convenience wrapper for `Vec<String>` to `Vec<Volume>` conversion.
    pub fn try_from_bulk(values: Vec<String>) -> Result<Vec<Self>, VolumeParseError> {
        values
            .into_iter()
            .map(|value| Self::try_from(value.as_str()))
            .collect()
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

impl Ord for Volume {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_string().cmp(&other.to_string())
    }
}

impl PartialOrd<Volume> for Volume {
    fn partial_cmp(&self, other: &Volume) -> Option<Ordering> {
        Some(self.cmp(other))
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

/// A `Mode` specifies whether the [`LocalNode`] is acting as a network client or server.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Mode {
    /// The [`LocalNode`] is acting as a network client (hbak binary).
    Client,
    /// The [`LocalNode`] is acting as a network server (hbakd binary).
    Server,
}

impl Mode {
    /// Returns the correct mountpoint for the `Mode`.
    pub fn mountpoint(&self) -> &'static str {
        match self {
            Self::Client => MOUNTPOINTC,
            Self::Server => MOUNTPOINTS,
        }
    }

    /// Returns the correct snapshot directory for the `Mode`.
    pub fn snapshot_dir(&self) -> &'static str {
        match self {
            Self::Client => SNAPSHOT_DIR_C,
            Self::Server => SNAPSHOT_DIR_S,
        }
    }

    /// Returns the correct backup directory for the `Mode`.
    pub fn backup_dir(&self) -> &'static str {
        match self {
            Self::Client => BACKUP_DIR_C,
            Self::Server => BACKUP_DIR_S,
        }
    }
}

/// A `LocalNode` represents the current machine.
pub struct LocalNode {
    config: NodeConfig,
    mode: Mode,
    _btrfs: UnmountDrop<Mount>,
}

impl LocalNode {
    /// Returns a new `LocalNode` representing the local machine.
    /// Shorthand for `LocalNode::with_config(mode, NodeConfig::load()?)`.
    pub fn new(mode: Mode) -> Result<Self, LocalNodeError> {
        let config = NodeConfig::load()?;
        Self::with_config(mode, config)
    }

    /// Returns a new `LocalNode` representing the local machine.
    /// The configuration is provided by the caller and **not** loaded from disk.
    /// The purpose of this method is to make recovery possible
    /// without requiring tedious pre-initialization by the user.
    pub fn with_config(mode: Mode, config: NodeConfig) -> Result<Self, LocalNodeError> {
        let device = config.device.clone();

        fs::create_dir_all(MOUNTPOINTC)?;
        fs::create_dir_all(MOUNTPOINTS)?;

        let mountpoint = mode.mountpoint();

        Ok(Self {
            config,
            mode,
            _btrfs: Mount::builder().data("compress=zstd").mount_autodrop(
                device,
                mountpoint,
                UnmountFlags::DETACH,
            )?,
        })
    }

    /// Returns a reference to the configuration of the `LocalNode`.
    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    /// Returns the [`Mode`] (network client or server) of the `LocalNode`.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Reports whether the `LocalNode` is the origin of the specified subvolume.
    pub fn owns_subvol(&self, subvol: &String) -> bool {
        self.config().subvols.contains(subvol)
    }

    /// Reports whether the `LocalNode` is the origin of the specified [`Snapshot`]
    /// by verifying the node name.
    pub fn owns_backup(&self, backup: &Snapshot) -> bool {
        backup.node_name() == self.config().node_name
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

        let src = Path::new(self.mode.mountpoint()).join(&subvol);
        let snapshot = Snapshot {
            node_name: self.name().to_string(),
            subvol,
            is_incremental,
            taken: Utc::now().naive_utc(),
        };
        let dst = snapshot.snapshot_path(self.mode);

        if dst.exists() {
            return Err(LocalNodeError::SnapshotExists(snapshot));
        }

        if !Command::new("btrfs")
            .arg("subvolume")
            .arg("snapshot")
            .arg("-r")
            .arg(src)
            .arg(dst)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?
            .wait()?
            .success()
        {
            return Err(LocalNodeError::BtrfsCmd);
        }

        Ok(snapshot)
    }

    /// Returns all snapshots of the specified subvolume or all subvolumes of this node.
    pub fn all_snapshots(&self, subvol: Option<String>) -> Result<Vec<Snapshot>, LocalNodeError> {
        match subvol {
            Some(subvol) if !self.owns_subvol(&subvol) => {
                return Err(LocalNodeError::ForeignSubvolume(subvol));
            }
            _ => {}
        }

        let snapshots = fs::read_dir(self.mode.snapshot_dir())?;
        let mut all_snapshots = Vec::new();
        for snapshot in snapshots {
            let snapshot = Snapshot::try_from(&*snapshot?.path())?;

            match &subvol {
                Some(subvol) if snapshot.subvol() != subvol => {}
                _ => all_snapshots.push(snapshot),
            }
        }

        Ok(all_snapshots)
    }

    /// Returns the latest full snapshot of the specified subvolume of this node.
    pub fn latest_snapshot_full(&self, subvol: String) -> Result<Snapshot, LocalNodeError> {
        self.all_snapshots(Some(subvol.clone()))?
            .into_iter()
            .filter(|snapshot| !snapshot.is_incremental())
            .max_by_key(|snapshot| snapshot.taken())
            .ok_or(LocalNodeError::NoFullSnapshot(subvol))
    }

    /// Returns the latest incremental snapshot of the specified subvolume of this node.
    pub fn latest_snapshot_incremental(&self, subvol: String) -> Result<Snapshot, LocalNodeError> {
        self.all_snapshots(Some(subvol.clone()))?
            .into_iter()
            .filter(|snapshot| snapshot.is_incremental())
            .max_by_key(|snapshot| snapshot.taken())
            .ok_or(LocalNodeError::NoIncrementalSnapshot(subvol))
    }

    /// Returns the latest snapshot, full or incremental, of the specified subvolume of this node.
    pub fn latest_snapshot(&self, subvol: String) -> Result<Snapshot, LocalNodeError> {
        [
            Some(self.latest_snapshot_full(subvol.clone())?),
            self.latest_snapshot_incremental(subvol.clone()).ok(),
        ]
        .into_iter()
        .flatten()
        .max_by_key(|snapshot| snapshot.taken())
        .ok_or(LocalNodeError::NoFullSnapshot(subvol))
    }

    /// Returns all full snapshots of the specified subvolume of this node
    /// taken after the provided timestamp.
    pub fn snapshot_full_after(
        &self,
        subvol: String,
        after: NaiveDateTime,
    ) -> Result<Vec<Snapshot>, LocalNodeError> {
        Ok(self
            .all_snapshots(Some(subvol))?
            .into_iter()
            .filter(|snapshot| !snapshot.is_incremental() && snapshot.taken() > after)
            .collect())
    }

    /// Returns all incremental snapshots of the specified subvolume of this node
    /// taken after the provided timestamp.
    pub fn snapshot_incremental_after(
        &self,
        subvol: String,
        after: NaiveDateTime,
    ) -> Result<Vec<Snapshot>, LocalNodeError> {
        Ok(self
            .all_snapshots(Some(subvol))?
            .into_iter()
            .filter(|snapshot| snapshot.is_incremental() && snapshot.taken() > after)
            .collect())
    }

    /// Returns the [`Snapshot`] to use as the parent of another *incremental* [`Snapshot`]
    /// when exporting. This is the previous incremental snapshot unless there have not been
    /// any incremental snapshots since the last full snapshot, in which case this method
    /// returns the full snapshot.
    pub fn parent_of(&self, child: &Snapshot) -> Result<Snapshot, LocalNodeError> {
        let previous_full = self
            .all_snapshots(Some(child.subvol().to_string()))?
            .into_iter()
            .filter(|snapshot| !snapshot.is_incremental())
            .filter(|snapshot| snapshot.taken() < child.taken())
            .max_by_key(|snapshot| snapshot.taken())
            .ok_or(LocalNodeError::NoFullSnapshot(child.subvol().to_string()))?;
        let previous_incremental = self
            .all_snapshots(Some(child.subvol().to_string()))?
            .into_iter()
            .filter(|snapshot| snapshot.is_incremental())
            .filter(|snapshot| snapshot.taken() < child.taken())
            .max_by_key(|snapshot| snapshot.taken());

        [Some(previous_full), previous_incremental]
            .into_iter()
            .flatten()
            .max_by_key(|snapshot| snapshot.taken())
            .ok_or(LocalNodeError::NoFullSnapshot(child.subvol().to_string()))
    }

    /// Returns a new [`crate::stream::SnapshotStream`]
    /// wrapping the provided [`Snapshot`].
    /// It is an error to call this method on a foreign [`Snapshot`].
    pub fn send_snapshot(
        &self,
        snapshot: &Snapshot,
    ) -> Result<SnapshotStream<BufReader<ChildStdout>>, LocalNodeError> {
        let src = snapshot.snapshot_path(self.mode);

        let mut cmd = Command::new("btrfs");
        let cmd = cmd.arg("send").arg("--compressed-data");
        let cmd = if snapshot.is_incremental() {
            cmd.arg("-p")
                .arg(self.parent_of(snapshot)?.snapshot_path(self.mode))
        } else {
            cmd
        }
        .arg(src)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

        SnapshotStream::new(
            BufReader::with_capacity(
                2 * CHUNKSIZE,
                cmd.stdout.ok_or(LocalNodeError::NoBtrfsOutput)?,
            ),
            &self.config().passphrase,
        )
    }

    /// Returns a new [`crate::stream::SnapshotStream`]
    /// wrapping the latest full snapshot of the specified subvolume.
    pub fn export_full(
        &self,
        subvol: String,
    ) -> Result<SnapshotStream<BufReader<ChildStdout>>, LocalNodeError> {
        self.send_snapshot(&self.latest_snapshot_full(subvol)?)
    }

    /// Returns a new [`io::Read`] wrapping the provided snapshot or backup.
    /// Performs encryption if exporting a local [`Snapshot`].
    pub fn export(&self, snapshot: &Snapshot) -> Result<Box<dyn BufRead + Send>, LocalNodeError> {
        if self.owns_backup(snapshot) {
            Ok(Box::new(self.send_snapshot(snapshot)?))
        } else {
            Ok(Box::new(BufReader::with_capacity(
                2 * CHUNKSIZE,
                File::open(snapshot.backup_path(self.mode))?,
            )))
        }
    }

    /// Writes the provided [`crate::stream::SnapshotStream`]
    /// to the specified local backup.
    pub fn backup<B: BufRead>(
        &self,
        mut stream: SnapshotStream<B>,
        snapshot: &Snapshot,
    ) -> Result<(), LocalNodeError> {
        let dst = snapshot.backup_path(self.mode);
        let mut file = BufWriter::with_capacity(2 * CHUNKSIZE, File::create(dst)?);

        io::copy(&mut stream, &mut file)?;
        Ok(())
    }

    /// Returns all backups that have been synchronized to this node
    /// of the specified [`Volume`] or all volumes.
    pub fn all_backups(&self, volume: Option<&Volume>) -> Result<Vec<Snapshot>, LocalNodeError> {
        let mut all_backups = Vec::new();

        let backups = fs::read_dir(self.mode.backup_dir())?;
        for backup in backups {
            let backup = backup?;

            if backup.path().extension() != Some(OsStr::new("part")) {
                let snapshot = Snapshot::try_from(&*backup.path())?;

                match volume {
                    Some(volume) if !snapshot.is_of_volume(volume) => {}
                    _ => all_backups.push(snapshot),
                }
            }
        }

        Ok(all_backups)
    }

    /// Returns the latest locally known full backup of the specified [`Volume`].
    pub fn latest_backup_full(&self, volume: Volume) -> Result<Snapshot, LocalNodeError> {
        self.all_backups(Some(&volume))?
            .into_iter()
            .filter(|backup| !backup.is_incremental())
            .max_by_key(|backup| backup.taken())
            .ok_or(LocalNodeError::NoFullBackup(volume))
    }

    /// Returns the latest locally known incremental backup of the specified [`Volume`].
    pub fn latest_backup_incremental(&self, volume: Volume) -> Result<Snapshot, LocalNodeError> {
        self.all_backups(Some(&volume))?
            .into_iter()
            .filter(|backup| backup.is_incremental())
            .max_by_key(|backup| backup.taken())
            .ok_or(LocalNodeError::NoIncrementalBackup(volume))
    }

    /// Returns all locally known full backups of the specified [`Volume`]
    /// taken after the provided timestamp.
    pub fn backup_full_after(
        &self,
        volume: Volume,
        after: NaiveDateTime,
    ) -> Result<Vec<Snapshot>, LocalNodeError> {
        Ok(self
            .all_backups(Some(&volume))?
            .into_iter()
            .filter(|backup| !backup.is_incremental() && backup.taken() > after)
            .collect())
    }

    /// Returns all locally known incremental backups of the specified [`Volume`]
    /// taken after the provided timestamp.
    pub fn backup_incremental_after(
        &self,
        volume: Volume,
        after: NaiveDateTime,
    ) -> Result<Vec<Snapshot>, LocalNodeError> {
        Ok(self
            .all_backups(Some(&volume))?
            .into_iter()
            .filter(|backup| backup.is_incremental() && backup.taken() > after)
            .collect())
    }

    /// Returns all locally know full backups or snapshots of the specified volume
    /// taken after the provided timestamp. Checks the correct location
    /// depending on whether the `LocalNode` owns the [`Volume`].
    pub fn all_full_after(
        &self,
        volume: Volume,
        after: NaiveDateTime,
    ) -> Result<Vec<Snapshot>, LocalNodeError> {
        if volume.node_name() == self.name() {
            self.snapshot_full_after(volume.subvol().to_string(), after)
        } else {
            self.backup_full_after(volume, after)
        }
    }

    /// Returns all locally know incremental backups or snapshots of the specified volume
    /// taken after the provided timestamp. Checks the correct location
    /// depending on whether the `LocalNode` owns the [`Volume`].
    pub fn all_incremental_after(
        &self,
        volume: Volume,
        after: NaiveDateTime,
    ) -> Result<Vec<Snapshot>, LocalNodeError> {
        if volume.node_name() == self.name() {
            self.snapshot_incremental_after(volume.subvol().to_string(), after)
        } else {
            self.backup_incremental_after(volume, after)
        }
    }

    /// Returns the latest full snapshot or backup of the specified [`Volume`].
    /// Checks the correct location depending on whether the `LocalNode` owns the [`Volume`].
    pub fn latest_full(&self, volume: Volume) -> Result<Snapshot, LocalNodeError> {
        if volume.node_name() == self.name() {
            self.latest_snapshot_full(volume.subvol().to_string())
        } else {
            self.latest_backup_full(volume)
        }
    }

    /// Returns the latest incremental snapshot or backup of the specified [`Volume`].
    /// Checks the correct location depending on whether the `LocalNode` owns the [`Volume`].
    pub fn latest_incremental(&self, volume: Volume) -> Result<Snapshot, LocalNodeError> {
        if volume.node_name() == self.name() {
            self.latest_snapshot_incremental(volume.subvol().to_string())
        } else {
            self.latest_backup_incremental(volume)
        }
    }

    /// Returns the latest locally known full and incremental backup timestamps
    /// in the form of a [`LatestSnapshots`] data structure.
    pub fn latest_snapshots(&self, volume: Volume) -> Result<LatestSnapshots, LocalNodeError> {
        Ok(LatestSnapshots {
            last_full: match self.latest_full(volume.clone()) {
                Ok(snapshot) => snapshot.taken(),
                Err(LocalNodeError::NoFullSnapshot(_)) => NaiveDateTime::MIN,
                Err(LocalNodeError::NoFullBackup(_)) => NaiveDateTime::MIN,
                Err(e) => return Err(e),
            },
            last_incremental: match self.latest_incremental(volume) {
                Ok(snapshot) => snapshot.taken(),
                Err(LocalNodeError::NoIncrementalSnapshot(_)) => NaiveDateTime::MIN,
                Err(LocalNodeError::NoIncrementalBackup(_)) => NaiveDateTime::MIN,
                Err(e) => return Err(e),
            },
        })
    }

    /// Returns a `btrfs receive` [`Child`] along with a new [`crate::stream::RecoveryStream`]
    /// restoring the subvolume written to the stream.
    ///
    /// # Safety
    ///
    /// It is required to wait for the returned [`Child`] to complete
    /// to ensure that all data is restored. Care needs to be taken
    /// that the `RecoveryStream` is dropped beforehand to prevent a deadlock.
    /// Furthermore the [`Child`] should be killed if any errors occur.
    pub fn recover(
        &self,
    ) -> Result<(Child, RecoveryStream<BufWriter<ChildStdin>, &str>), LocalNodeError> {
        let dst = self.mode.snapshot_dir();
        let mut cmd = Command::new("btrfs")
            .arg("receive")
            .arg(dst)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        let child_stdin = cmd.stdin.take().ok_or(LocalNodeError::NoBtrfsInput)?;

        Ok((
            cmd,
            RecoveryStream::new(
                BufWriter::with_capacity(2 * CHUNKSIZE, child_stdin),
                &self.config().passphrase,
            ),
        ))
    }

    /// Restores the latest full or incremental snapshot, whichever is later,
    /// of the specified subvolume. Only uses locally stored snapshots, remote recovery
    /// with the help of [`LocalNode::recover`] may be necessary.
    ///
    /// # Arguments
    ///
    /// * `subvol`: The subvolume to restore.
    /// * `ignore_fstab`: If the subvolume already exists, don't keep its `fstab(5)`.
    ///
    /// If the subvolume exists and the `ignore_fstab` argument is not set,
    /// the `/etc/fstab` file is saved to memory before restoring
    /// and written to the restored subvolume afterwards.
    /// This behavior is the most useful to the majority of users
    /// since it automatically handles changed UUIDs from OS reinstalls.
    pub fn restore(&self, subvol: String, ignore_fstab: bool) -> Result<(), LocalNodeError> {
        let subvol_path = Path::new(self.mode.mountpoint()).join(&subvol);

        let fstab = if subvol_path.exists() && !ignore_fstab {
            Some(fs::read(subvol_path.join("etc/fstab"))?)
        } else {
            None
        };

        if subvol_path.exists()
            && !Command::new("btrfs")
                .arg("subvolume")
                .arg("delete")
                .arg(&subvol_path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?
                .wait()?
                .success()
        {
            return Err(LocalNodeError::BtrfsCmd);
        }

        let snapshot = self.latest_snapshot(subvol)?;

        if !Command::new("btrfs")
            .arg("subvolume")
            .arg("snapshot")
            .arg(snapshot.snapshot_path(self.mode))
            .arg(&subvol_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?
            .wait()?
            .success()
        {
            return Err(LocalNodeError::BtrfsCmd);
        }

        if let Some(fstab) = fstab {
            fs::write(subvol_path.join("etc/fstab"), fstab)?;
        }

        Ok(())
    }

    /// Deletes the specified snapshot from the local or remote storage directory.
    pub fn delete(&self, snapshot: &Snapshot) -> Result<(), LocalNodeError> {
        if self.owns_backup(snapshot) {
            if !Command::new("btrfs")
                .arg("subvolume")
                .arg("delete")
                .arg(snapshot.snapshot_path(self.mode))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?
                .wait()?
                .success()
            {
                return Err(LocalNodeError::BtrfsCmd);
            }
        } else {
            fs::remove_file(snapshot.backup_path(self.mode))?;
        }

        let _ = fs::remove_file(snapshot.streaming_path(self.mode));

        Ok(())
    }
}

impl Node for LocalNode {
    /// Returns the name of the `LocalNode`.
    fn name(&self) -> &str {
        &self.config().node_name
    }
}

impl fmt::Display for LocalNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl PartialEq for LocalNode {
    fn eq(&self, other: &Self) -> bool {
        self.config().node_name == other.config().node_name
    }
}

impl Eq for LocalNode {}
