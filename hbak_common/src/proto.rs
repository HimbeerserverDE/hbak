use std::path::{Path, PathBuf};

use chrono::prelude::*;
use chrono::serde::ts_seconds;
use serde::{Serialize, Deserialize};

pub const SNAPSHOT_DIR: &str = "/mnt/hbak/snapshots";
pub const BACKUP_DIR: &str = "/mnt/hbak/backups";

/// A `Snapshot` uniquely identifies a full or incremental btrfs snapshot
/// of a node via the node name and creation date.
///
/// To construct this type, use [`Node::snapshot_now`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    node_name: String,
    #[serde(with = "ts_seconds")]
    taken: DateTime<Utc>,
}

impl Snapshot {
    const PATH_FMT: &str = "%Y%m%d%H%M%S";

    /// Returns the name of the node the `Snapshot` represents.
    pub fn node_name(&self) -> &str {
        &self.node_name
    }

    /// Returns the timestamp of when the `Snapshot` was taken.
    pub fn taken(&self) -> DateTime<Utc> {
        self.taken
    }

    /// Converts the `Snapshot` to its local storage location,
    /// i.e. a member of the `/mnt/hbak/snapshots` directory
    /// of its node's own snapshots.
    pub fn snapshot_path(&self) -> PathBuf {
        let mut path_buf = PathBuf::new();

        path_buf.push(SNAPSHOT_DIR);
        path_buf.push(self);

        path_buf
    }

    /// Converts the `Snapshots` to its remote storage location,
    /// i.e. a member of the `/mnt/hbak/backups` directory
    /// where other nodes may store it.
    pub fn backup_path(&self) -> PathBuf {
        let mut path_buf = PathBuf::new();

        path_buf.push(BACKUP_DIR);
        path_buf.push(self);

        path_buf
    }
}

impl AsRef<Path> for Snapshot {
    fn as_ref(&self) -> &Path {
        let taken_formatted = self.taken().format(Self::PATH_FMT);
        let file_name = format!("{}_{}", self.node_name(), taken_formatted);

        Path::new(&file_name)
    }
}

impl TryFrom<&str> for Snapshot {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        todo!()
    }
}

impl TryFrom<&Path> for Snapshot {
    type Error = ();

    fn try_from(value: &Path) -> Result<Self, Self::Error> {
        todo!()
    }
}

/// The `SnapshotMetadata` contains information on a [`Snapshot`]
/// including whether it is full or incremental.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    pub is_incremental: bool,
}
