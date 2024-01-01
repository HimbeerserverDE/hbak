use crate::SnapshotParseError;

use std::fmt;
use std::path::{Path, PathBuf};

use chrono::prelude::*;
use serde::{Deserialize, Serialize};

pub const SNAPSHOT_DIR: &str = "/mnt/hbak/snapshots";
pub const BACKUP_DIR: &str = "/mnt/hbak/backups";

/// A `Snapshot` uniquely identifies a full or incremental btrfs snapshot
/// of a node via the node name, subvolume name and creation date.
///
/// To construct this type, use [`Node::snapshot_now`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    node_name: String,
    subvol: String,
    taken: NaiveDateTime,
}

impl Snapshot {
    const PATH_FMT: &str = "%Y%m%d%H%M%S";

    /// Returns the name of the node the `Snapshot` represents.
    pub fn node_name(&self) -> &str {
        &self.node_name
    }

    /// Returns the name of the subvolume the `Snapshot` represents.
    pub fn subvol(&self) -> &str {
        &self.subvol
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
            "{}_{}_{}",
            self.node_name(),
            self.subvol(),
            self.taken().format(Self::PATH_FMT)
        )
    }
}

impl TryFrom<&str> for Snapshot {
    type Error = SnapshotParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut tokens = value.split('_');

        Ok(Self {
            node_name: tokens
                .next()
                .ok_or(SnapshotParseError::MissingNodeName)?
                .to_string(),
            subvol: tokens
                .next()
                .ok_or(SnapshotParseError::MissingSubvolume)?
                .to_string(),
            taken: NaiveDateTime::parse_from_str(
                tokens.next().ok_or(SnapshotParseError::MissingTimeTaken)?,
                Self::PATH_FMT,
            )?,
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

/// The `SnapshotMetadata` contains information on a [`Snapshot`]
/// including whether it is full or incremental.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    pub is_incremental: bool,
}
