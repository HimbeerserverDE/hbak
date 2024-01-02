use crate::config::NodeConfig;
use crate::{LocalNodeError, SnapshotParseError};

use std::fmt;
use std::path::{Path, PathBuf};

use chrono::prelude::*;
use serde::{Deserialize, Serialize};

pub const SNAPSHOT_DIR: &str = "/mnt/hbak/snapshots";
pub const BACKUP_DIR: &str = "/mnt/hbak/backups";

/// A `Snapshot` uniquely identifies a full or incremental btrfs snapshot
/// of a node via the node name, subvolume name and creation date.
///
/// To construct this type, use [`Volume::snapshot_now`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    node_name: String,
    subvol: String,
    is_incremental: bool,
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
            self.taken().format(Self::PATH_FMT)
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
            taken: NaiveDateTime::parse_from_str(taken, Self::PATH_FMT)?,
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
    pub fn from_subvol(subvol: String) -> Result<Self, LocalNodeError> {
        let node = Node::local()?;

        if node.owns_subvol(&subvol) {
            return Err(LocalNodeError::NoSuchSubvolume(subvol.clone()));
        }

        Ok(Self {
            node_name: node.name().to_string(),
            subvol,
        })
    }
}

/// A `Node` is a member of a distributed backup network
/// that can run its own `Volumes` and store those of other `Node`s.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Node {
    config: NodeConfig,
}

impl Node {
    /// Returns a new `Node` representing the local machine.
    pub fn local() -> Result<Self, LocalNodeError> {
        Ok(Self {
            config: NodeConfig::load()?,
        })
    }

    /// Returns the name of the `Node`.
    pub fn name(&self) -> &str {
        &self.config.node_name
    }

    /// Reports whether the `Node` is the origin of the specified subvolume.
    pub fn owns_subvol(&self, subvol: &String) -> bool {
        self.config.subvols.contains(subvol)
    }
}
