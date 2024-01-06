use crate::proto::Snapshot;

use std::io;

use thiserror::Error;

/// A `SnapshotParseError` indicates a failure parsing a `Snapshot`.
#[derive(Debug, Error)]
pub enum SnapshotParseError {
    /// The identifier is missing the node name or is completely empty.
    ///
    /// This variant should never actually happen:
    /// String splitting should always return at least one item.
    #[error("Incomplete snapshot identifier: Missing node name")]
    MissingNodeName,
    /// The identifier is missing the subvolume name.
    #[error("Incomplete snapshot identifier: Missing subvolume")]
    MissingSubvolume,
    /// The identifier is missing the snapshot type.
    #[error("Incomplete snapshot identifier: Missing snapshot type")]
    MissingType,
    /// The identifier is missing the timestamp of when the snapshot was taken.
    #[error("Incomplete snapshot identifier: Missing capture timestamp")]
    MissingTimeTaken,

    /// The snapshot type is invalid.
    /// Accepted values include "full" and "incr".
    #[error("Invalid snapshot type \"{0}\", expected \"full\" or \"incr\"")]
    InvalidType(String),

    /// When parsing from a [`std::path::Path`] this error indicates
    /// that [`std::path::Path::file_name`] returned `None`
    /// which happens when the last part of the path is the double dot.
    #[error("Snapshot path ends in ..")]
    NoFileName,

    /// When parsing from a [`std::path::Path`] this error indicates
    /// that the return value of [`std::path::Path::file_name`]
    /// could not be converted to a regular string
    /// due to it containing invalid Unicode.
    #[error("Snapshot path contains invalid unicode")]
    InvalidUnicode,

    /// The timestamp of when the snapshot was taken
    /// does not follow the `%Y%m%d%H%M%S` format.
    #[error("Unable to parse capture timestamp: {0}")]
    MalformedTimeTaken(#[from] chrono::ParseError),
}

/// A `VolumeParseError` indicates a failure parsing a `Volume`.
#[derive(Debug, Error)]
pub enum VolumeParseError {
    /// The identifier is missing the node name or is completely empty.
    ///
    /// This variant should never actually happen:
    /// String splitting should always return at least one item.
    #[error("Incomplete volume identifier: Missing node name")]
    MissingNodeName,
    /// The identifier is missing the subvolume name.
    #[error("Incomplete volume identifier: Missing subvolume")]
    MissingSubvolume,
}

/// A `LocalNodeError` indicates an error condition on the current node.
#[derive(Debug, Error)]
pub enum LocalNodeError {
    /// A btrfs command failed to execute correctly.
    #[error("Btrfs command execution failed")]
    BtrfsCmd,
    /// A btrfs command did not provide a stdin file.
    #[error("Btrfs command does not have stdin")]
    NoBtrfsInput,
    /// A btrfs command did not provide a stdout file.
    #[error("Btrfs command does not have stdout")]
    NoBtrfsOutput,

    /// A configuration file already exists on this node.
    #[error("Local node is already initialized")]
    ConfigExists,
    /// The permissions on the configuration file are insecure.
    #[error("Insecure config permissions (limit access to root user!)")]
    InsecurePerms,

    /// No full backup of the specified subvolume could be found on this node.
    #[error("No full backups of subvolume \"{0}\" exist locally")]
    NoFullBackup(String),
    /// No full snapshot of the specified subvolume could be found on this node.
    #[error("No full snapshots of subvolume \"{0}\" exist")]
    NoFullSnapshot(String),
    /// A snapshot with the same identifier already exists.
    #[error("A snapshot with identifier \"{0}\" already exists")]
    SnapshotExists(Snapshot),
    /// The snapshot cannot be restored to because it already exists.
    #[error("Cannot restore existing snapshot \"{0}\" from backup")]
    SnapshotNotGone(Snapshot),
    /// There was a failure parsing a `Snapshot`.
    #[error("Failed to parse snapshot identifier")]
    SnapshotParseError(#[from] SnapshotParseError),

    /// The specified subvolume is not owned by this node.
    #[error("Subvolume \"{0}\" is not owned by this node")]
    ForeignSubvolume(String),
    /// The specified subvolume does not exist on this node.
    #[error("Subvolume \"{0}\" does not exist")]
    NoSuchSubvolume(String),

    /// A `std::io::Error` I/O error occured.
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    /// Password-based key derivation using Argon2id failed.
    #[error("Password-based key derivation using Argon2id failed: {0}")]
    Argon2(#[from] argon2::Error),
    /// The encryption or decryption of some data failed.
    #[error("Encryption or decryption failure")]
    ChaCha20Poly1305(#[from] chacha20poly1305::Error),
    /// A `toml::ser::Error` TOML serialization error occured.
    #[error("TOML serialization error: {0}")]
    TomlSer(#[from] toml::ser::Error),
    /// A `toml::de::Error` TOML deserialization error occured.
    #[error("TOML deserialization error: {0}")]
    TomlDe(#[from] toml::de::Error),
}
