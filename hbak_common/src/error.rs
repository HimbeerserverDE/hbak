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

use crate::proto::{Snapshot, Volume};

use std::io;

use serde::{Deserialize, Serialize};
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
    /// No configuration file exists on this node.
    #[error("Local node is not initialized")]
    ConfigUninit,
    /// The permissions on the configuration file are insecure.
    #[error("Insecure config permissions (limit access to root user!)")]
    InsecurePerms,

    /// No full backup of the specified volume could be found on this node.
    #[error("No full backups of volume \"{0}\" exist locally")]
    NoFullBackup(Volume),
    /// No incremental backup of the specified volume could be found on this node.
    #[error("No incremental backups of volume \"{0}\" exist locally")]
    NoIncrementalBackup(Volume),
    /// No full snapshot of the specified subvolume could be found on this node.
    #[error("No full snapshots of subvolume \"{0}\" exist")]
    NoFullSnapshot(String),
    /// No incremental snapshot of the specified subvolume could be found on this node.
    #[error("No incremental snapshots of subvolume \"{0}\" exist")]
    NoIncrementalSnapshot(String),
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

/// A `NetworkError` indicates an error condition on a network connection.
/// It may be a low-level connection issue or a high-level protocol error.
#[derive(Debug, Error)]
pub enum NetworkError {
    /// A network reception represents an illegal state transition on the local node.
    #[error("Illegal state transition")]
    IllegalTransition,
    /// Unable to parse a [`Volume`].
    #[error("Unable to parse volume: {0}")]
    VolumeParseError(#[from] VolumeParseError),
    /// An error occured on the local node.
    #[error("Local error: {0}")]
    LocalError(#[from] LocalNodeError),
    /// A high-level `RemoteError` occured.
    #[error("Remote error: {0}")]
    RemoteError(#[from] RemoteError),

    /// A `std::io::Error` I/O error occured.
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    /// A bincode (de)serialization error occured.
    #[error("Bincode (de)serialization error: {0}")]
    Bincode(#[from] Box<bincode::ErrorKind>),
    /// The encryption or decryption of a network message failed.
    #[error("Encryption or decryption failure")]
    ChaCha20Poly1305(#[from] chacha20poly1305::Error),
}

/// A `RemoteError` indicates an error condition on the current session
/// or the remote node. This is a special case of [`NetworkError`].
#[derive(Clone, Debug, Eq, PartialEq, Error, Serialize, Deserialize)]
pub enum RemoteError {
    /// Access is denied by the remote node.
    /// May be an authentication or authorization failure, infer details from the context.
    #[error("Access denied by remote node")]
    AccessDenied,
    /// The remote node was denied access.
    /// May be an authentication or authorization failure, infer details from the context.
    #[error("Remote node is unauthorized")]
    Unauthorized,

    /// The backup has already been fully transferred
    /// and cannot be overwritten again for security reasons.
    #[error("Backup already transferred completely")]
    Immutable,

    /// A network transmission represents an illegal state transition on the remote node.
    #[error("Illegal state transition on remote node")]
    IllegalTransition,

    /// Cannot set up multiple concurrent streams in the same direction.
    #[error("Already streaming in this direction")]
    AlreadyStreaming,
    /// Unsolicited attempt to stream data.
    #[error("Not streaming in this direction")]
    NotStreaming,
    /// The remote node is unable to continue streaming *our* transmission.
    /// This is usually caused by a [`std::io::Error`] on the destination stream.
    #[error("Remote node reception failure")]
    RxError,
}
