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

/// A `LocalNodeError` indicates an error condition on the current node.
#[derive(Debug, Error)]
pub enum LocalNodeError {
    /// The specified subvolume does not exist on this node.
    #[error("Subvolume \"{0}\" does not exist")]
    NoSuchSubvolume(String),

    /// A `std::io::Error` I/O error occured.
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    /// A `toml::de::Error` TOML deserialization error occured.
    #[error("TOML deserialization error: {0}")]
    TomlDe(#[from] toml::de::Error),
}
