use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SnapshotParseError {
    #[error("Incomplete snapshot identifier: Missing node name")]
    MissingNodeName,
    #[error("Incomplete snapshot identifier: Missing subvolume")]
    MissingSubvolume,
    #[error("Incomplete snapshot identifier: Missing snapshot type")]
    MissingType,
    #[error("Incomplete snapshot identifier: Missing capture timestamp")]
    MissingTimeTaken,

    #[error("Invalid snapshot type \"{0}\", expected \"full\" or \"incr\"")]
    InvalidType(String),

    #[error("Snapshot path ends in ..")]
    NoFileName,

    #[error("Snapshot path contains invalid unicode")]
    InvalidUnicode,

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
