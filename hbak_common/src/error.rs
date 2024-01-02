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