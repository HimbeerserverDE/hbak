use thiserror::Error;

#[derive(Debug, Error)]
pub enum SnapshotParseError {
    #[error("Snapshot path contains invalid unicode")]
    InvalidUnicode,

    #[error("Incomplete snapshot identifier: Missing node name")]
    MissingNodeName,
    #[error("Incomplete snapshot identifier: Missing subvolume")]
    MissingSubvolume,
    #[error("Incomplete snapshot identifier: Missing capture timestamp")]
    MissingTimeTaken,
    #[error("Snapshot path ends in ..")]
    NoFileName,

    #[error("Unable to parse capture timestamp: {0}")]
    MalformedTimeTaken(#[from] chrono::ParseError),
}
