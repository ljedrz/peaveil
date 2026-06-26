//! Error types returned by the public `peaveil` API.

use thiserror::Error;

/// All errors that can be surfaced to the application through the
/// public `peaveil` API.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// An I/O error from the underlying `pea2pea` transport, e.g. a
    /// failed `connect`, `bind`, or socket read.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The peaveil frame does not fit in the configured peashape
    /// `frame_size`. Raise `frame_size` or lower `sample_size`.
    #[error("sample is too large for the configured frame size: need at least {needed} bytes of payload, have {available}")]
    SampleTooLarge {
        /// The number of payload bytes required to encode the
        /// requested `sample_size` peers, in bytes.
        needed: usize,
        /// The number of payload bytes available in the
        /// configured peashape `frame_size`, in bytes.
        available: usize,
    },

    /// A peer sample frame was received that could not be parsed.
    /// Treated as a no-op (the frame is dropped) rather than a
    /// hard error; surfaced for visibility.
    #[error("could not decode a peaveil sample: {0}")]
    Decode(String),

    /// The configuration is internally inconsistent.
    #[error("invalid configuration: {0}")]
    Config(String),
}

impl From<peashape::Error> for Error {
    fn from(e: peashape::Error) -> Self {
        match e {
            peashape::Error::Io(io) => Error::Io(io),
            // The peaveil layer never enqueues raw frames into
            // peashape, so the other variants are not reachable in
            // practice. They are reported as generic IO errors so
            // they cannot silently disappear.
            other => Error::Io(std::io::Error::other(other.to_string())),
        }
    }
}
