//! Crate error type. Everything fallible here returns [`Result`].

use std::io;
use std::path::PathBuf;

use thiserror::Error;

use crate::digest::{Algorithm, Digest};

/// The result type used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// An I/O operation failed; `context` names what was being done.
    ///
    /// The message is the context alone: the cause is `source`, where every
    /// chain-printing consumer looks for it, and a message that carried it
    /// too would say it twice there.
    #[error("{context}")]
    Io {
        context: String,
        #[source]
        source: io::Error,
    },

    /// A digest was not an even-length string of hexadecimal characters.
    #[error("not a valid digest: {0:?}")]
    InvalidDigest(String),

    /// A digest is too short to be sharded as deeply as this store shards.
    ///
    /// A lookup cannot get here: a digest of the store's own algorithm always
    /// reaches the store's depth, and any other length is
    /// [`Error::AlgorithmMismatch`] before the sharding is asked. What can is
    /// a maintenance pass meeting a hex-named stray shorter than the store
    /// shards deep, where it lands among the pass's failures.
    #[error("digest {digest} is too short for a store of depth {depth}: needs {needed} characters")]
    DigestTooShort {
        digest: Digest,
        depth: usize,
        needed: usize,
    },

    /// A digest has a length the store's algorithm can never produce, so it is
    /// another algorithm's and every answer computed with it would be wrong.
    ///
    /// What this catches is a store opened with the wrong algorithm: the
    /// digests in hand, and the names in the tree, are another hash's. Without
    /// the refusal every answer would be wrong *quietly* — a lookup finds
    /// nothing where the entry lies, and
    /// [`Store::verify`](crate::Store::verify) fails every healthy entry,
    /// which a pass that quarantines on `false` turns into a store set aside
    /// whole. Open the store with the algorithm that named it.
    ///
    /// What the length cannot catch is two algorithms of one size: SHA-256 and
    /// BLAKE3 digests are both 64 characters, and a store confusing those two
    /// is past telling from names alone.
    #[error(
        "digest {digest} has {} hex characters, a {algorithm} digest has {}: not this store's algorithm",
        .digest.len(),
        .algorithm.hex_len()
    )]
    AlgorithmMismatch {
        digest: Digest,
        algorithm: Algorithm,
    },

    /// A prefix handed to [`Store::matching`](crate::Store::matching) is
    /// empty or not hexadecimal, so no digest can begin with it.
    ///
    /// Deliberately not [`Error::InvalidDigest`]: a prefix is allowed to be
    /// odd-length and short, so it is not a digest that failed to parse, and
    /// the message a user reads should not claim it was one.
    #[error("not the beginning of a digest: {0:?}")]
    InvalidPrefix(String),

    /// A prefix handed to [`Store::matching`](crate::Store::matching) is too
    /// short to name anything narrower than a whole shard directory. See
    /// [`Store::min_prefix`](crate::Store::min_prefix).
    #[error(
        "prefix {prefix:?} is too short for a store of depth {depth}: needs {needed} characters"
    )]
    PrefixTooShort {
        prefix: String,
        depth: usize,
        needed: usize,
    },

    /// The requested shard depth cannot be cut out of this algorithm's digests.
    #[error("depth {depth} is too deep for {algorithm} digests: at most {max}")]
    InvalidDepth {
        depth: usize,
        algorithm: Algorithm,
        max: usize,
    },

    /// Every name [`Store::quarantine`](crate::Store::quarantine) could set an
    /// entry aside under is already taken, and it overwrites nothing.
    ///
    /// One entry that has come back damaged a hundred times over is not what
    /// this looks like in practice; something else is wrong.
    #[error("{}: cannot be set aside, every name is taken", .0.display())]
    QuarantineNamesTaken(PathBuf),

    /// A compressed entry was written or read, but the crate was built without
    /// the `zstd` feature.
    #[error("this build has no zstd support: enable the \"zstd\" feature")]
    CompressionUnavailable,

    /// An algorithm name from a config file or database was not recognised.
    #[error("unknown hash algorithm: {0:?}")]
    UnknownAlgorithm(String),

    /// A sealed entry was written or read, but the crate was built without the
    /// `crypt` feature.
    #[error("this build has no encryption support: enable the \"crypt\" feature")]
    EncryptionUnavailable,

    /// A key was not `Key::LEN` bytes long.
    #[error("a key is {expected} bytes, not {actual}")]
    KeyLength { expected: usize, actual: usize },

    /// The operating system would not hand out randomness.
    ///
    /// What `crypt::Key::random` needs, and with it every streamed write into a
    /// sealed store: the throwaway key such a write is held under until its
    /// digest is known comes from here. There is no fallback worth having — a
    /// key from anywhere else is not a key.
    #[error("no randomness available for a key")]
    Random,

    /// A sealed entry was met by a store that has no key.
    ///
    /// The store can still say that the entry is there, what it is called and
    /// where it lies — only its content is out of reach.
    #[error("{}: sealed, and this store has no key", .0.display())]
    KeyRequired(PathBuf),

    /// The first chunk of a sealed blob did not authenticate.
    ///
    /// The key is wrong, or the blob is damaged from its very first bytes, and
    /// nothing can tell those two apart: to the cipher both are "the tag does
    /// not match". Which is why this is not [`Error::Damaged`] — an entry that
    /// somebody tried to open with the wrong key must not be set aside as
    /// broken.
    #[error("not what was sealed here: the wrong key, or damaged from the start")]
    Unsealable,

    /// A chunk after the first did not authenticate, so the content is damaged.
    ///
    /// The key opened what came before it and is therefore right, which leaves
    /// only the bytes. Bit rot, a truncated file and a botched restore all
    /// arrive here. [`Store::verify`](crate::Store::verify) turns this into a
    /// plain `false`: it is the answer to the question that method asks.
    #[error("sealed content is damaged: the key opened this entry, its bytes changed")]
    Damaged,

    /// A sealed frame declares a version this build does not know.
    ///
    /// Written by a newer immure, and healthy: the key was never even tried.
    /// Which is why this is neither [`Error::Unsealable`] nor
    /// [`Error::Damaged`] — the one wrong answer here is quarantine. The
    /// entry is fine; the build is old.
    #[error("sealed frame version {0} is newer than this build understands")]
    FrameVersion(u8),

    /// A blob is too long to seal: past 2^32 chunks of 64 KiB, or 256 TiB.
    #[error("blob is too long to seal")]
    TooManyChunks,

    /// A file already lies under the name this operation was about to write,
    /// and it cannot be accounted for.
    ///
    /// The one case a conversion is allowed to find its destination taken is
    /// its own interrupted run, where what is there is this very entry in the
    /// new form and all that is left to do is let the old name go. Anything
    /// else — an empty file from a `cp` that was killed, a restore that
    /// recreated names before contents — stops the conversion, because the
    /// alternative is removing the only copy of the content on the strength of
    /// a name.
    ///
    /// [`Store::restore`](crate::Store::restore) answers the same way when the
    /// name it would give back is an entry's again: the store already answers
    /// for the content, the set-aside copy is redundant, and whether it may go
    /// is the caller's call — [`Store::discard`](crate::Store::discard), once
    /// made.
    #[error("{}: something else is already here that cannot be accounted for", .0.display())]
    Obstructed(PathBuf),
}

impl Error {
    /// Get the crate's own error back out of an [`io::Error`] a stream handed
    /// over.
    ///
    /// The streaming halves of the crate speak `io::Error`, because
    /// [`Read`](std::io::Read) and [`Write`](std::io::Write) leave them no
    /// other voice: a reader from
    /// [`Store::reader`](crate::Store::reader) or
    /// [`Store::reader_at`](crate::Store::reader_at), a `crypt::Opener`, a
    /// `crypt::Sealer`. When one of the crate's own answers ends such a stream
    /// — [`Error::Damaged`], [`Error::Unsealable`], [`Error::FrameVersion`],
    /// [`Error::TooManyChunks`],
    /// [`Error::Random`] — it travels *inside* the `io::Error`, and this is
    /// how it comes back out, so that mid-stream too an entry to set aside can
    /// be told from a disk that went away. Anything genuinely I/O keeps its
    /// shape as [`Error::Io`], with `context` saying what was being done.
    #[must_use]
    pub fn from_io(source: io::Error, context: impl Into<String>) -> Self {
        contextualise(source, || context.into())
    }
}

/// Attach human-readable context to an [`io::Error`].
///
/// The message is built lazily, so the common success path costs nothing:
///
/// ```ignore
/// fs::create_dir_all(&dir).ctx(|| format!("{}: creating shard", dir.display()))?;
/// ```
pub(crate) trait Context<T> {
    fn ctx(self, context: impl FnOnce() -> String) -> Result<T>;
}

impl<T> Context<T> for std::result::Result<T, io::Error> {
    fn ctx(self, context: impl FnOnce() -> String) -> Result<T> {
        self.map_err(|source| contextualise(source, context))
    }
}

/// What [`Context::ctx`] does to one error, for the callers that have an
/// [`io::Error`] in hand rather than a `Result` holding one.
pub(crate) fn contextualise(source: io::Error, context: impl FnOnce() -> String) -> Error {
    match source.downcast::<Error>() {
        // One of ours on its way back up through a `Read` or a `Write`, where
        // the only error type on offer is `io::Error`. It says more than the
        // context would, so it keeps its own shape: a caller can still match on
        // `Error::Damaged` after the bytes came through three layers of
        // adapters.
        Ok(err) => err,
        Err(source) => Error::Io {
            context: context(),
            source,
        },
    }
}
