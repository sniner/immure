//! Sealing a blob, and getting it back.
//!
//! One key, one nonce, one blob: XChaCha20-Poly1305 over the bytes, and that is
//! the whole job. The store uses this on its way to disk, and the same two
//! functions are public so a caller that also has files to seal outside the
//! store does not have to invent a second way of doing it.
//!
//! # The frame
//!
//! A sealed blob names its own format before anything else: four magic bytes
//! (`immr`), one version byte, then the nonce, then the chunks. The header is
//! read before the key is ever tried, so a frame written by a newer immure is
//! refused for what it is — [`Error::FrameVersion`](crate::Error::FrameVersion)
//! — rather than reported as a wrong key or as damage, which is what keeps a
//! maintenance pass from setting aside a healthy entry it is merely too old
//! to open. The version byte is also all the room future formats need: a
//! later version may lay out everything after its own byte differently.
//!
//! # Chunks
//!
//! A blob is sealed in 64 KiB chunks rather than as one message, because
//! [`Store::reader`](crate::Store::reader) promises that a caller can
//! read the head of an entry and stop. One tag over the whole file would leave
//! only two ways to keep that promise, and both are bad: buffer the entry
//! whole, or hand out bytes that have not been authenticated yet.
//!
//! Each chunk gets its own nonce, built from the fixed prefix plus the chunk's
//! number and a flag that marks the last one. Marking the end is what makes a
//! truncated file fail rather than read short: cutting the file at a chunk
//! boundary removes the chunk that says it is the last.
//!
//! The last chunk is always shorter than a full one — when the content divides
//! evenly, an empty final chunk is written — so the reader knows the end by the
//! length of what it read, without looking ahead.
//!
//! # The nonce
//!
//! A nonce has to be *unique*, not secret; it travels in the clear in every
//! AEAD format there is. So it does here: **every blob is sealed under a nonce
//! drawn there and then, and written out ahead of its first chunk.** Unsealing
//! needs the key and nothing else, and no caller is ever handed the choice.
//!
//! `XChaCha20`'s nonce is 192 bits precisely so that it can be drawn at
//! random without keeping a record of what has been used — which is the whole
//! reason for the extended nonce over `ChaCha20`'s. A nonce derived from the
//! content's digest would be tidier to look at and would cost 19 bytes less per
//! entry, but it makes "never twice under one key" a property every writing
//! path has to uphold on its own: a digest names as many files as the store
//! happens to hold under it, across renames, quarantines and re-adds, and no
//! single write can see the others. Drawing it is what makes the question not
//! arise.

/// The extra extension a sealed entry carries, after everything else:
/// `<digest>.<suffix>.zst.enc`.
pub(crate) const SUFFIX: &str = ".enc";

/// Whether this build can seal and unseal entries.
///
/// Known without the feature, like the `.enc` suffix itself: a build that
/// cannot open a sealed entry still has to recognise one, or it reports the
/// entries of an encrypted store as stray files.
#[must_use]
pub const fn available() -> bool {
    cfg!(feature = "crypt")
}

#[cfg(feature = "crypt")]
mod cipher;

#[cfg(feature = "crypt")]
pub use cipher::{Key, Opener, Sealer, open, seal};
