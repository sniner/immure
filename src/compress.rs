//! zstd, behind one seam.
//!
//! A store either compresses its entries or it does not, and everything else in
//! the crate copies bytes through the two functions here without knowing which.
//! The `zstd` feature decides whether the codec is compiled in at all; without
//! it, compressing or reading a `.zst` entry fails with
//! [`Error::CompressionUnavailable`] instead of quietly doing the wrong thing.

use std::io::{BufRead, BufReader, Read, Write};

#[cfg(not(feature = "zstd"))]
use crate::error::Error;
use crate::error::{Context as _, Result};

/// The extra extension a compressed entry carries, after its regular suffix:
/// `<digest>.json.zst`.
pub(crate) const SUFFIX: &str = ".zst";

/// Read buffer size — large enough that a caller after the first few
/// kilobytes of an entry gets them in one syscall.
pub(crate) const BLOCK_SIZE: usize = 64 * 1024;

/// Whether this build can read and write compressed entries.
#[must_use]
pub const fn available() -> bool {
    cfg!(feature = "zstd")
}

/// Copy all of `src` into `dst`, compressing on the way when asked to.
#[cfg(feature = "zstd")]
pub(crate) fn copy(src: &mut impl Read, dst: &mut impl Write, compress: bool) -> Result<u64> {
    if !compress {
        return std::io::copy(src, dst).ctx(|| "writing entry".into());
    }
    let mut encoder = zstd::Encoder::new(dst, zstd::DEFAULT_COMPRESSION_LEVEL)
        .ctx(|| "starting zstd compression".into())?;
    let written = std::io::copy(src, &mut encoder).ctx(|| "writing compressed entry".into())?;
    // Closes the frame into `dst` but leaves `dst` open, so the caller can still
    // flush it to the device before renaming it into place.
    encoder.finish().ctx(|| "finishing zstd frame".into())?;
    Ok(written)
}

#[cfg(not(feature = "zstd"))]
pub(crate) fn copy(src: &mut impl Read, dst: &mut impl Write, compress: bool) -> Result<u64> {
    if compress {
        return Err(Error::CompressionUnavailable);
    }
    std::io::copy(src, dst).ctx(|| "writing entry".into())
}

/// A buffered reader over an entry, decompressing when the entry is compressed.
///
/// Takes any reader, not just the file: a sealed entry arrives here already
/// unsealed, through `crypt::Opener`.
#[cfg(feature = "zstd")]
pub(crate) fn reader(src: impl Read + 'static, compressed: bool) -> Result<Box<dyn BufRead>> {
    let buffered = BufReader::with_capacity(BLOCK_SIZE, src);
    if !compressed {
        return Ok(Box::new(buffered));
    }
    let decoder =
        zstd::Decoder::with_buffer(buffered).ctx(|| "starting zstd decompression".into())?;
    Ok(Box::new(BufReader::with_capacity(BLOCK_SIZE, decoder)))
}

#[cfg(not(feature = "zstd"))]
pub(crate) fn reader(src: impl Read + 'static, compressed: bool) -> Result<Box<dyn BufRead>> {
    if compressed {
        return Err(Error::CompressionUnavailable);
    }
    Ok(Box::new(BufReader::with_capacity(BLOCK_SIZE, src)))
}
