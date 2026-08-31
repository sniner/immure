//! Hashes: the names entries are stored under.
//!
//! A [`Digest`] is a validated, lowercase hex string — the only thing a store
//! ever accepts as a name. [`Algorithm`] picks how one is computed, and
//! [`Hasher`] computes it incrementally, which is what lets an entry be hashed
//! while it streams past on its way to disk.

use std::fmt::{self, Write as _};
use std::io;
use std::str::FromStr;

use sha2::{Digest as _, Sha256, Sha384, Sha512};

use crate::error::{Error, Result};

/// The hash an entry is named after.
///
/// The default is SHA-256, on three counts at once: 64 hex characters, the
/// shortest of the four alongside BLAKE3; `sha256sum`, which is in coreutils
/// and has been for twenty years; and, on a CPU with SHA-2 instructions, the
/// fastest of the four. See the crate documentation for the measurement.
///
/// [`Algorithm::Blake3`] is the one to reach for where that last point does not
/// hold — an older x86-64 without SHA-NI hashes SHA-256 in software, and BLAKE3
/// is several times quicker there. It is worth measuring rather than assuming;
/// the answer is a property of the machine, not of the algorithm.
///
/// SHA-384 and SHA-512 are here for stores that are named with them already.
/// Both are slower than SHA-256 where SHA-2 instructions exist, and their names
/// are half again and twice as long.
///
/// Which hash a store uses is a property of the store, not of the entry:
/// nothing in a name says which one made it. A store opened with the wrong one
/// refuses the digests and names it is held against wherever the lengths give
/// it away ([`Error::AlgorithmMismatch`]);
/// SHA-256 and BLAKE3 write names of one length, and there content hashed
/// with the wrong one simply finds nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[non_exhaustive]
pub enum Algorithm {
    #[default]
    Sha256,
    Sha384,
    Sha512,
    Blake3,
}

impl Algorithm {
    /// The name used in config files and in [`FromStr`].
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Algorithm::Sha256 => "sha256",
            Algorithm::Sha384 => "sha384",
            Algorithm::Sha512 => "sha512",
            Algorithm::Blake3 => "blake3",
        }
    }

    /// How many hex characters this algorithm's digests have.
    #[must_use]
    pub const fn hex_len(self) -> usize {
        match self {
            Algorithm::Sha256 | Algorithm::Blake3 => 64,
            Algorithm::Sha384 => 96,
            Algorithm::Sha512 => 128,
        }
    }

    /// The deepest sharding these digests can carry — two hex characters per
    /// level.
    #[must_use]
    pub const fn max_depth(self) -> usize {
        self.hex_len() / 2
    }

    /// An empty incremental hasher.
    #[must_use]
    pub fn hasher(self) -> Hasher {
        Hasher(match self {
            Algorithm::Sha256 => State::Sha256(Sha256::new()),
            Algorithm::Sha384 => State::Sha384(Sha384::new()),
            Algorithm::Sha512 => State::Sha512(Sha512::new()),
            Algorithm::Blake3 => State::Blake3(Box::default()),
        })
    }

    /// Hash a buffer in one go.
    #[must_use]
    pub fn hash(self, data: &[u8]) -> Digest {
        let mut hasher = self.hasher();
        hasher.update(data);
        hasher.finish()
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Algorithm {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "sha256" | "sha-256" => Ok(Algorithm::Sha256),
            "sha384" | "sha-384" => Ok(Algorithm::Sha384),
            "sha512" | "sha-512" => Ok(Algorithm::Sha512),
            "blake3" => Ok(Algorithm::Blake3),
            _ => Err(Error::UnknownAlgorithm(s.to_string())),
        }
    }
}

/// An incremental hasher.
///
/// Implements [`io::Write`], so `io::copy(&mut reader, &mut hasher)` hashes a
/// stream without a buffer of its own.
pub struct Hasher(State);

// blake3's state is ~1.9 KiB, an order of magnitude more than the SHA-2 ones.
// Boxing it keeps the enum — and everything holding one — small.
enum State {
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
    Blake3(Box<blake3::Hasher>),
}

impl Hasher {
    /// Feed the next piece of content.
    pub fn update(&mut self, data: &[u8]) {
        match &mut self.0 {
            State::Sha256(h) => h.update(data),
            State::Sha384(h) => h.update(data),
            State::Sha512(h) => h.update(data),
            State::Blake3(h) => {
                h.update(data);
            }
        }
    }

    /// Consume the hasher and return the digest.
    #[must_use]
    pub fn finish(self) -> Digest {
        match self.0 {
            State::Sha256(h) => Digest(to_hex(&h.finalize())),
            State::Sha384(h) => Digest(to_hex(&h.finalize())),
            State::Sha512(h) => Digest(to_hex(&h.finalize())),
            State::Blake3(h) => Digest(h.finalize().to_hex().to_string()),
        }
    }
}

impl fmt::Debug for Hasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hasher").finish_non_exhaustive()
    }
}

impl io::Write for Hasher {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing into a String is infallible.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The hash of an entry's content, as lowercase hex — an entry's name, and the
/// only identity it has.
///
/// Constructed by hashing content ([`Algorithm::hash`], [`Hasher::finish`]) or
/// by parsing a string that came back from somewhere else — a database column,
/// a log file, a command line. Parsing validates, so a `Digest` in hand is
/// always well-formed; uppercase input is normalised to lowercase, since that
/// is how entries are named on disk.
///
/// ```
/// use immure::Digest;
///
/// let digest: Digest = "B94D27B9934D3E08".parse()?;
/// assert_eq!(digest.as_str(), "b94d27b9934d3e08");
/// assert!("not-hex".parse::<Digest>().is_err());
/// # Ok::<(), immure::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct Digest(String);

impl Digest {
    /// Validate a hex string as a digest.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidDigest`] when the string is empty, of odd length, or
    /// holds anything but hexadecimal characters.
    pub fn parse(s: &str) -> Result<Self> {
        let invalid = s.is_empty() || s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit());
        if invalid {
            return Err(Error::InvalidDigest(s.to_string()));
        }
        Ok(Digest(s.to_ascii_lowercase()))
    }

    /// The digest as lowercase hex.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// How many hex characters the digest has.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Always false — a digest is never empty, parsing rejects that.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }

    /// The first `depth` two-character shard components.
    ///
    /// # Errors
    ///
    /// [`Error::DigestTooShort`] when the digest cannot be cut that deeply.
    pub(crate) fn shards(&self, depth: usize) -> Result<impl Iterator<Item = &str>> {
        let needed = depth * 2;
        if self.0.len() < needed {
            return Err(Error::DigestTooShort {
                digest: self.clone(),
                depth,
                needed,
            });
        }
        Ok((0..depth).map(move |i| &self.0[i * 2..i * 2 + 2]))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Digest {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromStr for Digest {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Digest::parse(s)
    }
}

impl TryFrom<&str> for Digest {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self> {
        Digest::parse(s)
    }
}

impl TryFrom<String> for Digest {
    type Error = Error;

    fn try_from(s: String) -> Result<Self> {
        Digest::parse(&s)
    }
}

impl From<Digest> for String {
    fn from(digest: Digest) -> Self {
        digest.0
    }
}

// Deserialisation goes through the validating constructor rather than
// `transparent`, so a digest read out of JSON or TOML is as trustworthy as one
// that was parsed by hand.
#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Digest::parse(&raw).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        assert_eq!(
            Algorithm::Sha256.hash(b"hello world").as_str(),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
        assert_eq!(
            Algorithm::Sha384.hash(b"hello world").as_str(),
            "fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3\
             e417cb71ce646efd0819dd8c088de1bd"
        );
        assert_eq!(
            Algorithm::Sha384.hash(b"").as_str(),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da\
             274edebfe76f65fbd51ad2f14898b95b"
        );
    }

    #[test]
    fn hashing_in_pieces_matches_hashing_at_once() {
        for algorithm in [
            Algorithm::Sha256,
            Algorithm::Sha384,
            Algorithm::Sha512,
            Algorithm::Blake3,
        ] {
            let mut hasher = algorithm.hasher();
            hasher.update(b"hello ");
            hasher.update(b"world");
            assert_eq!(hasher.finish(), algorithm.hash(b"hello world"));
            assert_eq!(algorithm.hash(b"").len(), algorithm.hex_len());
        }
    }

    #[test]
    fn hasher_is_a_write_sink() {
        let mut hasher = Algorithm::Sha384.hasher();
        io::copy(&mut &b"hello world"[..], &mut hasher).unwrap();
        assert_eq!(hasher.finish(), Algorithm::Sha384.hash(b"hello world"));
    }

    #[test]
    fn parsing_validates_and_normalises() {
        assert_eq!(Digest::parse("AbCd").unwrap().as_str(), "abcd");
        assert!(Digest::parse("").is_err());
        assert!(Digest::parse("abc").is_err(), "odd length");
        assert!(Digest::parse("zz").is_err(), "not hex");
        assert!(Digest::parse("ab cd").is_err());
    }

    #[test]
    fn shards_cut_two_characters_per_level() {
        let digest = Digest::parse("aabbccdd").unwrap();
        assert_eq!(digest.shards(0).unwrap().count(), 0);
        assert_eq!(
            digest.shards(3).unwrap().collect::<Vec<_>>(),
            ["aa", "bb", "cc"]
        );
        assert!(digest.shards(5).is_err());
    }

    #[test]
    fn algorithm_names_round_trip() {
        for algorithm in [
            Algorithm::Sha256,
            Algorithm::Sha384,
            Algorithm::Sha512,
            Algorithm::Blake3,
        ] {
            assert_eq!(algorithm.name().parse::<Algorithm>().unwrap(), algorithm);
        }
        assert_eq!("SHA-384".parse::<Algorithm>().unwrap(), Algorithm::Sha384);
        assert!("md5".parse::<Algorithm>().is_err());
    }
}
