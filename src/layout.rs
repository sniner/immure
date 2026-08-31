//! Where an entry lives: the map from a digest to a path, and back.
//!
//! A digest is cut into two-character components, one per shard level, and the
//! entry sits at the bottom under its full digest:
//!
//! ```text
//! <root>/a1/b2/a1b2c3….json      depth 2, suffix ".json"
//! <root>/a1/a1b2c3….log.zst      depth 1, suffix ".log", compressed
//! ```
//!
//! Sharding exists because a quarter of a million files in one directory is
//! painful on every filesystem and unusable on some. Two levels give 65 536
//! buckets, which is the right order of magnitude for a store of hundreds of
//! thousands of entries; a few thousand are fine with one level.

use std::path::{Path, PathBuf};

use crate::compress;
use crate::crypt;
use crate::digest::Digest;
use crate::error::Result;

/// The suffix entries get when none is chosen.
pub const DEFAULT_SUFFIX: &str = ".dat";

/// What a quarantined entry carries on top of its name — see
/// [`Store::quarantine`](crate::Store::quarantine).
///
/// It is what takes the file out of the store's name space: nothing parses a
/// name ending in it as an entry any more, so a walk, a lookup and the
/// existence check behind `add` all stop seeing it.
pub const QUARANTINE_SUFFIX: &str = ".corrupt";

/// Which of the three shapes an entry lies in.
///
/// Written into the name rather than recorded anywhere, the way compression
/// always was: reading follows what is on disk, so a store can hold all three
/// at once and a half-finished conversion is not a broken store.
///
/// There is no fourth: sealed entries are always compressed underneath, so one
/// digest has exactly one set of bytes going into the cipher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Form {
    /// The content, as it came.
    Raw,
    /// zstd.
    Zstd,
    /// zstd, then sealed.
    Enc,
}

impl Form {
    /// The form a store writes new entries in.
    pub(crate) fn of(compress: bool, encrypt: bool) -> Self {
        match (compress, encrypt) {
            (_, true) => Form::Enc,
            (true, false) => Form::Zstd,
            (false, false) => Form::Raw,
        }
    }

    pub(crate) fn is_compressed(self) -> bool {
        matches!(self, Form::Zstd | Form::Enc)
    }

    pub(crate) fn is_encrypted(self) -> bool {
        matches!(self, Form::Enc)
    }

    /// All three, this one first — the order [`Store::candidates`] looks in.
    pub(crate) fn with_others_after(self) -> [Form; 3] {
        match self {
            Form::Raw => [Form::Raw, Form::Zstd, Form::Enc],
            Form::Zstd => [Form::Zstd, Form::Enc, Form::Raw],
            Form::Enc => [Form::Enc, Form::Zstd, Form::Raw],
        }
    }

    /// What this form is worth as a number, for remembering it across calls.
    pub(crate) fn as_u8(self) -> u8 {
        match self {
            Form::Raw => 0,
            Form::Zstd => 1,
            Form::Enc => 2,
        }
    }

    /// Back from [`Form::as_u8`]; anything else is [`Form::Raw`].
    pub(crate) fn from_u8(value: u8) -> Self {
        match value {
            1 => Form::Zstd,
            2 => Form::Enc,
            _ => Form::Raw,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Layout {
    root: PathBuf,
    suffix: String,
    depth: usize,
    /// `<suffix>.zst` and `<suffix>.zst.enc`, built once.
    ///
    /// Both are fixed for the life of a layout, and [`parse_name`](Layout::parse_name)
    /// is on the path of every name a store reads — a walk over a store asks it
    /// once per file, and `Store::named_at` can ask it twice per path.
    compressed_suffix: String,
    sealed_suffix: String,
}

impl Layout {
    pub(crate) fn new(root: PathBuf, suffix: &str, depth: usize) -> Self {
        let suffix = normalise_suffix(suffix);
        let compressed_suffix = format!("{suffix}{}", compress::SUFFIX);
        let sealed_suffix = format!("{compressed_suffix}{}", crypt::SUFFIX);
        Layout {
            root,
            suffix,
            depth,
            compressed_suffix,
            sealed_suffix,
        }
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn suffix(&self) -> &str {
        &self.suffix
    }

    pub(crate) fn depth(&self) -> usize {
        self.depth
    }

    /// The directory an entry with this digest belongs in.
    pub(crate) fn shard(&self, digest: &Digest) -> Result<PathBuf> {
        let mut path = self.root.clone();
        path.extend(digest.shards(self.depth)?);
        Ok(path)
    }

    /// The directory an entry whose digest begins like this belongs in.
    ///
    /// For looking one up by the beginning of its name, which is not a digest
    /// and may not even be of even length. Everything past the shard is
    /// ignored; `prefix` has to be at least `depth * 2` characters long.
    pub(crate) fn shard_of(&self, prefix: &str) -> PathBuf {
        debug_assert!(
            prefix.len() >= self.depth * 2,
            "prefix shorter than a shard"
        );
        let mut path = self.root.clone();
        path.extend((0..self.depth).map(|i| &prefix[i * 2..i * 2 + 2]));
        path
    }

    /// What an entry with this digest is called.
    pub(crate) fn file_name(&self, digest: &Digest, form: Form) -> String {
        let mut name = format!("{digest}{}", self.suffix);
        if form.is_compressed() {
            name.push_str(compress::SUFFIX);
        }
        if form.is_encrypted() {
            name.push_str(crypt::SUFFIX);
        }
        name
    }

    /// The full path of an entry, whether or not it is there.
    pub(crate) fn path(&self, digest: &Digest, form: Form) -> Result<PathBuf> {
        Ok(self.shard(digest)?.join(self.file_name(digest, form)))
    }

    /// Read a file name back: the digest it stands for, and which form it lies
    /// in. `None` for anything that is not an entry of this store.
    ///
    /// Longest tail first, or `.json.zst.enc` would be read as an entry whose
    /// suffix happens to end in `.zst`.
    pub(crate) fn parse_name(&self, name: &str) -> Option<(Digest, Form)> {
        let (stem, form) = if let Some(stem) = name.strip_suffix(&self.sealed_suffix) {
            (stem, Form::Enc)
        } else if let Some(stem) = name.strip_suffix(&self.compressed_suffix) {
            (stem, Form::Zstd)
        } else {
            (name.strip_suffix(&self.suffix)?, Form::Raw)
        };
        Digest::parse(stem).ok().map(|digest| (digest, form))
    }

    /// Read a quarantined file's name back: the digest it was filed under
    /// before its content stopped matching it, and the form it lies in. `None`
    /// for anything else.
    ///
    /// The form matters as much as the digest. What was set aside is still
    /// sealed, or still compressed, and a caller coming back for the bytes has
    /// to be given them the way it would be given any other entry's — the
    /// alternative is handing out ciphertext that reads like content.
    ///
    /// The counterpart to [`parse_name`](Layout::parse_name), and needed for
    /// the same reason: what an earlier pass set aside has to be recognised for
    /// what it is, or every pass after that reports it as a stray file.
    pub(crate) fn parse_quarantined(&self, name: &str) -> Option<(Digest, Form)> {
        let entry = if let Some(entry) = name.strip_suffix(QUARANTINE_SUFFIX) {
            entry
        } else {
            // A numbered one: the plain name was already taken when this was
            // set aside.
            let (head, serial) = name.rsplit_once('.')?;
            if serial.is_empty() || !serial.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            head.strip_suffix(QUARANTINE_SUFFIX)?
        };
        self.parse_name(entry)
    }

    /// What an entry is called once its name has been taken away from it.
    pub(crate) fn quarantine_name(name: &str, serial: usize) -> String {
        if serial == 0 {
            format!("{name}{QUARANTINE_SUFFIX}")
        } else {
            format!("{name}{QUARANTINE_SUFFIX}.{serial}")
        }
    }
}

/// A suffix always starts with a dot; nothing at all means the default.
///
/// Entries are told apart from strays by their suffix, so the empty string
/// would make every file in the tree an entry. That is why it falls back
/// rather than being honoured.
fn normalise_suffix(suffix: &str) -> String {
    let trimmed = suffix.trim();
    if trimmed.is_empty() || trimmed == "." {
        return DEFAULT_SUFFIX.to_string();
    }
    if trimmed.starts_with('.') {
        trimmed.to_string()
    } else {
        format!(".{trimmed}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest() -> Digest {
        Digest::parse("aabbccddee").unwrap()
    }

    fn layout(suffix: &str, depth: usize) -> Layout {
        Layout::new(PathBuf::from("/store"), suffix, depth)
    }

    #[test]
    fn suffixes_are_normalised() {
        assert_eq!(normalise_suffix("json"), ".json");
        assert_eq!(normalise_suffix(" .json "), ".json");
        assert_eq!(normalise_suffix(""), DEFAULT_SUFFIX);
        assert_eq!(normalise_suffix("   "), DEFAULT_SUFFIX);
        assert_eq!(normalise_suffix("."), DEFAULT_SUFFIX);
    }

    #[test]
    fn paths_shard_two_characters_per_level() {
        assert_eq!(
            layout("json", 2).path(&digest(), Form::Raw).unwrap(),
            Path::new("/store/aa/bb/aabbccddee.json")
        );
        assert_eq!(
            layout("jsonl", 1).path(&digest(), Form::Zstd).unwrap(),
            Path::new("/store/aa/aabbccddee.jsonl.zst")
        );
        assert_eq!(
            layout("json", 2).path(&digest(), Form::Enc).unwrap(),
            Path::new("/store/aa/bb/aabbccddee.json.zst.enc"),
            "sealed entries are compressed underneath, so both tails are there"
        );
        assert_eq!(
            layout("json", 0).path(&digest(), Form::Raw).unwrap(),
            Path::new("/store/aabbccddee.json"),
            "depth 0 is a flat store"
        );
    }

    #[test]
    fn a_digest_too_short_for_the_depth_is_refused() {
        // The digest has ten characters: five levels fit, six do not.
        assert!(layout("json", 5).path(&digest(), Form::Raw).is_ok());
        assert!(layout("json", 6).path(&digest(), Form::Raw).is_err());
    }

    #[test]
    fn a_shard_can_be_found_from_the_beginning_of_a_name() {
        // Not a digest: odd length, and shorter than one.
        assert_eq!(
            layout("json", 2).shard_of("aabbc"),
            Path::new("/store/aa/bb")
        );
        assert_eq!(layout("json", 1).shard_of("aabbc"), Path::new("/store/aa"));
        assert_eq!(
            layout("json", 0).shard_of("aabbc"),
            Path::new("/store"),
            "a flat store has one shard, and it is the root"
        );
    }

    #[test]
    fn names_parse_back_into_digests() {
        let layout = layout("json", 2);
        assert_eq!(
            layout.parse_name("aabbccddee.json"),
            Some((digest(), Form::Raw))
        );
        assert_eq!(
            layout.parse_name("aabbccddee.json.zst"),
            Some((digest(), Form::Zstd))
        );
    }

    #[test]
    fn a_quarantined_name_still_says_which_entry_it_was() {
        let layout = layout("json", 2);
        assert_eq!(
            layout.parse_quarantined("aabbccddee.json.corrupt"),
            Some((digest(), Form::Raw))
        );
        assert_eq!(
            layout.parse_quarantined("aabbccddee.json.zst.corrupt"),
            Some((digest(), Form::Zstd)),
            "a compressed entry is quarantined the same way, and still says so"
        );
        assert_eq!(
            layout.parse_quarantined("aabbccddee.json.corrupt.3"),
            Some((digest(), Form::Raw)),
            "the fourth time this one came back broken"
        );

        assert_eq!(
            layout.parse_quarantined("aabbccddee.json"),
            None,
            "an entry"
        );
        assert_eq!(layout.parse_quarantined("notes.json.corrupt"), None);
        assert_eq!(layout.parse_quarantined("aabbccddee.txt.corrupt"), None);
        assert_eq!(
            layout.parse_quarantined("aabbccddee.json.corrupt.x"),
            None,
            "not a number"
        );
    }

    #[test]
    fn a_quarantined_name_is_the_entry_name_plus_the_suffix() {
        assert_eq!(
            Layout::quarantine_name("aabbccddee.json", 0),
            "aabbccddee.json.corrupt"
        );
        assert_eq!(
            Layout::quarantine_name("aabbccddee.json", 2),
            "aabbccddee.json.corrupt.2"
        );
    }

    #[test]
    fn strays_are_not_entries() {
        let layout = layout("json", 2);
        assert_eq!(layout.parse_name("notes.json"), None, "not a digest");
        assert_eq!(layout.parse_name("aabbccddee.txt"), None, "wrong suffix");
        assert_eq!(layout.parse_name("aabbccddee"), None, "no suffix");
        assert_eq!(
            layout.parse_name("aabbccddee.json.zst.enc"),
            Some((digest(), Form::Enc)),
            "the longest tail wins, or this reads as a suffix ending in .zst"
        );
        assert_eq!(layout.parse_name("aabbccddee.json.tmp"), None);
        assert_eq!(layout.parse_name("aabbccdde.json"), None, "odd length");
    }
}
