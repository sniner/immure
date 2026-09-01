//! The store: add content, get it back, keep it honest.

use std::fs::{self, File};
use std::io::{self, BufRead, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::{Duration, SystemTime};

use tracing::{debug, info, warn};

use crate::compress;
use crate::crypt;
use crate::digest::{Algorithm, Digest, Hasher};
use crate::error::{Context as _, Error, Result, contextualise};
use crate::layout::{DEFAULT_SUFFIX, Form, Layout};
use crate::protect::{self, Protection};
use crate::temp::{self, TempFile};

/// How deep a store shards by default: 65 536 buckets, enough for the
/// hundreds of thousands of entries a single machine holds.
pub const DEFAULT_DEPTH: usize = 2;

/// How long a temporary file has to have been lying untouched before
/// [`Store::prune_temp_files`] treats it as abandoned: 24 hours.
pub const DEFAULT_TEMP_MIN_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// How many names [`Store::quarantine`] tries before giving up. Enough to get
/// past what earlier runs set aside for content that keeps coming back damaged.
const QUARANTINE_ATTEMPTS: usize = 100;

/// Whether [`Store::add`] found the content already there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
pub enum Status {
    /// The content was written now.
    New,
    /// The content was already in the store; nothing was written.
    Exists,
}

impl Status {
    /// True when this call is what put the content in the store.
    #[must_use]
    pub const fn is_new(self) -> bool {
        matches!(self, Status::New)
    }
}

/// A stored object: what it is called, and where it lies.
///
/// Only the store makes one — [`Store::add`], [`Store::entries`],
/// [`Store::entry_at`] — so an `Entry` in hand says its path has been read as
/// one of this store's names. That is what [`Store::verify`] and
/// [`Store::quarantine`] take it for: the question "is this file even an
/// entry?" is answered by [`Store::entry_at`] once, not by every method
/// again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    digest: Digest,
    path: PathBuf,
    /// Which of the three shapes the file is in.
    ///
    /// Read off the name once, by whoever knew the store's suffix, and carried
    /// from there. Working it out again from the path alone is what nothing
    /// here does any more: the tail of a name only says which form an entry is
    /// in if the suffix in front of it is known, and a store whose suffix is
    /// `.enc` or `.zst` would otherwise have every one of its plain entries
    /// taken for a sealed one.
    form: Form,
}

impl Entry {
    /// The hash of the content — the entry's name and its whole identity.
    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    /// Where the entry lies right now.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether this entry is stored compressed. A sealed entry always is.
    ///
    /// Compression is a property of the file, not of the store: a store that
    /// compresses still reads the plain entries written before it did.
    #[must_use]
    pub fn is_compressed(&self) -> bool {
        self.form.is_compressed()
    }

    /// Whether this entry is stored sealed.
    ///
    /// Like compression, a property of the file: a store that has been given a
    /// key still reads the entries written before it had one, and a store
    /// halfway through `encrypt_all` holds both kinds.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.form.is_encrypted()
    }
}

/// A file [`Store::quarantine`] set aside: what it was filed under, where it
/// lies now, and the form its bytes are still in.
///
/// Made by [`Store::quarantined`]. Only the name was read — nothing says
/// whether the bytes behind it are still what they were when the file was set
/// aside.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quarantined {
    digest: Digest,
    path: PathBuf,
    /// Which of the three shapes the bytes are in. Setting a file aside does
    /// not change its bytes, so what was sealed or compressed still is.
    form: Form,
}

impl Quarantined {
    /// The digest the file was filed under before its content stopped
    /// matching it — the claim [`Store::quarantine`] took away.
    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    /// Where the file lies now.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether the bytes are still compressed.
    #[must_use]
    pub fn is_compressed(&self) -> bool {
        self.form.is_compressed()
    }

    /// Whether the bytes are still sealed: any salvage needs the key.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.form.is_encrypted()
    }
}

/// What a pass over every entry in a store did — a bulk (de)compression, a
/// sealing, a key change.
///
/// The three counts are meant to be told apart. "Already there" and "not this
/// pass's business" both leave an entry untouched, but only the first one says
/// the pass is *finished* with it — which is the question a caller asks before
/// it destroys an old key.
#[derive(Debug, Default)]
pub struct Conversion {
    /// Entries rewritten by this run.
    pub converted: usize,
    /// Entries this run applies to that were already the way it wants them,
    /// and so cost nothing but the look that established it.
    pub already: usize,
    /// Entries outside what this run is for, left alone. A sealed entry met by
    /// `compress_all`, an entry that was never sealed met by `change_key`.
    pub skipped: usize,
    /// Entries that could not be converted. The rest of the run went on
    /// regardless — one unreadable file should not stop a maintenance pass over
    /// a whole archive.
    ///
    /// Not all of these are worth a second run: see
    /// [`Failure::recoverable`], and [`unfinished`](Conversion::unfinished)
    /// for the question a caller actually has.
    pub failed: Vec<Failure>,
}

impl Conversion {
    /// The failures a later run could still do something about.
    ///
    /// The rest are entries no run will ever move — a file whose seal does not
    /// authenticate under either key. Leaving them out is what makes the count
    /// usable: a key change over a store holding one unreadable quarantined
    /// entry would otherwise never report itself finished, and the old key
    /// could never be destroyed.
    pub fn unfinished(&self) -> impl Iterator<Item = &Failure> {
        self.failed.iter().filter(|failure| failure.recoverable)
    }

    /// Whether this run is through with the store: nothing left that another
    /// run of it could still move.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.unfinished().next().is_none()
    }
}

/// One entry a bulk operation could not handle.
#[derive(Debug)]
pub struct Failure {
    pub path: PathBuf,
    pub error: Error,
    /// Whether running the pass again could still move this entry.
    ///
    /// `false` for an entry that is beyond any run of it — its seal does not
    /// authenticate under either key, or another file of the same run already
    /// carries its digest. Such an entry is reported because it is not where
    /// the pass wanted it, not because anything is left to try.
    pub recoverable: bool,
}

/// A content-addressed store under one directory.
///
/// Entries are named after the hash of their content, so writing the same bytes
/// twice is a no-op, a file carries its own integrity check, and nothing is ever
/// modified in place. See the [crate documentation](crate) for the shape this
/// takes on disk.
///
/// A `Store` is a handle, not a lock: it holds no open files, so it is cheap
/// to clone, safe to share across threads, and several processes can write into
/// one store at once. The little it learns as it goes — whether write
/// protection holds where it lies — is shared between its clones and never
/// written down.
#[derive(Debug, Clone)]
pub struct Store {
    layout: Layout,
    algorithm: Algorithm,
    compress: bool,
    #[cfg(feature = "crypt")]
    key: Option<Arc<crypt::Key>>,
    protection: Protection,
    /// Which of an entry's three possible names to try first — see
    /// [`Store::candidates`].
    first_form: Arc<AtomicU8>,
    /// Whether this store's key has opened one of its entries yet — see
    /// [`Store::verify`].
    #[cfg(feature = "crypt")]
    key_proven: Arc<AtomicBool>,
}

/// Configures a [`Store`]. Made by [`Store::builder`].
#[derive(Debug, Clone)]
pub struct Builder {
    root: PathBuf,
    suffix: String,
    depth: usize,
    algorithm: Algorithm,
    compress: bool,
    #[cfg(feature = "crypt")]
    key: Option<Arc<crypt::Key>>,
}

impl Builder {
    /// The extension entries get, `.dat` by default.
    ///
    /// A leading dot is optional, and so is the whole thing: the empty
    /// string — or a lone dot — names entries by digest alone, with only
    /// `.zst` and `.zst.enc` ever on top. Where a store holds one kind of
    /// content, the suffix is worth setting to what that is (`.json`,
    /// `.pdf`): a store is a lot easier to work with by hand when `file`,
    /// `grep` and the desktop know what they are looking at. Where it holds
    /// anything at all, there is nothing truthful to write, and none is the
    /// honest choice.
    ///
    /// Either way the digest is what tells entries from strays — a name has
    /// to parse back into even-length hex. A bare store just casts the
    /// widest net, so its tree should hold nothing whose name could pass for
    /// one.
    #[must_use]
    pub fn suffix(mut self, suffix: &str) -> Self {
        self.suffix = suffix.to_string();
        self
    }

    /// How many levels of two-character directories to shard into.
    ///
    /// `0` puts everything in one flat directory, which is fine for a handful
    /// of entries and miserable for a million.
    #[must_use]
    pub fn depth(mut self, depth: usize) -> Self {
        self.depth = depth;
        self
    }

    /// Which hash entries are named after. Changing it on an existing store
    /// makes its entries unfindable — the names no longer match.
    #[must_use]
    pub fn algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Compress new entries with zstd.
    ///
    /// Only new ones: reading always follows the file, so a store can be
    /// switched over at any time and the entries already there stay readable.
    /// [`Store::compress_all`] converts the backlog.
    #[must_use]
    pub fn compress(mut self, compress: bool) -> Self {
        self.compress = compress;
        self
    }

    /// Whether a key was given, whatever this build can do with it.
    // Without the feature there is no key field to look at, and the answer is
    // a constant — which is what clippy sees.
    #[cfg_attr(not(feature = "crypt"), allow(clippy::unused_self))]
    fn has_key(&self) -> bool {
        #[cfg(feature = "crypt")]
        {
            self.key.is_some()
        }
        #[cfg(not(feature = "crypt"))]
        {
            false
        }
    }

    /// Seal new entries with this key, and unseal what is read back.
    ///
    /// A key implies compression: a sealed entry is always compressed
    /// underneath, so [`compresses`](Store::compresses) answers `true` for an
    /// encrypting store whatever [`compress`](Builder::compress) was told.
    ///
    /// Nothing about the key is written into the store, and nothing has to be:
    /// an entry carries its own nonce. A store therefore stays what it was
    /// — a tree of files whose names say everything about where they lie — and
    /// the key is the caller's to keep, along with whatever it takes to get it
    /// back. There is no wrong key to be told apart from a missing one at
    /// build time; both show up when an entry is opened.
    #[cfg(feature = "crypt")]
    #[must_use]
    pub fn key(mut self, key: crypt::Key) -> Self {
        self.key = Some(Arc::new(key));
        self
    }

    /// Hand back the configured store, touching nothing on disk.
    ///
    /// A handle is a description of where a store lies and how it is laid out,
    /// and describing one is not the same as making one: a store that is not
    /// there is not created by asking about it. That matters most where it is
    /// least visible — a root on a share that is not mounted would otherwise
    /// get an empty store written onto the mount point, and the run that comes
    /// after it finds an archive that has lost everything.
    ///
    /// What is only being read never needs the directory. Writing makes what it
    /// needs, and [`create`](Builder::create) is for a caller that means to make
    /// the store now.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidDepth`] when the digests of the chosen algorithm are too
    /// short for the requested depth, [`Error::CompressionUnavailable`] when
    /// compression was asked for and the `zstd` feature is off, and
    /// [`Error::EncryptionUnavailable`] when a key was given and the `crypt`
    /// feature is off.
    pub fn build(self) -> Result<Store> {
        if self.depth > self.algorithm.max_depth() {
            return Err(Error::InvalidDepth {
                depth: self.depth,
                algorithm: self.algorithm,
                max: self.algorithm.max_depth(),
            });
        }
        // Fail here rather than on the first write, which may be a long way
        // into a run. On the form that will be written, not on what compression
        // was asked for: a sealed entry is compressed whatever the answer to
        // that was.
        let form = Form::of(self.compress, self.has_key());
        if form.is_compressed() && !compress::available() {
            return Err(Error::CompressionUnavailable);
        }
        if form.is_encrypted() && !crypt::available() {
            return Err(Error::EncryptionUnavailable);
        }
        Ok(Store {
            layout: Layout::new(self.root, &self.suffix, self.depth),
            algorithm: self.algorithm,
            compress: self.compress,
            #[cfg(feature = "crypt")]
            key: self.key,
            protection: Protection::default(),
            #[cfg(feature = "crypt")]
            key_proven: Arc::new(AtomicBool::new(false)),
            // The caller's own preference is the best guess available before
            // anything has been looked at, and costs nothing if it is wrong.
            first_form: Arc::new(AtomicU8::new(form.as_u8())),
        })
    }

    /// Make the store's root directory, and hand back the store.
    ///
    /// The one place that says "there is to be a store here". Everything else
    /// takes the directory as it finds it, so this is what an `init` command
    /// calls and what a caller reaches for when the first write should not be
    /// the moment a typo in a path becomes a directory.
    ///
    /// Existing directories are left as they are: a store is opened by
    /// [`build`](Builder::build) and this is nothing to be afraid of running
    /// twice.
    ///
    /// # Errors
    ///
    /// As [`build`](Builder::build), plus [`Error::Io`] when the directory
    /// cannot be created.
    pub fn create(self) -> Result<Store> {
        let root = self.root.clone();
        let store = self.build()?;
        fs::create_dir_all(&root).ctx(|| format!("{}: creating store", root.display()))?;
        Ok(store)
    }
}

impl Store {
    /// Start configuring a store under `root`.
    #[must_use]
    pub fn builder(root: impl Into<PathBuf>) -> Builder {
        Builder {
            root: root.into(),
            suffix: DEFAULT_SUFFIX.to_string(),
            depth: DEFAULT_DEPTH,
            algorithm: Algorithm::default(),
            compress: false,
            #[cfg(feature = "crypt")]
            key: None,
        }
    }

    /// Open a store under `root` with every default: `.dat` entries, two shard
    /// levels, SHA-256 names, no compression.
    ///
    /// Touches nothing on disk, and says nothing about whether a store is
    /// there — see [`Builder::build`].
    ///
    /// # Errors
    ///
    /// Nothing the defaults can trip over; the signature is a [`Result`]
    /// because [`Builder::build`] is one, and a configured store can fail it.
    pub fn open(root: impl Into<PathBuf>) -> Result<Store> {
        Store::builder(root).build()
    }

    /// Open a store under `root` with every default, making the directory if it
    /// is not there. The counterpart to [`open`](Store::open).
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the directory cannot be created.
    pub fn create(root: impl Into<PathBuf>) -> Result<Store> {
        Store::builder(root).create()
    }

    /// The directory the store lives in.
    #[must_use]
    pub fn root(&self) -> &Path {
        self.layout.root()
    }

    /// The extension entries carry, dot included — empty for a store that
    /// names entries by digest alone.
    #[must_use]
    pub fn suffix(&self) -> &str {
        self.layout.suffix()
    }

    /// How many levels of shard directories the store uses.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.layout.depth()
    }

    /// How much of a digest [`matching`](Store::matching) needs to look one up.
    ///
    /// Two characters per shard level, plus two: the shard levels only say
    /// which directory to read, so a prefix that stops there names every entry
    /// in it. Worth asking before a prompt or a help text is written — it is
    /// what a store of this depth can actually resolve, and hard-coding a
    /// number instead is how a tool ends up assuming somebody else's depth.
    #[must_use]
    pub fn min_prefix(&self) -> usize {
        (self.depth() + 1) * 2
    }

    /// Which hash entries are named after.
    #[must_use]
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Whether new entries are sealed.
    #[must_use]
    pub fn encrypts(&self) -> bool {
        self.form().is_encrypted()
    }

    /// Whether new entries are written compressed. True for an encrypting
    /// store: a sealed entry is always compressed underneath.
    #[must_use]
    pub fn compresses(&self) -> bool {
        self.form().is_compressed()
    }

    /// The form this store writes new entries in.
    fn form(&self) -> Form {
        Form::of(self.compress, self.has_key())
    }

    /// Whether this store was given a key.
    // Without the feature there is no key field to look at, and the answer is
    // a constant — which is what clippy sees.
    #[cfg_attr(not(feature = "crypt"), allow(clippy::unused_self))]
    fn has_key(&self) -> bool {
        #[cfg(feature = "crypt")]
        {
            self.key.is_some()
        }
        #[cfg(not(feature = "crypt"))]
        {
            false
        }
    }

    /// The name this content would be stored under, without touching the disk.
    #[must_use]
    pub fn digest(&self, data: &[u8]) -> Digest {
        self.algorithm.hash(data)
    }

    /// A fresh hasher for the store's algorithm, for hashing content the store
    /// never sees.
    #[must_use]
    pub fn hasher(&self) -> Hasher {
        self.algorithm.hasher()
    }

    /// Store `data`, or notice that it is already there.
    ///
    /// The content is hashed first, so re-adding an entry the store already has
    /// costs one hash and one `stat` — no writing, and the returned path is the
    /// existing entry, in whatever form it was stored.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the entry cannot be written, and
    /// [`Error::DigestTooShort`] when the store shards deeper than its digests
    /// allow.
    pub fn add(&self, data: &[u8]) -> Result<(Status, Entry)> {
        let digest = self.algorithm.hash(data);
        if let Some((path, form)) = self.locate(&digest)? {
            debug!(path = %path.display(), "entry already stored");
            return Ok((Status::Exists, Entry { digest, path, form }));
        }
        let form = self.form();
        let path = self.write(&digest, &mut &data[..])?;
        Ok((Status::New, Entry { digest, path, form }))
    }

    /// Store everything `source` yields, hashing it as it goes past.
    ///
    /// For content that does not fit comfortably in memory, or that arrives
    /// from a socket. Unlike [`add`](Store::add) this cannot know the digest
    /// before it has read everything, so a duplicate is written to a temporary
    /// file and thrown away again rather than never written at all — the return
    /// value still says [`Status::Exists`] and the store is untouched.
    ///
    /// In a store that seals, the temporary file is sealed as it is written,
    /// under the store's own key — the nonce is drawn before the first byte
    /// goes down and does not wait on the digest. So this is one pass over the
    /// content and one temporary file, and nothing ever lies in `tmp/` in the
    /// clear.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when reading or writing fails, [`Error::KeyRequired`] for
    /// a sealing store with no key, and [`Error::Random`] when the system will
    /// not hand out a nonce.
    pub fn add_reader(&self, source: impl Read) -> Result<(Status, Entry)> {
        let mut source = HashingReader {
            inner: source,
            hasher: self.algorithm.hasher(),
        };
        let form = self.form();
        let mut temp = TempFile::create_in(&self.temp_dir()?)?;
        // The digest is not known yet, so there is nothing to name in the
        // message if this fails.
        self.encode(
            &mut source,
            &mut temp,
            &|| "sealing the entry".to_string(),
            form,
        )?;
        let digest = source.hasher.finish();

        if let Some((path, stored)) = self.locate(&digest)? {
            debug!(path = %path.display(), "entry already stored");
            return Ok((
                Status::Exists,
                Entry {
                    digest,
                    path,
                    form: stored,
                },
            ));
        }
        let path = self.place(temp, &digest)?;
        Ok((Status::New, Entry { digest, path, form }))
    }

    /// Where the entry with this digest is, if it is there at all.
    ///
    /// Both forms are looked for, so a store finds what a differently
    /// configured store wrote. Which of them is looked at first is whichever
    /// one this store last found, which adapts as a store is converted.
    ///
    /// # Errors
    ///
    /// [`Error::AlgorithmMismatch`] when the digest has a length this store's
    /// algorithm can never produce — it is another hash's, and "not there"
    /// would be the wrong answer to a question about the wrong store. And
    /// [`Error::Io`] when the answer cannot be had at all.
    pub fn find(&self, digest: &Digest) -> Result<Option<PathBuf>> {
        Ok(self.locate(digest)?.map(|(path, _)| path))
    }

    /// As [`find`](Store::find), and with the form of the name that answered.
    ///
    /// Which the lookup knows anyway — it is what it looked under — so there is
    /// nothing to be gained by parsing it back out of the path afterwards.
    fn locate(&self, digest: &Digest) -> Result<Option<(PathBuf, Form)>> {
        for (candidate, form) in self.candidates(digest)? {
            match fs::metadata(&candidate) {
                Ok(metadata) if metadata.is_file() => {
                    self.learn(form);
                    return Ok(Some((candidate, form)));
                }
                // A directory under an entry's name is not an entry.
                Ok(_) => {}
                // The miss is the answer; the other name may still be there.
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                // Anything else is a store that cannot be read rather than one
                // that does not hold this. Saying "not there" to an unreachable
                // share is how a backup decides to fetch everything again, and
                // how `add` writes an entry that was already stored.
                Err(err) => {
                    return Err(err).ctx(|| format!("{}: looking for entry", candidate.display()));
                }
            }
        }
        Ok(None)
    }

    /// Whether the store holds this digest.
    ///
    /// # Errors
    ///
    /// As [`find`](Store::find).
    pub fn contains(&self, digest: &Digest) -> Result<bool> {
        Ok(self.find(digest)?.is_some())
    }

    /// Where an entry with this digest *would* be written, whether or not it
    /// exists.
    ///
    /// # Errors
    ///
    /// As [`find`](Store::find).
    pub fn destination(&self, digest: &Digest) -> Result<PathBuf> {
        self.own_digest(digest)?;
        self.layout.path(digest, self.form())
    }

    /// The digests of every entry whose own begins with `prefix`, sorted.
    ///
    /// A digest is up to 128 characters and nobody types one. The beginning of
    /// one names an entry just as well as long as it names only one, the way a
    /// short commit hash does, and it costs a single directory listing to find
    /// out — a store is filed by exactly that beginning.
    ///
    /// Which is also the limit. The beginning of a digest *is* the shard the
    /// entry lies in, so a prefix that stops at the shard boundary names the
    /// shard and narrows nothing within it — at least one level's worth beyond
    /// it has to be given, which is what [`min_prefix`](Store::min_prefix)
    /// answers. Anything shorter is refused rather than answered with a whole
    /// directory. A prefix that is a whole digest is answered like any other,
    /// with the one entry it names or with nothing.
    ///
    /// An entry that lies in the store in both forms is one entry and is named
    /// once.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPrefix`] when `prefix` is empty or is not hexadecimal,
    /// [`Error::PrefixTooShort`] when it is shorter than the shard it would be
    /// looked up in, and [`Error::Io`] when the shard exists but cannot be
    /// read.
    pub fn matching(&self, prefix: &str) -> Result<Vec<Digest>> {
        let prefix = prefix.to_ascii_lowercase();
        if prefix.is_empty() || !prefix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(Error::InvalidPrefix(prefix));
        }
        let needed = self.min_prefix();
        if prefix.len() < needed {
            return Err(Error::PrefixTooShort {
                prefix,
                depth: self.depth(),
                needed,
            });
        }
        let shard = self.layout.shard_of(&prefix);
        let listing = match fs::read_dir(&shard) {
            Ok(listing) => listing,
            // No shard is no match, not a failure: a prefix nobody has stored
            // anything under is exactly the answer being asked for.
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(err).ctx(|| format!("{}: reading shard", shard.display())),
        };

        let mut found = Vec::new();
        for item in listing {
            let item = item.ctx(|| format!("{}: reading shard", shard.display()))?;
            let Some(name) = item.file_name().to_str().map(str::to_string) else {
                continue;
            };
            let matched = self
                .layout
                .parse_name(&name)
                .map(|(digest, _)| digest)
                .filter(|digest| digest.as_str().starts_with(&prefix));
            if let Some(digest) = matched {
                found.push(digest);
            }
        }
        found.sort();
        found.dedup();
        Ok(found)
    }

    /// Read a whole entry by digest. `None` when it is not there.
    ///
    /// Costs one `open` in the ordinary case: the entry is opened rather than
    /// asked about first, which adapts as a store is converted.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the entry cannot be read, and
    /// [`Error::CompressionUnavailable`] for a compressed entry in a build
    /// without zstd.
    pub fn read(&self, digest: &Digest) -> Result<Option<Vec<u8>>> {
        let Some(mut reader) = self.reader(digest)? else {
            return Ok(None);
        };
        let mut buffer = Vec::new();
        reader
            .read_to_end(&mut buffer)
            .ctx(|| format!("{digest}: reading entry"))?;
        Ok(Some(buffer))
    }

    /// A streaming reader over the entry with this digest. `None` when the
    /// store holds nothing under it.
    ///
    /// For everyone who has a digest and wants what is behind it: where the
    /// entry lies is the store's business, and whether it lies compressed is
    /// nobody's. There is no mode to pass, because there is nothing to do to an
    /// entry but read it — its name is the hash of its content, so writing to
    /// one would only break the name.
    ///
    /// Nothing about the content is assumed here. A caller that only wants the
    /// first few kilobytes — the header of a document, the magic bytes of an
    /// image — reads until it has them and drops the reader, and a compressed
    /// entry is decompressed only as far as it got.
    ///
    /// The reader itself fails with [`io::Error`] — its trait allows nothing
    /// else. When what ended the stream is one of the crate's own answers, a
    /// sealed chunk that stopped authenticating above all, that answer
    /// travels *inside* the `io::Error`:
    /// [`Error::from_io`](crate::Error::from_io) gets it back out, so that
    /// mid-stream too [`Error::Damaged`] can be told from a disk that went
    /// away.
    ///
    /// # Errors
    ///
    /// As [`read`](Store::read).
    pub fn reader(&self, digest: &Digest) -> Result<Option<Box<dyn BufRead>>> {
        match self.open_entry(digest)? {
            Some((file, form, path)) => self.decode(file, form, &path).map(Some),
            None => Ok(None),
        }
    }

    /// Take the form off a file that was just opened: unseal, then decompress.
    ///
    /// The nonce an entry was sealed under stands at the front of the file, so
    /// this needs the key and the bytes and nothing that was worked out from
    /// the name.
    #[cfg_attr(not(feature = "crypt"), allow(clippy::unused_self))]
    fn decode<R: Read + 'static>(
        &self,
        file: R,
        form: Form,
        path: &Path,
    ) -> Result<Box<dyn BufRead>> {
        if !form.is_encrypted() {
            return compress::reader(file, form.is_compressed());
        }
        #[cfg(feature = "crypt")]
        {
            let Some(key) = self.key.as_deref() else {
                return Err(Error::KeyRequired(path.to_path_buf()));
            };
            let opener = crypt::Opener::new(key, file);
            // A chunk that opens proves the key, and `verify` needs to know.
            let opener = Proving {
                inner: opener,
                proven: Arc::clone(&self.key_proven),
            };
            compress::reader(opener, true)
        }
        #[cfg(not(feature = "crypt"))]
        {
            let _ = (file, path);
            Err(Error::EncryptionUnavailable)
        }
    }

    /// Read a whole entry by path, decompressing if it is compressed.
    ///
    /// # Errors
    ///
    /// As [`read`](Store::read).
    pub fn read_at(&self, path: &Path) -> Result<Vec<u8>> {
        // Only a raw entry is the bytes it holds. Compressed or sealed, the
        // file has to go through the reader — which includes one that was set
        // aside: `.corrupt` on the end of a name does not undo the sealing.
        //
        // The name is read once and handed on. `parse_name` is on the path of
        // every name a store reads, and asking for the form and then going
        // through `reader_at` would parse it a second time — twice more again for
        // a quarantined name, where the first parse misses before
        // `parse_quarantined` tries.
        let form = self.form_at(path);
        if form.unwrap_or(Form::Raw) == Form::Raw {
            return fs::read(path).ctx(|| format!("{}: reading entry", path.display()));
        }
        let file = File::open(path).ctx(|| format!("{}: opening entry", path.display()))?;
        let mut reader = self.decode_named(file, form, path)?;
        let mut buffer = Vec::new();
        reader
            .read_to_end(&mut buffer)
            .ctx(|| format!("{}: reading entry", path.display()))?;
        Ok(buffer)
    }

    /// A streaming reader over an entry, decompressing if it is compressed.
    ///
    /// Once this call has handed the reader over, failures speak
    /// [`io::Error`]; see [`reader`](Store::reader) for getting the
    /// crate's own answers back out of one.
    ///
    /// # Errors
    ///
    /// As [`read`](Store::read).
    pub fn reader_at(&self, path: &Path) -> Result<Box<dyn BufRead>> {
        let (file, form) = self.open_at(path)?;
        self.decode_named(file, form, path)
    }

    /// As [`reader_at`](Store::reader_at), and with it the flag that says whether a
    /// failure came from the file rather than from what was decoding it.
    ///
    /// Only [`digest_of`](Store::digest_of) wants that, which is why it is not
    /// what `reader` is built on: `Watched` costs an allocation, and it hides
    /// `File`'s own `read_to_end` — the one that sizes its buffer from the
    /// file — behind a trait object.
    fn reader_watched(&self, path: &Path) -> Result<(Box<dyn BufRead>, Arc<AtomicBool>)> {
        let (file, form) = self.open_at(path)?;
        let failed = Arc::new(AtomicBool::new(false));
        let src = Watched {
            inner: file,
            failed: Arc::clone(&failed),
        };
        Ok((self.decode_named(src, form, path)?, failed))
    }

    /// Open the file at `path`, and read the form out of its name while it is
    /// at it.
    ///
    /// `None` for a file this store did not name, which is not an error here —
    /// it is handed out as it lies.
    fn open_at(&self, path: &Path) -> Result<(File, Option<Form>)> {
        let form = self.form_at(path);
        let file = File::open(path).ctx(|| format!("{}: opening entry", path.display()))?;
        Ok((file, form))
    }

    /// The form a path's name says it is in, quarantined names included.
    fn form_at(&self, path: &Path) -> Option<Form> {
        self.named_at(path).map(|(_, form)| form)
    }

    /// Take the form off what was opened at a path, going by that path's name.
    fn decode_named<R: Read + 'static>(
        &self,
        src: R,
        form: Option<Form>,
        path: &Path,
    ) -> Result<Box<dyn BufRead>> {
        let Some(form) = form else {
            // Nothing this store named is nothing this store put a form on.
            return compress::reader(src, false);
        };
        self.decode(src, form, path)
    }

    /// The entry this path is, if it is one of this store's.
    ///
    /// The counterpart to [`entries`](Store::entries): the same question, asked
    /// about one path instead of about the whole tree. For anything walking a
    /// store for its own reasons, and for anything handed a path that has to
    /// become a digest again.
    ///
    /// Only the file name is read — no I/O, and nothing about the directories
    /// in front of it. A path copied out of a report written on another machine
    /// still names its entry, and a name that parses is an entry's name whether
    /// or not anybody has stored it; [`find`](Store::find) and
    /// [`contains`](Store::contains) are what answer whether it is there.
    ///
    /// `None` for anything this store did not name: a stray `.DS_Store`, a file
    /// under the wrong suffix, a leftover in `tmp/`.
    #[must_use]
    pub fn entry_at(&self, path: &Path) -> Option<Entry> {
        let name = path.file_name()?.to_str()?;
        let (digest, form) = self.layout.parse_name(name)?;
        Some(Entry {
            digest,
            path: path.to_path_buf(),
            form,
        })
    }

    /// Hash an entry's content — its *actual* name, as opposed to the one it
    /// is filed under.
    ///
    /// # Errors
    ///
    /// As [`read`](Store::read).
    pub fn digest_of(&self, path: &Path) -> Result<Digest> {
        let (mut reader, failed) = self.reader_watched(path)?;
        let mut hasher = self.algorithm.hasher();
        match std::io::copy(&mut reader, &mut hasher) {
            Ok(_) => Ok(hasher.finish()),
            Err(err) => {
                // The decoder gave up on a frame the file handed it whole. That
                // is the entry, not the disk — which is the same answer a
                // sealed entry gives as `Error::Damaged`, and the same one
                // `verify` turns into a plain `false`.
                //
                // `Watched` sits under the decoder and so answers "did the
                // file fail", which is not the same question as "was this the
                // content's fault" — but it is the only half of it that can be
                // told from here, and it is the half that matters: a read that
                // failed is the disk's business, not the entry's.
                //
                // What is left out on top of that is the machine rather than
                // the content. A decoder that cannot allocate says nothing
                // about the bytes, and answering `false` to that would take a
                // healthy entry's name away for it — see `out_of_memory`,
                // which has to read the message because zstd gives it no kind
                // to go by.
                //
                // Not by the error *kind*, which is where this went wrong
                // before: zstd reports a rejected frame through
                // `io::Error::other`, so a damaged frame header arrives as
                // `ErrorKind::Other` and only a truncated frame as
                // `UnexpectedEof`. Gating on the kinds a frame was assumed to
                // produce let every header-level corruption through as an
                // error, where the whole point of this is a plain `false`.
                let damaged = !failed.load(Ordering::Relaxed) && !out_of_memory(&err);
                match contextualise(err, || format!("{}: hashing", path.display())) {
                    Error::Io { .. } if damaged => Err(Error::Damaged),
                    err => Err(err),
                }
            }
        }
    }

    /// Check an entry against its own name.
    ///
    /// An [`Entry`] comes from [`entries`](Store::entries), from
    /// [`add`](Store::add), or — for a path from elsewhere, a report, a
    /// command line — through [`entry_at`](Store::entry_at), which is where
    /// "is this file an entry at all?" is answered.
    ///
    /// This is the guarantee content addressing buys: a name that is a hash of
    /// the content detects bit rot, a truncated write and a botched restore
    /// alike, without a second copy or a checksum file to keep in sync.
    ///
    /// The name has to be one this store's algorithm could have written at
    /// all. Held against another algorithm's — the store opened with the
    /// wrong one — the answer is [`Error::AlgorithmMismatch`] rather than a
    /// `false` that would read as damage and send healthy entries to
    /// quarantine.
    ///
    /// A sealed entry is only answered for once this store's key is known to be
    /// the right one. The cipher cannot tell a wrong key from bytes that are
    /// damaged from the first chunk, and most entries are a single chunk — so
    /// for those, "the tag does not match" is genuinely ambiguous and comes
    /// back as [`Error::Unsealable`] rather than as `false`. The ambiguity is
    /// gone the moment anything in this store has opened under this key:
    /// [`read`](Store::read), [`read_at`](Store::read_at) or an earlier
    /// `verify` all settle it as a side effect, [`prove_key`](Store::prove_key) settles it
    /// deliberately, and [`key_proven`](Store::key_proven) says whether it is
    /// settled. A pass that acts on `false` starts with `prove_key`: left to
    /// settle as it goes, the answer would depend on walk order — an entry
    /// damaged in its first chunk, met before the first healthy one, would
    /// come back ambiguous on this run and every run after.
    ///
    /// Which means the answer is only as good as the key: hand a store the
    /// wrong one and every entry in it fails, as it should. What is worth
    /// knowing is that a [`change_key`](Store::change_key) run that was
    /// interrupted leaves a store holding entries under two keys, and for the
    /// ones it has not reached yet this store's key *is* the wrong one — they
    /// come back as `false` like anything else it cannot open. Finish the key
    /// change before running a pass that sets entries aside.
    ///
    /// # Errors
    ///
    /// [`Error::AlgorithmMismatch`] when the entry is named by another
    /// algorithm's digest — nothing about it was established then, least of
    /// all damage — and [`Error::Unsealable`] for a sealed entry that failed
    /// on its first chunk while this store's key is still unproven. Otherwise
    /// as [`read`](Store::read).
    ///
    /// # Examples
    ///
    /// A pass over a whole store. There are three answers and they are three
    /// different things — only one of them is a reason to take a name away:
    ///
    /// ```no_run
    /// use immure::Store;
    ///
    /// let store = Store::open("/srv/store")?;
    /// for entry in store.entries() {
    ///     let entry = entry?;
    ///     match store.verify(&entry) {
    ///         // The bytes are not what the name says, which is what
    ///         // `quarantine` is for.
    ///         Ok(false) => {
    ///             let aside = store.quarantine(&entry)?;
    ///             println!("{}: set aside as {}", entry.digest(), aside.path().display());
    ///         }
    ///         Ok(true) => {}
    ///         // Nothing was established about this entry: it could not be
    ///         // read, or its seal is ambiguous while the key is unproven.
    ///         // Setting it aside on that would take a healthy entry's name
    ///         // away for a reason that is not the entry's.
    ///         Err(err) => println!("{}: {err}", entry.path().display()),
    ///     }
    /// }
    /// # Ok::<(), immure::Error>(())
    /// ```
    pub fn verify(&self, entry: &Entry) -> Result<bool> {
        self.own_digest(&entry.digest)?;
        self.content_matches(&entry.path, &entry.digest)
    }

    /// Whether the bytes at `path` hash to `expected`, with damage answered
    /// as `false` — the question behind [`verify`](Store::verify) and
    /// [`restore`](Store::restore), answered the same way for both.
    fn content_matches(&self, path: &Path, expected: &Digest) -> Result<bool> {
        match self.digest_of(path) {
            Ok(actual) => Ok(actual == *expected),
            // A sealed file whose key opened it and whose bytes then failed to
            // authenticate is damaged, which is exactly the question asked
            // here — `false`, not an error the caller has to translate. The
            // same goes for a compressed file whose frame the decoder refused.
            Err(Error::Damaged) => Ok(false),
            // The first chunk did not authenticate. That is the wrong key —
            // unless this key has already opened something here, and then the
            // key is not what is wrong with it.
            #[cfg(feature = "crypt")]
            Err(Error::Unsealable) if self.key_proven.load(Ordering::Relaxed) => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Whether this store's key has opened one of its entries yet.
    ///
    /// The state behind [`verify`](Store::verify)'s answer for a sealed entry
    /// that fails on its first chunk: the cipher cannot tell a wrong key from
    /// bytes damaged from the start, so as long as nothing has opened, that
    /// failure is [`Error::Unsealable`] rather than `false`. Once anything
    /// opens under this key the ambiguity is settled, for this handle and its
    /// clones, and `verify` answers `false` there like for any other damage.
    ///
    /// Handle state, not store state: a fresh handle starts unproven, and
    /// nothing is written down — the way everything a store learns about
    /// itself holds for a run and no longer.
    /// [`prove_key`](Store::prove_key) settles it deliberately.
    #[cfg(feature = "crypt")]
    #[must_use]
    pub fn key_proven(&self) -> bool {
        self.key_proven.load(Ordering::Relaxed)
    }

    /// Read until one entry opens under this store's key, and say whether one
    /// did.
    ///
    /// What to call before a pass that acts on `false` from
    /// [`verify`](Store::verify). Left to settle the key as it goes, such a
    /// pass answers by walk order: entries met before the first healthy
    /// sealed one come back [`Error::Unsealable`], and the next run meets
    /// them in the same order again — an entry damaged in its first chunk,
    /// lying ahead of every healthy one, would stay ambiguous forever. One
    /// proven chunk beforehand takes the order out of the answer.
    ///
    /// `Ok(false)` means nothing here can prove the key: the store holds no
    /// sealed entry, or none of its sealed entries opens under this key. The
    /// second is what a wrong key looks like — not a state to act on `false`
    /// in.
    ///
    /// Costs one opened chunk when the first sealed entry is healthy, and a
    /// walk at worst. An entry that does not open or cannot be read says
    /// nothing about the key and is passed over for the next.
    ///
    /// # Errors
    ///
    /// [`Error::KeyRequired`] for a store without a key — there is nothing to
    /// prove — and [`Error::Io`] when the store cannot be walked.
    #[cfg(feature = "crypt")]
    pub fn prove_key(&self) -> Result<bool> {
        if !self.has_key() {
            return Err(Error::KeyRequired(self.root().to_path_buf()));
        }
        if self.key_proven() {
            return Ok(true);
        }
        for entry in self.entries() {
            let entry = entry?;
            if !entry.is_encrypted() {
                continue;
            }
            // One byte settles the first chunk, and any opened chunk settles
            // the key — `key_proven` catches the case where the read failed
            // on a later chunk after earlier ones opened.
            let mut probe = [0u8; 1];
            if let Ok(mut reader) = self.reader_at(&entry.path) {
                if reader.read(&mut probe).is_ok() || self.key_proven() {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Take an entry's name away from it, keeping every byte, and say what it
    /// is called now.
    ///
    /// What to do with an entry that has just failed [`verify`](Store::verify).
    /// Renamed, never deleted: content with a flipped bit is still almost all of
    /// the content, and throwing away what was only just found to be damaged is
    /// the worse of the two ways to be wrong. What has to stop is the *claim* —
    /// while the file is named after a hash it does not have, the store goes on
    /// answering that this content is present, and nothing ever fetches it
    /// again. Afterwards [`find`](Store::find), [`entries`](Store::entries) and
    /// the existence check behind [`add`](Store::add) no longer see it, so
    /// storing those bytes again is a new entry.
    ///
    /// The file stays in its shard rather than moving to a directory of its
    /// own — where a file lies is itself information, and a store with a second
    /// place to look in is a store to explain. It is recognisable by name:
    /// [`quarantined_at`](Store::quarantined_at) is how a walk tells what an
    /// earlier pass set aside from a stray file, instead of reporting it afresh
    /// every run.
    ///
    /// Numbered when the plain name is taken, which is what content that was
    /// fetched again and broke a second time looks like. Nothing is overwritten.
    ///
    /// # Errors
    ///
    /// [`Error::QuarantineNamesTaken`] when every name is in use, and
    /// [`Error::Io`] when the rename fails.
    pub fn quarantine(&self, entry: &Entry) -> Result<Quarantined> {
        let name = self.layout.file_name(&entry.digest, entry.form);
        for serial in 0..QUARANTINE_ATTEMPTS {
            let target = entry
                .path
                .with_file_name(Layout::quarantine_name(&name, serial));
            // A rename overwrites, so the free name is looked for first. Two
            // runs cannot lose content between the two calls: a target name is
            // derived from the entry being set aside, so the only file either
            // of them could rename onto it is the very one the other just
            // moved, and the loser gets its "no such file" instead.
            if target.exists() {
                continue;
            }
            fs::rename(&entry.path, &target).ctx(|| {
                format!(
                    "{}: setting aside as {}",
                    entry.path.display(),
                    target.display()
                )
            })?;
            warn!(
                path = %entry.path.display(),
                aside = %target.display(),
                "content does not match its name, entry set aside"
            );
            return Ok(Quarantined {
                digest: entry.digest.clone(),
                path: target,
                form: entry.form,
            });
        }
        Err(Error::QuarantineNamesTaken(entry.path.clone()))
    }

    /// The set-aside file this path is, if it is one — or `None` for
    /// anything else, a live entry included.
    ///
    /// What [`entry_at`](Store::entry_at) is for an entry: the gate from a
    /// path into the store's vocabulary, here for what
    /// [`quarantine`](Store::quarantine) left behind — so that a pass over
    /// the tree can tell an entry, something an earlier pass set aside, and a
    /// file that is neither apart. Only the name is read; nothing says
    /// whether the content behind it is still there or ever was.
    #[must_use]
    pub fn quarantined_at(&self, path: &Path) -> Option<Quarantined> {
        let name = path.file_name()?.to_str()?;
        let (digest, form) = self.layout.parse_quarantined(name)?;
        Some(Quarantined {
            digest,
            path: path.to_path_buf(),
            form,
        })
    }

    /// Walk everything earlier passes set aside, in whatever order the
    /// filesystem offers.
    ///
    /// The other half of [`quarantine`](Store::quarantine): a file keeps its
    /// bytes so that something can come back for them, and this is how it is
    /// found again without walking the tree by hand. Each item says what the
    /// file was filed under and where it lies now. [`read_at`](Store::read_at)
    /// hands its bytes back the way it would an entry's,
    /// [`restore`](Store::restore) is for the one that turns out to be a
    /// false alarm, and [`discard`](Store::discard) for the one whose content
    /// has been fetched again — or given up on.
    ///
    /// Like [`entries`](Store::entries), the walk reports directories it
    /// cannot read and skips over what this store did not name.
    pub fn quarantined(&self) -> impl Iterator<Item = Result<Quarantined>> + '_ {
        Entries::new(self, Walk::SetAside).map(|item| {
            item.map(|entry| Quarantined {
                digest: entry.digest,
                path: entry.path,
                form: entry.form,
            })
        })
    }

    /// Give a set-aside file its name back, if its bytes deserve it. `None`
    /// when they still do not match, and the file stays where it is.
    ///
    /// The check is the one [`verify`](Store::verify) makes, so nothing can
    /// come back that would not verify the moment it did: the bytes are
    /// hashed, held against the digest the file was filed under, and only a
    /// match is renamed. What this is for is the set-aside file that was a
    /// false alarm rather than damage — a verifying pass run while
    /// [`change_key`](Store::change_key) was half done, a quarantine called
    /// on the wrong entry.
    ///
    /// Content that arrived again in the meantime is only in the way when it
    /// took the very name this would give back; an entry in another form is a
    /// neighbour, not an obstacle, like any store holding one content in two
    /// forms.
    ///
    /// # Errors
    ///
    /// [`Error::AlgorithmMismatch`] when the digest the file was filed under
    /// is another algorithm's, and [`Error::Obstructed`] when its name is an
    /// entry's again — the store already answers for the content, this copy
    /// is redundant, and [`discard`](Store::discard) is the answer once the
    /// caller agrees. Otherwise as [`verify`](Store::verify): a sealed file
    /// needs the key, and an unproven key leaves [`Error::Unsealable`]
    /// standing.
    pub fn restore(&self, aside: &Quarantined) -> Result<Option<Entry>> {
        self.own_digest(&aside.digest)?;
        if !self.content_matches(&aside.path, &aside.digest)? {
            debug!(path = %aside.path.display(), "still not its content, stays set aside");
            return Ok(None);
        }
        let destination = aside
            .path
            .with_file_name(self.layout.file_name(&aside.digest, aside.form));
        // A rename overwrites, so the taken name has to be looked for first.
        // The window between the look and the rename is the one `quarantine`
        // accepts for the same reason: the only file another writer could put
        // there carries this digest's own content.
        if destination.exists() {
            return Err(Error::Obstructed(destination));
        }
        fs::rename(&aside.path, &destination).ctx(|| {
            format!(
                "{}: giving the name back to {}",
                aside.path.display(),
                destination.display()
            )
        })?;
        info!(
            path = %destination.display(),
            "content matches its name after all, entry restored"
        );
        Ok(Some(Entry {
            digest: aside.digest.clone(),
            path: destination,
            form: aside.form,
        }))
    }

    /// Delete a file [`quarantine`](Store::quarantine) set aside. The end of
    /// a salvage, whichever way it went: the content was fetched again, or
    /// given up on.
    ///
    /// Taking a [`Quarantined`], only what quarantine set aside can even be
    /// named here: a live entry goes through [`remove`](Store::remove), by
    /// digest, and everything else in the tree is out of reach — the way
    /// every sweep here only touches what the store itself wrote. The write
    /// protection the file kept from its days as an entry is no obstacle, the
    /// same as it is none to `remove`.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the file cannot be removed — one that is already
    /// gone included, because whoever names a file to be rid of has to hear
    /// that somebody else was rid of it first.
    pub fn discard(&self, aside: &Quarantined) -> Result<()> {
        protect::remove_file(&aside.path)
            .ctx(|| format!("{}: discarding set-aside file", aside.path.display()))?;
        debug!(path = %aside.path.display(), "set-aside file discarded");
        Ok(())
    }

    /// Delete an entry. Returns whether there was one.
    ///
    /// Rare in a store that only grows, and the one operation that can lose
    /// data: nothing here tracks whether something else still refers to that
    /// content. An entry's write protection is no obstacle — it was never
    /// about deletion, and a store has to be able to remove what it protected
    /// itself.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the entry exists but cannot be removed.
    pub fn remove(&self, digest: &Digest) -> Result<bool> {
        let Some(path) = self.find(digest)? else {
            return Ok(false);
        };
        protect::remove_file(&path).ctx(|| format!("{}: removing entry", path.display()))?;
        debug!(path = %path.display(), "entry removed");
        Ok(true)
    }

    /// Walk every entry in the store, in whatever order the filesystem offers.
    ///
    /// Files that are not named after a digest are skipped rather than
    /// reported: a store is a directory tree, and directory trees collect
    /// `.DS_Store` and friends. Directories that cannot be read *are* reported,
    /// so a walk never quietly covers less than it claims to.
    ///
    /// Each directory's listing is read whole before its first entry is
    /// handed out, so what the walk yields may be renamed or removed while
    /// the walk runs, and holding the iterator costs one directory's listing
    /// of memory, never the store's.
    ///
    /// Symlinked directories are not descended into — a store is a tree, and a
    /// symlink is how a tree turns into a circle. A symlink to a *file* named
    /// after a digest is an entry like any other.
    #[must_use]
    pub fn entries(&self) -> Entries<'_> {
        Entries::new(self, Walk::Entries)
    }

    /// Compress every plain entry in the store.
    ///
    /// Runs regardless of how the store itself is configured; the two are
    /// independent. Each entry is rewritten to a temporary file and renamed
    /// into place before the original goes, so an interrupted run leaves both
    /// forms behind at worst — harmless, and cleaned up by the next run.
    ///
    /// # Errors
    ///
    /// [`Error::CompressionUnavailable`] in a build without zstd, and
    /// [`Error::Io`] when the store cannot be walked. Failures on individual
    /// entries land in [`Conversion::failed`] instead.
    pub fn compress_all(&self) -> Result<Conversion> {
        if !compress::available() {
            return Err(Error::CompressionUnavailable);
        }
        self.convert_all(Form::Zstd, |form| {
            if form.is_encrypted() {
                Step::Skipped
            } else if form.is_compressed() {
                Step::Already
            } else {
                Step::Converted
            }
        })
    }

    /// Decompress every compressed entry in the store. The mirror image of
    /// [`compress_all`](Store::compress_all).
    ///
    /// # Errors
    ///
    /// As [`compress_all`](Store::compress_all).
    pub fn decompress_all(&self) -> Result<Conversion> {
        if !compress::available() {
            return Err(Error::CompressionUnavailable);
        }
        self.convert_all(Form::Raw, |form| {
            if form.is_encrypted() {
                Step::Skipped
            } else if form.is_compressed() {
                Step::Converted
            } else {
                Step::Already
            }
        })
    }

    /// Seal every entry that is not sealed yet, with this store's key.
    ///
    /// How an existing store is turned into an encrypted one. Entries that are
    /// already sealed are left where they are and counted as
    /// [`already`](Conversion::already): re-sealing one would cost a rewrite
    /// and change nothing about it.
    ///
    /// # Errors
    ///
    /// [`Error::KeyRequired`] for a store without a key, and otherwise as
    /// [`compress_all`](Store::compress_all).
    #[cfg(feature = "crypt")]
    pub fn encrypt_all(&self) -> Result<Conversion> {
        if !self.has_key() {
            return Err(Error::KeyRequired(self.root().to_path_buf()));
        }
        self.convert_all(Form::Enc, |form| {
            if form.is_encrypted() {
                Step::Already
            } else {
                Step::Converted
            }
        })
    }

    /// Unseal every sealed entry, leaving it compressed.
    ///
    /// The mirror image of [`encrypt_all`](Store::encrypt_all): what turns a
    /// sealed store back into a plain one, for good.
    ///
    /// Not the way to change a key. Running this and then `encrypt_all` with
    /// another key would leave every entry lying unsealed on disk in between,
    /// for as long as the two passes take — [`change_key`](Store::change_key)
    /// does the same job one entry at a time and never writes anything in the
    /// clear.
    ///
    /// # Errors
    ///
    /// As [`encrypt_all`](Store::encrypt_all). An entry the key cannot open
    /// lands in [`Conversion::failed`], and the run goes on.
    #[cfg(feature = "crypt")]
    pub fn decrypt_all(&self) -> Result<Conversion> {
        if !self.has_key() {
            return Err(Error::KeyRequired(self.root().to_path_buf()));
        }
        self.convert_all(Form::Zstd, |form| {
            if form.is_encrypted() {
                Step::Converted
            } else if form.is_compressed() {
                Step::Already
            } else {
                // Not "already unsealed": an unsealing pass has no business
                // with an entry that was never sealed at all, which is the
                // same answer `change_key` gives the same file. An entry that
                // is already in the target form is a different matter and is
                // `already`, the way it is for every other pass.
                Step::Skipped
            }
        })
    }

    /// Move every sealed entry from this store's key to `new`.
    ///
    /// A whole key change, in one pass. An entry is opened with the old key and
    /// sealed again with the new one as it streams past, chunk by chunk;
    /// nothing is ever written unsealed, and nothing is unpacked — what goes
    /// into the new cipher is the same zstd frame that came out of the old one.
    ///
    /// Each entry is sealed under a nonce drawn for that write, so a key change
    /// is a fresh nonce as well and there is nothing to carry across.
    ///
    /// Interruptible. Each entry is replaced by a rename, so a crash leaves
    /// every one of them under one key or the other and never in between, and a
    /// second run finishes what the first started — an entry the new key
    /// already opens is recognised by that and counted as
    /// [`already`](Conversion::already). Which also makes the pass idempotent:
    /// running it twice costs one read per entry and changes nothing.
    ///
    /// What an earlier pass [set aside](Store::quarantine) is moved as well,
    /// and that is not a detail. A quarantined entry is still sealed and
    /// [`read_at`](Store::read_at) still hands its content back; one left behind here
    /// would be under a key that is about to be destroyed, and the salvage the
    /// quarantine was for would be over. It keeps the name it was set aside
    /// under — the bytes are replaced where they lie.
    ///
    /// A digest can name several files: a quarantined one keeps the digest it
    /// was filed under, and the name it was set aside from can be taken by the
    /// same content arriving again. Each of them is sealed under a nonce of its
    /// own, so each is resealed on its own terms and the walk order decides
    /// nothing.
    ///
    /// Entries that are not sealed at all are skipped;
    /// [`encrypt_all`](Store::encrypt_all) is what brings those in.
    ///
    /// The run is finished with the store when
    /// [`is_finished`](Conversion::is_finished) says so, and then the old key is
    /// no longer needed. Not "when `failed` is empty": an entry whose seal does
    /// not authenticate under either key lands in `failed` on this run and on
    /// every later one, and holding the old key for it would mean holding it
    /// for good — the old key opens it no better than the new one does.
    ///
    /// Until then the store holds entries under two keys, and neither key is
    /// the right one for all of them. Do not run a pass that quarantines on
    /// [`verify`](Store::verify) over a store in that state: for the entries
    /// this run has not reached, the store's key is simply the wrong key, and
    /// they answer like anything else it cannot open.
    ///
    /// # Errors
    ///
    /// [`Error::KeyRequired`] for a store that has no key to change away from,
    /// and [`Error::Io`] when the store cannot be walked. An entry that neither
    /// key opens lands in [`Conversion::failed`], and the run goes on.
    #[cfg(feature = "crypt")]
    pub fn change_key(&self, new: &crypt::Key) -> Result<Conversion> {
        let Some(old) = self.key.as_deref() else {
            return Err(Error::KeyRequired(self.root().to_path_buf()));
        };
        self.pass(Walk::All, |entry| {
            if !entry.form.is_encrypted() {
                return Ok(Step::Skipped);
            }
            if self.reseal(entry, old, new)? {
                Ok(Step::Converted)
            } else {
                Ok(Step::Already)
            }
        })
    }

    /// Take one entry off `old` and put it under `new`, in place. `false` when
    /// it was already under `new` and nothing was written.
    ///
    /// The old nonce comes off the file and the new one is drawn as it is
    /// written, so there is nothing to carry from one seal to the other and
    /// nothing this call has to know about the rest of the run.
    #[cfg(feature = "crypt")]
    fn reseal(&self, entry: &Entry, old: &crypt::Key, new: &crypt::Key) -> Result<bool> {
        if opens_with(&entry.path, new)? {
            return Ok(false);
        }

        let file =
            File::open(&entry.path).ctx(|| format!("{}: opening entry", entry.path.display()))?;
        let mut payload = crypt::Opener::new(old, file);
        let mut temp = TempFile::create_in(&self.temp_dir()?)?;
        let mut sealer = crypt::Sealer::new(new, temp.file_mut())
            .ctx(|| format!("{}: sealing under the new key", entry.digest))?;
        // The frame passes from one cipher into the other and is not looked at:
        // no zstd here, and no buffer holding more than a chunk.
        io::copy(&mut payload, &mut sealer)
            .ctx(|| format!("{}: sealing under the new key", entry.digest))?;
        sealer
            .finish()
            .ctx(|| format!("{}: sealing under the new key", entry.digest))?;
        // Before the rename that replaces what it is reading, and not because
        // this platform needs it — the handle would keep the old inode alive.
        // The next one might.
        drop(payload);

        // Onto its own name: an entry keeps it through a key change, because
        // the name is the hash of the content and the content did not change.
        // The rename is atomic, so the entry is under one key or the other.
        //
        // `replace`, not `persist`: the destination is this entry, so it is
        // always there, and `persist` would read every failed rename as a race
        // it lost and report an entry moved that never was.
        temp.replace(&entry.path, &self.protection)?;
        debug!(path = %entry.path.display(), "entry moved to the new key");
        Ok(true)
    }

    /// Remove the temporary files left behind by writes that never finished,
    /// and report how many went away.
    ///
    /// A write that is interrupted leaves one in `tmp/`, and because the name
    /// belongs to one writer, no later run reuses or overwrites it — so nothing
    /// removes them by itself. They are inert: [`entries`](Store::entries) does
    /// not yield them and [`add`](Store::add) never looks at them, which is
    /// exactly why they would go on collecting unseen.
    ///
    /// Two conditions, and both are deliberate. Only files older than `min_age`,
    /// because a younger one may belong to a writer that is still going — and
    /// age is the only criterion available, since the pid in the name says
    /// nothing about a process on another host and a store can be reachable from
    /// more than one. And only files this store's writers make: `tmp/` is the
    /// store's, but a directory is still a directory, and a sweep of everything
    /// in it would delete what it never wrote.
    ///
    /// Nothing calls this on its own. It walks one directory, so it is cheap
    /// enough to hang off whatever pass already maintains the store; see
    /// [`DEFAULT_TEMP_MIN_AGE`] for a sensible age. The count is worth passing
    /// on rather than swallowing: each one is a write that was interrupted.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when `tmp/` exists but cannot be read. A file that cannot
    /// be stat'ed or removed is logged and kept, not raised — a sweep is
    /// housekeeping, and one stubborn leftover is no reason to fail the pass.
    pub fn prune_temp_files(&self, min_age: Duration) -> Result<usize> {
        let dir = self.root().join(temp::DIR);
        let listing = match fs::read_dir(&dir) {
            Ok(listing) => listing,
            // A store nothing has been written to yet has no `tmp/`.
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(err) => {
                return Err(err).ctx(|| format!("{}: reading temporary directory", dir.display()));
            }
        };
        // An age no `SystemTime` can reach back past leaves everything young.
        let Some(cutoff) = SystemTime::now().checked_sub(min_age) else {
            return Ok(0);
        };

        let mut removed = 0;
        for item in listing {
            let item = item.ctx(|| format!("{}: reading temporary directory", dir.display()))?;
            if !item.file_name().to_str().is_some_and(temp::is_temp_name) {
                continue;
            }
            let path = item.path();
            // `DirEntry::metadata` does not follow a symlink, so one pointing at
            // an entry reads as a symlink here and is left where it is.
            let metadata = match item.metadata() {
                Ok(metadata) => metadata,
                Err(err) => {
                    debug!(path = %path.display(), %err, "temporary file kept");
                    continue;
                }
            };
            if !metadata.is_file() {
                continue;
            }
            match metadata.modified() {
                Ok(modified) if modified <= cutoff => {}
                // Young enough that a writer may still have it open, or of an
                // age this platform will not say. Either way it stays.
                Ok(_) => continue,
                Err(err) => {
                    debug!(path = %path.display(), %err, "temporary file kept");
                    continue;
                }
            }
            match protect::remove_file(&path) {
                Ok(()) => {
                    info!(path = %path.display(), "leftover of an interrupted write, removed");
                    removed += 1;
                }
                Err(err) => debug!(path = %path.display(), %err, "temporary file kept"),
            }
        }
        Ok(removed)
    }

    /// Remove the shard directories that no longer hold anything, and report
    /// how many went away.
    ///
    /// A shard is created the first time an entry hashes into it and nothing
    /// removes it when the last entry leaves. A store that only grows never
    /// notices; one whose entries can go is left with a skeleton of empty
    /// directories.
    ///
    /// This cannot take data with it: `rmdir` refuses a directory that still
    /// holds anything, so a shard goes exactly when it is empty — including
    /// when it went empty between the walk and the call. The root and the
    /// temporary directory stay.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the store cannot be walked.
    pub fn prune_empty_dirs(&self) -> Result<usize> {
        let mut dirs = Vec::new();
        collect_dirs(self.root(), true, &mut dirs)?;
        // Deepest first, so a shard emptied by its own children can go too.
        dirs.sort_by_key(|path| std::cmp::Reverse(path.components().count()));

        let mut removed = 0;
        for dir in dirs {
            match fs::remove_dir(&dir) {
                Ok(()) => removed += 1,
                Err(err) => debug!(path = %dir.display(), %err, "shard kept"),
            }
        }
        Ok(removed)
    }

    // -- internals ---------------------------------------------------------

    /// The digest and form behind a name of this store's, whether the name is
    /// an entry's or one an entry was set aside under.
    fn named_at(&self, path: &Path) -> Option<(Digest, Form)> {
        let name = path.file_name()?.to_str()?;
        self.layout
            .parse_name(name)
            .or_else(|| self.layout.parse_quarantined(name))
    }

    /// Refuse a digest whose length this store's algorithm can never produce.
    ///
    /// Another algorithm's digest is not a name here, and answering it anyway
    /// would always be wrong quietly: a lookup that finds nothing where the
    /// entry lies, a verification that fails a healthy entry. The comparison
    /// is the whole cost, and it is as much as the tree affords — SHA-256 and
    /// BLAKE3 digests are the same length, and those two stay past telling
    /// apart.
    fn own_digest(&self, digest: &Digest) -> Result<()> {
        if digest.len() == self.algorithm.hex_len() {
            return Ok(());
        }
        Err(Error::AlgorithmMismatch {
            digest: digest.clone(),
            algorithm: self.algorithm,
        })
    }

    /// The three names an entry with this digest could have, likeliest first.
    ///
    /// A digest does not name a file: it names `<digest><suffix>`,
    /// `<digest><suffix>.zst` and `<digest><suffix>.zst.enc`, and nothing in
    /// the tree says which of them is there. Asking before reading costs a
    /// round trip on top of the one that reads, and over a network share that
    /// is the difference between reading a store once and reading it twice —
    /// so the file is opened and the miss is the answer.
    ///
    /// Which to try first is remembered from the last one that answered. A
    /// store is normally all one way, so after the first entry every further
    /// one costs a single look; a half-converted store corrects itself as it
    /// goes and pays one wasted look per switch, which is what makes this a
    /// guess that adapts rather than a setting somebody has to keep true.
    ///
    /// Deliberately not written down anywhere: it has to hold for a run and not
    /// beyond one, and a value on disk about how a store happens to be stored
    /// would be wrong from the first [`compress_all`](Store::compress_all).
    fn candidates(&self, digest: &Digest) -> Result<[(PathBuf, Form); 3]> {
        self.own_digest(digest)?;
        let shard = self.layout.shard(digest)?;
        let first = Form::from_u8(self.first_form.load(Ordering::Relaxed));
        Ok(first
            .with_others_after()
            .map(|form| (shard.join(self.layout.file_name(digest, form)), form)))
    }

    /// Remember which form actually answered.
    fn learn(&self, form: Form) {
        self.first_form.store(form.as_u8(), Ordering::Relaxed);
    }

    /// Open the entry with this digest, whichever of its two names it has.
    fn open_entry(&self, digest: &Digest) -> Result<Option<(File, Form, PathBuf)>> {
        for (candidate, form) in self.candidates(digest)? {
            match File::open(&candidate) {
                Ok(file) => {
                    self.learn(form);
                    return Ok(Some((file, form, candidate)));
                }
                // The miss is the answer; the other name may still be there.
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(err).ctx(|| format!("{}: opening entry", candidate.display()));
                }
            }
        }
        Ok(None)
    }

    fn temp_dir(&self) -> Result<PathBuf> {
        let dir = self.root().join(temp::DIR);
        fs::create_dir_all(&dir)
            .ctx(|| format!("{}: creating temporary directory", dir.display()))?;
        Ok(dir)
    }

    /// Write new content whose digest is already known.
    fn write(&self, digest: &Digest, source: &mut impl Read) -> Result<PathBuf> {
        let mut temp = TempFile::create_in(&self.temp_dir()?)?;
        self.encode(
            source,
            &mut temp,
            &|| format!("{digest}: sealing entry"),
            self.form(),
        )?;
        self.place(temp, digest)
    }

    /// Put content into `temp` in the given form: compress, then seal.
    ///
    /// `what` names the entry in a failure. It is a closure rather than the
    /// digest because the streaming path has no digest yet — which is the
    /// whole of what the two callers do differently.
    #[cfg_attr(not(feature = "crypt"), allow(clippy::unused_self))]
    fn encode(
        &self,
        source: &mut impl Read,
        temp: &mut TempFile,
        what: &dyn Fn() -> String,
        form: Form,
    ) -> Result<()> {
        if !form.is_encrypted() {
            compress::copy(source, temp.file_mut(), form.is_compressed())?;
            return Ok(());
        }
        #[cfg(feature = "crypt")]
        {
            // Before a byte is read rather than after. A store whose form is
            // sealed has a key by construction, so this is a conversion asking
            // for a form the store cannot write — but a source that came off a
            // socket cannot be offered a second time, so it is settled here
            // and not further down.
            let Some(key) = self.key.as_deref() else {
                return Err(Error::KeyRequired(temp.path().to_path_buf()));
            };
            seal_into(source, temp, key, what)
        }
        #[cfg(not(feature = "crypt"))]
        {
            let _ = (source, temp, what);
            Err(Error::EncryptionUnavailable)
        }
    }

    /// Move a finished temporary file into the shard it belongs in.
    fn place(&self, temp: TempFile, digest: &Digest) -> Result<PathBuf> {
        let shard = self.layout.shard(digest)?;
        fs::create_dir_all(&shard)
            .ctx(|| format!("{}: creating shard directory", shard.display()))?;
        let path = shard.join(self.layout.file_name(digest, self.form()));
        temp.persist(&path, &self.protection)?;
        debug!(path = %path.display(), "entry stored");
        Ok(path)
    }

    /// Rewrite every entry that `plan` says needs it into `target`.
    ///
    /// What is not converted is not a failure: an entry `plan` has no business
    /// with is [`skipped`](Conversion::skipped) and one it finds already in
    /// `target` is [`already`](Conversion::already). A maintenance pass that
    /// meets a sealed entry it must not touch has met something normal.
    fn convert_all(&self, target: Form, plan: impl Fn(Form) -> Step) -> Result<Conversion> {
        // Not over what an earlier pass set aside. A conversion gives an entry
        // the name its digest and the target form make — and that name is
        // precisely what `quarantine` took away from it, so converting one
        // would quietly put a file back in the store that was found not to be
        // what it claims. `change_key` can walk them because it writes onto the
        // name it was given.
        self.pass(Walk::Entries, |entry| match plan(entry.form) {
            Step::Converted => self
                .convert(entry, entry.form, target)
                .map(|()| Step::Converted),
            settled => Ok(settled),
        })
    }

    /// Walk the store and let `step` do one entry at a time, keeping the tally.
    ///
    /// One failure does not end the run — a single unreadable file should not
    /// stop a maintenance pass over a whole archive — it lands in
    /// [`Conversion::failed`] and the walk goes on. Whether it was worth
    /// trying again is decided here, from the error: an entry that cannot be
    /// opened at all is past any run of this pass.
    fn pass(&self, walk: Walk, mut step: impl FnMut(&Entry) -> Result<Step>) -> Result<Conversion> {
        // One directory's worth at a time, its handle already closed (see
        // Entries): `step` may rename and unlink in the shard an entry came
        // from, and a store of a million entries is never held in memory
        // whole. A walk error ends the run where it stands — what was
        // converted stays converted, which is the interruptibility every
        // pass already promises.
        let mut result = Conversion::default();
        for entry in Entries::new(self, walk) {
            let entry = entry?;
            match step(&entry) {
                Ok(Step::Converted) => result.converted += 1,
                Ok(Step::Already) => result.already += 1,
                Ok(Step::Skipped) => result.skipped += 1,
                Err(error) => {
                    let recoverable = !matches!(error, Error::Unsealable | Error::Damaged);
                    warn!(
                        path = %entry.path.display(),
                        %error,
                        recoverable,
                        "conversion failed"
                    );
                    result.failed.push(Failure {
                        path: entry.path,
                        error,
                        recoverable,
                    });
                }
            }
        }
        Ok(result)
    }

    /// Rewrite one entry into `target`, and take its old name away.
    ///
    /// What travels through the middle here is the entry's *stored* payload,
    /// not its content: a compressed entry stays a zstd frame the whole way,
    /// and turning `.zst` into `.zst.enc` is a matter of sealing the frame that
    /// is already lying there. Unpacking and repacking it would be work for
    /// nothing.
    fn convert(&self, entry: &Entry, from: Form, target: Form) -> Result<()> {
        let source = &entry.path;
        let shard = self.layout.shard(&entry.digest)?;
        let destination = shard.join(self.layout.file_name(&entry.digest, target));

        // What an interrupted run leaves behind: the new form is in place and
        // the old name is still there too. The conversion has happened, and all
        // that is left of it is to let the old name go. Writing the entry a
        // second time would cost a rewrite and change nothing about it.
        //
        // Held against the content, not just the name. This is the one place in
        // the crate that removes an entry it did not itself write, and a name
        // is thin evidence: an empty file left by a `cp` that was killed, or a
        // restore that recreated names before contents, would otherwise be
        // taken for the conversion and cost the only copy there is.
        if destination.is_file() {
            match self.digest_of(&destination) {
                Ok(actual) if actual == entry.digest => {}
                Ok(_) => return Err(Error::Obstructed(destination)),
                // Unreadable is not "this entry" either. The cause is worth
                // having, but not worth putting in front of the one thing the
                // caller has to act on, which is that the name is taken by
                // something this run cannot account for.
                Err(error) => {
                    warn!(
                        path = %destination.display(),
                        %error,
                        "a file is in the way of a conversion and cannot be read"
                    );
                    return Err(Error::Obstructed(destination));
                }
            }
            debug!(path = %destination.display(), "already converted, dropping the old name");
            return protect::remove_file(source)
                .ctx(|| format!("{}: removing converted entry", source.display()));
        }

        let payload = self.payload(source, from)?;
        let mut temp = TempFile::create_in(&self.temp_dir()?)?;
        self.repack(payload, &mut temp, &entry.digest, from, target)?;
        // The replacement is on the device before the original goes. This is
        // the one path in the crate where a crash could take content with it
        // rather than merely leave it half-written: everywhere else the store
        // only ever gains an entry.
        temp.persist(&destination, &self.protection)?;

        protect::remove_file(source)
            .ctx(|| format!("{}: removing converted entry", source.display()))
    }

    /// An entry's stored bytes with nothing but its seal taken off: the zstd
    /// frame of a compressed entry, the content itself of a plain one.
    #[cfg_attr(not(feature = "crypt"), allow(clippy::unused_self))]
    fn payload(&self, path: &Path, form: Form) -> Result<Box<dyn Read>> {
        let file = File::open(path).ctx(|| format!("{}: opening entry", path.display()))?;
        if !form.is_encrypted() {
            return Ok(Box::new(file));
        }
        #[cfg(feature = "crypt")]
        {
            let Some(key) = self.key.as_deref() else {
                return Err(Error::KeyRequired(path.to_path_buf()));
            };
            Ok(Box::new(crypt::Opener::new(key, file)))
        }
        #[cfg(not(feature = "crypt"))]
        Err(Error::EncryptionUnavailable)
    }

    /// Write a payload out in `target` form, changing only what differs.
    ///
    /// Both forms are compressed or neither is, in every conversion but the two
    /// that cross that line — so zstd runs here only when the two sides
    /// genuinely disagree about it, and never on the way from one sealed form
    /// to another.
    #[cfg_attr(not(feature = "crypt"), allow(clippy::unused_self))]
    fn repack(
        &self,
        payload: Box<dyn Read>,
        temp: &mut TempFile,
        digest: &Digest,
        from: Form,
        target: Form,
    ) -> Result<()> {
        let mut source: Box<dyn Read> = if from.is_compressed() && !target.is_compressed() {
            Box::new(compress::reader(payload, true)?)
        } else {
            payload
        };
        let compress_now = !from.is_compressed() && target.is_compressed();

        if !target.is_encrypted() {
            compress::copy(&mut source, temp.file_mut(), compress_now)?;
            return Ok(());
        }
        #[cfg(feature = "crypt")]
        {
            let Some(key) = self.key.as_deref() else {
                return Err(Error::KeyRequired(temp.path().to_path_buf()));
            };
            let mut sealer = crypt::Sealer::new(key, temp.file_mut())
                .ctx(|| format!("{digest}: sealing entry"))?;
            compress::copy(&mut source, &mut sealer, compress_now)?;
            sealer.finish().ctx(|| format!("{digest}: sealing entry"))?;
            Ok(())
        }
        #[cfg(not(feature = "crypt"))]
        {
            let _ = (source, digest);
            Err(Error::EncryptionUnavailable)
        }
    }
}

/// Compress `source` into `temp`, sealing it as it goes under `key`.
///
/// Every write into a sealed store comes through here, the streaming one
/// included: the nonce is drawn by the sealer, so there is nothing a caller
/// has to know or hand in, and one place knows how the bytes go down.
#[cfg(feature = "crypt")]
fn seal_into(
    source: &mut impl Read,
    temp: &mut TempFile,
    key: &crypt::Key,
    what: &dyn Fn() -> String,
) -> Result<()> {
    let mut sealer = crypt::Sealer::new(key, temp.file_mut()).ctx(what)?;
    compress::copy(source, &mut sealer, true)?;
    sealer.finish().ctx(what)?;
    Ok(())
}

/// Whether this key opens that entry.
///
/// One chunk settles it: a key that is wrong fails on the first one, which is
/// what [`Error::Unsealable`] means. So this costs a single read however long
/// the entry is.
#[cfg(feature = "crypt")]
fn opens_with(path: &Path, key: &crypt::Key) -> Result<bool> {
    let file = File::open(path).ctx(|| format!("{}: opening entry", path.display()))?;
    let mut opener = crypt::Opener::new(key, file);
    let mut probe = [0u8; 1];
    match opener
        .read(&mut probe)
        .ctx(|| format!("{}: trying a key", path.display()))
    {
        // Including a read of nothing: an entry with no content still has a
        // chunk, and authenticating it is the whole question here.
        Ok(_) => Ok(true),
        // The wrong key, or damage from the very first byte. Neither is an
        // entry this key holds.
        Err(Error::Unsealable) => Ok(false),
        Err(err) => Err(err),
    }
}

/// Whether this is the decoder saying it could not allocate.
///
/// Read out of the message, because libzstd puts every one of its error codes
/// through `io::Error::new(ErrorKind::Other, msg)` and keeps nothing else of
/// them: an allocation failure arrives looking exactly like a rejected frame,
/// and the message is the only thing that tells them apart.
///
/// What it can be about is the decompression window, which the decoder sizes
/// from the frame header on its first read and which libzstd will not let past
/// 128 MiB. Nothing else on this path grows with the entry — the reader hands
/// the hasher one buffer at a time, and every buffer in between is a fixed
/// size.
///
/// `ErrorKind::OutOfMemory` is not also asked, though it looks like it belongs
/// here. The one thing on this path that raises it is a read of the file, and
/// `Watched` records that as the file having failed, which settles the question
/// before this is reached.
///
/// The message holds for as long as libzstd words it this way. Should that
/// change, an allocation failure is read as damage, which is what a store
/// answers to anything it cannot tell apart from damage.
fn out_of_memory(err: &io::Error) -> bool {
    err.to_string().contains("not enough memory")
}

/// Every directory below `root`, deepest last, the root itself excluded.
fn collect_dirs(root: &Path, is_store_root: bool, found: &mut Vec<PathBuf>) -> Result<()> {
    let listing = fs::read_dir(root).ctx(|| format!("{}: reading directory", root.display()))?;
    for item in listing {
        let item = item.ctx(|| format!("{}: reading directory", root.display()))?;
        if is_store_root && item.file_name() == temp::DIR {
            continue;
        }
        let path = item.path();
        // Not `path.is_dir()`: a symlink to a directory is not a shard, and
        // following one could walk in a circle.
        let file_type = item
            .file_type()
            .ctx(|| format!("{}: reading directory entry", path.display()))?;
        if file_type.is_dir() {
            collect_dirs(&path, false, found)?;
            found.push(path);
        }
    }
    Ok(())
}

/// Which of a store's files a walk yields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Walk {
    /// Entries only — what [`Store::entries`] hands out.
    Entries,
    /// Entries and what was set aside — what a key change has to move.
    #[cfg(feature = "crypt")]
    All,
    /// Only what was set aside — what [`Store::quarantined`] hands out.
    SetAside,
}

/// Iterator over a store's entries, made by [`Store::entries`].
///
/// A directory's listing is read whole, and its handle closed again, before
/// the first name out of it is handed over. Two things rest on that. What the
/// walk yields may be renamed or unlinked while the walk runs — renaming and
/// unlinking in a directory that is being read is not something every
/// filesystem defines an answer for, and every maintenance pass does exactly
/// that to the entries it is handed. And the memory of walking a store of any
/// size is one directory's listing: a shard, for a store that shards; the
/// whole root only for a flat one, where the root is the one directory there
/// is.
pub struct Entries<'a> {
    layout: &'a Layout,
    /// Directories seen and not yet read.
    dirs: Vec<PathBuf>,
    /// What the directory read last held, on its way out.
    ready: std::vec::IntoIter<Result<Entry>>,
    /// Which names are yielded: [`Store::change_key`] has to see what was set
    /// aside on top of the entries, [`Store::quarantined`] only that.
    walk: Walk,
}

impl<'a> Entries<'a> {
    fn new(store: &'a Store, walk: Walk) -> Self {
        Entries {
            layout: &store.layout,
            dirs: vec![store.root().to_path_buf()],
            ready: Vec::new().into_iter(),
            walk,
        }
    }

    /// Read one directory whole and close it again, leaving what it held in
    /// `ready` and its subdirectories on the pile.
    ///
    /// Every trouble on the way is an item, never an end: a directory that
    /// cannot be opened is one `Err`, an unreadable name is an `Err` among
    /// the `Ok`s, and the walk goes on either way — so a walk never quietly
    /// covers less than it claims to.
    fn load(&mut self, dir: &Path) {
        let is_root = dir == self.layout.root();
        let listing = match fs::read_dir(dir) {
            Ok(listing) => listing,
            Err(err) => {
                let doing = if is_root {
                    "reading store"
                } else {
                    "reading directory"
                };
                self.ready = vec![Err(Error::Io {
                    context: format!("{}: {doing}", dir.display()),
                    source: err,
                })]
                .into_iter();
                return;
            }
        };
        let mut found = Vec::new();
        for item in listing {
            let item = match item {
                Ok(item) => item,
                Err(err) => {
                    found.push(Err(Error::Io {
                        context: format!("{}: reading directory", dir.display()),
                        source: err,
                    }));
                    continue;
                }
            };
            // From the directory entry itself, so a symlink reads as a symlink:
            // descending into one could walk in a circle, and the cost of a
            // `stat` per file adds up over a store with a million of them.
            let file_type = match item.file_type() {
                Ok(file_type) => file_type,
                Err(err) => {
                    found.push(Err(Error::Io {
                        context: format!("{}: reading directory entry", item.path().display()),
                        source: err,
                    }));
                    continue;
                }
            };
            let path = item.path();
            if file_type.is_dir() {
                // `tmp` sits directly under the root and holds half-written
                // entries, which are nobody's business but the store's.
                if is_root && item.file_name() == temp::DIR {
                    continue;
                }
                self.dirs.push(path);
                continue;
            }
            let file_name = item.file_name();
            let Some(name) = file_name.to_str() else {
                continue;
            };
            if self.walk != Walk::SetAside {
                if let Some((digest, form)) = self.layout.parse_name(name) {
                    found.push(Ok(Entry { digest, path, form }));
                    continue;
                }
            }
            if self.walk != Walk::Entries {
                if let Some((digest, form)) = self.layout.parse_quarantined(name) {
                    found.push(Ok(Entry { digest, path, form }));
                }
            }
        }
        self.ready = found.into_iter();
    }
}

impl Iterator for Entries<'_> {
    type Item = Result<Entry>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(item) = self.ready.next() {
                return Some(item);
            }
            let dir = self.dirs.pop()?;
            self.load(&dir);
        }
    }
}

/// What one entry of a pass needs, and afterwards what it got.
///
/// The same three values on the way in and on the way out: a step planned as
/// `Converted` is one to do, and a step that comes back `Converted` is one that
/// was done. See [`Store::pass`] and [`Conversion`].
#[derive(Debug, Clone, Copy)]
enum Step {
    /// Rewrite it.
    Converted,
    /// In scope, and already the way this pass wants it.
    Already,
    /// Not this pass's business.
    Skipped,
}

/// A reader that hashes what it hands out.
struct HashingReader<R> {
    inner: R,
    hasher: Hasher,
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.hasher.update(&buf[..read]);
        Ok(read)
    }
}

/// A reader that remembers whether the failure was its own.
///
/// zstd reports a frame it cannot make sense of and a disk it cannot read the
/// same way — an `io::Error` out of the decoder — and those are opposite
/// answers: one is an entry to set aside, the other is a store that is not
/// reachable. This sits under the decoder, so afterwards it is known which of
/// the two happened.
struct Watched<R> {
    inner: R,
    failed: Arc<AtomicBool>,
}

impl<R: Read> Read for Watched<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.inner.read(out).inspect_err(|err| {
            // Not `Interrupted`: every layer above this one retries it and
            // reads on — `fill`, the zstd decoder, `io::copy` — so the file
            // did not fail. Recording it would stand for the whole of the
            // read, and a chunk that is genuinely damaged later on would be
            // answered as the disk's fault, which is an error where `verify`
            // owes a plain `false`.
            if err.kind() != io::ErrorKind::Interrupted {
                self.failed.store(true, Ordering::Relaxed);
            }
        })
    }
}

/// A reader that reports back that this store's key opened an entry.
///
/// Any byte handed over — the end of the blob included — means a chunk
/// authenticated, and a chunk that authenticates proves the key. See
/// [`Store::verify`], which is what the answer is for.
#[cfg(feature = "crypt")]
struct Proving<R> {
    inner: R,
    proven: Arc<AtomicBool>,
}

#[cfg(feature = "crypt")]
impl<R: Read> Read for Proving<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(out)?;
        self.proven.store(true, Ordering::Relaxed);
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A source that refuses once with `kind` and reads on afterwards.
    struct Hiccup {
        kind: io::ErrorKind,
        refused: bool,
        rest: &'static [u8],
    }

    impl Read for Hiccup {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if !self.refused {
                self.refused = true;
                return Err(io::Error::new(self.kind, "not this time"));
            }
            let take = out.len().min(self.rest.len());
            out[..take].copy_from_slice(&self.rest[..take]);
            self.rest = &self.rest[take..];
            Ok(take)
        }
    }

    fn watch(kind: io::ErrorKind) -> (io::Result<u64>, Vec<u8>, bool) {
        let failed = Arc::new(AtomicBool::new(false));
        let mut src = Watched {
            inner: Hiccup {
                kind,
                refused: false,
                rest: b"the rest of the entry",
            },
            failed: Arc::clone(&failed),
        };
        let mut out = Vec::new();
        let copied = io::copy(&mut src, &mut out);
        let failed = failed.load(Ordering::Relaxed);
        (copied, out, failed)
    }

    #[test]
    fn an_interruption_that_was_retried_is_not_the_file_failing() {
        let (copied, out, failed) = watch(io::ErrorKind::Interrupted);

        copied.expect("every layer above this one reads on past an interruption");
        assert_eq!(out, b"the rest of the entry");
        assert!(
            !failed,
            "the read carried on and finished, so nothing about the file went wrong"
        );
    }

    #[test]
    fn a_read_that_really_failed_is_remembered() {
        let (copied, _, failed) = watch(io::ErrorKind::PermissionDenied);

        assert!(copied.is_err());
        assert!(failed, "and it is the file's fault, not the content's");
    }

    #[test]
    fn a_decoder_that_cannot_allocate_is_not_damage() {
        // What libzstd calls it, through `io::Error::new(ErrorKind::Other, msg)`.
        assert!(out_of_memory(&io::Error::other(
            "Allocation error : not enough memory"
        )));
        assert!(
            !out_of_memory(&io::Error::other("Unknown frame descriptor")),
            "a rejected frame comes the same way and is the entry's fault"
        );
    }
}
