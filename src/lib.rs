//! Content-addressed storage: files named by the hash of their content.
//!
//! A file's name *is* its own hash. That one rule is what the rest follows
//! from: an entry is written once and never modified, adding the same bytes
//! twice is a no-op, and every file carries its own integrity check — hashing
//! the file and reading its name settles whether it is intact, with no database
//! and no checksum file to keep in sync.
//!
//! ```no_run
//! use immure::{Algorithm, Status, Store};
//!
//! let store = Store::builder("/srv/store")
//!     .suffix(".json")
//!     .depth(2)
//!     .algorithm(Algorithm::Sha256)
//!     .compress(true)
//!     .build()?;
//!
//! let (status, entry) = store.add(b"the content of an entry")?;
//! if status == Status::New {
//!     println!("stored as {}", entry.path().display());
//! }
//!
//! assert_eq!(store.read(entry.digest())?.as_deref(), Some(&b"the content of an entry"[..]));
//! assert!(store.verify(&entry)?);
//! # Ok::<(), immure::Error>(())
//! ```
//!
//! # Choosing a hash
//!
//! [`Algorithm::Sha256`] is the default, and wins on all three counts that
//! matter here. Hashing 256 MiB single-threaded, on an Apple Silicon machine:
//!
//! ```text
//! sha256      77 ms   3.25 GiB/s    64 hex characters   sha256sum
//! blake3     111 ms   2.25 GiB/s    64 hex characters   b3sum
//! sha384     136 ms   1.84 GiB/s    96 hex characters   sha384sum
//! sha512     136 ms   1.84 GiB/s   128 hex characters   sha512sum
//! ```
//!
//! Shortest names alongside BLAKE3, quickest of the four, and the one tool of
//! the four that is already on the machine — `sha256sum` has been in coreutils
//! for twenty years, `b3sum` is an install. That last point is what the whole
//! design rests on: a name is worth something because anyone can hold content
//! against it without this library.
//!
//! The speed column is the one to distrust. SHA-256 is that quick because the
//! CPU has instructions for it — `ARMv8` here, SHA-NI on x86-64 from AMD Zen and
//! Intel Ice Lake. Without them SHA-256 is hashed in software and
//! [`Algorithm::Blake3`] is several times quicker, which is what it is here for.
//! Measure it on the machine that will do the work rather than believing this
//! table:
//!
//! ```no_run
//! use immure::{Algorithm, Store};
//!
//! let store = Store::builder("/srv/store")
//!     .algorithm(Algorithm::Blake3)
//!     .build()?;
//! # Ok::<(), immure::Error>(())
//! ```
//!
//! SHA-384 and SHA-512 are here for stores already named with them. Which hash
//! a store uses is a property of the store and not of the entry: nothing in a
//! name says which one made it. A store opened with the wrong one refuses the
//! digests and names it is held against wherever the lengths give it away
//! ([`Error::AlgorithmMismatch`]); SHA-256 and BLAKE3 write names of one
//! length, and there content hashed with the wrong one simply finds nothing.
//! `depth` and `suffix` are likewise picked once and kept with the store, the
//! way the key is kept.
//!
//! # On disk
//!
//! The digest is cut into two-character directory components — as many as the
//! store's `depth` — and the entry sits at the bottom under its full digest:
//!
//! ```text
//! /srv/store/
//!     fd/bd/fdbd8e75a67f29f701a4e040385e2e23986303ea….json.zst
//!     tmp/                       half-written entries live here, briefly
//! ```
//!
//! Sharding is what keeps a quarter of a million files out of one directory.
//! Two levels give 65 536 buckets; one is plenty for a store with a few
//! thousand entries.
//!
//! Nothing but the tree itself is needed to read a store back. There is no
//! index, no manifest and no lock file, and every question — what is in here,
//! is it intact, what is this file — is answered by the names. A store survives
//! this crate.
//!
//! A handle onto one is a description of where it lies, and nothing more:
//! [`Store::open`] and [`Builder::build`] touch no disk, because a store that is
//! not there is not created by asking about it. A root on a share that is not
//! mounted would otherwise get an empty store written onto the mount point.
//! Writing makes the directories it needs as it goes, and [`Store::create`] is
//! for a caller that means to make the store now.
//!
//! Which is also how an entry is looked up: [`Store::read`] and
//! [`Store::reader`] open the file the digest names rather than asking
//! about it first, and [`Store::matching`] takes the beginning of a digest —
//! the shard the entry lies in — so a short id names an entry the way a short
//! commit hash does.
//!
//! # Writing
//!
//! Entries are written to `tmp/` and renamed into place only once complete. A
//! rename within one filesystem is atomic on everything in practical use, so a
//! reader sees an entry whole or not at all, and an interrupted run leaves a
//! stray temporary file rather than a truncated entry.
//!
//! Durability is not a setting. Each entry reaches the device before the rename
//! that names it, and the directory entry is flushed after — in that order,
//! because a rename can otherwise overtake the content it publishes and leave a
//! file under a name claiming to be the hash of bytes that never arrived.
//! Nothing would find that out: a store answers "is this here?" by looking at
//! names, not by reading them.
//!
//! Concurrency needs no coordination: writers pick unique temporary names, and
//! two processes storing the same bytes race to rename identical content into
//! the same place. What a writer that never finished leaves in `tmp/` is
//! nobody's to reuse, so [`Store::prune_temp_files`] is how those go.
//!
//! What is immutable by construction is also marked as such: the write bits
//! come off just before an entry takes its name, so nothing that opens one
//! finds an invitation to change it. Comfort rather than security — it stops
//! the editor that "repairs" the file it is displaying, not anybody who means
//! it, and it does not stand in the way of [`Store::remove`]. A filesystem that
//! does not carry the mode is noticed at the first entry and not asked again;
//! a refused `chmod` never costs a store the content it was writing.
//!
//! # When an entry is damaged
//!
//! [`Store::verify`] holds an entry against the name it is filed under, and that
//! is the whole point of naming a file after its content: bit rot, a truncated
//! write and a botched restore all show up as a name the bytes no longer have.
//! Nothing else in a store can notice — every other question is answered by
//! looking at names, never by reading them.
//!
//! What to do with one is [`Store::quarantine`]. The file keeps every byte and
//! loses the name, so the store stops answering that this content is present and
//! whatever fetched it the first time can fetch it again. Deleting it would be
//! the worse of the two ways to be wrong: content with a flipped bit is still
//! almost all of the content.
//!
//! What was set aside stays reachable: [`Store::quarantined`] walks it,
//! [`Store::restore`] gives a false alarm its name back — the same check as
//! `verify`, so nothing comes back that would not pass it — and
//! [`Store::discard`] is how a copy leaves for good once its content was
//! fetched again, or given up on.
//!
//! # Compression
//!
//! Entries can be stored zstd-compressed, which shows up as a `.zst` on top of
//! the regular suffix. Compression is a property of the *file*, not of the
//! store: reading follows whatever is on disk, so a store can be switched over
//! at any time and [`Store::compress_all`] / [`Store::decompress_all`] convert
//! the backlog. The digest is always of the uncompressed content — the same
//! bytes get the same name either way.
//!
//! Turning off the crate's default `zstd` feature drops the codec. A store then
//! refuses to compress instead of quietly storing plain bytes under a `.zst`
//! name.
//!
//! # Encryption
//!
//! With the `crypt` feature and a key, entries are sealed with
//! XChaCha20-Poly1305 on their way to disk, which shows up as an `.enc` after
//! the `.zst`. Sealing implies compression, so an entry lies in one of three
//! forms and never a fourth: `<digest><suffix>`, `.zst`, or `.zst.enc`.
//!
//! What does *not* change is everything else. The name is still the digest of
//! the content, so duplicates are still decided before a byte is written, and
//! everything a store answers by looking at names — [`Store::find`],
//! [`Store::contains`], [`Store::matching`], [`Store::entries`],
//! [`Store::remove`], [`Store::quarantine`] — keeps working without the key.
//! Nothing is written into the tree beyond the entries themselves: each one
//! names its own frame — magic, version byte, then the nonce it was sealed
//! under — in its own first bytes, so there is no key file, no manifest and no
//! configuration to keep, and a store is still nothing but the files it holds.
//! A frame written by a newer immure is refused as [`Error::FrameVersion`]
//! before the key is ever tried: a healthy entry, an old build, and nothing to
//! quarantine.
//!
//! The key is 32 bytes and comes from the caller
//! (`Builder::key`). Where it comes from — a key file, a
//! passphrase through a password KDF, a token — is deliberately not this
//! crate's business, and neither is the salt or seed that goes with it.
//!
//! What a caller has to handle: [`Error::KeyRequired`] when a sealed entry is
//! met by a store without one, and two failures that are worth telling apart.
//! [`Error::Unsealable`] means the first chunk did not authenticate — the wrong
//! key, or content damaged from its first bytes, and nothing can say which.
//! [`Error::Damaged`] means a later one did not, so the key has already proved
//! itself and the bytes are what is wrong. Only the second is a reason to
//! [`quarantine`](Store::quarantine) anything, which is why
//! [`Store::verify`] turns it into a plain `false` and lets the other through —
//! until this store's key has opened something, after which a first chunk
//! failing is damage as well. That matters because most entries are a single
//! chunk, and for those there is no later one to prove the key with.
//! `Store::prove_key` settles that deliberately — one opened chunk, before a
//! pass that acts on `false` — and `Store::key_proven` says where a handle
//! stands.
//!
//! `Store::encrypt_all` seals a store that was not sealed before, and
//! `Store::decrypt_all` turns a sealed store back into a plain one.
//! `Store::change_key` moves a store from one key to another in a single pass,
//! one entry at a time: the frame goes straight from one cipher into the next,
//! so nothing is unpacked and nothing is ever written in the clear.

#![forbid(unsafe_code)]

mod compress;
mod layout;
mod protect;
mod temp;

pub mod crypt;
pub mod digest;
pub mod error;
pub mod store;

pub use compress::available as compression_available;
#[cfg(feature = "crypt")]
pub use crypt::Key;
pub use crypt::available as encryption_available;
pub use digest::{Algorithm, Digest, Hasher};
pub use error::{Error, Result};
pub use layout::{DEFAULT_SUFFIX, QUARANTINE_SUFFIX};
pub use store::{
    Builder, Conversion, DEFAULT_DEPTH, DEFAULT_TEMP_MIN_AGE, Entries, Entry, Failure, Quarantined,
    Status, Store,
};
