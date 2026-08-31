//! The cipher itself: chunk framing, keys, nonces.

use std::fmt;
use std::io::{self, Read, Write};

use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// Plaintext bytes in a full chunk.
const CHUNK: usize = 64 * 1024;

/// What Poly1305 adds to every chunk.
const TAG: usize = 16;

/// A full chunk as it lies on disk. Anything shorter than this is the last one.
const SEALED_CHUNK: usize = CHUNK + TAG;

/// The part of a chunk nonce that is the same for a whole blob. The rest is
/// the chunk number and the end marker.
const PREFIX: usize = 24 - 4 - 1;

/// The key a blob is sealed with: 32 bytes, and nothing else.
///
/// Where they come from is not this crate's business. A key file, a passphrase
/// put through a password KDF, a hardware token — all of that lives with the
/// caller, along with the salt or seed it needs, which is exactly why a store
/// needs nothing written into it to be opened again.
///
/// The bytes are wiped when the key is dropped, and never printed: `Debug`
/// shows the type and nothing of the value.
///
/// What that covers is this value. Moving a key is a copy of its bytes and a
/// forget of the source, so a caller that built one out of an array of its own
/// still holds that array, and every frame the key passed through on its way
/// here keeps whatever was left on the stack. [`Key::random`] hands out a key
/// that was never anywhere else, which is the only way to be sure of it.
#[derive(Clone)]
pub struct Key([u8; Key::LEN]);

impl Key {
    /// How many bytes a key is.
    pub const LEN: usize = 32;

    /// Take these 32 bytes as the key.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LEN]) -> Self {
        Key(bytes)
    }

    /// A fresh key from the operating system's randomness.
    ///
    /// Where a store's own key comes from is the caller's business — this is
    /// for the keys nobody keeps: whatever needs a key that lives and dies
    /// inside one process.
    ///
    /// # Errors
    ///
    /// [`Error::Random`] when the system will not hand out randomness. There is
    /// nothing to fall back to, and a key that is not random is not a key.
    pub fn random() -> Result<Self> {
        let mut bytes = [0u8; Self::LEN];
        getrandom::fill(&mut bytes).map_err(|_| Error::Random)?;
        let key = Key(bytes);
        // The array is a copy of the key and outlives the move into `Key`,
        // which is a memcpy and leaves the source where it was.
        bytes.zeroize();
        Ok(key)
    }

    /// Take a key out of a slice that has to be exactly [`Key::LEN`] long.
    ///
    /// # Errors
    ///
    /// [`Error::KeyLength`] when it is not.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let mut bytes: [u8; Self::LEN] = bytes.try_into().map_err(|_| Error::KeyLength {
            expected: Self::LEN,
            actual: bytes.len(),
        })?;
        let key = Key(bytes);
        // This copy of the key outlives the move into `Key`, which is a memcpy
        // and leaves the source where it was. The caller's slice is its own.
        bytes.zeroize();
        Ok(key)
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(&self.0.into())
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(…)")
    }
}

/// What makes one blob's chunk nonces different from every other blob's.
///
/// Drawn from the operating system's randomness for every blob that is sealed,
/// and written out ahead of the first chunk — so unsealing needs nothing but the
/// key, and no caller ever chooses one. `XChaCha20`'s nonce is long enough that
/// drawing it is safe without keeping a record of what has been used, which is
/// what the extended nonce is for; deriving it instead would put the burden of
/// "never twice under one key" back on whoever writes the next blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Nonce([u8; Nonce::LEN]);

impl Nonce {
    /// How many bytes the fixed part of a nonce is.
    const LEN: usize = PREFIX;

    /// Take these bytes as the nonce.
    const fn new(bytes: [u8; Self::LEN]) -> Self {
        Nonce(bytes)
    }

    /// A fresh nonce from the operating system's randomness.
    fn random() -> Result<Self> {
        let mut bytes = [0u8; Self::LEN];
        getrandom::fill(&mut bytes).map_err(|_| Error::Random)?;
        Ok(Nonce(bytes))
    }

    /// The nonce of one chunk: the prefix, the chunk's number, and whether it
    /// is the last one.
    fn chunk(self, number: u32, last: bool) -> XNonce {
        let mut nonce = [0u8; 24];
        nonce[..Self::LEN].copy_from_slice(&self.0);
        nonce[Self::LEN..Self::LEN + 4].copy_from_slice(&number.to_be_bytes());
        nonce[23] = u8::from(last);
        nonce.into()
    }
}

/// Seal a blob whole.
///
/// The nonce is drawn here and travels in the blob, so the caller keeps nothing
/// but the key.
///
/// # Errors
///
/// [`Error::Random`] when the system will not hand out a nonce, and
/// [`Error::TooManyChunks`] for a blob beyond 256 TiB. The cipher itself cannot
/// fail here.
pub fn seal(key: &Key, plain: &[u8]) -> Result<Vec<u8>> {
    let chunks = plain.len() / CHUNK + 1;
    let mut out = Vec::with_capacity(Nonce::LEN + plain.len() + chunks * TAG);
    let mut sealer = Sealer::new(key, &mut out).map_err(unwrap_io)?;
    sealer.write_all(plain).map_err(unwrap_io)?;
    sealer.finish().map_err(unwrap_io)?;
    Ok(out)
}

/// Unseal a blob whole.
///
/// # Errors
///
/// [`Error::Unsealable`] when the very first chunk does not authenticate —
/// which is the wrong key, or a blob damaged from its first bytes, and there is
/// no telling those two apart. A blob too short to hold a nonce answers the
/// same way, for the same reason: nothing in it authenticates.
/// [`Error::Damaged`] when a later chunk does not: the key opened what came
/// before it, so the key is right and the bytes are not.
pub fn open(key: &Key, sealed: &[u8]) -> Result<Vec<u8>> {
    let mut plain = Vec::with_capacity(sealed.len());
    Opener::new(key, sealed)
        .read_to_end(&mut plain)
        .map_err(unwrap_io)?;
    Ok(plain)
}

/// Get the crate error back out of an [`io::Error`] this module put in.
fn unwrap_io(err: io::Error) -> Error {
    match err.downcast::<Error>() {
        Ok(err) => err,
        Err(err) => Error::Io {
            context: "sealing".to_string(),
            source: err,
        },
    }
}

/// A writer that seals what is written through it.
///
/// Nothing reaches `dst` unsealed, and [`finish`](Sealer::finish) has to be
/// called: it writes the chunk that marks the end. Dropping a `Sealer` without
/// finishing leaves a blob that cannot be unsealed, which is the right way
/// round — a half-written entry is one the store never names.
///
/// The nonce is drawn when the sealer is made and goes out ahead of the first
/// chunk. There is no way to hand one in, which is the point: a nonce used
/// twice under one key is the one mistake this format cannot survive, and the
/// only sure way to rule it out is that nobody gets to pick.
///
/// Failures speak [`io::Error`], as [`Write`] demands. What is the crate's
/// own — [`Error::Random`] drawing the nonce, [`Error::TooManyChunks`] past
/// 256 TiB — travels inside one, and
/// [`Error::from_io`](crate::Error::from_io) gets it back out.
pub struct Sealer<W: Write> {
    cipher: XChaCha20Poly1305,
    nonce: Nonce,
    number: u32,
    pending: Vec<u8>,
    /// One chunk on its way out, reused for every chunk. `encrypt_in_place`
    /// needs the bytes contiguous and grows them by a tag, so they cannot go
    /// straight out of `pending`.
    chunk: Vec<u8>,
    dst: W,
}

impl<W: Write> Sealer<W> {
    /// Seal everything written here into `dst`, under a nonce drawn now.
    ///
    /// The nonce goes out first, before any chunk, so `dst` holds everything
    /// unsealing needs bar the key.
    ///
    /// # Errors
    ///
    /// [`io::Error`] from `dst`, and [`Error::Random`] wrapped in one when the
    /// system will not hand out a nonce. There is nothing to fall back to: a
    /// nonce that is not random is one that can repeat.
    pub fn new(key: &Key, mut dst: W) -> io::Result<Self> {
        let nonce = Nonce::random().map_err(io::Error::other)?;
        dst.write_all(&nonce.0)?;
        Ok(Sealer {
            cipher: key.cipher(),
            nonce,
            number: 0,
            pending: Vec::with_capacity(CHUNK),
            chunk: Vec::with_capacity(CHUNK + TAG),
            dst,
        })
    }

    /// Write the final chunk and hand `dst` back.
    ///
    /// Takes the sealer with it, because a blob that has been finished cannot
    /// be added to: a chunk written after the one that marks the end is one no
    /// reader will ever reach, and a sealer that allowed it would turn a
    /// mistake into content that quietly goes missing.
    ///
    /// # Errors
    ///
    /// [`io::Error`] from `dst`, and [`Error::TooManyChunks`] wrapped in one
    /// for a blob past 256 TiB.
    pub fn finish(mut self) -> io::Result<W> {
        // A full buffer here would make the last chunk a full one, and the
        // reader knows the end by its length. It goes out as an ordinary chunk
        // and an empty one follows it.
        if self.pending.len() == CHUNK {
            self.seal_chunk(CHUNK, false)?;
        }
        let rest = self.pending.len();
        self.seal_chunk(rest, true)?;
        Ok(self.dst)
    }

    /// Seal the first `len` bytes of what is pending.
    fn seal_chunk(&mut self, len: usize, last: bool) -> io::Result<()> {
        self.chunk.clear();
        self.chunk.extend_from_slice(&self.pending[..len]);
        self.pending.drain(..len);
        let nonce = self.nonce.chunk(self.number, last);
        self.cipher
            .encrypt_in_place(&nonce, b"", &mut self.chunk)
            .map_err(|_| io::Error::other("sealing a chunk"))?;
        self.number = self
            .number
            .checked_add(1)
            .ok_or_else(|| io::Error::other(Error::TooManyChunks))?;
        self.dst.write_all(&self.chunk)
    }
}

impl<W: Write> Write for Sealer<W> {
    /// Takes a chunk's worth at a time, and says so.
    ///
    /// A partial write is what `Write` is for. Swallowing the whole slice
    /// instead would mean holding a copy of it — and moving the untouched tail
    /// down by a chunk for every chunk that goes out, which turns sealing a
    /// large blob in one call into quadratic work.
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        // A full buffer can only go out once something follows it: the last
        // chunk is sealed under a different nonce, and `data` is what says this
        // one is not it.
        if self.pending.len() == CHUNK {
            self.seal_chunk(CHUNK, false)?;
        }
        let take = (CHUNK - self.pending.len()).min(data.len());
        self.pending.extend_from_slice(&data[..take]);
        Ok(take)
    }

    fn flush(&mut self) -> io::Result<()> {
        // What is pending cannot go out yet — it may still turn out to be the
        // last chunk, which is sealed under a different nonce.
        self.dst.flush()
    }
}

/// Why a reader ended, kept so that every read after it says the same thing.
///
/// The reason cannot be worked out again from where the reader stopped: a
/// chunk that did not authenticate and a source that could not be read both
/// end it, and they are opposite answers — one names an entry to set aside,
/// the other a store that is not reachable. Answering one for the other has a
/// maintenance pass take a healthy entry's name away over a flaky disk.
///
/// An [`io::Error`] is not `Clone`, so what can be kept of a source failure is
/// its kind and what it said. Both survive the rebuild, and both are what a
/// caller goes on.
enum Spoiled {
    /// The first chunk did not authenticate: the wrong key, or bytes damaged
    /// from the start, and no telling which.
    Unsealable,
    /// A later one did not, so the key is proven and the bytes are not.
    Damaged,
    /// More chunks than the counter can name.
    TooManyChunks,
    /// The source itself failed, and this is what it said.
    Source(io::ErrorKind, String),
}

impl Spoiled {
    /// What a chunk that does not authenticate means, by where it sits.
    ///
    /// A wrong key and damaged bytes look identical to the cipher — both are
    /// "the tag does not match" — but not at the same place. Once one chunk
    /// has opened, the key is proven: whatever fails after that is the
    /// content. The distinction decides whether an entry may be set aside as
    /// damaged or whether the caller was simply holding the wrong key, and
    /// quarantining a healthy entry is not a mistake to make quietly.
    ///
    /// What it cannot tell on its own is a blob that fits in a single chunk:
    /// there is no second one to prove the key with.
    /// [`Store::verify`](crate::Store::verify) takes that up with what it knows
    /// about the store around the entry.
    fn failure(number: u32) -> Self {
        if number == 0 {
            Spoiled::Unsealable
        } else {
            Spoiled::Damaged
        }
    }

    /// The error to hand back for this reason, as often as it is asked for.
    fn error(&self) -> io::Error {
        match self {
            Spoiled::Unsealable => io::Error::other(Error::Unsealable),
            Spoiled::Damaged => io::Error::other(Error::Damaged),
            Spoiled::TooManyChunks => io::Error::other(Error::TooManyChunks),
            Spoiled::Source(kind, message) => io::Error::new(*kind, message.clone()),
        }
    }
}

/// A reader that unseals what it hands out.
///
/// Reading stops at the end of the blob, and a blob that was cut short fails
/// rather than ending quietly: the chunk that marks the end is missing.
///
/// A failure ends the stream for good, and every further read repeats it. For
/// a chunk that did not authenticate that is because the only bytes there
/// would be to carry on with are the ones that just failed to authenticate,
/// and handing those out as content is the one thing a reader like this must
/// never do. For a source that could not be read it is because the bytes it
/// did hand over before failing are already gone, so there is no position to
/// resume from.
///
/// Failures speak [`io::Error`], as [`Read`] demands. A chunk that did not
/// authenticate is in there as [`Error::Unsealable`] or [`Error::Damaged`],
/// and [`Error::from_io`](crate::Error::from_io) gets it back out — a source
/// failure keeps its own kind and message, so the two stay apart.
pub struct Opener<R: Read> {
    cipher: XChaCha20Poly1305,
    /// Read off the front of `src` before the first chunk, and `None` until
    /// then. Nothing else in the blob can be opened without it.
    nonce: Option<Nonce>,
    number: u32,
    plain: Vec<u8>,
    taken: usize,
    src: R,
    done: bool,
    /// Why this reader ended, and `None` while it has not. Never cleared.
    spoiled: Option<Spoiled>,
}

impl<R: Read> Opener<R> {
    /// Unseal everything read from `src`.
    ///
    /// The nonce comes off the front of `src` at the first read, so the key is
    /// all the caller has to have kept.
    pub fn new(key: &Key, src: R) -> Self {
        Opener {
            cipher: key.cipher(),
            nonce: None,
            number: 0,
            plain: Vec::new(),
            taken: 0,
            src,
            done: false,
            spoiled: None,
        }
    }

    /// Read and unseal the next chunk, or notice that there is none.
    ///
    /// Into the buffer this reader already owns: a chunk is read into it and
    /// opened in place, so a blob of any length costs the one allocation. Which
    /// is why every way out of here that is not `Ok` empties the buffer first —
    /// what is in it until the decrypt returns is the *sealed* chunk, and
    /// [`Read::read`] tells "there is plaintext waiting" from "there is not" by
    /// that buffer's length.
    fn next_chunk(&mut self) -> io::Result<()> {
        let number = self.number;
        let nonce = if let Some(nonce) = self.nonce {
            nonce
        } else {
            let mut bytes = [0u8; Nonce::LEN];
            let read = match fill(&mut self.src, &mut bytes) {
                Ok(read) => read,
                Err(err) => return Err(self.spoil_source(err)),
            };
            // Too short to hold a nonce is too short to hold anything that
            // could authenticate, which is what a failed first chunk means.
            if read < Nonce::LEN {
                return Err(self.spoil(Spoiled::failure(0)));
            }
            let nonce = Nonce::new(bytes);
            self.nonce = Some(nonce);
            nonce
        };
        self.plain.clear();
        self.plain.resize(SEALED_CHUNK, 0);
        let read = match fill(&mut self.src, &mut self.plain) {
            Ok(read) => read,
            Err(err) => return Err(self.spoil_source(err)),
        };
        self.plain.truncate(read);

        // A full chunk is never the last one, so a short read is the end — and
        // a stream that stops without one was cut short.
        let last = read < SEALED_CHUNK;
        if last && read < TAG {
            return Err(self.spoil(Spoiled::failure(number)));
        }

        let chunk = nonce.chunk(number, last);
        if self
            .cipher
            .decrypt_in_place(&chunk, b"", &mut self.plain)
            .is_err()
        {
            return Err(self.spoil(Spoiled::failure(number)));
        }
        // Through `spoil` like everything else: the buffer is holding the
        // opened chunk while `taken` still stands on the last one, and leaving
        // it that way is what the invariant above rules out. `read` would go on
        // to subtract the one from the other.
        let Some(next) = number.checked_add(1) else {
            return Err(self.spoil(Spoiled::TooManyChunks));
        };
        self.number = next;

        self.taken = 0;
        self.done = last;
        Ok(())
    }

    /// Leave the buffer holding nothing, end this reader for `reason`, and
    /// hand back the error that says so.
    fn spoil(&mut self, reason: Spoiled) -> io::Error {
        self.plain.clear();
        self.taken = 0;
        let err = reason.error();
        self.spoiled = Some(reason);
        err
    }

    /// As [`spoil`](Opener::spoil), for a source that could not be read, and
    /// handing that failure straight back with everything it carries.
    ///
    /// A source failure is the end of this reader like any other, though it
    /// looks like the one worth retrying: the chunk never arrived, so nothing
    /// was decided about it. But [`fill`] has already taken however many bytes
    /// it got before the error and dropped them, so a second attempt would
    /// start in the middle of a chunk and report healthy content as damaged.
    /// There is no position to resume from, so there is no retry to offer.
    fn spoil_source(&mut self, err: io::Error) -> io::Error {
        self.plain.clear();
        self.taken = 0;
        self.spoiled = Some(Spoiled::Source(err.kind(), err.to_string()));
        err
    }
}

impl<R: Read> Read for Opener<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        // A reader that has ended gives the same answer however often it is
        // asked, and the answer is whatever ended it.
        if let Some(reason) = &self.spoiled {
            return Err(reason.error());
        }
        while self.taken == self.plain.len() {
            if self.done {
                return Ok(0);
            }
            self.next_chunk()?;
        }
        let take = out.len().min(self.plain.len() - self.taken);
        out[..take].copy_from_slice(&self.plain[self.taken..self.taken + take]);
        self.taken += take;
        Ok(take)
    }
}

/// Read until the buffer is full or the source is spent, and say how much came.
///
/// [`Read::read`] is allowed to hand over less than it was asked for, which
/// here would look exactly like the end of the blob.
fn fill(src: &mut impl Read, buffer: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match src.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Key {
        Key::new([7u8; Key::LEN])
    }

    /// Where the first chunk starts: the nonce comes before it.
    const BODY: usize = Nonce::LEN;

    fn roundtrip(len: usize) {
        let plain: Vec<u8> = (0..len)
            .map(|i| u8::try_from(i % 251).expect("under 251"))
            .collect();
        let sealed = seal(&key(), &plain).unwrap();
        assert_ne!(sealed, plain, "the bytes on disk are not the content");
        assert_eq!(open(&key(), &sealed).unwrap(), plain);
    }

    #[test]
    fn a_blob_comes_back_the_way_it_went_in() {
        for len in [0, 1, 100, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK + 7] {
            roundtrip(len);
        }
    }

    #[test]
    fn the_same_content_is_never_sealed_the_same_way_twice() {
        // The whole reason the nonce is drawn rather than derived. Two blobs of
        // one content under one key have to differ, or a store that holds both
        // hands out their relationship for nothing.
        let sealed = seal(&key(), b"content worth keeping twice").unwrap();
        let again = seal(&key(), b"content worth keeping twice").unwrap();

        assert_ne!(sealed[..BODY], again[..BODY], "a fresh nonce each time");
        assert_ne!(sealed[BODY..], again[BODY..], "and so a different sealing");
        assert_eq!(
            open(&key(), &sealed).unwrap(),
            open(&key(), &again).unwrap()
        );
    }

    #[test]
    fn a_blob_is_framed_the_same_whether_it_goes_in_whole_or_in_pieces() {
        let plain: Vec<u8> = (0..3 * CHUNK + 7)
            .map(|i| u8::try_from(i % 251).expect("under 251"))
            .collect();
        let whole = seal(&key(), &plain).unwrap();

        let mut piecemeal = Vec::new();
        let mut sealer = Sealer::new(&key(), &mut piecemeal).unwrap();
        for piece in plain.chunks(1000) {
            sealer.write_all(piece).unwrap();
        }
        sealer.finish().unwrap();

        // Not byte for byte — the nonces differ — but chunk for chunk, which is
        // what the length says and is all the caller could influence.
        assert_eq!(
            whole.len(),
            piecemeal.len(),
            "the framing does not depend on the caller"
        );
        assert_eq!(open(&key(), &piecemeal).unwrap(), plain);
    }

    #[test]
    fn a_write_takes_one_chunk_at_a_time_and_says_how_much_it_took() {
        let mut out = Vec::new();
        let mut sealer = Sealer::new(&key(), &mut out).unwrap();

        let taken = sealer.write(&vec![0u8; 3 * CHUNK]).unwrap();

        assert_eq!(
            taken, CHUNK,
            "swallowing the whole slice would mean holding a copy of it and \
             moving the untouched tail down once per chunk"
        );
    }

    #[test]
    fn the_nonce_comes_before_the_first_chunk() {
        let sealed = seal(&key(), b"").unwrap();
        // An empty blob is one empty chunk and its tag, and nothing else — so
        // whatever is in front of that is the nonce and is exactly as long as
        // one.
        assert_eq!(sealed.len(), Nonce::LEN + TAG);
    }

    #[test]
    fn the_last_chunk_is_never_a_full_one() {
        // Exactly one chunk of content: a full chunk, then an empty one that
        // says the blob ends there.
        let sealed = seal(&key(), &vec![0u8; CHUNK]).unwrap();
        assert_eq!(sealed.len(), BODY + SEALED_CHUNK + TAG);
    }

    #[test]
    fn another_key_does_not_open_it() {
        let sealed = seal(&key(), b"secret").unwrap();
        let other = Key::new([8u8; Key::LEN]);
        assert!(matches!(open(&other, &sealed), Err(Error::Unsealable)));
    }

    #[test]
    fn a_changed_byte_does_not_open_it() {
        let mut sealed = seal(&key(), b"secret").unwrap();
        sealed[BODY + 2] ^= 0x01;
        assert!(matches!(open(&key(), &sealed), Err(Error::Unsealable)));
    }

    #[test]
    fn a_changed_nonce_does_not_open_it() {
        // The nonce travels in the clear and nothing signs it — but it is what
        // every chunk is opened under, so touching it is as good as touching
        // the content.
        let mut sealed = seal(&key(), b"secret").unwrap();
        sealed[2] ^= 0x01;
        assert!(matches!(open(&key(), &sealed), Err(Error::Unsealable)));
    }

    #[test]
    fn a_blob_too_short_to_hold_a_nonce_does_not_open_at_all() {
        let sealed = seal(&key(), b"secret").unwrap();
        for len in [0, 1, Nonce::LEN - 1] {
            assert!(
                matches!(open(&key(), &sealed[..len]), Err(Error::Unsealable)),
                "nothing in {len} bytes authenticates"
            );
        }
    }

    #[test]
    fn a_blob_cut_short_does_not_open_at_all() {
        // Two chunks and a bit: cutting at the chunk boundary leaves something
        // that would decrypt cleanly if the end were not marked. The first
        // chunk opens, so the key is proven and what is missing is content.
        let plain = vec![0u8; 2 * CHUNK + 10];
        let sealed = seal(&key(), &plain).unwrap();

        let cut = &sealed[..BODY + SEALED_CHUNK];
        assert!(matches!(open(&key(), cut), Err(Error::Damaged)));

        let cut = &sealed[..sealed.len() - 1];
        assert!(matches!(open(&key(), cut), Err(Error::Damaged)));
    }

    #[test]
    fn reading_on_past_a_chunk_that_did_not_authenticate_hands_out_nothing() {
        // The buffer a chunk is opened in is the one it was read into, so a
        // failed decrypt leaves the sealed chunk lying in it. Asking again must
        // fail again rather than copy that out as content.
        let plain = vec![0u8; 2 * CHUNK];
        let sealed = seal(&key(), &plain).unwrap();
        let other = Key::new([9u8; Key::LEN]);

        let mut opener = Opener::new(&other, &sealed[..]);
        let mut out = vec![0u8; sealed.len()];
        for _ in 0..3 {
            let err = opener.read(&mut out).expect_err("nothing here opens");
            assert!(matches!(
                err.downcast::<Error>(),
                Ok(Error::Unsealable) | Err(_)
            ));
        }
        assert!(
            out.iter().all(|byte| *byte == 0),
            "not a byte was handed out"
        );

        // The same once a chunk has opened and the next one is damaged: what
        // comes back is the failure, not the tail of the chunk that failed.
        let mut sealed = seal(&key(), &plain).unwrap();
        sealed[BODY + SEALED_CHUNK + 10] ^= 0x01;
        let mut opener = Opener::new(&key(), &sealed[..]);
        let mut first = vec![0u8; CHUNK];
        opener
            .read_exact(&mut first)
            .expect("the first chunk opens");
        for _ in 0..3 {
            opener.read(&mut out).expect_err("the second one does not");
        }
    }

    #[test]
    fn damage_past_the_first_chunk_is_told_apart_from_a_wrong_key() {
        let plain = vec![0u8; 2 * CHUNK];
        let mut sealed = seal(&key(), &plain).unwrap();
        // Well inside the second chunk: the first one still opens, which is
        // what proves the key and makes this the entry's fault.
        sealed[BODY + SEALED_CHUNK + 10] ^= 0x01;

        assert!(matches!(open(&key(), &sealed), Err(Error::Damaged)));
    }

    #[test]
    fn chunks_cannot_be_swapped_around() {
        let plain: Vec<u8> = (0..3 * CHUNK)
            .map(|i| u8::try_from(i % 251).expect("under 251"))
            .collect();
        let sealed = seal(&key(), &plain).unwrap();

        let mut swapped = sealed.clone();
        let (first, rest) = swapped[BODY..].split_at_mut(SEALED_CHUNK);
        first.swap_with_slice(&mut rest[..SEALED_CHUNK]);

        assert!(matches!(open(&key(), &swapped), Err(Error::Unsealable)));
    }

    #[test]
    fn a_reader_stops_where_the_caller_stops() {
        let plain = vec![42u8; 3 * CHUNK];
        let sealed = seal(&key(), &plain).unwrap();

        let mut opener = Opener::new(&key(), &sealed[..]);
        let mut head = [0u8; 10];
        opener.read_exact(&mut head).unwrap();

        assert_eq!(head, [42u8; 10]);
    }

    #[test]
    fn a_source_that_failed_says_so_on_every_read() {
        /// Hands out `bytes` and then refuses.
        struct Cut {
            bytes: Vec<u8>,
            offset: usize,
        }

        impl Read for Cut {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                if self.offset == self.bytes.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "the disk went away",
                    ));
                }
                let take = out.len().min(self.bytes.len() - self.offset);
                out[..take].copy_from_slice(&self.bytes[self.offset..self.offset + take]);
                self.offset += take;
                Ok(take)
            }
        }

        let sealed = seal(&key(), &vec![0u8; 2 * CHUNK]).unwrap();
        let mut opener = Opener::new(
            &key(),
            Cut {
                bytes: sealed[..BODY + 100].to_vec(),
                offset: 0,
            },
        );

        let mut out = vec![0u8; CHUNK];
        for _ in 0..3 {
            let err = opener.read(&mut out).expect_err("the source is gone");
            assert_eq!(
                err.kind(),
                io::ErrorKind::BrokenPipe,
                "what ended the reader is what it goes on saying"
            );
            assert!(
                err.downcast::<Error>().is_err(),
                "a disk that stopped answering is not a seal that did not authenticate"
            );
        }
    }

    #[test]
    fn a_key_is_thirty_two_bytes() {
        assert!(Key::from_slice(&[0u8; 32]).is_ok());
        assert!(matches!(
            Key::from_slice(&[0u8; 31]),
            Err(Error::KeyLength {
                expected: 32,
                actual: 31
            })
        ));
    }

    #[test]
    fn a_key_does_not_print_itself() {
        assert_eq!(format!("{:?}", key()), "Key(…)");
    }
}
