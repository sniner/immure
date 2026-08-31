# immure

Content-addressed file storage for Rust: a file's name is the hash of its own
content. To immure is to wall something in — an entry is written once, walled
in behind its own name, and never altered.

```rust
use immure::{Status, Store};

let store = Store::builder("/srv/store")
    .suffix(".json")
    .compress(true)
    .build()?;

let (status, entry) = store.add(content)?;
if status == Status::Exists {
    // Those exact bytes were already in the archive. Nothing was written.
}

let content = store.read(entry.digest())?;    // by name
let found = store.matching("fdbd8e")?;        // or by the beginning of one
assert!(store.verify(&entry)?);               // still what it says it is?
```

## Why

One rule — *the file's name is the hash of its content* — buys three things at
once, and none of them needs a database:

**Deduplication is free.** The same bytes produce the same name, so storing
something twice is a no-op that costs one hash and one `stat`. An incremental
backup that re-fetches an overlapping window does not grow the archive.

**Every file carries its own integrity check.** No checksum file to keep in
sync, no manifest to lose. Hashing the file and reading its name settles whether
it is intact, decades from now, with no knowledge of this library or the
application that wrote it:

```sh
$ sha256sum b94d27b9934d3e08a52e52d7da7dabfa….json
b94d27b9934d3e08a52e52d7da7dabfa…  b94d27b9….json   # intact
```

Which tool it is depends on the store's algorithm — see [Choosing a
hash](#choosing-a-hash).

A compressed entry wants `zstd -dc` in front of that, and a sealed one wants the
key — see [Encryption](#encryption), where that promise is spelled out again
with what it costs.

**Nothing is ever modified.** An entry is written once and then only read or
deleted. There is no in-place update to be interrupted halfway, which is what
makes the whole thing tolerable on an SMB or NFS share where a torn write is a
real possibility, and what makes concurrent writers a non-event.

What you give up is equally clear: you cannot name things yourself, and you
cannot change a stored object — changing it makes it a different object with a
different name. A CAS is for content that is finished when it arrives: archived
documents, images, blobs, build artefacts, backup chunks.

## On disk

The digest is cut into two-character directory components — as many as the
store's `depth` — and the entry sits at the bottom under its full digest:

```
/srv/store/
├── b9/
│   └── 4d/
│       └── b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9.json.zst
├── e3/
│   └── b0/
│       └── e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.json
└── tmp/                    half-written entries, briefly
```

Sharding is what keeps a quarter of a million files out of a single directory —
painful on every filesystem, unusable on some. Two levels give 65 536 buckets;
one level is plenty below a few thousand entries; `depth(0)` is flat.

Nothing but the tree itself is needed to read a store back. No index, no
manifest, no lock file. Every question — what is in here, is it intact, what is
this file — is answered by the names, so a store outlives this library.

That layout is the contract, not this library: entries named `<digest><suffix>`,
sharded two characters per level, `.zst` on top for compressed ones, `.corrupt`
for quarantined ones. Anything that follows those four rules reads and writes the
same store, whatever wrote it. What the tree does *not* say is which hash made
the names, how deep the sharding goes or what the suffix is — those are the
caller's to remember, the way the key is.

## Using it

Configure a store once and share the handle; it holds no open files, and the
little it learns as it goes is never written down:

```rust
use immure::{Algorithm, Store};

let store = Store::builder("/srv/store")
    .suffix(".json")               // what the entries are; ".dat" by default
    .depth(2)                      // shard levels; 2 by default
    .algorithm(Algorithm::Sha256)  // SHA-256/384/512 or BLAKE3; SHA-256 by default
    .compress(false)               // zstd for new entries
    .build()?;
```

### Choosing a hash

SHA-256 is the default, and wins on all three counts that matter here. Hashing
256 MiB single-threaded, on an Apple Silicon machine:

| | | | name length | tool |
|---|---|---|---|---|
| **SHA-256** | 77 ms | **3.25 GiB/s** | **64** | `sha256sum`, coreutils |
| BLAKE3 | 111 ms | 2.25 GiB/s | **64** | `b3sum`, an install |
| SHA-384 | 136 ms | 1.84 GiB/s | 96 | `sha384sum`, coreutils |
| SHA-512 | 136 ms | 1.84 GiB/s | 128 | `sha512sum`, coreutils |

Shortest names alongside BLAKE3, quickest of the four, and the one tool of the
four that is already on the machine. That last column is what the whole design
rests on: a name is worth something because anyone can hold content against it
without this library, on a machine nobody configured for the purpose.

**The speed column is the one to distrust.** SHA-256 is that quick because the
CPU has instructions for it — ARMv8 here, SHA-NI on x86-64 from AMD Zen and
Intel Ice Lake onwards. Without them SHA-256 is hashed in software and BLAKE3 is
several times quicker, which is what it is here for. Measure on the machine that
will do the work rather than believing this table; the answer is a property of
the machine, not of the algorithm.

SHA-384 and SHA-512 are for stores already named with them. Length-extension
resistance, the usual reason to prefer SHA-384 over SHA-256, buys nothing here:
it matters when a hash is used as a naive MAC over `secret ‖ message`, and a
content-addressed name is a hash of public bytes with nothing in front of them.

Which hash a store uses is a property of the store and not of the entry —
nothing in a name says which one made it. A store opened with the wrong one
refuses the digests and names it is held against wherever the lengths give it
away (`Error::AlgorithmMismatch`), rather than answering wrongly and quietly:
lookups would find nothing where the entry lies, and `verify` would fail every
healthy entry. SHA-256 and BLAKE3 write names of one length, and there content
hashed with the wrong one simply finds nothing. `depth` and `suffix` are
likewise picked once and kept with the store, the way the key is kept.

`build` touches nothing on disk. A handle is a description of where a store
lies, and describing one is not the same as making one: a store that is not
there is not created by asking about it, which matters most where it is least
visible — a root on a share that is not mounted would otherwise get an empty
store written onto the mount point, and the next run finds an archive that has
lost everything. Writing makes the directories it needs as it goes; `create`
(and `Store::create`) is for a caller that means to make the store now.

| | |
|---|---|
| `add(&[u8])` / `add_reader(impl Read)` | store content, or notice it is already there |
| `find` / `contains` / `destination` | where an entry is, or would be |
| `matching(prefix)` | look one up by the beginning of its name |
| `read` / `reader` | read it back by digest, whole or as a stream |
| `read_at` / `reader_at` | the same by path, for a walk that already has one |
| `digest` / `hasher` | name content without storing it |
| `digest_of` / `verify` | what a file *is* versus what it claims to be |
| `quarantine` / `quarantined_at` | take a damaged entry's name away, and recognise one that lost it |
| `entries` / `entry_at` | walk the store, or ask what one file in it is |
| `remove` / `prune_empty_dirs` / `prune_temp_files` | the only three ways anything goes away |
| `compress_all` / `decompress_all` | convert the whole store, either direction |

`add` hashes first and writes only when the content is new. `add_reader` cannot
know the digest before it has read everything, so it streams into a temporary
file and hashes on the way past — right for content that does not fit
comfortably in memory, or that arrives from a socket.

`read` and `reader` take a digest and open the entry rather than asking
about it first: a digest names two candidate files — with and without the `.zst`
— and nothing in the tree says which is there, so the miss is the answer. Which
one to try first is remembered from the last that answered, so a store that is
all one way costs a single `open` per entry, and one that is half converted
corrects itself as it goes. Over a network share that is the difference between
reading a store once and reading it twice.

`matching` takes the beginning of a digest and gives back every entry whose own
begins with it, the way a short commit hash works — nobody types 64 characters.
The beginning of a digest *is* the shard the entry lies in, so it costs one
directory listing. For the same reason it needs `2 * (depth + 1)` characters —
six at the default depth — since a prefix that stops at the shard boundary names
the directory and narrows nothing inside it; `min_prefix` is that number, worth
asking rather than hard-coding into a prompt that then assumes somebody else's
depth.

Nothing here knows what is inside an entry, and reading is streamed for exactly
that reason: a caller after the head of one — a header block, the magic bytes of
an image — reads until it has it and drops the reader, and a compressed entry is
decompressed only that far. Where a head is a small fraction of the bytes, that
is the difference between indexing an archive and reading all of it. Where the
head ends is the caller's question; a store that answered it would have to know
what its entries are.

## Compression

Entries can be stored zstd-compressed, which shows up as `.zst` on top of the
regular suffix. Compression is a property of the **file**, not of the store:
reading follows whatever is on disk, so a store can be switched over at any
time, both forms coexist, and `compress_all` converts the backlog when it
suits. The digest is always of the *uncompressed* content — the same bytes get
the same name either way, so switching does not orphan anything.

## Encryption

With the `crypt` feature and a key, entries are sealed with XChaCha20-Poly1305
on their way to disk, which shows up as an `.enc` after the `.zst`:

```rust
use immure::{Key, Store};

let store = Store::builder("/srv/store")
    .suffix(".json")
    .key(Key::new(bytes))      // 32 of them, from wherever you keep them
    .build()?;
```

Sealing implies compression, so an entry lies in one of three forms and never a
fourth: `<digest><suffix>`, `.zst`, `.zst.enc`. That rule is what gives one
digest exactly one set of bytes going into the cipher.

**Under the hood.** The cipher is XChaCha20-Poly1305 — the RustCrypto
implementation, no cryptography of this crate's own — over the zstd frame:
compressed first, sealed second, because ciphertext does not compress. The
frame is cut into 64 KiB chunks and each is sealed on its own, so a reader
hands back nothing it has not authenticated and can still stop after the head
of an entry without holding the file whole. Each chunk's 24-byte nonce is a
19-byte prefix drawn fresh from the operating system's randomness for that one
sealing — XChaCha20's extended nonce is what makes drawing at random safe
without bookkeeping — plus the chunk's number and a flag on the last chunk, so
chunks cannot be reordered, dropped or spliced in from another entry, and a
file cut at a chunk boundary fails instead of reading short. The prefix
travels in the clear ahead of the first chunk, which is all an entry stores
besides the ciphertext; what sealing costs on disk is those 19 bytes once and
a 16-byte Poly1305 tag per 64 KiB.

**What does not change is everything else.** The name is still the hash of the
*content*, so duplicates are still decided before a byte is sealed, and
everything a store answers by looking at names — `find`, `contains`, `matching`,
`entries`, `remove`, `quarantine` — works without the key. Nothing is written
into the tree either: an entry carries the nonce it was sealed under in its own
first bytes, so there is no key file, no manifest and no configuration to keep
in step. A store is still nothing but the files it holds.

**The key is 32 bytes and the crate does nothing else with it.** Where they come
from — a key file, a passphrase through a password KDF, a token — is the
caller's business, along with the salt or seed that goes with it, and that is
deliberate: it is what keeps the store free of anything that would have to be
stored to open it again. Note that "hash the passphrase" is not a KDF; Argon2id
or scrypt is, and a plain SHA-256 of a human's passphrase is a few seconds of
GPU time.

**What it costs.** `verify` needs the key, because checking an entry against its
name means reading its content. Hashing the file and reading its name no longer
settles anything on its own for a sealed entry, and neither does any other tool
that does not hold the key. And a name is still a public function of its
content, so anyone who can list the tree can test a guess for presence — the
content stays sealed, the presence of a guessed content does not.

**Two failures worth telling apart.** `Error::Unsealable` means the first chunk
did not authenticate: the wrong key, or content damaged from its first bytes,
and nothing can say which. `Error::Damaged` means a later one did not — the key
already opened what came before it, so the key is right and the bytes are not.
Only the second is a reason to quarantine anything, which is why `verify` turns
it into a plain `false` and lets the other through as an error — until the key
has opened something in that store, after which a first chunk failing is damage
too. Most entries are a single chunk, so without that there would be nothing to
prove the key with and no short entry could ever be called damaged. A pass that
acts on `false` therefore starts with `prove_key`, which reads until one entry
opens and so takes the walk order out of the answer; `key_proven` says where a
handle stands. A sealed entry met by a store without a key is
`Error::KeyRequired`.

The answer is of course only as good as the key: hand a store the wrong one and
every entry in it fails, which is the right answer to the question that was
asked. Worth knowing is that an interrupted `change_key` leaves a store holding
entries under two keys, and for the ones it has not reached yet this store's key
*is* the wrong one — finish the key change before running a pass that sets
entries aside.

**Changing a key** is `change_key`, one pass over the store and one entry at a
time: opened with the old key and sealed again with the new one as it streams
past. The zstd frame goes straight from one cipher into the other, so no entry
is ever unpacked and none is ever written in the clear. The old nonce comes off
the front and a fresh one is drawn for the new seal, the way every write draws
one. Each entry is replaced by a rename, so an interrupted run leaves every one
of them under one key or the other, and running it again from the old key's
handle finishes the job. What an
earlier pass set aside is moved too — a quarantined entry is still sealed and
still readable, and one left behind would be stranded under a key that is about
to be destroyed. The run is finished with the store when nothing landed in
`Conversion::failed`.

`encrypt_all` seals a store that was not sealed before, and `decrypt_all` turns
a sealed store back into a plain one. `compress_all` and `decompress_all` leave
sealed entries alone; unsealing is not something a compression pass should do
quietly. None of the four touches what was set aside: a conversion gives an
entry the name its digest makes, and that name is exactly what `quarantine` took
away from it.

Every one of these passes reports a `Conversion`, and its three counts are meant
to be told apart: `converted` was rewritten now, `already` was in scope and
found the way the pass wants it, `skipped` was never this pass's business. Only
the first two together say a pass is finished with an entry — which is the
question to ask before an old key is destroyed.

## Crashes and concurrent writers

Entries are written into `tmp/` and renamed into their shard only once
complete. A rename within one filesystem is atomic on everything in practical
use, so a reader sees an entry whole or not at all, and an interrupted run
leaves a stray temporary file rather than a truncated entry.

Durability is not a setting. Every entry is flushed to the device **before** the
rename that names it, and the shard directory **after** it. The order is the
whole point: a rename can otherwise overtake the content it publishes, and what
appears is a file under a name claiming to be the hash of bytes that never
arrived. Nothing would ever find out — the store answers "is this here?" by
looking at names, not by reading them — so an entry that is present but wrong
outlives every later chance to notice, which is not a trade a caller should be
able to make. A flush per entry is a device round trip; a store that can lie
about what is in it is not worth the one it saves.

Several threads and several processes can write into one store without
coordination: temporary names are unique per writer, and two writers storing
the same bytes race to rename identical content into the same place. There is
no lock file.

What a crash leaves behind is one file in `tmp/`, and because its name belongs
to the writer that opened it, no later run reuses or overwrites it. Nothing else
looks there either, so they collect unseen until `prune_temp_files` sweeps them
— only those old enough that no live writer can still hold one, and only the
ones this store wrote. It reports how many went: each is a write that was
interrupted, which is worth knowing rather than tidying away.

## Damaged entries

`verify` holds an entry against the name it is filed under, and that is what
naming a file after its content is for: bit rot, a truncated write and a botched
restore all show up as a name the bytes no longer have. Nothing else in a store
can notice — every other question is answered by looking at names, never by
reading them.

What to do with one that fails is `quarantine`. The file keeps every byte and
loses the name:

```
fd/bd/fdbd8e75….json            →  fd/bd/fdbd8e75….json.corrupt
```

Deleting it would be the worse of the two ways to be wrong — content with a
flipped bit is still almost all of the content. What has to stop is the *claim*:
while the file is named after a hash it does not have, the store goes on
answering that this content is present, and nothing ever fetches it again.
Afterwards `find`, `entries` and the existence check behind `add` no longer see
it, so storing those bytes again is a new entry.

A pass over a store has three answers to tell apart, and only one of them is a
reason to take a name away:

```rust
for entry in store.entries() {
    let entry = entry?;
    match store.verify(&entry) {
        // The bytes are not what the name says.
        Ok(false) => { store.quarantine(&entry)?; }
        Ok(true) => {}
        // Nothing was established about this entry: it could not be read, or
        // its seal is ambiguous while the key is unproven. Setting it aside on
        // that would take a healthy entry's name away for a reason that is not
        // the entry's.
        Err(err) => eprintln!("{}: {err}", entry.path().display()),
    }
}
```

It stays in its shard rather than moving to a directory of its own — where a
file lies is itself information, and a store with a second place to look in is a
store to explain. `quarantined_at` is how a walk tells what an earlier pass set
aside from a stray file, instead of reporting it afresh every run. A second
quarantine of the same name is numbered; nothing is overwritten.

Setting a file aside is half the story; the store can also be asked what lies
aside and what should become of it. `quarantined` walks everything earlier
passes set aside, `read_at` hands the bytes back the way it would an entry's,
and the two ways out are `restore` and `discard`. `restore` gives a false alarm its
name back — the check is the one `verify` makes, so nothing comes back that
would not pass it, and a file that is genuinely damaged stays aside however
often it is asked. `discard` deletes a copy for good once its content was
fetched again, or given up on; the write protection the file kept from its days
as an entry is no obstacle, on Windows included.

## Write protection

An entry altered in place breaks the name it is filed under, so the write bits
come off just before it takes that name — nothing that opens one finds an
invitation to change it. Comfort rather than security: it stops the editor that
"repairs" the file it is displaying, not anybody who means it, and it says
nothing about deletion. `remove`, `compress_all` and `prune_temp_files` all get
past it, because a store has to be able to remove what it protected itself.

A filesystem that does not carry the mode is noticed at the first entry and not
asked again — a desktop-mounted SMB share reports a successful `chmod` and
changes nothing. Either way the store goes on writing: a refused `chmod` never
costs an entry.

## Features

| feature | default | what it does |
|---|---|---|
| `zstd` | yes | transparent zstd compression. Off drops the C library — a store then *refuses* to compress rather than quietly storing plain bytes under a `.zst` name |
| `serde` | no | `Serialize`/`Deserialize` for `Digest`, `Algorithm` and `Status`. A digest deserialises through the validating parser, so one read out of JSON is as trustworthy as one parsed by hand |
| `crypt` | no | Sealing entries with XChaCha20-Poly1305, and `crypt::seal`/`crypt::open` for blobs that never reach a store. Implies `zstd`, because a sealed entry is always compressed underneath |

## License

Apache-2.0. See [LICENSE](LICENSE).
