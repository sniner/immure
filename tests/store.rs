//! What a store promises through its public API.

use std::collections::HashMap;
use std::fs;
use std::io::Read as _;
use std::path::PathBuf;
use std::time::Duration;

use immure::{Algorithm, DEFAULT_TEMP_MIN_AGE, Digest, Error, Status, Store};
use tempfile::TempDir;

fn store_in(dir: &TempDir) -> Store {
    Store::builder(dir.path().join("cas"))
        .suffix(".json")
        .build()
        .unwrap()
}

// -- storing -----------------------------------------------------------------

#[test]
fn a_suffix_that_looks_like_a_form_is_still_only_a_suffix() {
    let dir = TempDir::new().unwrap();
    let store = Store::builder(dir.path().join("cas"))
        .suffix(".enc")
        .build()
        .unwrap();

    let (_, entry) = store.add(b"neither sealed nor compressed").unwrap();

    assert!(
        !entry.is_encrypted(),
        "the suffix is the caller's, not a form"
    );
    assert!(!entry.is_compressed());
    assert_eq!(
        store.read_at(entry.path()).unwrap(),
        b"neither sealed nor compressed"
    );
    assert!(store.verify(&entry).unwrap());
    #[cfg(feature = "zstd")]
    assert_eq!(
        store.compress_all().unwrap().converted,
        1,
        "and a maintenance pass sees it for what it is"
    );
}

#[test]
#[cfg(feature = "zstd")]
fn a_compressed_entry_that_was_cut_short_is_an_answer_and_not_an_error() {
    let dir = TempDir::new().unwrap();
    let store = Store::builder(dir.path().join("cas"))
        .suffix(".json")
        .compress(true)
        .build()
        .unwrap();
    let content: Vec<u8> = (0..40_000u32)
        .map(|n| u8::try_from(n % 251).unwrap())
        .collect();
    let (_, entry) = store.add(&content).unwrap();

    let bytes = fs::read(entry.path()).unwrap();
    tamper(entry.path(), &bytes[..bytes.len() / 2]);

    assert!(
        !store.verify(&entry).unwrap(),
        "a frame the decoder cannot finish is a damaged entry, not an unreachable disk"
    );
}

#[test]
#[cfg(feature = "zstd")]
fn a_damaged_frame_header_is_an_answer_too() {
    let dir = TempDir::new().unwrap();
    let store = Store::builder(dir.path().join("cas"))
        .suffix(".json")
        .compress(true)
        .build()
        .unwrap();
    let content: Vec<u8> = (0..40_000u32)
        .map(|n| u8::try_from(n % 251).unwrap())
        .collect();
    let (_, entry) = store.add(&content).unwrap();
    let clean = fs::read(entry.path()).unwrap();

    // The nine bytes of the zstd frame header, where the decoder rejects the
    // frame outright rather than working through it. It reports that through
    // `io::Error::other`, so it arrives as `ErrorKind::Other` — which is what
    // makes this worth a test of its own: only a truncated frame comes back as
    // `UnexpectedEof`, and a gate built on that kind alone let every one of
    // these through as an error where the answer is a plain `false`.
    for at in 0..9usize {
        let mut bytes = clean.clone();
        bytes[at] ^= 0xff;
        tamper(entry.path(), &bytes);

        assert!(
            !store.verify(&entry).unwrap(),
            "byte {at} of the frame header is damage, not a failure to look"
        );
    }

    // And past the header, where the frame decodes to bytes that simply are
    // not the ones the name is a hash of.
    let mut bytes = clean.clone();
    let late = bytes.len() - 20;
    bytes[late] ^= 0xff;
    tamper(entry.path(), &bytes);
    assert!(!store.verify(&entry).unwrap());
}

#[test]
fn opening_a_store_does_not_create_one() {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("deep/down/cas");

    let store = Store::open(&root).unwrap();

    assert!(
        !root.exists(),
        "a store that is not there is not created by asking about it"
    );
    assert_eq!(store.root(), root);
    assert_eq!(store.suffix(), ".dat");
    assert_eq!(store.algorithm(), Algorithm::Sha256);
    assert!(
        store.entries().next().unwrap().is_err(),
        "and a walk says so, rather than reporting an empty store"
    );
}

#[test]
fn creating_a_store_makes_its_directory() {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("deep/down/cas");

    let store = Store::create(&root).unwrap();

    assert!(root.is_dir());
    assert_eq!(store.entries().count(), 0);

    Store::create(&root).unwrap();
    assert!(root.is_dir(), "a store that is there is left as it is");
}

#[test]
fn the_first_write_makes_what_it_needs() {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("deep/down/cas");
    let store = Store::builder(&root).suffix(".json").build().unwrap();

    let (status, entry) = store.add(b"hello world").unwrap();

    assert_eq!(status, Status::New);
    assert!(entry.path().is_file());
    assert_eq!(store.entries().count(), 1);
}

#[test]
fn an_entry_is_named_after_its_content() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);

    let (status, entry) = store.add(b"hello world").unwrap();

    assert_eq!(status, Status::New);
    assert!(status.is_new());
    assert_eq!(entry.digest(), &Algorithm::Sha256.hash(b"hello world"));
    assert_eq!(
        entry.path().file_name().unwrap().to_str().unwrap(),
        format!("{}.json", entry.digest())
    );
    assert_eq!(fs::read(entry.path()).unwrap(), b"hello world");
    assert!(store.verify(&entry).unwrap());
}

#[test]
fn adding_the_same_content_twice_stores_it_once() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);

    let (first, one) = store.add(b"hello world").unwrap();
    let (second, two) = store.add(b"hello world").unwrap();

    assert_eq!(first, Status::New);
    assert_eq!(second, Status::Exists);
    assert!(!second.is_new());
    assert_eq!(one, two);
    assert_eq!(store.entries().count(), 1);
}

#[test]
fn a_reader_is_stored_without_being_buffered_whole() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    let content = "line\n".repeat(10_000);

    let (status, entry) = store.add_reader(content.as_bytes()).unwrap();

    assert_eq!(status, Status::New);
    assert_eq!(entry.digest(), &store.digest(content.as_bytes()));
    assert_eq!(store.read_at(entry.path()).unwrap(), content.as_bytes());

    // The same content through the other door is recognised, and the temporary
    // file it was streamed into is gone again.
    let (status, same) = store.add_reader(content.as_bytes()).unwrap();
    assert_eq!(status, Status::Exists);
    assert_eq!(same.path(), entry.path());
    assert_eq!(store.entries().count(), 1);
    assert_eq!(temp_files(store.root()), Vec::<PathBuf>::new());
}

#[test]
fn an_entry_can_be_found_read_and_removed_by_digest() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    let (_, entry) = store.add(b"find me").unwrap();

    assert!(store.contains(entry.digest()).unwrap());
    assert_eq!(
        store.find(entry.digest()).unwrap(),
        Some(entry.path().to_path_buf())
    );
    assert_eq!(store.read(entry.digest()).unwrap().unwrap(), b"find me");
    assert_eq!(store.destination(entry.digest()).unwrap(), entry.path());

    assert!(store.remove(entry.digest()).unwrap());

    assert!(!store.contains(entry.digest()).unwrap());
    assert_eq!(store.read(entry.digest()).unwrap(), None);
    assert!(!store.remove(entry.digest()).unwrap(), "already gone");
    // The path where it would go is still known — that is not a lookup.
    assert_eq!(store.destination(entry.digest()).unwrap(), entry.path());
}

#[test]
fn nothing_is_written_when_the_content_is_unreadable() {
    struct Failing;
    impl std::io::Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("no"))
        }
    }

    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);

    assert!(store.add_reader(Failing).is_err());

    assert_eq!(store.entries().count(), 0);
    assert_eq!(temp_files(store.root()), Vec::<PathBuf>::new());
}

#[test]
fn a_store_with_one_shard_level_reads_its_entries_back() {
    let dir = TempDir::new().unwrap();
    let store = Store::builder(dir.path().join("cas"))
        .suffix(".jsonl")
        .depth(1)
        .build()
        .unwrap();

    let (_, entry) = store.add(b"{\"a\":1}\n").unwrap();

    assert_eq!(store.read_at(entry.path()).unwrap(), b"{\"a\":1}\n");
    assert!(store.verify(&entry).unwrap());
}

// -- layout ------------------------------------------------------------------

#[test]
fn depth_decides_how_deeply_entries_are_sharded() {
    for depth in [0, 1, 2, 3] {
        let dir = TempDir::new().unwrap();
        let store = Store::builder(dir.path().join("cas"))
            .depth(depth)
            .build()
            .unwrap();

        let (_, entry) = store.add(b"depth test").unwrap();

        let relative = entry.path().strip_prefix(store.root()).unwrap();
        assert_eq!(relative.components().count(), depth + 1);
        assert_eq!(store.depth(), depth);
    }
}

#[test]
fn a_suffix_without_a_dot_gets_one() {
    let dir = TempDir::new().unwrap();
    let store = Store::builder(dir.path().join("cas"))
        .suffix("json")
        .build()
        .unwrap();

    assert_eq!(store.suffix(), ".json");
    let (_, entry) = store.add(b"content").unwrap();
    assert_eq!(entry.path().extension().unwrap(), "json");
}

#[test]
fn a_store_cannot_shard_deeper_than_its_digests_reach() {
    let dir = TempDir::new().unwrap();

    let err = Store::builder(dir.path())
        .algorithm(Algorithm::Sha256)
        .depth(33)
        .build()
        .unwrap_err();

    assert!(matches!(err, Error::InvalidDepth { max: 32, .. }), "{err}");
}

#[test]
fn a_digest_from_another_algorithm_is_refused_rather_than_misfiled() {
    let dir = TempDir::new().unwrap();
    let store = Store::builder(dir.path().join("cas"))
        .algorithm(Algorithm::Sha384)
        .depth(4)
        .build()
        .unwrap();

    // A whole SHA-256 digest, and a fragment: neither is a name here.
    let foreign = Algorithm::Sha256.hash(b"named elsewhere");
    let fragment: Digest = "aabbcc".parse().unwrap();

    for digest in [&foreign, &fragment] {
        assert!(matches!(
            store.find(digest).unwrap_err(),
            Error::AlgorithmMismatch { .. }
        ));
    }
}

#[test]
fn the_wrong_algorithm_is_told_before_it_answers_wrongly() {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("cas");
    let old = Store::builder(&root)
        .algorithm(Algorithm::Sha384)
        .build()
        .unwrap();
    let (_, entry) = old.add(b"named before the default changed").unwrap();

    // The same store, opened with the default algorithm instead of its own.
    let wrong = Store::open(&root).unwrap();

    // Refused rather than answered wrongly: a lookup would find nothing where
    // the entry lies, and a `false` from verify would send a healthy entry to
    // quarantine.
    assert!(matches!(
        wrong.find(entry.digest()).unwrap_err(),
        Error::AlgorithmMismatch { .. }
    ));
    assert!(matches!(
        wrong.verify(&entry).unwrap_err(),
        Error::AlgorithmMismatch { .. }
    ));

    // Opened with its own algorithm, the store answers as it always did.
    let right = Store::builder(&root)
        .algorithm(Algorithm::Sha384)
        .build()
        .unwrap();
    assert_eq!(
        right.find(entry.digest()).unwrap(),
        Some(entry.path().to_path_buf())
    );
    assert!(right.verify(&entry).unwrap());
}

#[test]
fn any_algorithm_can_name_the_entries() {
    let dir = TempDir::new().unwrap();
    let store = Store::builder(dir.path().join("cas"))
        .algorithm(Algorithm::Blake3)
        .build()
        .unwrap();

    let (_, entry) = store.add(b"hello world").unwrap();

    assert_eq!(entry.digest().len(), 64);
    assert_eq!(entry.digest(), &Algorithm::Blake3.hash(b"hello world"));
    assert!(store.verify(&entry).unwrap());
}

// -- write protection --------------------------------------------------------

/// Whether anybody at all may write to this file.
fn writable(path: &std::path::Path) -> bool {
    !fs::metadata(path).unwrap().permissions().readonly()
}

/// Change what a stored entry holds, behind the store's back.
///
/// Entries are written without their write bits, so a test playing bit rot, a
/// botched restore or a viewer that "repairs" the file it is showing has to
/// take the protection off first — which is the whole effort it was ever meant
/// to cost. It goes back on afterwards, so what the store then has in front of
/// it is what it would really find: a protected entry whose bytes are wrong.
fn tamper(path: &std::path::Path, content: &[u8]) {
    let original = fs::metadata(path).unwrap().permissions();
    let mut lifted = original.clone();
    // World-writable for the length of one write, in a directory that goes
    // away with the test. The mode below is what the store is left with.
    #[allow(clippy::permissions_set_readonly_false)]
    lifted.set_readonly(false);
    fs::set_permissions(path, lifted).unwrap();
    fs::write(path, content).unwrap();
    fs::set_permissions(path, original).unwrap();
}

#[test]
fn a_stored_entry_is_as_read_only_as_its_name_claims() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);

    let (_, entry) = store.add(b"hello world").unwrap();

    assert!(!writable(entry.path()));
    assert_eq!(fs::read(entry.path()).unwrap(), b"hello world");
}

#[test]
fn a_protected_entry_can_still_be_removed() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    let (_, entry) = store.add(b"hello world").unwrap();

    assert!(store.remove(entry.digest()).unwrap());

    assert!(!entry.path().exists());
}

#[test]
#[cfg(feature = "zstd")]
fn a_protected_store_can_still_be_converted() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    store.add(b"one").unwrap();
    store.add(b"two").unwrap();

    let result = store.compress_all().unwrap();

    assert_eq!(result.converted, 2);
    assert!(result.failed.is_empty(), "{:?}", result.failed);
    for entry in store.entries() {
        let entry = entry.unwrap();
        assert!(entry.is_compressed());
        assert!(!writable(entry.path()), "and protected again afterwards");
    }
}

#[test]
fn a_protected_leftover_is_still_swept_up() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    store.add(b"one").unwrap();
    // A writer that died between the write protection and the rename leaves a
    // temporary file the store itself made unwritable.
    let leftover = store.root().join("tmp/424242-9.tmp");
    fs::write(&leftover, b"half an entry").unwrap();
    let mut permissions = fs::metadata(&leftover).unwrap().permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&leftover, permissions).unwrap();

    assert_eq!(store.prune_temp_files(Duration::ZERO).unwrap(), 1);

    assert!(!leftover.exists());
}

// -- reading by digest -------------------------------------------------------

#[test]
fn an_entry_can_be_read_by_its_digest_alone() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    let (_, entry) = store.add(b"hello world").unwrap();

    let mut reader = store.reader(entry.digest()).unwrap().unwrap();
    let mut content = Vec::new();
    reader.read_to_end(&mut content).unwrap();

    assert_eq!(content, b"hello world");
    assert_eq!(store.read(entry.digest()).unwrap().unwrap(), b"hello world");
}

#[test]
#[cfg(feature = "zstd")]
fn reading_by_digest_follows_whichever_form_is_there() {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("cas");
    let plain = Store::builder(&root).suffix(".json").build().unwrap();
    let zstd = Store::builder(&root)
        .suffix(".json")
        .compress(true)
        .build()
        .unwrap();
    let (_, written_plain) = plain.add(b"stored plain").unwrap();
    let (_, written_zstd) = zstd.add(b"stored compressed").unwrap();

    // Each store reads the entry the other wrote, and going back and forth is
    // what makes the guess about which name to try first wrong every time.
    for _ in 0..3 {
        assert_eq!(
            plain.read(written_zstd.digest()).unwrap().unwrap(),
            b"stored compressed"
        );
        assert_eq!(
            plain.read(written_plain.digest()).unwrap().unwrap(),
            b"stored plain"
        );
        assert_eq!(
            zstd.read(written_plain.digest()).unwrap().unwrap(),
            b"stored plain"
        );
    }
}

#[test]
fn a_directory_under_an_entry_name_is_not_an_entry() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    let digest = store.digest(b"hello world");
    fs::create_dir_all(store.destination(&digest).unwrap()).unwrap();

    assert_eq!(store.find(&digest).unwrap(), None);
    assert!(!store.contains(&digest).unwrap());
}

#[test]
#[cfg(unix)]
fn a_store_that_cannot_be_read_is_not_a_store_that_is_empty() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    let digest = store.digest(b"hello world");
    // A file where the first shard directory belongs. Looking below it does not
    // fail with "no such file": it fails with "not a directory", and answering
    // that with "not there" is how a backup decides to fetch everything again.
    fs::create_dir_all(store.root()).unwrap();
    fs::write(store.root().join(&digest.as_str()[..2]), b"in the way").unwrap();

    assert!(matches!(store.find(&digest), Err(Error::Io { .. })));
    assert!(store.contains(&digest).is_err());
}

#[test]
fn a_digest_the_store_does_not_hold_reads_as_nothing() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);

    let absent = store.digest(b"never stored");

    assert!(store.reader(&absent).unwrap().is_none());
    assert!(store.read(&absent).unwrap().is_none());
}

// -- looking one up by the beginning of its name -----------------------------

/// Two different contents whose digests begin with the same `n` characters.
///
/// Searched for rather than written down, because the answer depends on the
/// store's algorithm — but the search runs over a fixed series, so the pair it
/// finds is the same one every time.
fn colliding(store: &Store, n: usize) -> (Vec<u8>, Vec<u8>) {
    let mut seen: HashMap<String, Vec<u8>> = HashMap::new();
    for i in 0..1_000_000u32 {
        let content = format!("entry {i}").into_bytes();
        let head = store.digest(&content).as_str()[..n].to_string();
        if let Some(first) = seen.insert(head, content.clone()) {
            return (first, content);
        }
    }
    panic!("no two of a million digests share their first {n} characters");
}

#[test]
fn the_beginning_of_a_digest_names_the_entry_it_belongs_to() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    let (_, entry) = store.add(b"hello world").unwrap();
    store.add(b"something else").unwrap();

    let id = &entry.digest().as_str()[..12];

    assert_eq!(store.matching(id).unwrap(), vec![entry.digest().clone()]);
    // Upper case is the same name, and so is the whole thing.
    assert_eq!(
        store.matching(&id.to_uppercase()).unwrap(),
        vec![entry.digest().clone()]
    );
    assert_eq!(
        store.matching(entry.digest().as_str()).unwrap(),
        vec![entry.digest().clone()]
    );
}

#[test]
fn a_beginning_that_fits_more_than_one_entry_names_them_all() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    let (one, two) = colliding(&store, store.min_prefix());
    let (_, first) = store.add(&one).unwrap();
    let (_, second) = store.add(&two).unwrap();
    store.add(b"in another shard entirely").unwrap();

    let shared = first.digest().as_str()[..store.min_prefix()].to_string();
    let mut expected = vec![first.digest().clone(), second.digest().clone()];
    expected.sort();

    assert_eq!(store.matching(&shared).unwrap(), expected);
}

#[test]
fn an_entry_lying_in_both_forms_is_named_once() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    let (_, entry) = store.add(b"hello world").unwrap();
    // What an interrupted conversion leaves: one entry under both its names.
    fs::copy(entry.path(), entry.path().with_extension("json.zst")).unwrap();

    let found = store.matching(&entry.digest().as_str()[..12]).unwrap();

    assert_eq!(found, vec![entry.digest().clone()]);
}

#[test]
fn a_beginning_nothing_is_stored_under_names_nothing() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    store.add(b"hello world").unwrap();

    assert_eq!(store.matching("abcdef").unwrap(), Vec::<Digest>::new());
}

#[test]
fn a_beginning_too_short_to_look_up_says_how_much_is_needed() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);

    // Two shard levels name the directory and narrow nothing inside it, so
    // four characters is a whole directory rather than an entry.
    assert_eq!(store.min_prefix(), 6);
    let error = store.matching("abcde").unwrap_err();

    assert!(matches!(error, Error::PrefixTooShort { needed: 6, .. }));
    assert_eq!(
        error.to_string(),
        "prefix \"abcde\" is too short for a store of depth 2: needs 6 characters"
    );
}

#[test]
fn how_much_of_a_name_is_needed_follows_the_depth() {
    let dir = TempDir::new().unwrap();
    let shallow = Store::builder(dir.path().join("one"))
        .depth(1)
        .build()
        .unwrap();
    let flat = Store::builder(dir.path().join("flat"))
        .depth(0)
        .build()
        .unwrap();

    assert_eq!(shallow.min_prefix(), 4);
    assert_eq!(flat.min_prefix(), 2);

    let (_, entry) = flat.add(b"hello world").unwrap();
    let head = entry.digest().as_str()[..2].to_string();
    assert_eq!(flat.matching(&head).unwrap(), vec![entry.digest().clone()]);
    assert!(matches!(
        flat.matching(&head[..1]).unwrap_err(),
        Error::PrefixTooShort { needed: 2, .. }
    ));
}

#[test]
fn a_beginning_that_is_not_a_digest_at_all_is_refused() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);

    assert!(matches!(
        store.matching("not-hex").unwrap_err(),
        Error::InvalidPrefix(_)
    ));
    assert!(matches!(
        store.matching("").unwrap_err(),
        Error::InvalidPrefix(_)
    ));
}

// -- what a file is ----------------------------------------------------------

#[test]
fn a_path_says_which_entry_it_is() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    let (_, entry) = store.add(b"hello world").unwrap();

    let found = store.entry_at(entry.path()).unwrap();

    assert_eq!(found, entry);
    assert!(!found.is_compressed());
}

#[test]
#[cfg(feature = "zstd")]
fn a_compressed_entry_says_so_as_well() {
    let dir = TempDir::new().unwrap();
    let store = Store::builder(dir.path().join("cas"))
        .suffix(".json")
        .compress(true)
        .build()
        .unwrap();
    let (_, entry) = store.add(b"hello world").unwrap();

    let found = store.entry_at(entry.path()).unwrap();

    assert_eq!(found.digest(), entry.digest());
    assert!(found.is_compressed());
}

#[test]
fn what_this_store_did_not_name_is_not_an_entry() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    let (_, entry) = store.add(b"hello world").unwrap();

    for stray in [
        entry.path().with_file_name(".DS_Store"),
        entry.path().with_file_name("notes.json"),
        entry.path().with_extension("txt"),
        store.root().join("tmp/424242-1.tmp"),
        store.root().to_path_buf(),
    ] {
        assert_eq!(store.entry_at(&stray), None, "{}", stray.display());
    }
}

#[test]
fn a_name_is_an_entry_wherever_it_was_copied_from() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    let digest = store.digest(b"hello world");

    // A path out of a report written on another machine: the directories in
    // front of it are somebody else's, and nothing has been stored here at all.
    let elsewhere = PathBuf::from(format!("/srv/somewhere/else/{digest}.json"));

    assert_eq!(store.entry_at(&elsewhere).unwrap().digest(), &digest);
    assert!(
        !store.contains(&digest).unwrap(),
        "naming it is not holding it"
    );
}

// -- walking -----------------------------------------------------------------

#[test]
fn walking_finds_the_entries_and_ignores_everything_else() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    let (_, first) = store.add(b"one").unwrap();
    let (_, second) = store.add(b"two").unwrap();

    // Things that are in the tree but are not entries.
    fs::write(store.root().join(".DS_Store"), b"junk").unwrap();
    fs::write(first.path().with_file_name("notes.json"), b"by hand").unwrap();
    fs::write(first.path().with_extension("txt"), b"wrong suffix").unwrap();
    let temp_dir = store.root().join("tmp");
    fs::create_dir_all(&temp_dir).unwrap();
    fs::write(temp_dir.join(format!("{}.json", second.digest())), b"half").unwrap();

    let mut found = store
        .entries()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .into_iter()
        .map(|entry| entry.digest().clone())
        .collect::<Vec<_>>();
    found.sort();
    let mut expected = vec![first.digest().clone(), second.digest().clone()];
    expected.sort();

    assert_eq!(found, expected);
}

#[test]
fn pruning_removes_the_shards_that_went_empty() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    let (_, kept) = store.add(b"keep me").unwrap();
    let (_, gone) = store.add(b"remove me").unwrap();
    store.remove(gone.digest()).unwrap();

    let removed = store.prune_empty_dirs().unwrap();

    assert_eq!(removed, store.depth(), "every level of that entry's shard");
    assert!(!gone.path().parent().unwrap().exists());
    assert!(kept.path().is_file(), "a shard still in use is untouched");
    assert!(store.root().is_dir(), "the root always stays");
}

#[test]
fn pruning_an_emptied_store_leaves_the_root_and_the_temp_dir() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    let (_, entry) = store.add(b"lonely").unwrap();
    store.remove(entry.digest()).unwrap();

    store.prune_empty_dirs().unwrap();

    assert!(store.root().is_dir());
    assert_eq!(store.entries().count(), 0);
    assert!(
        store.root().join("tmp").is_dir(),
        "the temp directory is the store's own, not a stray shard"
    );
}

#[test]
fn a_write_that_never_finished_is_swept_up_once_it_is_old_enough() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    let (_, entry) = store.add(b"one").unwrap();
    // What a writer that died mid-entry leaves behind. Nothing reuses the name,
    // so nothing removes it either.
    let leftover = store.root().join("tmp/424242-7.tmp");
    fs::write(&leftover, b"half an entry").unwrap();

    let swept = store.prune_temp_files(DEFAULT_TEMP_MIN_AGE).unwrap();
    assert_eq!(swept, 0, "a live writer could still hold one this young");
    assert!(leftover.is_file());

    let swept = store.prune_temp_files(Duration::ZERO).unwrap();
    assert_eq!(swept, 1, "the count is the point: a write was interrupted");
    assert!(!leftover.exists());
    assert!(entry.path().is_file(), "an entry is not a leftover");
}

#[test]
fn a_sweep_leaves_what_this_store_did_not_write() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    store.add(b"one").unwrap();
    let temp_dir = store.root().join("tmp");
    // Somebody else replacing their own file through the same tree.
    let stranger = temp_dir.join("state.json.tmp");
    fs::write(&stranger, b"not the store's").unwrap();
    // A directory is never a half-written entry, whatever it is called.
    let namesake = temp_dir.join("424242-8.tmp");
    fs::create_dir(&namesake).unwrap();

    assert_eq!(store.prune_temp_files(Duration::ZERO).unwrap(), 0);

    assert!(stranger.is_file());
    assert!(namesake.is_dir());
}

#[test]
fn sweeping_a_store_nothing_was_ever_written_to_finds_nothing() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);

    assert_eq!(store.prune_temp_files(Duration::ZERO).unwrap(), 0);
}

#[test]
#[cfg(unix)]
fn an_unreadable_shard_is_reported_and_the_walk_goes_on() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    let (_, anchor) = store.add(b"anchor").unwrap();
    // A second entry whose first shard level differs, so exactly one of the
    // two lies behind the directory made unreadable.
    let mut n = 0;
    let other = loop {
        let (_, entry) = store.add(format!("probe {n}").as_bytes()).unwrap();
        if entry.digest().as_str()[..2] != anchor.digest().as_str()[..2] {
            break entry;
        }
        n += 1;
    };
    let shard = anchor
        .path()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();

    fs::set_permissions(&shard, fs::Permissions::from_mode(0o000)).unwrap();
    let items: Vec<_> = store.entries().collect();
    fs::set_permissions(&shard, fs::Permissions::from_mode(0o700)).unwrap();

    let errors = items.iter().filter(|item| item.is_err()).count();
    if errors == 0 {
        // A directory's mode does not stand in root's way, and this test has
        // nothing to say then.
        return;
    }
    assert_eq!(errors, 1, "the unreadable shard is one error, not silence");
    let found: Vec<_> = items.iter().filter_map(|item| item.as_ref().ok()).collect();
    assert!(
        found.iter().any(|entry| **entry == other),
        "the rest of the walk still happened"
    );
    assert!(
        !found.iter().any(|entry| **entry == anchor),
        "what lies behind the unreadable shard is out of reach, and reported so"
    );
}

#[test]
#[cfg(all(unix, feature = "zstd"))]
fn a_pass_over_a_store_it_cannot_fully_walk_says_so() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    let (_, entry) = store.add(b"behind a wall").unwrap();
    let shard = entry
        .path()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();

    fs::set_permissions(&shard, fs::Permissions::from_mode(0o000)).unwrap();
    let result = store.compress_all();
    fs::set_permissions(&shard, fs::Permissions::from_mode(0o700)).unwrap();

    let Err(err) = result else {
        // Root again: nothing was unreadable, nothing to assert.
        return;
    };
    assert!(matches!(err, Error::Io { .. }));
}

#[test]
#[cfg(unix)]
fn a_symlinked_directory_does_not_turn_the_walk_into_a_circle() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    let (_, entry) = store.add(b"one").unwrap();
    let shard = entry.path().parent().unwrap();

    // A shard that points back at the root: following it would recurse until
    // the path runs out of characters.
    std::os::unix::fs::symlink(store.root(), shard.join("loop")).unwrap();

    assert_eq!(store.entries().count(), 1);
    assert_eq!(store.prune_empty_dirs().unwrap(), 0);
}

// -- integrity ---------------------------------------------------------------

#[test]
fn verification_catches_content_that_no_longer_matches_its_name() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    let (_, entry) = store.add(b"original content").unwrap();
    assert!(store.verify(&entry).unwrap());

    tamper(entry.path(), b"tampered with");

    assert!(!store.verify(&entry).unwrap());
    assert_eq!(
        store.digest_of(entry.path()).unwrap(),
        store.digest(b"tampered with")
    );
}

#[test]
fn a_file_that_is_not_an_entry_cannot_be_verified() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    fs::create_dir_all(store.root()).unwrap();
    let stray = store.root().join("notes.json");
    fs::write(&stray, b"by hand").unwrap();

    // verify takes an Entry, and a stray never becomes one: the question is
    // answered by entry_at, once, instead of by every method again.
    assert_eq!(store.entry_at(&stray), None);
}

// -- setting a damaged entry aside -------------------------------------------

fn file_name(path: &std::path::Path) -> String {
    path.file_name().unwrap().to_str().unwrap().to_string()
}

#[test]
fn a_damaged_entry_loses_its_name_and_keeps_its_bytes() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    let (_, entry) = store.add(b"original content").unwrap();
    tamper(entry.path(), b"tampered with");
    assert!(!store.verify(&entry).unwrap());

    let aside = store.quarantine(&entry).unwrap();

    assert_eq!(
        file_name(aside.path()),
        format!("{}.json.corrupt", entry.digest())
    );
    assert_eq!(
        fs::read(aside.path()).unwrap(),
        b"tampered with",
        "every byte is still there"
    );
    assert!(!entry.path().exists());

    // What has stopped is the claim: nothing answers for that digest any more.
    assert_eq!(store.find(entry.digest()).unwrap(), None);
    assert!(!store.contains(entry.digest()).unwrap());
    assert!(store.read(entry.digest()).unwrap().is_none());
    assert_eq!(store.entries().count(), 0);
    assert_eq!(
        store
            .matching(&entry.digest().as_str()[..store.min_prefix()])
            .unwrap(),
        Vec::<Digest>::new()
    );

    // Which is what lets the content be fetched and stored again.
    let (status, again) = store.add(b"original content").unwrap();
    assert_eq!(status, Status::New);
    assert_eq!(again.path(), entry.path());
}

#[test]
fn what_was_set_aside_is_recognised_rather_than_reported_again() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    // Not re-read here: the caller has just verified it, and reading every
    // entry a second time is the expensive half of a check run.
    let (_, entry) = store.add(b"original content").unwrap();
    let aside = store.quarantine(&entry).unwrap();

    assert_eq!(store.quarantined_at(aside.path()), Some(aside.clone()));
    assert_eq!(aside.digest(), entry.digest());
    assert_eq!(store.entry_at(aside.path()), None, "no longer an entry");
    assert_eq!(
        store.quarantined_at(entry.path()),
        None,
        "and gone from there"
    );

    let stray = entry.path().with_file_name("notes.json.corrupt");
    fs::write(&stray, b"by hand").unwrap();
    assert_eq!(store.quarantined_at(&stray), None);
}

#[test]
fn content_that_breaks_again_is_set_aside_beside_the_first() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    let (_, first) = store.add(b"original content").unwrap();
    let one = store.quarantine(&first).unwrap();
    // Fetched again, and damaged again. Twice.
    let (_, second) = store.add(b"original content").unwrap();
    let two = store.quarantine(&second).unwrap();
    let (_, third) = store.add(b"original content").unwrap();
    let three = store.quarantine(&third).unwrap();

    assert_eq!(
        file_name(two.path()),
        format!("{}.json.corrupt.1", first.digest())
    );
    assert_eq!(
        file_name(three.path()),
        format!("{}.json.corrupt.2", first.digest())
    );
    assert_eq!(
        fs::read(one.path()).unwrap(),
        b"original content",
        "nothing is ever overwritten"
    );
    assert_eq!(store.quarantined_at(three.path()), Some(three));
}

#[test]
fn only_an_entry_can_be_set_aside() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    fs::create_dir_all(store.root()).unwrap();
    let stray = store.root().join("notes.json");
    fs::write(&stray, b"by hand").unwrap();

    // quarantine takes an Entry, and a stray never becomes one.
    assert_eq!(store.entry_at(&stray), None);
    assert!(stray.is_file(), "and it stays exactly where it was");
}

#[test]
fn what_lies_aside_can_be_walked() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    let (_, keeps) = store.add(b"stays an entry").unwrap();
    let (_, breaks) = store.add(b"loses its name").unwrap();
    tamper(breaks.path(), b"changed behind the store's back");
    let aside = store.quarantine(&breaks).unwrap();

    let found: Vec<_> = store.quarantined().collect::<Result<_, _>>().unwrap();

    assert_eq!(found.len(), 1, "what was set aside, and nothing else");
    assert_eq!(found[0], aside);
    assert_eq!(found[0].digest(), breaks.digest());
    assert!(!found[0].is_compressed());

    // The two walks divide the tree between them: the healthy entry is
    // nobody's set-aside file, the set-aside file is nobody's entry.
    let entries: Vec<_> = store.entries().collect::<Result<_, _>>().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].digest(), keeps.digest());
}

#[test]
fn a_false_alarm_gets_its_name_back() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    let (_, entry) = store.add(b"set aside by mistake").unwrap();
    // Quarantine renames on trust, so a healthy file can lie aside.
    let aside = store.quarantine(&entry).unwrap();
    assert!(store.find(entry.digest()).unwrap().is_none());

    let restored = store.restore(&aside).unwrap().expect("a match comes back");

    assert_eq!(restored, entry, "the entry it was, name and all");
    assert!(store.verify(&restored).unwrap());
    assert_eq!(
        store.find(entry.digest()).unwrap(),
        Some(entry.path().to_path_buf())
    );
    assert_eq!(
        store.quarantined().count(),
        0,
        "nothing lies aside any more"
    );
}

#[test]
fn what_is_still_damaged_stays_aside() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    let (_, entry) = store.add(b"about to break").unwrap();
    tamper(entry.path(), b"broken");
    let aside = store.quarantine(&entry).unwrap();

    let restored = store.restore(&aside).unwrap();

    assert!(restored.is_none(), "the bytes still do not match the name");
    assert!(aside.path().is_file(), "and the file stays where it lies");
    assert!(store.find(entry.digest()).unwrap().is_none());
}

#[test]
fn a_name_taken_again_obstructs_the_restore() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    let (_, entry) = store.add(b"fetched twice").unwrap();
    let aside = store.quarantine(&entry).unwrap();
    // The content arrived again while the copy lay aside.
    store.add(b"fetched twice").unwrap();

    let err = store.restore(&aside).unwrap_err();

    assert!(matches!(err, Error::Obstructed(taken) if taken == *entry.path()));
    // The store answers for the content again, so the copy may go.
    store.discard(&aside).unwrap();
    assert!(!aside.path().exists());
    assert!(store.verify(&entry).unwrap());
}

#[test]
fn only_what_was_set_aside_can_be_restored_or_discarded() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    let (_, entry) = store.add(b"a live entry").unwrap();

    // restore and discard take a Quarantined, and quarantined_at is the one
    // gate that makes one: a live entry answers None there — deleting one is
    // `remove`'s job, by digest — and so does a stray, however its name ends.
    assert_eq!(store.quarantined_at(entry.path()), None);
    let stray = entry.path().with_file_name("notes.json.corrupt");
    fs::write(&stray, b"somebody's notes").unwrap();
    assert_eq!(store.quarantined_at(&stray), None);

    // What quarantine set aside goes, write protection and all.
    tamper(entry.path(), b"broken");
    let aside = store.quarantine(&entry).unwrap();
    store.discard(&aside).unwrap();
    assert!(!aside.path().exists());
}

// -- reading part of an entry ------------------------------------------------

#[test]
fn a_reader_hands_over_as_much_as_the_caller_asks_for() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    let mut content = b"HEADER\n\n".to_vec();
    content.extend(b"payload".repeat(100_000));
    let (_, entry) = store.add(&content).unwrap();

    // The store knows nothing about what is in an entry. A caller that wants
    // the head of it — a header block, a magic number — reads until it has it
    // and drops the reader; the rest never comes off the disk.
    let mut reader = store.reader(entry.digest()).unwrap().unwrap();
    let mut head = vec![0u8; 8];
    reader.read_exact(&mut head).unwrap();
    drop(reader);

    assert_eq!(head, b"HEADER\n\n");
}

#[test]
#[cfg(feature = "zstd")]
fn a_compressed_entry_is_decompressed_only_as_far_as_it_is_read() {
    let dir = TempDir::new().unwrap();
    let store = Store::builder(dir.path().join("cas"))
        .suffix(".json")
        .compress(true)
        .build()
        .unwrap();
    let mut content = b"HEADER\n\n".to_vec();
    content.extend(b"payload".repeat(100_000));
    let (_, entry) = store.add(&content).unwrap();

    let mut reader = store.reader(entry.digest()).unwrap().unwrap();
    let mut head = vec![0u8; 8];
    reader.read_exact(&mut head).unwrap();
    drop(reader);

    assert_eq!(head, b"HEADER\n\n");
}

// -- compression -------------------------------------------------------------

#[test]
fn a_build_without_zstd_refuses_to_compress_rather_than_pretending() {
    assert_eq!(immure::compression_available(), cfg!(feature = "zstd"));

    if !immure::compression_available() {
        let dir = TempDir::new().unwrap();
        let err = Store::builder(dir.path())
            .compress(true)
            .build()
            .unwrap_err();
        assert!(matches!(err, Error::CompressionUnavailable), "{err}");
    }
}

#[test]
#[cfg(feature = "zstd")]
fn compressed_entries_round_trip_and_keep_their_uncompressed_name() {
    let dir = TempDir::new().unwrap();
    let store = Store::builder(dir.path().join("cas"))
        .suffix(".json")
        .compress(true)
        .build()
        .unwrap();
    let content = b"compressible ".repeat(500);

    let (status, entry) = store.add(&content).unwrap();

    assert_eq!(status, Status::New);
    assert!(entry.is_compressed());
    assert!(entry.path().to_str().unwrap().ends_with(".json.zst"));
    assert!(fs::metadata(entry.path()).unwrap().len() < content.len() as u64);
    assert_eq!(store.read_at(entry.path()).unwrap(), content);
    // The name is the hash of the content, not of the compressed file.
    assert_eq!(entry.digest(), &store.digest(&content));
    assert!(store.verify(&entry).unwrap());
    assert_eq!(store.add(&content).unwrap().0, Status::Exists);
}

#[test]
#[cfg(feature = "zstd")]
fn the_two_forms_find_each_other() {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("cas");
    let plain = Store::builder(&root).suffix(".json").build().unwrap();
    let zstd = Store::builder(&root)
        .suffix(".json")
        .compress(true)
        .build()
        .unwrap();

    let (_, written_plain) = plain.add(b"stored plain").unwrap();
    let (_, written_zstd) = zstd.add(b"stored compressed").unwrap();

    // Neither store rewrites what the other left behind…
    assert_eq!(zstd.add(b"stored plain").unwrap().0, Status::Exists);
    assert_eq!(plain.add(b"stored compressed").unwrap().0, Status::Exists);
    // …both find it…
    assert_eq!(
        plain.find(written_zstd.digest()).unwrap(),
        Some(written_zstd.path().to_path_buf())
    );
    assert_eq!(
        zstd.find(written_plain.digest()).unwrap(),
        Some(written_plain.path().to_path_buf())
    );
    // …and both read it.
    assert_eq!(
        plain.read_at(written_zstd.path()).unwrap(),
        b"stored compressed"
    );
    assert_eq!(zstd.read_at(written_plain.path()).unwrap(), b"stored plain");
    assert_eq!(plain.entries().count(), 2);
}

#[test]
#[cfg(feature = "zstd")]
fn a_whole_store_can_be_compressed_and_uncompressed_again() {
    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);
    let contents: Vec<Vec<u8>> = (0..5)
        .map(|n| format!("entry {n}\n").repeat(100).into_bytes())
        .collect();
    let digests: Vec<_> = contents
        .iter()
        .map(|content| store.add(content).unwrap().1.digest().clone())
        .collect();

    let compressed = store.compress_all().unwrap();
    assert_eq!(compressed.converted, 5);
    assert_eq!(compressed.skipped, 0);
    assert!(compressed.failed.is_empty());
    assert!(store.entries().all(|entry| entry.unwrap().is_compressed()));

    // Nothing moved: the entries still answer to the same digests, and the
    // content is unchanged.
    for (digest, content) in digests.iter().zip(&contents) {
        assert_eq!(store.read(digest).unwrap().as_ref(), Some(content));
    }

    // A second pass has nothing left to do — and says so as "already there"
    // rather than as "not my business".
    let again = store.compress_all().unwrap();
    assert_eq!((again.converted, again.already, again.skipped), (0, 5, 0));

    let plain = store.decompress_all().unwrap();
    assert_eq!((plain.converted, plain.already, plain.skipped), (5, 0, 0));
    assert!(store.entries().all(|entry| !entry.unwrap().is_compressed()));
    for (digest, content) in digests.iter().zip(&contents) {
        assert_eq!(store.read(digest).unwrap().as_ref(), Some(content));
        let path = store.find(digest).unwrap().unwrap();
        assert!(store.verify(&store.entry_at(&path).unwrap()).unwrap());
    }
}

#[test]
#[cfg(feature = "zstd")]
fn converting_a_mixed_store_touches_only_what_needs_it() {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("cas");
    let plain = Store::builder(&root).suffix(".json").build().unwrap();
    let zstd = Store::builder(&root)
        .suffix(".json")
        .compress(true)
        .build()
        .unwrap();
    plain.add(b"stored plain").unwrap();
    zstd.add(b"stored compressed").unwrap();

    let result = plain.compress_all().unwrap();

    assert_eq!(
        (result.converted, result.already, result.skipped),
        (1, 1, 0)
    );
    assert_eq!(plain.entries().count(), 2);
}

// -- the handle itself -------------------------------------------------------

#[test]
fn a_store_can_be_shared_across_threads() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Store>();

    let dir = TempDir::new().unwrap();
    let store = store_in(&dir);

    std::thread::scope(|scope| {
        for n in 0..8 {
            let store = &store;
            scope.spawn(move || {
                // Half the threads store the same bytes, so they race for the
                // same name; the other half store their own.
                let content = format!("entry {}", n % 4);
                store.add(content.as_bytes()).unwrap();
            });
        }
    });

    assert_eq!(store.entries().count(), 4);
    assert_eq!(temp_files(store.root()), Vec::<PathBuf>::new());
}

/// Whatever is left lying around in the store's temporary directory.
fn temp_files(root: &std::path::Path) -> Vec<PathBuf> {
    let temp = root.join("tmp");
    if !temp.is_dir() {
        return Vec::new();
    }
    fs::read_dir(temp)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect()
}

// -- encryption --------------------------------------------------------------

#[cfg(feature = "crypt")]
mod encryption {
    use super::{TempDir, file_name, tamper};
    use immure::{Error, Key, Status, Store};
    use std::fs;
    use std::io::Read as _;
    use std::path::Path;

    fn key(byte: u8) -> Key {
        Key::new([byte; Key::LEN])
    }

    fn sealed_store(root: &Path, byte: u8) -> Store {
        Store::builder(root)
            .suffix(".json")
            .key(key(byte))
            .build()
            .unwrap()
    }

    /// Content that zstd cannot shrink, so a sealed entry really does span
    /// several chunks. A plain counter would compress to nothing.
    fn incompressible(len: usize) -> Vec<u8> {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                u8::try_from(state & 0xff).unwrap()
            })
            .collect()
    }

    #[test]
    fn what_is_stored_sealed_comes_back_and_is_not_on_disk_in_the_clear() {
        let dir = TempDir::new().unwrap();
        let store = sealed_store(&dir.path().join("cas"), 1);

        let (status, entry) = store.add(b"the quick brown fox").unwrap();

        assert_eq!(status, Status::New);
        assert!(entry.is_encrypted(), "written in the sealed form");
        assert!(entry.is_compressed(), "and compressed underneath it");
        assert!(file_name(entry.path()).ends_with(".json.zst.enc"));

        let on_disk = fs::read(entry.path()).unwrap();
        assert!(
            !on_disk.windows(3).any(|window| window == b"fox"),
            "the content is not lying there to be read"
        );
        assert_eq!(
            store.read(entry.digest()).unwrap().as_deref(),
            Some(&b"the quick brown fox"[..])
        );
    }

    #[test]
    fn the_name_is_still_the_digest_of_the_content() {
        let dir = TempDir::new().unwrap();
        let plain = Store::builder(dir.path().join("plain"))
            .suffix(".json")
            .build()
            .unwrap();
        let sealed = sealed_store(&dir.path().join("sealed"), 1);

        let (_, one) = plain.add(b"same bytes").unwrap();
        let (_, other) = sealed.add(b"same bytes").unwrap();

        assert_eq!(
            one.digest(),
            other.digest(),
            "sealing changes the file, never the address"
        );
    }

    #[test]
    fn the_same_content_is_stored_once() {
        let dir = TempDir::new().unwrap();
        let store = sealed_store(&dir.path().join("cas"), 1);

        store.add(b"once").unwrap();
        let (status, _) = store.add(b"once").unwrap();

        assert_eq!(
            status,
            Status::Exists,
            "duplicates are decided by the name, before anything is sealed"
        );
        assert_eq!(store.entries().count(), 1);
    }

    #[test]
    fn a_streamed_entry_is_sealed_too() {
        let dir = TempDir::new().unwrap();
        let store = sealed_store(&dir.path().join("cas"), 1);
        let content = incompressible(300 * 1024);

        let (_, entry) = store.add_reader(&content[..]).unwrap();

        assert!(entry.is_encrypted());
        assert_eq!(store.read(entry.digest()).unwrap(), Some(content));
    }

    #[test]
    fn one_content_under_one_key_is_never_the_same_bytes_twice() {
        // Two stores so that neither can answer "already here". Both write
        // paths draw a nonce of their own, so nothing about the stored bytes
        // says these two hold the same thing — a name is what says that, and a
        // name is only as public as the directory it lies in.
        let dir = TempDir::new().unwrap();
        let content = incompressible(200_000);

        let one = sealed_store(&dir.path().join("one"), 4);
        let (_, first) = one.add(&content).unwrap();
        let two = sealed_store(&dir.path().join("two"), 4);
        let (_, second) = two.add_reader(&content[..]).unwrap();

        assert_eq!(
            first.digest(),
            second.digest(),
            "the same content, either way"
        );
        assert_ne!(
            fs::read(first.path()).unwrap(),
            fs::read(second.path()).unwrap(),
            "and not the same bytes on disk"
        );
        assert_eq!(one.read_at(first.path()).unwrap(), content);
        assert_eq!(two.read_at(second.path()).unwrap(), content);
    }

    #[test]
    fn a_store_without_the_key_can_say_where_an_entry_is_but_not_what_it_holds() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("cas");
        let (_, entry) = sealed_store(&root, 1).add(b"content").unwrap();

        let keyless = Store::builder(&root).suffix(".json").build().unwrap();

        assert!(
            keyless.contains(entry.digest()).unwrap(),
            "everything answered by names stays keyless"
        );
        assert_eq!(keyless.entries().count(), 1);
        assert!(matches!(
            keyless.read(entry.digest()),
            Err(Error::KeyRequired(_))
        ));
    }

    #[test]
    fn the_wrong_key_does_not_open_an_entry() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("cas");
        let (_, entry) = sealed_store(&root, 1).add(b"content").unwrap();

        let wrong = sealed_store(&root, 2);

        assert!(matches!(wrong.read(entry.digest()), Err(Error::Unsealable),));
    }

    #[test]
    fn a_damaged_entry_is_damaged_and_a_wrong_key_is_not() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("cas");
        let store = sealed_store(&root, 1);
        // Several chunks, so there is a "later chunk" to damage: once one has
        // opened, the key is proven and what fails after it is the content.
        let (_, damaged) = store.add(&incompressible(300 * 1024)).unwrap();
        let (_, healthy) = store.add(b"nothing wrong with this one").unwrap();

        let mut bytes = fs::read(damaged.path()).unwrap();
        let late = bytes.len() - 100;
        bytes[late] ^= 0x01;
        tamper(damaged.path(), &bytes);

        assert!(
            !store.verify(&damaged).unwrap(),
            "damage past the first chunk is an answer, not an error"
        );
        assert!(
            matches!(
                sealed_store(&root, 2).verify(&healthy),
                Err(Error::Unsealable)
            ),
            "a healthy entry held against the wrong key must not read as damaged"
        );
    }

    #[test]
    fn a_short_sealed_entry_is_answered_for_once_the_key_has_opened_something() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("cas");
        let store = sealed_store(&root, 1);
        // One chunk, which is what most entries are: there is no later chunk
        // here to prove the key with.
        let (_, damaged) = store.add(b"short enough to be a single chunk").unwrap();
        let (_, healthy) = store.add(b"nothing wrong with this one").unwrap();

        let mut bytes = fs::read(damaged.path()).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        tamper(damaged.path(), &bytes);

        let fresh = sealed_store(&root, 1);
        assert!(
            matches!(fresh.verify(&damaged), Err(Error::Unsealable)),
            "nothing has opened yet, so a wrong key is still an explanation"
        );

        fresh.read(healthy.digest()).unwrap().unwrap();

        assert!(
            !fresh.verify(&damaged).unwrap(),
            "the key has opened an entry in this store, so this one is damaged"
        );
    }

    #[test]
    fn a_sealed_entry_that_was_set_aside_still_reads_as_its_content() {
        let dir = TempDir::new().unwrap();
        let store = sealed_store(&dir.path().join("cas"), 5);
        let (_, entry) = store.add(b"content that was set aside").unwrap();

        let aside = store.quarantine(&entry).unwrap();

        assert_eq!(
            store.quarantined_at(aside.path()).unwrap().digest(),
            entry.digest()
        );
        assert_eq!(
            store.read_at(aside.path()).unwrap(),
            b"content that was set aside",
            "`.corrupt` on the end of a name does not unseal it, and handing \
             the file back would hand back ciphertext"
        );
    }

    #[test]
    fn a_sealed_entry_that_is_intact_verifies() {
        let dir = TempDir::new().unwrap();
        let store = sealed_store(&dir.path().join("cas"), 1);
        let (_, entry) = store.add(&incompressible(200 * 1024)).unwrap();

        assert!(store.verify(&entry).unwrap());
    }

    #[test]
    fn a_reader_over_a_sealed_entry_stops_where_the_caller_stops() {
        let dir = TempDir::new().unwrap();
        let store = sealed_store(&dir.path().join("cas"), 1);
        let mut content = b"HEADER\n\n".to_vec();
        content.extend(incompressible(300 * 1024));
        let (_, entry) = store.add(&content).unwrap();

        let mut reader = store.reader(entry.digest()).unwrap().unwrap();
        let mut head = [0u8; 8];
        reader.read_exact(&mut head).unwrap();
        drop(reader);

        assert_eq!(&head, b"HEADER\n\n");
    }

    #[test]
    fn all_three_forms_live_in_one_store_and_are_all_found() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("cas");
        let raw = Store::builder(&root).suffix(".json").build().unwrap();
        let zstd = Store::builder(&root)
            .suffix(".json")
            .compress(true)
            .build()
            .unwrap();
        let enc = sealed_store(&root, 1);

        let (_, one) = raw.add(b"raw one").unwrap();
        let (_, two) = zstd.add(b"compressed one").unwrap();
        let (_, three) = enc.add(b"sealed one").unwrap();

        assert_eq!(enc.entries().count(), 3);
        assert_eq!(
            enc.read(one.digest()).unwrap().as_deref(),
            Some(&b"raw one"[..])
        );
        assert_eq!(
            enc.read(two.digest()).unwrap().as_deref(),
            Some(&b"compressed one"[..])
        );
        assert_eq!(
            enc.read(three.digest()).unwrap().as_deref(),
            Some(&b"sealed one"[..])
        );
    }

    #[test]
    fn a_whole_store_can_be_sealed_afterwards() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("cas");
        let plain = Store::builder(&root).suffix(".json").build().unwrap();
        let digests: Vec<_> = (0..3)
            .map(|n| {
                plain
                    .add(format!("entry {n}").as_bytes())
                    .unwrap()
                    .1
                    .digest()
                    .clone()
            })
            .collect();

        let sealed = sealed_store(&root, 1);
        let run = sealed.encrypt_all().unwrap();

        assert_eq!((run.converted, run.already, run.skipped), (3, 0, 0));
        assert!(run.failed.is_empty());
        for (n, digest) in digests.iter().enumerate() {
            let entry = sealed.find(digest).unwrap().unwrap();
            assert!(file_name(&entry).ends_with(".zst.enc"));
            assert_eq!(
                sealed.read(digest).unwrap(),
                Some(format!("entry {n}").into_bytes())
            );
        }
        assert_eq!(
            sealed.encrypt_all().unwrap().already,
            3,
            "a second run seals nothing again"
        );
    }

    #[test]
    fn a_store_can_be_unsealed_and_sealed_again_under_another_key() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("cas");
        let old = sealed_store(&root, 1);
        let (_, entry) = old.add(b"content that outlives its key").unwrap();

        assert_eq!(old.decrypt_all().unwrap().converted, 1);
        let new = sealed_store(&root, 2);
        assert_eq!(new.encrypt_all().unwrap().converted, 1);

        assert_eq!(
            new.read(entry.digest()).unwrap().as_deref(),
            Some(&b"content that outlives its key"[..])
        );
        assert!(
            matches!(old.read(entry.digest()), Err(Error::Unsealable)),
            "the old key no longer opens it"
        );
    }

    #[test]
    fn a_key_is_changed_one_entry_at_a_time_and_never_in_the_clear() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("cas");
        let old = sealed_store(&root, 1);
        let contents: Vec<Vec<u8>> = (0..3).map(|n| incompressible(70_000 + n * 1000)).collect();
        let entries: Vec<_> = contents
            .iter()
            .map(|content| old.add(content).unwrap().1)
            .collect();

        let run = old.change_key(&key(2)).unwrap();

        assert_eq!((run.converted, run.skipped), (3, 0));
        assert!(run.failed.is_empty());

        let new = sealed_store(&root, 2);
        for (entry, content) in entries.iter().zip(&contents) {
            assert!(
                entry.path().is_file(),
                "an entry keeps its name through a key change: the content did not change"
            );
            assert!(
                file_name(entry.path()).ends_with(".json.zst.enc"),
                "and its form: it was sealed before and it is sealed now"
            );
            assert_eq!(new.read(entry.digest()).unwrap().as_ref(), Some(content));
            assert!(
                matches!(old.read(entry.digest()), Err(Error::Unsealable)),
                "the old key no longer opens it"
            );
        }
        assert!(
            !root
                .join("tmp")
                .read_dir()
                .unwrap()
                .any(|item| item.is_ok()),
            "and nothing is left lying in tmp/"
        );
    }

    #[test]
    fn a_key_change_that_was_interrupted_picks_up_where_it_stopped() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("cas");

        // What a run that stopped after the first entry leaves behind: one
        // entry under each key, in one store. Two handles put it there, which
        // is the only way to build the state from outside the crate.
        let (moved, left_behind) = half_migrated(&root);
        let before = fs::read(&left_behind.path).unwrap();

        // Resumed the way it was started: from the handle holding the key
        // that is being moved away from.
        let resumed = sealed_store(&root, 1);
        let run = resumed.change_key(&key(2)).unwrap();

        assert_eq!(
            (run.converted, run.already, run.skipped),
            (1, 1, 0),
            "the one that was left behind is moved, the one that was done is not"
        );
        assert!(run.failed.is_empty());
        assert_ne!(fs::read(&left_behind.path).unwrap(), before);

        let new = sealed_store(&root, 2);
        for entry in [&moved, &left_behind] {
            assert_eq!(new.read_at(&entry.path).unwrap(), entry.content);
        }

        // And a run over a store that is through it changes nothing.
        let again = resumed.change_key(&key(2)).unwrap();
        assert_eq!((again.converted, again.already, again.skipped), (0, 2, 0));
    }

    #[test]
    fn a_key_change_takes_what_was_set_aside_with_it() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("cas");
        let store = sealed_store(&root, 1);
        let (_, entry) = store.add(b"set aside, and still worth keeping").unwrap();
        let aside = store.quarantine(&entry).unwrap();

        let run = store.change_key(&key(2)).unwrap();

        assert_eq!((run.converted, run.already, run.skipped), (1, 0, 0));
        // Still set aside — it keeps the name it was given — and still
        // readable, which is the whole reason it was kept rather than deleted.
        assert!(file_name(aside.path()).ends_with(".corrupt"));
        let new = sealed_store(&root, 2);
        assert_eq!(
            new.read_at(aside.path()).unwrap(),
            b"set aside, and still worth keeping"
        );
    }

    #[test]
    fn one_digest_naming_two_files_is_two_sealings_and_no_trouble() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("cas");
        let store = sealed_store(&root, 1);
        let (_, broken) = store.add(b"content that broke and came back").unwrap();
        let aside = store.quarantine(&broken).unwrap();
        // Setting one aside frees its name, so the same content arriving again
        // takes it and one digest names two files. Each was sealed under a
        // nonce drawn for that write, so the two are unrelated on disk — which
        // is the whole reason the nonce is not the digest.
        let (_, live) = store.add(b"content that broke and came back").unwrap();
        assert_eq!(live.digest(), broken.digest());
        assert_ne!(
            fs::read(aside.path()).unwrap(),
            fs::read(live.path()).unwrap(),
            "one content under one key, sealed twice and not the same twice"
        );

        let run = store.change_key(&key(2)).unwrap();

        assert_eq!(
            (run.converted, run.already, run.skipped),
            (2, 0, 0),
            "both of them move; neither is any of the other's business"
        );
        assert!(run.failed.is_empty());
        assert!(run.is_finished());

        let new = sealed_store(&root, 2);
        assert_eq!(
            new.read_at(live.path()).unwrap(),
            b"content that broke and came back"
        );
        assert_eq!(
            new.read_at(aside.path()).unwrap(),
            b"content that broke and came back",
            "the salvage came along, and the old key is not needed for it"
        );
        assert_ne!(
            fs::read(aside.path()).unwrap(),
            fs::read(live.path()).unwrap(),
            "and under the new key they are still two sealings, not one"
        );
    }

    #[test]
    fn a_damaged_entry_does_not_hold_back_the_copy_that_was_set_aside() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("cas");
        let store = sealed_store(&root, 1);
        let content = incompressible(300 * 1024);
        let (_, entry) = store.add(&content).unwrap();
        let aside = store.quarantine(&entry).unwrap();
        let (_, live) = store.add(&content).unwrap();

        // Past the first chunk, so the key is proven by what opened before it
        // and this is the content's fault rather than the key's.
        let mut bytes = fs::read(live.path()).unwrap();
        let at = bytes.len() - 100;
        bytes[at] ^= 0xff;
        tamper(live.path(), &bytes);

        let run = store.change_key(&key(2)).unwrap();

        assert_eq!(run.converted, 1, "the copy that was set aside moves");
        assert_eq!(run.failed.len(), 1);
        assert_eq!(run.failed[0].path, *live.path());
        assert!(matches!(run.failed[0].error, Error::Damaged));
        assert!(
            run.is_finished(),
            "and nothing readable is left behind for the old key"
        );

        let new = sealed_store(&root, 2);
        assert_eq!(
            new.read_at(aside.path()).unwrap(),
            content,
            "the salvage came with it, so the old key can go"
        );
    }

    #[test]
    fn an_unsealing_pass_counts_what_it_applies_to() {
        let dir = TempDir::new().unwrap();
        let store = sealed_store(&dir.path().join("cas"), 1);
        store.add(b"one").unwrap();
        store.add(b"two").unwrap();

        let first = store.decrypt_all().unwrap();
        assert_eq!((first.converted, first.already, first.skipped), (2, 0, 0));

        let again = store.decrypt_all().unwrap();
        assert_eq!(
            (again.converted, again.already, again.skipped),
            (0, 2, 0),
            "an entry already in the form the pass wants is one it applies to"
        );

        assert_eq!(store.decompress_all().unwrap().converted, 2);
        let raw = store.decrypt_all().unwrap();
        assert_eq!(
            (raw.converted, raw.already, raw.skipped),
            (0, 0, 2),
            "an entry that was never sealed is not this pass's business at all"
        );
    }

    #[test]
    fn a_key_change_is_through_even_with_an_entry_neither_key_opens() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("cas");
        let store = sealed_store(&root, 1);
        // Damaged past the first chunk, so it is the content and not the key,
        // and then set aside — which is the ordinary way a quarantined entry
        // comes about.
        let (_, entry) = store.add(&incompressible(300 * 1024)).unwrap();
        let mut bytes = fs::read(entry.path()).unwrap();
        let late = bytes.len() - 100;
        bytes[late] ^= 0x01;
        tamper(entry.path(), &bytes);
        assert!(!store.verify(&entry).unwrap());
        let aside = store.quarantine(&entry).unwrap();

        let run = store.change_key(&key(2)).unwrap();

        assert_eq!(run.failed.len(), 1);
        assert_eq!(run.failed[0].path, *aside.path());
        assert!(
            !run.failed[0].recoverable,
            "neither key opens it, so there is nothing a second run would do"
        );
        assert!(
            run.is_finished(),
            "or the old key could never be destroyed, for an entry it cannot \
             open either"
        );
        assert_eq!(run.unfinished().count(), 0);
    }

    #[test]
    #[cfg(unix)]
    fn a_key_change_that_cannot_move_an_entry_does_not_report_it_moved() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = TempDir::new().unwrap();
        let root = dir.path().join("cas");
        let store = sealed_store(&root, 1);
        let (_, entry) = store.add(b"this one is not going anywhere").unwrap();
        let before = fs::read(entry.path()).unwrap();

        // An entry is replaced by a rename onto its own name, so its own name
        // being taken is not evidence of anything. A shard that cannot be
        // written is the cheapest way to make that rename fail.
        let shard = entry.path().parent().unwrap();
        let saved = fs::metadata(shard).unwrap().permissions();
        fs::set_permissions(shard, fs::Permissions::from_mode(0o555)).unwrap();
        let run = store.change_key(&key(2));
        fs::set_permissions(shard, saved).unwrap();

        let run = run.unwrap();
        assert_eq!((run.converted, run.already, run.skipped), (0, 0, 0));
        assert_eq!(run.failed.len(), 1, "reported, not counted as converted");
        assert_eq!(run.failed[0].path, *entry.path());
        assert_eq!(fs::read(entry.path()).unwrap(), before);
    }

    /// A store holding one entry under each key: what an interrupted
    /// [`Store::change_key`] leaves behind. The first is through it.
    fn half_migrated(root: &Path) -> (Stored, Stored) {
        let new = sealed_store(root, 2);
        let (_, moved) = new.add(b"already under the new key").unwrap();
        let old = sealed_store(root, 1);
        let (_, left_behind) = old.add(b"never reached by the run").unwrap();
        (
            Stored {
                path: moved.path().to_path_buf(),
                content: b"already under the new key".to_vec(),
            },
            Stored {
                path: left_behind.path().to_path_buf(),
                content: b"never reached by the run".to_vec(),
            },
        )
    }

    struct Stored {
        path: std::path::PathBuf,
        content: Vec<u8>,
    }

    #[test]
    fn a_key_change_leaves_what_is_not_sealed_alone() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("cas");
        let plain = Store::builder(&root).suffix(".json").build().unwrap();
        let (_, plain_entry) = plain.add(b"never was sealed").unwrap();

        let sealed = sealed_store(&root, 1);
        let (_, sealed_entry) = sealed.add(b"sealed from the start").unwrap();

        let run = sealed.change_key(&key(2)).unwrap();

        assert_eq!((run.converted, run.skipped), (1, 1));
        assert!(plain_entry.path().is_file(), "the plain entry is untouched");
        assert!(sealed_entry.path().is_file());
    }

    #[test]
    fn sealing_an_entry_seals_the_frame_it_already_had() {
        use immure::crypt::Opener;

        let dir = TempDir::new().unwrap();
        let root = dir.path().join("cas");
        let plain = Store::builder(&root)
            .suffix(".json")
            .compress(true)
            .build()
            .unwrap();
        let content = incompressible(200_000);
        let (_, entry) = plain.add(&content).unwrap();
        let frame = fs::read(entry.path()).unwrap();

        let sealed = sealed_store(&root, 7);
        assert_eq!(sealed.encrypt_all().unwrap().converted, 1);

        let path = sealed.find(entry.digest()).unwrap().unwrap();
        let file = fs::File::open(&path).unwrap();
        let mut opened = Vec::new();
        Opener::new(&key(7), file).read_to_end(&mut opened).unwrap();

        assert_eq!(
            opened, frame,
            "the zstd frame that was already there went into the cipher as it was, \
             rather than being unpacked and packed again"
        );
    }

    #[test]
    fn an_interrupted_conversion_is_finished_rather_than_sealed_a_second_time() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("cas");
        let plain = Store::builder(&root)
            .suffix(".json")
            .compress(true)
            .build()
            .unwrap();
        let (_, entry) = plain
            .add(b"content that outlived an interrupted run")
            .unwrap();
        let frame = fs::read(entry.path()).unwrap();

        let sealed = sealed_store(&root, 3);
        assert_eq!(sealed.encrypt_all().unwrap().converted, 1);
        let sealed_path = sealed.find(entry.digest()).unwrap().unwrap();
        let ciphertext = fs::read(&sealed_path).unwrap();

        // What a crash between putting the sealed form in place and removing
        // the compressed one leaves behind: both names, one digest.
        fs::write(entry.path(), &frame).unwrap();

        let run = sealed.encrypt_all().unwrap();

        assert_eq!(run.converted, 1);
        assert!(!entry.path().exists(), "the leftover is what goes");
        assert_eq!(
            fs::read(&sealed_path).unwrap(),
            ciphertext,
            "and the sealed entry is not written a second time under the same nonce"
        );
    }

    #[test]
    fn a_stranger_under_the_new_name_does_not_cost_an_entry_its_content() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("cas");
        let plain = Store::builder(&root)
            .suffix(".json")
            .compress(true)
            .build()
            .unwrap();
        let (_, entry) = plain.add(b"the only copy there is").unwrap();

        // Not an interrupted run: an empty file under the name the conversion
        // is about to write, of the kind a killed `cp` or a restore that
        // recreated names before contents leaves behind. Taking it for a
        // finished conversion would unlink the content on the strength of a
        // name.
        let obstruction = entry.path().with_file_name(format!(
            "{}.enc",
            entry.path().file_name().unwrap().to_string_lossy()
        ));
        fs::write(&obstruction, b"").unwrap();

        let sealed = sealed_store(&root, 4);
        let run = sealed.encrypt_all().unwrap();

        assert_eq!(run.converted, 0);
        assert_eq!(run.failed.len(), 1);
        assert!(matches!(run.failed[0].error, Error::Obstructed(_)));
        assert!(entry.path().is_file(), "the content is still there");
        assert_eq!(
            plain.read(entry.digest()).unwrap().unwrap(),
            b"the only copy there is"
        );
    }

    #[test]
    fn a_streamed_entry_is_never_in_the_clear_while_it_is_being_written() {
        use std::sync::{Arc, Mutex};

        /// A source that looks into `tmp/` while the store is still reading it.
        struct Peeking {
            content: Vec<u8>,
            offset: usize,
            tmp: std::path::PathBuf,
            seen: Arc<Mutex<Vec<Vec<u8>>>>,
        }

        impl std::io::Read for Peeking {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                // Once enough has gone past for the sealer to have written a
                // chunk, take a copy of whatever is lying in tmp/.
                let mut seen = self.seen.lock().unwrap();
                if self.offset > 150_000 && seen.len() < 4 {
                    for item in fs::read_dir(&self.tmp).into_iter().flatten().flatten() {
                        match fs::read(item.path()) {
                            Ok(bytes) if !bytes.is_empty() => seen.push(bytes),
                            _ => {}
                        }
                    }
                }
                drop(seen);
                let take = out.len().min(self.content.len() - self.offset);
                out[..take].copy_from_slice(&self.content[self.offset..self.offset + take]);
                self.offset += take;
                Ok(take)
            }
        }

        let dir = TempDir::new().unwrap();
        let root = dir.path().join("cas");
        let store = sealed_store(&root, 9);
        let content = incompressible(400_000);
        let seen = Arc::new(Mutex::new(Vec::new()));

        let (_, entry) = store
            .add_reader(Peeking {
                content: content.clone(),
                offset: 0,
                tmp: root.join("tmp"),
                seen: Arc::clone(&seen),
            })
            .unwrap();

        let seen = seen.lock().unwrap();
        assert!(
            !seen.is_empty(),
            "the test proves nothing unless it caught the write in progress"
        );
        for snapshot in seen.iter() {
            assert!(
                !snapshot.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]),
                "a bare zstd frame is lying in tmp/"
            );
            assert!(
                !snapshot
                    .windows(64)
                    .any(|window| window == &content[1000..1064]),
                "the content is lying in tmp/ for anyone to read"
            );
        }
        drop(seen);

        assert_eq!(store.read(entry.digest()).unwrap().as_ref(), Some(&content));
    }

    #[test]
    fn a_compression_pass_leaves_sealed_entries_alone() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("cas");
        let store = sealed_store(&root, 1);
        let (_, entry) = store.add(b"sealed").unwrap();

        let run = store.decompress_all().unwrap();

        assert_eq!((run.converted, run.skipped), (0, 1));
        assert!(
            entry.path().is_file(),
            "decompressing one would mean unsealing it, which is not what was asked"
        );
        assert_eq!(store.compress_all().unwrap().skipped, 1);
    }

    #[test]
    fn a_store_without_a_key_refuses_to_seal() {
        let dir = TempDir::new().unwrap();
        let store = Store::builder(dir.path().join("cas"))
            .suffix(".json")
            .build()
            .unwrap();

        assert!(matches!(store.encrypt_all(), Err(Error::KeyRequired(_))));
    }

    #[test]
    fn a_key_is_never_printed() {
        let dir = TempDir::new().unwrap();
        let store = sealed_store(&dir.path().join("cas"), 1);

        let shown = format!("{store:?}");

        assert!(shown.contains("Key(…)"), "the store says it has one");
        assert!(
            !shown.contains("[1,"),
            "and not a byte of what it is: {shown}"
        );
    }

    #[test]
    fn damage_mid_stream_can_be_told_from_a_failed_disk() {
        let dir = TempDir::new().unwrap();
        let store = sealed_store(&dir.path().join("cas"), 7);
        let content = incompressible(200 * 1024);
        let (_, entry) = store.add(&content).unwrap();

        // A byte flipped well past the first chunk: the key proves itself
        // before the damage is met.
        let mut bytes = fs::read(entry.path()).unwrap();
        let at = bytes.len() - 20;
        bytes[at] ^= 0x01;
        tamper(entry.path(), &bytes);

        let mut reader = store.reader(entry.digest()).unwrap().unwrap();
        let mut out = Vec::new();
        let err = reader.read_to_end(&mut out).unwrap_err();

        // The reader speaks io::Error, and the crate's answer travels inside.
        assert!(matches!(
            Error::from_io(err, "streaming the entry"),
            Error::Damaged
        ));

        // A failure that really is I/O keeps its shape, under the context.
        let io = std::io::Error::other("the disk went away");
        assert!(matches!(
            Error::from_io(io, "streaming the entry"),
            Error::Io { .. }
        ));
    }

    #[test]
    fn what_was_set_aside_sealed_comes_back_sealed() {
        let dir = TempDir::new().unwrap();
        let store = sealed_store(&dir.path().join("cas"), 7);
        let (_, entry) = store.add(b"sealed and set aside by mistake").unwrap();
        let aside = store.quarantine(&entry).unwrap();

        let found: Vec<_> = store.quarantined().map(Result::unwrap).collect();
        assert_eq!(found.len(), 1);
        assert!(found[0].is_encrypted(), "any salvage needs the key");

        let restored = store.restore(&aside).unwrap().expect("comes back");

        assert_eq!(restored, entry, "the sealed entry it was");
        assert!(store.verify(&restored).unwrap());
    }

    #[test]
    fn a_fresh_handle_can_prove_its_key_deliberately() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("cas");
        sealed_store(&root, 7).add(b"something sealed").unwrap();

        let fresh = sealed_store(&root, 7);
        assert!(!fresh.key_proven(), "a fresh handle has opened nothing yet");
        assert!(fresh.prove_key().unwrap());
        assert!(fresh.key_proven());
        assert!(fresh.prove_key().unwrap(), "asking again costs nothing");
    }

    #[test]
    fn a_wrong_key_proves_nothing() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("cas");
        sealed_store(&root, 7).add(b"sealed under seven").unwrap();

        let wrong = sealed_store(&root, 9);

        assert!(
            !wrong.prove_key().unwrap(),
            "no false is to be trusted here"
        );
        assert!(!wrong.key_proven());
    }

    #[test]
    fn a_store_with_nothing_sealed_proves_nothing() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("cas");
        Store::builder(&root)
            .suffix(".json")
            .build()
            .unwrap()
            .add(b"a plain entry")
            .unwrap();

        let sealed = sealed_store(&root, 7);

        assert!(!sealed.prove_key().unwrap(), "nothing here can prove a key");
    }

    #[test]
    fn proving_needs_a_key() {
        let dir = TempDir::new().unwrap();
        let store = Store::builder(dir.path().join("cas")).build().unwrap();

        assert!(matches!(
            store.prove_key().unwrap_err(),
            Error::KeyRequired(_)
        ));
    }

    #[test]
    fn a_proven_key_settles_the_first_chunk_ambiguity() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("cas");
        let store = sealed_store(&root, 7);
        store.add(b"the healthy one").unwrap();
        let (_, damaged) = store.add(b"about to lose its first chunk").unwrap();
        // A byte inside the first sealed chunk, past the nonce: to a fresh
        // handle this entry alone is indistinguishable from a wrong key.
        let mut bytes = fs::read(damaged.path()).unwrap();
        bytes[21] ^= 0x01;
        tamper(damaged.path(), &bytes);

        let fresh = sealed_store(&root, 7);
        assert!(fresh.prove_key().unwrap(), "the healthy entry proves it");
        assert!(
            !fresh.verify(&damaged).unwrap(),
            "settled: damage, not a wrong key, whatever order the walk took"
        );
    }
}
