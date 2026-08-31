//! The half-written entry, and what happens to it when writing goes wrong.
//!
//! An entry is written to a temporary file under `<root>/tmp/` and renamed into
//! its shard only once it is complete. A rename within one filesystem is atomic
//! everywhere in practical use, so a reader sees an entry either not at all or
//! whole — never the first half of an entry that a crash cut short. That is
//! also why the temporary file lives inside the store: a rename across
//! filesystems is a copy, and a copy is not atomic.
//!
//! [`TempFile`] removes itself when dropped, so every way out of a write —
//! an I/O error, an early return, a panic — leaves the store as it was.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use tracing::debug;

use crate::error::{Context as _, Result};
use crate::protect::{self, Protection};

/// Directory for half-written entries, directly under the store root.
pub(crate) const DIR: &str = "tmp";

/// What a temporary file is called, after `<pid>-<serial>`.
const SUFFIX: &str = ".tmp";

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A file that deletes itself unless it is [`persist`](TempFile::persist)ed.
#[derive(Debug)]
pub(crate) struct TempFile {
    path: PathBuf,
    file: Option<File>,
    persisted: bool,
}

impl TempFile {
    /// Create a new temporary file in `dir`, which must exist.
    ///
    /// The name is unique per process and per creation, so several writers can
    /// work in one store without stepping on each other — including two runs
    /// storing the same content at the same time.
    pub(crate) fn create_in(dir: &Path) -> Result<Self> {
        let pid = std::process::id();
        loop {
            let serial = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = dir.join(format!("{pid}-{serial}{SUFFIX}"));
            // `create_new` refuses an existing file, so a leftover from an
            // earlier crash is never written over.
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => {
                    return Ok(TempFile {
                        path,
                        file: Some(file),
                        persisted: false,
                    });
                }
                // Taken by another writer: try the next name.
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
                Err(err) => {
                    return Err(err).ctx(|| format!("{}: creating temporary file", path.display()));
                }
            }
        }
    }

    /// Where the temporary file lies, for a second pass over what was just
    /// written to it.
    #[cfg(feature = "crypt")]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn file_mut(&mut self) -> &mut File {
        // Only `persist` takes the file, and it consumes `self`.
        self.file.as_mut().expect("temporary file is still open")
    }

    /// Flush the finished file to the device and move it to `dest`.
    ///
    /// `dest`'s parent directory has to exist.
    ///
    /// Both flushes are unconditional, and their order is the point. The
    /// content reaches the device *before* the rename, or a power cut can
    /// publish a file under a name claiming to be the hash of bytes that never
    /// arrived — and nothing would ever find out, because a store answers "is
    /// this entry here?" by looking at names, not by reading them. The
    /// directory entry is flushed *after* the rename, or the bytes survive with
    /// nothing pointing at them.
    ///
    /// Neither is optional. An entry that is present but wrong is
    /// indistinguishable from a good one, and an entry that is gone was already
    /// accounted for by whoever stored it — a caller cannot recover from either
    /// by writing the same content again, so there is no state here worth
    /// letting one opt into.
    ///
    /// One gap is left open deliberately. When this entry is the first of its
    /// shard, the directory holding it is itself a new name in the directory
    /// above, and that one is not flushed — what is synced is the shard, not its
    /// parent. Every filesystem in practical use commits the creation along with
    /// the transaction this sync forces; POSIX does not say it has to. Closing
    /// it properly would mean a second sync per shard, for a window that only
    /// exists for the first entry to land in one of 65 536 directories.
    ///
    /// Only for a `dest` that does not exist yet, which is what makes the race
    /// check in [`rename_to`](TempFile::rename_to) sound: an entry that
    /// appeared under a name nobody had taken is another writer's, holding the
    /// same content by construction. To
    /// write onto a name that is *already* an entry's — a key change, where the
    /// entry keeps its name — use [`replace`](TempFile::replace), where a
    /// rename that fails is a failure and nothing else.
    pub(crate) fn persist(self, dest: &Path, protection: &Protection) -> Result<()> {
        self.rename_to(dest, protection, true)
    }

    /// As [`persist`](TempFile::persist), onto a name that is expected to be
    /// taken.
    ///
    /// The destination existing says nothing here — it is the point — so every
    /// rename that does not happen is reported. What does not have to be
    /// reported is a destination whose own write protection is in the way:
    /// [`rename_to`](TempFile::rename_to) lifts it and asks again, because on
    /// Windows `MoveFileEx` will not replace a file carrying
    /// `FILE_ATTRIBUTE_READONLY` and that is every entry a protected store
    /// holds.
    ///
    /// Gated with the key change because that is the only thing in the crate
    /// that writes onto a name an entry already holds; nothing about it is
    /// specific to sealing.
    #[cfg(feature = "crypt")]
    pub(crate) fn replace(self, dest: &Path, protection: &Protection) -> Result<()> {
        self.rename_to(dest, protection, false)
    }

    fn rename_to(mut self, dest: &Path, protection: &Protection, may_lose: bool) -> Result<()> {
        // `file_mut` only ever borrows, so the file is still here.
        let file = self.file.take().expect("temporary file is still open");
        file.sync_all()
            .ctx(|| format!("{}: flushing to device", self.path.display()))?;
        drop(file);

        // Protection goes on here, on the temporary file and before the rename,
        // so an entry is protected from the second it carries its name and
        // there is no window in between.
        protection.apply(&self.path);

        let mut renamed = fs::rename(&self.path, dest);
        if let Err(err) = &renamed {
            if dest.is_file() {
                // Losing a race against another writer is not a failure:
                // entries are named after their content, so whoever got there
                // first put the same bytes in place. The temporary file stays
                // this call's to clean up, which is what dropping unpersisted
                // does.
                if may_lose {
                    debug!(path = %dest.display(), "entry appeared while it was being written");
                    return Ok(());
                }
                // Onto a name that is meant to be taken, and refused because
                // the file there is write-protected. Windows will not let
                // `MoveFileEx` replace a file carrying
                // `FILE_ATTRIBUTE_READONLY`, which is every entry a protected
                // store holds — so a key change would fail on all of them and
                // never be able to finish. The flag comes off and the rename is
                // asked a second time, the way `protect::remove_file` walks
                // through the same wall for `unlink`.
                //
                // Both halves of the condition are needed. `PermissionDenied`
                // is also what a rename refused for the directory's mode, a
                // sticky bit, an immutable flag or a sharing violation looks
                // like, and lifting the destination's protection does nothing
                // for any of those — it would only leave an entry of a
                // protected store writable for no gain.
                if err.kind() == io::ErrorKind::PermissionDenied && protect::is_read_only(dest) {
                    debug!(path = %dest.display(), "refused, lifting the write protection");
                    protect::unprotect(dest);
                    renamed = fs::rename(&self.path, dest);
                    if renamed.is_err() {
                        // The destination is still the store's, so it goes back
                        // to being protected. Whatever refused the second
                        // attempt is what the caller is told about.
                        protection.apply(dest);
                    }
                }
            }
        }
        if let Err(err) = renamed {
            return Err(err)
                .ctx(|| format!("{}: renaming to {}", self.path.display(), dest.display()));
        }
        self.persisted = true;

        // The rename itself is durable only once the directory entry is
        // flushed too. Best effort: not every filesystem lets a directory be
        // opened, and the rename is atomic there regardless.
        if let Some(parent) = dest.parent() {
            sync_dir(parent);
        }
        Ok(())
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if self.persisted {
            return;
        }
        if let Err(err) = protect::remove_file(&self.path) {
            debug!(path = %self.path.display(), %err, "could not remove temporary file");
        }
    }
}

/// Whether `name` is one a writer of this store hands out: `<pid>-<serial>.tmp`.
///
/// What makes a leftover the store's to remove. The temporary directory belongs
/// to the store, but a directory is still a directory — a sweep that took
/// everything in it would delete what it never wrote.
pub(crate) fn is_temp_name(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(SUFFIX) else {
        return false;
    };
    let Some((pid, serial)) = stem.split_once('-') else {
        return false;
    };
    !pid.is_empty()
        && !serial.is_empty()
        && pid
            .bytes()
            .chain(serial.bytes())
            .all(|byte| byte.is_ascii_digit())
}

/// Flush a directory entry. Failures are logged, not raised: on the platforms
/// that refuse to open a directory this costs durability of the last update
/// only, and there is nothing the caller could do about it.
fn sync_dir(path: &Path) {
    match File::open(path) {
        Ok(dir) => {
            if let Err(err) = dir.sync_all() {
                debug!(path = %path.display(), %err, "directory sync failed");
            }
        }
        Err(err) => debug!(path = %path.display(), %err, "directory not open-able for sync"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn a_dropped_temporary_file_takes_itself_with_it() {
        let dir = tempfile::tempdir().unwrap();
        let temp = TempFile::create_in(dir.path()).unwrap();
        let path = temp.path.clone();
        assert!(path.is_file());
        drop(temp);
        assert!(!path.exists());
    }

    #[test]
    fn persisting_moves_the_file_and_keeps_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut temp = TempFile::create_in(dir.path()).unwrap();
        temp.file_mut().write_all(b"content").unwrap();
        let source = temp.path.clone();
        let dest = dir.path().join("kept");

        temp.persist(&dest, &Protection::default()).unwrap();

        assert_eq!(fs::read(&dest).unwrap(), b"content");
        assert!(!source.exists());
    }

    #[test]
    #[cfg(all(unix, feature = "crypt"))]
    fn a_rename_refused_by_the_directory_leaves_the_entry_protected() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let shard = dir.path().join("shard");
        fs::create_dir(&shard).unwrap();
        let dest = shard.join("entry");
        fs::write(&dest, b"the entry that is there").unwrap();

        let protection = Protection::default();
        protection.apply(&dest);
        assert!(protect::is_read_only(&dest), "a protected store's entry");

        let mut temp = TempFile::create_in(dir.path()).unwrap();
        temp.file_mut().write_all(b"what would replace it").unwrap();

        // The directory refuses the rename, not the file — so lifting the
        // file's protection cannot help, and the file has to keep it.
        fs::set_permissions(&shard, fs::Permissions::from_mode(0o500)).unwrap();
        let refused = temp.replace(&dest, &protection);
        fs::set_permissions(&shard, fs::Permissions::from_mode(0o700)).unwrap();

        if refused.is_ok() {
            // A directory's mode does not stand in root's way, and this test
            // has nothing to say then.
            return;
        }
        assert!(protect::is_read_only(&dest), "still protected");
        assert_eq!(fs::read(&dest).unwrap(), b"the entry that is there");
    }

    #[test]
    fn every_temporary_file_gets_its_own_name() {
        let dir = tempfile::tempdir().unwrap();
        let first = TempFile::create_in(dir.path()).unwrap();
        let second = TempFile::create_in(dir.path()).unwrap();
        assert_ne!(first.path, second.path);
    }

    #[test]
    fn a_temporary_file_is_recognised_by_its_name() {
        let dir = tempfile::tempdir().unwrap();
        let temp = TempFile::create_in(dir.path()).unwrap();
        let name = temp.path.file_name().unwrap().to_str().unwrap();
        assert!(is_temp_name(name), "{name}");

        assert!(is_temp_name("1234-0.tmp"));
        assert!(!is_temp_name("1234-0.tmp.bak"), "not the whole name");
        assert!(!is_temp_name("state.json.tmp"), "somebody else's");
        assert!(!is_temp_name("-0.tmp"), "no pid");
        assert!(!is_temp_name("1234-.tmp"), "no serial");
        assert!(!is_temp_name("1234-0"), "no suffix");
    }
}
