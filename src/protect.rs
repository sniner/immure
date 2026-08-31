//! Write protection on a finished entry, and getting past it again.
//!
//! An entry is named after the hash of its content, so anything that changes it
//! breaks the name. That is true by construction and until now not something
//! the file itself said: the write bits come off just before an entry takes its
//! name, so nothing that opens one finds an invitation to change it.
//!
//! Comfort, not security. It stops a slip — the editor that "repairs" the text
//! file it is displaying — and not a decision, and it says nothing about
//! deletion. Whether the filesystem carries the mode at all is not something
//! that can be asked in advance, so it is settled by trying: see
//! [`Protection`].

use std::fs;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use tracing::debug;

/// Not yet tried on this store.
const UNKNOWN: u8 = 0;
/// A `chmod` here was made and read back.
const HOLDS: u8 = 1;
/// This filesystem does not carry the mode, and is not asked again.
const IGNORED: u8 = 2;

/// What a store has found out about write protection where it lies.
///
/// Shared between the clones of one [`Store`](crate::Store) and settled once:
/// the first entry protected has its mode read back, because a desktop-mounted
/// SMB share reports a successful `chmod` and changes nothing, and a store that
/// re-learned that per entry would pay a `stat` for every write. From then on
/// the `chmod` alone is made, and the first one refused gives protection up for
/// this store for good.
///
/// Nothing here ever fails. A file that could not be protected is still a file
/// that was stored, and an entry lost over a refused `chmod` would be the
/// protection costing more than it is worth.
#[derive(Debug, Clone, Default)]
pub(crate) struct Protection {
    state: Arc<AtomicU8>,
}

impl Protection {
    /// Take the write bits off `path`, leaving the read bits alone.
    pub(crate) fn apply(&self, path: &Path) {
        match self.state.load(Ordering::Relaxed) {
            // The first entry settles it, by reading the mode back.
            UNKNOWN => {
                let holds = drop_write_bits(path) && is_read_only(path);
                self.state
                    .store(if holds { HOLDS } else { IGNORED }, Ordering::Relaxed);
                debug!(holds, "write protection settled for this store");
            }
            // Settled as holding: the `chmod` alone from here on, and the
            // first one refused gives protection up for good.
            HOLDS => {
                let held = drop_write_bits(path);
                if !held {
                    debug!("write protection no longer holds here, giving it up");
                    self.state.store(IGNORED, Ordering::Relaxed);
                }
            }
            // Given up on, and nothing else is reachable.
            _ => {}
        }
    }
}

/// Delete a file, including one this store write-protected.
///
/// Under POSIX the protection does not stand in the way: `unlink` asks the
/// directory's write bit, not the file's. Windows refuses while the read-only
/// attribute is set, which would leave a store unable to remove the very
/// entries it protected itself — so the flag comes off and the file is asked to
/// go a second time.
///
/// Whatever that second attempt says is what the caller hears: something
/// deleting a file it means to be rid of has to be told that it is still there.
pub(crate) fn remove_file(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {}
        result => return result,
    }
    debug!(path = %path.display(), "refused, lifting the write protection");
    unprotect(path);
    fs::remove_file(path)
}

/// Take the write protection back off `path`, best effort.
///
/// Windows refuses more than `unlink` while `FILE_ATTRIBUTE_READONLY` is set:
/// `MoveFileEx` will not replace such a file either, which is every entry a
/// protected store holds and every destination a key change renames onto. The
/// callers that hit that wall lift the flag and ask a second time, and this is
/// the lifting.
///
/// Best effort by design: whatever the second attempt says is what the caller
/// hears, so a protection that could not be lifted needs no answer of its own.
pub(crate) fn unprotect(path: &Path) {
    match fs::metadata(path) {
        Ok(metadata) => {
            let mut permissions = metadata.permissions();
            allow_write(&mut permissions);
            if let Err(err) = fs::set_permissions(path, permissions) {
                debug!(path = %path.display(), %err, "write protection could not be lifted");
            }
        }
        Err(err) => debug!(path = %path.display(), %err, "unreadable before a second attempt"),
    }
}

/// Make a set of permissions writable enough that the file can be deleted.
fn allow_write(permissions: &mut fs::Permissions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        // The owner's bit alone. `set_readonly(false)` hands the file to
        // everybody, which is not what lifting a protection should mean —
        // and this path is Windows's anyway.
        permissions.set_mode(permissions.mode() | 0o200);
    }
    #[cfg(not(unix))]
    permissions.set_readonly(false);
}

/// Take the write bits off, saying whether the call itself went through.
fn drop_write_bits(path: &Path) -> bool {
    let mut permissions = match fs::metadata(path) {
        Ok(metadata) => metadata.permissions(),
        Err(err) => {
            debug!(path = %path.display(), %err, "not write-protected");
            return false;
        }
    };
    permissions.set_readonly(true);
    if let Err(err) = fs::set_permissions(path, permissions) {
        debug!(path = %path.display(), %err, "not write-protected");
        return false;
    }
    true
}

/// Whether the write bits are really gone, which only a second look can say.
pub(crate) fn is_read_only(path: &Path) -> bool {
    match fs::metadata(path) {
        Ok(metadata) => metadata.permissions().readonly(),
        Err(err) => {
            debug!(path = %path.display(), %err, "unreadable right after chmod");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn file_in(dir: &Path, name: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(b"content").unwrap();
        path
    }

    fn writable(path: &Path) -> bool {
        !fs::metadata(path).unwrap().permissions().readonly()
    }

    #[test]
    fn a_protected_file_is_not_writable() {
        let dir = tempfile::tempdir().unwrap();
        let path = file_in(dir.path(), "entry");

        Protection::default().apply(&path);

        assert!(!writable(&path));
    }

    #[test]
    fn a_protected_file_can_still_be_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = file_in(dir.path(), "entry");

        Protection::default().apply(&path);

        assert_eq!(fs::read(&path).unwrap(), b"content");
    }

    #[test]
    fn a_protected_file_can_still_be_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let path = file_in(dir.path(), "entry");
        Protection::default().apply(&path);

        remove_file(&path).unwrap();

        assert!(!path.exists());
    }

    #[test]
    fn removing_something_that_is_not_there_says_so() {
        let dir = tempfile::tempdir().unwrap();

        let err = remove_file(&dir.path().join("never-was")).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn a_filesystem_that_refuses_is_not_asked_twice() {
        let dir = tempfile::tempdir().unwrap();
        let protection = Protection::default();

        // The first file settles it, and a file that is not there is the one
        // refusal available on every platform.
        protection.apply(&dir.path().join("never-was"));
        let path = file_in(dir.path(), "entry");
        protection.apply(&path);

        assert!(
            writable(&path),
            "protection was given up on, so nothing happened"
        );
    }

    #[test]
    fn what_one_clone_settles_holds_for_the_others() {
        let dir = tempfile::tempdir().unwrap();
        let protection = Protection::default();
        let clone = protection.clone();

        protection.apply(&dir.path().join("never-was"));
        let path = file_in(dir.path(), "entry");
        clone.apply(&path);

        assert!(writable(&path));
    }
}
