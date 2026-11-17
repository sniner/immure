# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com).

## [Unreleased]

### Fixed

- **A batch that could not be named lost its entries**: when flushing or renaming failed (a full
  disk, a share that went away), the temporary files of the entries not named yet were removed,
  although `add` had answered for them, and the next `Store::flush` succeeded with nothing left
  to do. These entries now stay in the batch, the store keeps answering for them, and the next
  flush tries them again

## [0.4.0] - 2026-11-16

### Breaking changes

- **Flushing**: a store now flushes in batches by default (`Flush::Batch` of 100). A new entry
  gets its name, and its file is at `Entry::path`, when its batch is named: after 100 entries,
  at `Store::flush`, or when the last handle onto the store is dropped. Until then it reads back
  like any other entry. For the behaviour of 0.3, build the store with `.flush(Flush::Each)`

### Added

- **`Builder::flush`** and **`Flush`**: `Each` flushes every entry before `add` returns,
  `Batch(n)` flushes n entries together with two device flushes instead of two per entry, and
  `OnRequest` names entries at once and flushes them only at `Store::flush`. On macOS a batch
  costs the drive one cache flush instead of one per file
- **`Store::flush`**, **`Store::flushes`**, and **`Store::with_flush`** for a handle onto the same
  store that flushes another way
- **`send_to_device`** and **`flush_device`**: the two halves of `sync_file`, for a caller that
  flushes several files of its own together

### Changed

- **`compress_all`, `decompress_all`, `encrypt_all`, `decrypt_all`, `change_key`** replace entries
  in batches of the store's batch size, 100 under `Flush::OnRequest`. The old files are removed
  only after the new ones are flushed

## [0.3.3] - 2026-11-05

### Added

- **`Builder::create_root`**: with `false`, a write no longer makes the store's root directory
  when it is missing, and fails with the new `Error::RootMissing` instead. Shard directories
  below an existing root are still made. For a caller that renames a store directory as a
  whole: a writer arriving after the rename does not bring the directory back under its old
  name

### Changed

- **Two writers storing the same content at once**: the one that loses the race no longer
  renames onto the name the other took. It leaves the name alone, reads the other writer's
  entry back and checks it against the digest; an entry that does not match is reported as
  `Error::Obstructed`. On macOS over SMB a rename onto a taken name is two steps, and two
  writers doing it at once could leave the name with an empty file

## [0.3.2] - 2026-11-04

### Added

- **`sync_file`**: flushes a file to the device the same way the store flushes its entries, so
  a caller that writes a file of its own next to a store gets the same fallback to `fsync` on
  macOS filesystems without `F_FULLFSYNC`, such as SMB mounts

## [0.3.1] - 2026-11-04

### Fixed

- **macOS, SMB mounts**: storing an entry no longer fails with `flushing to device: Operation not
  supported (os error 45)`. Where a filesystem does not support `F_FULLFSYNC`, the entry is
  flushed with `fsync` instead

## [0.3.0] - 2026-09-01

### Breaking changes

- **Sealed frame**: a sealed blob now starts with a self-describing header — magic bytes `immr`
  and a format version — ahead of the nonce. Blobs sealed by 0.2.x or earlier no longer open;
  re-seal them by running `decrypt_all` with the old version, then `encrypt_all` with this one.
  A frame declaring a newer version than the build understands is refused as the new
  `Error::FrameVersion` instead of being mistaken for a wrong key or damage, so it is never
  quarantined

## [0.2.0] - 2026-09-01

### Added

- **`Builder::suffix`** honours the empty string (or a lone dot) as "no suffix": entries are then
  named by digest alone, with only `.zst` / `.zst.enc` on top. Previously an empty suffix fell
  back to `.dat`

## [0.1.0] - 2026-08-31

Initial release.
