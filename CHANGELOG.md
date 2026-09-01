# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com).

## [Unreleased]

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
