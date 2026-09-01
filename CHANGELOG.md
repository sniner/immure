# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com).

## [Unreleased]

### Added

- **`Builder::suffix`** honours the empty string (or a lone dot) as "no suffix": entries are then
  named by digest alone, with only `.zst` / `.zst.enc` on top. Previously an empty suffix fell
  back to `.dat`

## [0.1.0] - 2026-08-31

Initial release.
