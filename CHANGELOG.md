# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Breaking:** `Config.MaxAnnouncements` has no default of 16 and no maximum of 256: zero now means no cap, any positive number is a cap, and a negative one is `ErrInvalidConfig`.
- **Breaking:** `Config.MaxRecordsPerTopic` and `Config.MaxRecordsPerIP` no longer have a range maximum of 65536: a larger value is now accepted, where it returned `ErrInvalidConfig`. Both only count records against `MaxRecords`, which bounds the memory of the store, so a value above `MaxRecords` has the effect of `MaxRecords`. A value below 1 is still invalid.

## [0.1.0] - 2026-11-20

### Added

- First release of kolo-dht.
