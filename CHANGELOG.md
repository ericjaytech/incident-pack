# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-08-30

### Added

- Preview, collection and verification commands for one systemd service.
- Fixed allowlist collectors for service state, resource pressure, bounded journal records,
  installed package metadata and service-unit metadata.
- Explicit, bounded DNS and TCP checks that send no application payload.
- Streaming redaction, hard size and duration limits, configurable artifact exclusions and clear
  root-execution acknowledgement.
- Private archive staging, deterministic manifests, artifact checksums and verification before
  publication.
- Concise summaries with partial-result, truncation and redaction reporting.
- Python and shell quality gates for the primary Ubuntu and Python versions.

### Security

- Environment variables, process arguments, private keys, credential stores, arbitrary paths and
  configuration-file contents are outside the collection contract.
- Existing outputs, symlink outputs, unsafe archive members and forbidden content are rejected.

[Unreleased]: https://github.com/ericjaytech/incident-pack/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ericjaytech/incident-pack/releases/tag/v0.1.0
