# Security model

Incident Pack creates diagnostic evidence intended for human review and service desk escalation. Diagnostic logs are untrusted, potentially sensitive input. The tool therefore minimises collection before applying redaction and archive controls.

This document defines the version 0.1 security boundary. It is a contract, not a claim that automated redaction can recognise every secret format.

## Assets

Incident Pack must protect:

- credentials, tokens and private-key material that may appear in logs;
- host and user identifiers that are unnecessary for escalation;
- diagnostic evidence while it is staged and archived;
- the integrity of the bundle and its checksum manifest;
- the host from command injection, unintended network activity and privilege escalation.

## Trust boundaries

Untrusted data enters through:

- command-line service names, durations, paths, exclusions and network targets;
- TOML configuration;
- output from system commands and virtual files;
- journal messages;
- existing archives supplied to `--verify`.

Every boundary requires strict parsing, size limits and generic error reporting. Host output never becomes a command, path or configuration instruction.

## Threats and controls

### Command injection

Service names and targets use narrow parsers. Subprocesses receive argument arrays and fixed executables. The implementation must not use `shell=True`, `eval`, sourced host files or user-defined command templates.

### Information disclosure

Collection uses an evidence allowlist. Version 0.1 prohibits environment variables, process arguments, arbitrary file content, credential stores, private keys, shell history and configuration contents. Journal free text will be redacted before it is written to staging and scanned again for mandatory forbidden forms.

Package names, service names and requested network targets can still identify a system's purpose. A human must inspect the completed bundle before sharing it.

### Tampering and unsafe archives

The manifest records the size and SHA-256 of every evidence artifact. The manifest cannot contain its own checksum or a post-build verification result. The verifier independently rejects missing, extra, duplicate or mismatched files and unsafe member types or paths.

Only a successfully verified archive is published. The command prints its SHA-256 after verification so the digest can be recorded outside the archive.

### Denial of service

Inputs, subprocess duration, journal range, record count, individual message size, artifact size, total uncompressed content and archive size are bounded. Collection streams free text rather than accumulating an unbounded journal in memory.

### Privilege escalation

Incident Pack never invokes `sudo`, `su` or another elevation mechanism. Non-root collection records inaccessible evidence as unavailable. A process already running as effective UID 0 must receive explicit `--allow-root` acknowledgement. Root execution does not widen the evidence allowlist or remove limits.

### Network surprise

No active external check runs by default. DNS and TCP checks require explicit targets, have bounded timeouts and target counts, and send no application payload. The tool never reads proxy environment variables.

## Prohibited sources

The following sources cannot be re-enabled by configuration:

- process environments and command lines;
- private keys, credential stores and authentication databases;
- memory dumps, packet captures and browser data;
- shell history, arbitrary logs and arbitrary paths;
- configuration-file contents;
- user-defined shell commands;
- automatic uploads or ticket-system integrations.

Configuration may exclude allowed artifacts or reduce limits. It cannot add a new evidence source.

## Staging and publication

The collector will create a private staging directory with mode `0700`. Regular staged files and the final archive use mode `0600`. Existing outputs and symlink outputs are refused. Failure before verification removes the temporary archive and does not publish a final bundle.

Archive members must use safe relative POSIX paths. Absolute paths, traversal components, duplicate names, links, devices, FIFOs, sockets and undeclared members are rejected.

## Failure semantics

Unavailable evidence is not a successful check. Each planned artifact is marked `collected`, `excluded`, `skipped` or `error`. Truncation is explicit. A bundle is `partial` when any artifact is not collected or is truncated.

A security-boundary failure prevents publication. An optional capability failure may still produce a verified partial bundle whose summary explains the limitation.

## Residual risks

- Unknown or unusually encoded secrets may evade built-in redaction rules.
- File metadata, package names, service names and user-requested targets may still reveal operational context.
- SHA-256 protects integrity comparison but does not encrypt evidence or prove who created it.
- A privileged caller can read more host evidence even though the source allowlist is unchanged.
- A verified archive is structurally consistent, not automatically appropriate for a particular recipient.

Users must inspect a bundle before sharing it and apply an approved external encryption process when policy requires encryption.
