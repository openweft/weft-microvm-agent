# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Dynamic security-group subscriber** : new firewall concern
  wires the NATS-driven config applier pattern (one Subscriber +
  one ApplyFunc) to the host-side SG ruleset. Reconciles via
  nftables against the in-VM `pod.Firewall` type from
  `weft-microvm-init`. Idempotent ; missed publishes self-heal on
  the next message. Commit `6d0e970`.

### Fixed

- **Shutdown handling** (real bug) : `agent` now closes NATS
  connections and cancels the `watchAndRunBoot` context on
  shutdown, then reaps the `cfs-client` subprocess. Previously a
  SIGTERM would leak the NATS conn + leave `cfs-client` orphaned
  until the kernel cleaned up. Commit `11f1275`.

## [0.1.0] - 2026-05-31

Initial release. In-VM agent for weft microVMs. NATS-driven
config applier (one Subscriber + ApplyFunc per concern : mesh
WireGuard, mounts SFTP/FUSE, firewall nftables). BSD 3-Clause
LICENSE (`7758001`).
