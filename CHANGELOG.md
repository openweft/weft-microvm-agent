# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2026-11-25

### Added

- **Guest secrets on dynamic mounts** : a `weft.mounts.<vmID>` message may
  carry `access_key_ref` / `secret_key_ref` (GuestSecrets secret ids) and a
  `secret_version` instead of inline keys. The agent fetches them over
  AF_VSOCK (`--guestplane-port`, default 7777) from the host's
  `weft.guest.v1.GuestSecrets/Fetch`, wipes the buffers once the cfs-client
  config (0600) is written, and refetches when a re-published message
  carries a different `secret_version` (rotation = unmount + remount). A
  failed fetch leaves the existing mount up. A ref set together with its
  inline field is refused. Inline keys still work, with a deprecation
  warning. Off Linux there is no vsock transport: refs are refused.
- Bumps `weft-microvm-init` to v0.4.0 and `weft-proto` to v0.24.0. The
  `BindStream` fix of v0.4.3 is untouched.

## [0.3.1] - 2026-06-14

### Fixed

- **Shutdown leaks** : the SIGTERM handler now closes the embedded
  sshd listener and calls `cubefs.Registry.UnmountAll()` before
  `GracefulStop`. Pre-fix, the sshd Accept loop survived as a
  leaked goroutine until poweroff, and live CubeFS FUSE mounts
  (plus their `cfs-client` processes) outlived a cooperative
  shutdown — preventing the same VM's reboot from cleanly
  re-mounting at the same paths. The sshd path also swallows
  `net.ErrClosed` from the deliberate close so the shutdown log
  stays quiet on the happy path.

### Added

- **Firewall status emitter** (reverse direction of the SG
  subscriber). New `pkg/firewallstatus` runs a 10-second ticker
  (`--firewall-status-every`) that polls the in-VM nftables
  `weft-fw` table via `network.ReadFirewallStatus` and publishes
  a `pod.FirewallStatus` JSON on `weft.firewall.<vm-id>.status`.
  Same pattern `weft-router`'s `statusemitter` uses for its
  `RouterStatus`. Auto-active when `--firewall-vm-id` is set ;
  first publish fires immediately on Run entry so dashboards see
  a value inside a second of boot. New `firewall_linux.go` /
  `firewall_other.go` tag split binds `firewallStatusRead` to
  `network.ReadFirewallStatus` on Linux and to a "requires linux"
  stub on darwin. Commit `354de43`.

## [0.2.0] - 2026-06-02

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
