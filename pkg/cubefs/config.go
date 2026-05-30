// Package cubefs mounts a CubeFS volume inside the guest by driving the
// CubeFS FUSE client (cfs-client) — CubeFS being the platform's RWX share
// backend (a CNCF distributed POSIX + S3 filesystem, since it replaced the
// SFTP server). The mount is a real kernel FUSE mount, transparent to
// every guest process and (via bind-mounts) to containers.
//
// cfs-client is itself a Go FUSE daemon ; we generate its config, exec it,
// and manage its lifetime in a Registry so dynamic event-bus updates can
// mount/unmount/replace by ID — the propagation path (pkg/mounts) is
// unchanged from the SFTP backend; only this engine differs.
package cubefs

import (
	"encoding/json"
	"strings"

	"github.com/openweft/weft-microvm-init/pkg/pod"
)

// Binary is the cfs-client executable. The guest image / initrd provides
// it (CubeFS's client is Go). Overridable for tests / non-PATH installs.
var Binary = "cfs-client"

// clientCfg is the subset of cfs-client's config.json we set. Field names
// match CubeFS's client config schema.
type clientCfg struct {
	MountPoint string `json:"mountPoint"`
	VolName    string `json:"volName"`
	Owner      string `json:"owner"`
	MasterAddr string `json:"masterAddr"` // comma-separated host:port list
	LogDir     string `json:"logDir"`
	LogLevel   string `json:"logLevel"`
	AccessKey  string `json:"accessKey,omitempty"`
	SecretKey  string `json:"secretKey,omitempty"`
	SubDir     string `json:"subdir,omitempty"`
	ReadOnly   bool   `json:"rdonly,omitempty"`
}

// clientConfig renders the cfs-client config.json for a CubeFS share mount.
// Pure (no I/O), so it's unit-testable without a cluster.
func clientConfig(spec pod.ShareMount, logDir string) ([]byte, error) {
	c := spec.CubeFS
	cfg := clientCfg{
		MountPoint: spec.MountPoint,
		VolName:    c.Volume,
		Owner:      c.Owner,
		MasterAddr: strings.Join(c.Masters, ","),
		LogDir:     logDir,
		LogLevel:   "warn",
		AccessKey:  c.AccessKey,
		SecretKey:  c.SecretKey,
		SubDir:     c.SubDir,
		ReadOnly:   spec.Readonly,
	}
	return json.MarshalIndent(cfg, "", "  ")
}
