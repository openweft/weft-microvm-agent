// Copyright (c) the openweft/weft-microvm-agent authors.
// SPDX-License-Identifier: BSD-3-Clause

// Package atomicfile writes a file's whole content in one durable,
// crash-safe step: a reader either sees the previous content or the
// new content, never a partial write.
//
// The recipe is the standard one — create a temporary file in the
// SAME directory as the target (so os.Rename is a same-filesystem
// atomic replace), write the bytes, set the mode (and optionally the
// owner), fsync the file so the data reaches stable storage, close,
// rename over the target, then fsync the PARENT directory so the
// rename itself is durable across a crash. On any failure the
// temporary file is removed and the original target is left untouched.
//
// Every syscall the flow depends on is reachable through a package
// function variable so the error branches are drivable in tests on
// any OS (see the seams below); production code never touches them.
package atomicfile

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Seams. Each is a thin wrapper over the real syscall so a test can
// swap it for a failing stub and exercise the matching error branch.
// They are unexported and restored via defer in tests.
var (
	createTemp = func(dir, pattern string) (*os.File, error) { return os.CreateTemp(dir, pattern) }
	writeAll   = func(f *os.File, data []byte) (int, error) { return f.Write(data) }
	chmodFile  = func(f *os.File, perm fs.FileMode) error { return f.Chmod(perm) }
	chownFile  = func(f *os.File, uid, gid int) error { return f.Chown(uid, gid) }
	syncFile   = func(f *os.File) error { return f.Sync() }
	closeFile  = func(f *os.File) error { return f.Close() }
	renameFile = os.Rename
	removeFile = os.Remove
	syncDir    = fsyncDir
)

// options holds the resolved Option values. uid/gid default to -1,
// meaning "leave ownership as the process created it" (no chown).
type options struct {
	uid int
	gid int
}

// Option customises a Write.
type Option func(*options)

// WithOwner requests that the target be chowned to uid:gid before it
// is renamed into place. Passing a negative uid OR gid is a no-op —
// the caller can pass through unknown/irrelevant ids (as on darwin,
// where the agent's chown is not meaningful) without a branch of its
// own.
func WithOwner(uid, gid int) Option {
	return func(o *options) {
		o.uid = uid
		o.gid = gid
	}
}

// Write atomically replaces the file at path with data, giving the
// result mode perm. The parent directory of path must already exist
// and be writable. See the package doc for the durability contract.
func Write(path string, data []byte, perm fs.FileMode, opts ...Option) error {
	o := options{uid: -1, gid: -1}
	for _, opt := range opts {
		opt(&o)
	}

	dir := filepath.Dir(path)
	f, err := createTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp in %s: %w", dir, err)
	}
	tmp := f.Name()

	// abort closes and removes the temp file, then wraps err. Both
	// cleanup steps are best-effort — the caller already has a real
	// failure to act on.
	abort := func(err error) error {
		_ = closeFile(f)
		_ = removeFile(tmp)
		return err
	}

	if _, err := writeAll(f, data); err != nil {
		return abort(fmt.Errorf("write temp %s: %w", tmp, err))
	}
	if err := chmodFile(f, perm); err != nil {
		return abort(fmt.Errorf("chmod temp %s: %w", tmp, err))
	}
	if o.uid >= 0 && o.gid >= 0 {
		if err := chownFile(f, o.uid, o.gid); err != nil {
			return abort(fmt.Errorf("chown temp %s to %d:%d: %w", tmp, o.uid, o.gid, err))
		}
	}
	if err := syncFile(f); err != nil {
		return abort(fmt.Errorf("fsync temp %s: %w", tmp, err))
	}
	if err := closeFile(f); err != nil {
		_ = removeFile(tmp)
		return fmt.Errorf("close temp %s: %w", tmp, err)
	}
	if err := renameFile(tmp, path); err != nil {
		_ = removeFile(tmp)
		return fmt.Errorf("rename %s -> %s: %w", tmp, path, err)
	}
	// The data is durable and the target now points at it; make the
	// rename itself durable by fsyncing the directory that holds the
	// (now-renamed) entry.
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("fsync dir %s: %w", dir, err)
	}
	return nil
}

// fsyncDir opens dir and fsyncs it, forcing the directory entry
// changed by the rename to stable storage.
func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
