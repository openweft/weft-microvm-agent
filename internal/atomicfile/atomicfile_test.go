// Copyright (c) the openweft/weft-microvm-agent authors.
// SPDX-License-Identifier: BSD-3-Clause

package atomicfile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// restoreSeams snapshots every seam and returns a func that restores
// them, so a failing-stub test never leaks into the next one.
func restoreSeams(t *testing.T) {
	t.Helper()
	ct, wa, cm, cw, sf, cf, rn, rm, sd := createTemp, writeAll, chmodFile, chownFile, syncFile, closeFile, renameFile, removeFile, syncDir
	t.Cleanup(func() {
		createTemp, writeAll, chmodFile, chownFile, syncFile, closeFile, renameFile, removeFile, syncDir = ct, wa, cm, cw, sf, cf, rn, rm, sd
	})
}

var errBoom = errors.New("boom")

// TestWriteHappyPath proves the real atomic replace end to end: the
// target ends up with the exact bytes and perm, and no temp file is
// left behind in the directory.
func TestWriteHappyPath(t *testing.T) {
	restoreSeams(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "file")

	want := []byte("hello atomic world")
	if err := Write(target, want, 0o640); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("content = %q, want %q", got, want)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("perm = %o, want 0640", info.Mode().Perm())
	}

	// No temp artefact must remain.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "file" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("dir entries = %v, want exactly [file]", names)
	}
}

// TestWriteReplacesExisting proves an existing target is overwritten
// atomically (previous content fully replaced, perm re-applied).
func TestWriteReplacesExisting(t *testing.T) {
	restoreSeams(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "file")
	if err := os.WriteFile(target, []byte("OLD CONTENT LONGER"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := Write(target, []byte("new"), 0o644); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "new" {
		t.Fatalf("content = %q, want %q", got, "new")
	}
	info, _ := os.Stat(target)
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("perm = %o, want 0644", info.Mode().Perm())
	}
}

// TestWriteWithOwnerNoop drives the WithOwner path where uid/gid are
// negative — chown must be skipped. We assert chownFile is NOT called.
func TestWriteWithOwnerNoop(t *testing.T) {
	restoreSeams(t)
	called := false
	chownFile = func(f *os.File, uid, gid int) error { called = true; return nil }

	dir := t.TempDir()
	target := filepath.Join(dir, "file")
	if err := Write(target, []byte("x"), 0o600, WithOwner(-1, 1000)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if called {
		t.Fatal("chownFile was called for a negative uid; expected no-op")
	}
}

// TestWriteWithOwnerApplied drives the chown branch through the REAL
// (unstubbed) chownFile seam with the process's own uid/gid, which
// always succeed without privilege — so the default seam body itself
// is exercised, not a stub.
func TestWriteWithOwnerApplied(t *testing.T) {
	restoreSeams(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "file")
	if err := Write(target, []byte("x"), 0o600, WithOwner(os.Getuid(), os.Getgid())); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("target missing after owner-applied write: %v", err)
	}
}

// tmpCount counts non-directory entries whose name marks them as our
// temp files, to assert cleanup on the error paths.
func leftoverTemps(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	n := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) != "" || e.Name()[0] == '.' {
			n++
		}
	}
	return n
}

func TestWriteCreateTempFails(t *testing.T) {
	restoreSeams(t)
	createTemp = func(dir, pattern string) (*os.File, error) { return nil, errBoom }
	err := Write(filepath.Join(t.TempDir(), "f"), []byte("x"), 0o600)
	if !errors.Is(err, errBoom) {
		t.Fatalf("err = %v, want errBoom", err)
	}
}

func TestWriteWriteFails(t *testing.T) {
	restoreSeams(t)
	dir := t.TempDir()
	writeAll = func(f *os.File, data []byte) (int, error) { return 0, errBoom }
	err := Write(filepath.Join(dir, "f"), []byte("x"), 0o600)
	if !errors.Is(err, errBoom) {
		t.Fatalf("err = %v, want errBoom", err)
	}
	if n := leftoverTemps(t, dir); n != 0 {
		t.Fatalf("leftover temp files = %d, want 0", n)
	}
}

func TestWriteChmodFails(t *testing.T) {
	restoreSeams(t)
	dir := t.TempDir()
	chmodFile = func(f *os.File, perm fs.FileMode) error { return errBoom }
	err := Write(filepath.Join(dir, "f"), []byte("x"), 0o600)
	if !errors.Is(err, errBoom) {
		t.Fatalf("err = %v, want errBoom", err)
	}
	if n := leftoverTemps(t, dir); n != 0 {
		t.Fatalf("leftover temp files = %d, want 0", n)
	}
}

func TestWriteChownFails(t *testing.T) {
	restoreSeams(t)
	dir := t.TempDir()
	chownFile = func(f *os.File, uid, gid int) error { return errBoom }
	err := Write(filepath.Join(dir, "f"), []byte("x"), 0o600, WithOwner(0, 0))
	if !errors.Is(err, errBoom) {
		t.Fatalf("err = %v, want errBoom", err)
	}
	if n := leftoverTemps(t, dir); n != 0 {
		t.Fatalf("leftover temp files = %d, want 0", n)
	}
}

func TestWriteFsyncFails(t *testing.T) {
	restoreSeams(t)
	dir := t.TempDir()
	syncFile = func(f *os.File) error { return errBoom }
	err := Write(filepath.Join(dir, "f"), []byte("x"), 0o600)
	if !errors.Is(err, errBoom) {
		t.Fatalf("err = %v, want errBoom", err)
	}
	if n := leftoverTemps(t, dir); n != 0 {
		t.Fatalf("leftover temp files = %d, want 0", n)
	}
}

func TestWriteCloseFails(t *testing.T) {
	restoreSeams(t)
	dir := t.TempDir()
	closeFile = func(f *os.File) error { _ = f.Close(); return errBoom }
	err := Write(filepath.Join(dir, "f"), []byte("x"), 0o600)
	if !errors.Is(err, errBoom) {
		t.Fatalf("err = %v, want errBoom", err)
	}
	if n := leftoverTemps(t, dir); n != 0 {
		t.Fatalf("leftover temp files = %d, want 0", n)
	}
}

// TestWriteRenameFailsLeavesOriginal proves a failed rename removes
// the temp file AND leaves the original target byte-for-byte intact.
func TestWriteRenameFailsLeavesOriginal(t *testing.T) {
	restoreSeams(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "file")
	original := []byte("ORIGINAL DO NOT TOUCH")
	if err := os.WriteFile(target, original, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	renameFile = func(oldpath, newpath string) error { return errBoom }
	err := Write(target, []byte("replacement"), 0o600)
	if !errors.Is(err, errBoom) {
		t.Fatalf("err = %v, want errBoom", err)
	}
	got, rerr := os.ReadFile(target)
	if rerr != nil {
		t.Fatalf("ReadFile: %v", rerr)
	}
	if string(got) != string(original) {
		t.Fatalf("target mutated on failed rename: got %q, want %q", got, original)
	}
	// Only the original file must remain.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != "file" {
		t.Fatalf("dir not clean after failed rename: %v", entries)
	}
}

func TestWriteSyncDirFails(t *testing.T) {
	restoreSeams(t)
	dir := t.TempDir()
	syncDir = func(string) error { return errBoom }
	err := Write(filepath.Join(dir, "f"), []byte("x"), 0o600)
	if !errors.Is(err, errBoom) {
		t.Fatalf("err = %v, want errBoom", err)
	}
	// Rename already succeeded before the dir fsync, so the target
	// exists even though Write reports the durability failure.
	if _, serr := os.Stat(filepath.Join(dir, "f")); serr != nil {
		t.Fatalf("target missing after rename+syncDir-fail: %v", serr)
	}
}

// TestFsyncDirOpenError covers the os.Open error branch of the real
// fsyncDir (the default syncDir), which the happy path never hits.
func TestFsyncDirOpenError(t *testing.T) {
	restoreSeams(t)
	if err := fsyncDir(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("fsyncDir on missing dir: want error, got nil")
	}
}
