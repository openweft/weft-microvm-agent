//go:build linux

// properties_linux.go — concrete ApplyFunc for the properties
// subscriber. Mirrors the desired set to a POSIX tree under root :
// each property key becomes a file (with directory nesting on "/"),
// values are written atomically (tmp + rename per file), and files
// that aren't in the desired set anymore are removed.
//
// The whole sync isn't transactional — partial application is the
// realistic worst case (e.g. crash mid-sync). The next publish from
// the host converges the tree ; a reader catching the partial state
// sees a subset, never a corrupted file (per-file rename is atomic).

package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/openweft/weft-vm-agent/pkg/properties"
)

// propertiesApplyer returns an ApplyFunc that syncs the property
// tree under root. The directory is created on first apply ; the
// caller is expected to point at /run/weft/properties (tmpfs) in
// production so the tree clears on reboot.
func propertiesApplyer(root string) properties.ApplyFunc {
	return func(ps properties.PropertySet) error {
		if err := os.MkdirAll(root, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", root, err)
		}

		// Index the desired set as full filesystem paths so the
		// garbage-collection pass below can do an O(1) lookup.
		want := make(map[string]string, len(ps.Properties))
		for k, v := range ps.Properties {
			want[filepath.Join(root, k)] = v
		}

		// Walk the existing tree, delete files not in want.
		existing, err := collectFiles(root)
		if err != nil {
			return fmt.Errorf("walk %s: %w", root, err)
		}
		for _, p := range existing {
			if _, keep := want[p]; keep {
				continue
			}
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove stale %s: %w", p, err)
			}
		}

		// Write desired entries. Sort for deterministic ordering
		// (helps when reading logs / debugging an apply).
		keys := make([]string, 0, len(ps.Properties))
		for k := range ps.Properties {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, k := range keys {
			path := filepath.Join(root, k)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return fmt.Errorf("mkdir parent of %s: %w", path, err)
			}
			tmp := path + ".tmp"
			if err := os.WriteFile(tmp, []byte(ps.Properties[k]), 0o644); err != nil {
				return fmt.Errorf("write tmp %s: %w", tmp, err)
			}
			if err := os.Rename(tmp, path); err != nil {
				_ = os.Remove(tmp)
				return fmt.Errorf("rename %s -> %s: %w", tmp, path, err)
			}
		}

		// Best-effort prune of now-empty directories left behind by
		// removed nested keys. Errors are non-fatal — extra empty
		// dirs don't break correctness, they're just noise.
		pruneEmptyDirs(root, root)
		return nil
	}
}

// collectFiles returns absolute paths of every regular file under
// root (skips symlinks + directories — properties are plain files).
func collectFiles(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		// Skip our own .tmp files — they're transient artefacts of a
		// concurrent write, not real properties.
		if filepath.Ext(p) == ".tmp" {
			return nil
		}
		out = append(out, p)
		return nil
	})
	return out, err
}

// pruneEmptyDirs walks dir bottom-up and removes empty directories.
// stops at root (never removes the property-tree root itself).
func pruneEmptyDirs(root, dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pruneEmptyDirs(root, filepath.Join(dir, e.Name()))
	}
	if dir == root {
		return
	}
	// ReadDir again — pruning may have left dir empty.
	if entries, _ := os.ReadDir(dir); len(entries) == 0 {
		_ = os.Remove(dir)
	}
}
