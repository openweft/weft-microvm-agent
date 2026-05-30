// boot.go — concrete Cloner + Puller injected into boot.Runner.
// Both libs are pure-Go (go-git, oras-go) so this file builds on
// linux and darwin alike — no /usr/bin/git in the ramdisk and no
// build-tag split. The Runner hooks stay the seam tests use.

package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"

	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/openweft/weft-microvm-agent/pkg/boot"
)

// gitClone is the boot.Runner.Cloner production wiring. Honours ctx
// (caller's timeout / cancel). Cloning is full (no --depth=1) because
// go-git's ref resolution covers branch / tag / commit-sha in one
// API surface only on a full clone ; first-boot payloads are small
// enough that the size trade-off doesn't matter.
func gitClone(ctx context.Context, url, ref, dst string) error {
	repo, err := git.PlainCloneContext(ctx, dst, false, &git.CloneOptions{URL: url})
	if err != nil {
		return fmt.Errorf("clone %s: %w", url, err)
	}
	if ref == "" {
		return nil
	}
	// ResolveRevision handles "<sha>", "<branch>", "<tag>", and
	// short SHAs uniformly — no need to guess which kind of ref the
	// operator stamped.
	hash, err := repo.ResolveRevision(plumbing.Revision(ref))
	if err != nil {
		return fmt.Errorf("resolve %q: %w", ref, err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		return err
	}
	if err := wt.Checkout(&git.CheckoutOptions{Hash: *hash}); err != nil {
		return fmt.Errorf("checkout %q (%s): %w", ref, hash, err)
	}
	return nil
}

// ociPull is the boot.Runner.Puller production wiring. Uses ORAS to
// fetch an OCI artifact (any media type — tarball, raw files, helm
// chart, ...) into dst as a file.Store. url is the repository
// reference (e.g. "ghcr.io/openweft/boot-payload") ; ref is a tag or
// digest. Defaults to "latest" when ref is empty, mirroring docker
// pull semantics.
//
// Anonymous pulls only — private registries need an auth.Client
// wired here later. For openweft's own boot payloads (public OCI
// artifacts on GHCR) anonymous suffices.
func ociPull(ctx context.Context, url, ref, dst string) error {
	if ref == "" {
		ref = "latest"
	}
	// remote.NewRepository expects "host/repo" — strip scheme if the
	// operator stamped a full URL.
	url = strings.TrimPrefix(url, "oci://")
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")

	if err := os.MkdirAll(dst, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dst, err)
	}
	store, err := file.New(dst)
	if err != nil {
		return fmt.Errorf("file store %s: %w", dst, err)
	}
	defer store.Close()

	repo, err := remote.NewRepository(url)
	if err != nil {
		return fmt.Errorf("repo %s: %w", url, err)
	}
	if _, err := oras.Copy(ctx, repo, ref, store, ref, oras.DefaultCopyOptions); err != nil {
		return fmt.Errorf("oras copy %s@%s: %w", url, ref, err)
	}
	return nil
}

// bootRunner is the production wiring of boot.Runner. Centralised
// here so main.go's startup block stays focused on flag parsing.
func bootRunner(workDir, sentinelPath string, logOut interface{ Write([]byte) (int, error) }) *boot.Runner {
	return &boot.Runner{
		WorkDir:      workDir,
		SentinelPath: sentinelPath,
		LogOut:       logOut,
		Cloner:       gitClone,
		Puller:       ociPull,
	}
}
