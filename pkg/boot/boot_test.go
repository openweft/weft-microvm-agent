package boot

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadFromPropertiesDir_AllMissing(t *testing.T) {
	c, err := ReadFromPropertiesDir(t.TempDir())
	if err != nil {
		t.Fatalf("ReadFromPropertiesDir: %v", err)
	}
	if !c.IsEmpty() {
		t.Errorf("missing files should yield empty Config, got %+v", c)
	}
}

func TestReadFromPropertiesDir_Loads(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "weft.boot"), 0o755); err != nil {
		t.Fatal(err)
	}
	writes := map[string]string{
		"weft.boot/source.kind": "git\n",
		"weft.boot/source.url":  "https://example.com/repo.git\n",
		"weft.boot/source.ref":  "main",
		"weft.boot/script":      "#!/bin/sh\necho hi\n",
	}
	for k, v := range writes {
		if err := os.WriteFile(filepath.Join(dir, k), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	c, err := ReadFromPropertiesDir(dir)
	if err != nil {
		t.Fatalf("ReadFromPropertiesDir: %v", err)
	}
	if c.SourceKind != "git" || c.SourceURL != "https://example.com/repo.git" || c.SourceRef != "main" {
		t.Errorf("config mis-read: %+v", c)
	}
	if !strings.Contains(c.Script, "echo hi") {
		t.Errorf("script body lost: %q", c.Script)
	}
}

func TestRunner_RunStampsSentinel(t *testing.T) {
	dir := t.TempDir()
	r := &Runner{
		WorkDir:      filepath.Join(dir, "work"),
		SentinelPath: filepath.Join(dir, "state", "provisioned"),
	}
	if err := r.Run(context.Background(), Config{Script: "echo ok"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, err := os.Stat(r.SentinelPath); err != nil {
		t.Errorf("sentinel not created: %v", err)
	}
}

func TestRunner_RunIdempotentWhenSentinelPresent(t *testing.T) {
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "p")
	if err := os.WriteFile(sentinel, []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	called := false
	r := &Runner{
		WorkDir:      filepath.Join(dir, "work"),
		SentinelPath: sentinel,
		Cloner: func(ctx context.Context, _, _, _ string) error {
			called = true
			return nil
		},
	}
	// Even with a git source, the runner must early-exit on
	// sentinel-present and not invoke the cloner.
	cfg := Config{SourceKind: "git", SourceURL: "x", Script: "echo x"}
	if err := r.Run(context.Background(), cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if called {
		t.Error("Cloner should not be called when sentinel exists")
	}
}

func TestRunner_GitWithoutClonerErrors(t *testing.T) {
	dir := t.TempDir()
	r := &Runner{
		WorkDir:      filepath.Join(dir, "work"),
		SentinelPath: filepath.Join(dir, "p"),
	}
	err := r.Run(context.Background(), Config{SourceKind: "git", SourceURL: "x"})
	if err == nil {
		t.Error("expected error when SourceKind=git but Cloner is nil")
	}
}

func TestRunner_OCIIsExplicitlyUnwired(t *testing.T) {
	dir := t.TempDir()
	r := &Runner{
		WorkDir:      filepath.Join(dir, "work"),
		SentinelPath: filepath.Join(dir, "p"),
	}
	err := r.Run(context.Background(), Config{SourceKind: "oci", SourceURL: "x"})
	if err == nil || !strings.Contains(err.Error(), "oci provisioning not yet wired") {
		t.Errorf("expected explicit OCI-not-wired error, got %v", err)
	}
}

func TestRunner_UnknownSourceKindErrors(t *testing.T) {
	dir := t.TempDir()
	r := &Runner{
		WorkDir:      filepath.Join(dir, "work"),
		SentinelPath: filepath.Join(dir, "p"),
	}
	err := r.Run(context.Background(), Config{SourceKind: "weirdthing"})
	if err == nil {
		t.Error("expected error for unknown source kind")
	}
}

func TestRunner_RunsScriptInPayloadCWD(t *testing.T) {
	dir := t.TempDir()
	work := filepath.Join(dir, "work")
	payload := filepath.Join(work, "payload")
	if err := os.MkdirAll(payload, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(payload, "marker"), []byte("here"), 0o644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	r := &Runner{
		WorkDir:      work,
		SentinelPath: filepath.Join(dir, "p"),
		LogOut:       &out,
		Cloner: func(ctx context.Context, url, ref, dst string) error {
			// Cloner is a no-op : payload is already set up by the
			// test. Just ensure the runner reaches us, then bow out
			// without overwriting the test fixture.
			return nil
		},
	}
	cfg := Config{
		SourceKind: "git", SourceURL: "fake", SourceRef: "main",
		// The script must run in <work>/payload, where `marker` is.
		// `cat marker` proves the CWD is right.
		Script: "cat marker",
	}
	if err := r.Run(context.Background(), cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(out.String(), "here") {
		t.Errorf("script output missing payload-side fixture: %q", out.String())
	}
}

func TestRunner_EmptyConfigStampsSentinel(t *testing.T) {
	dir := t.TempDir()
	r := &Runner{
		WorkDir:      filepath.Join(dir, "work"),
		SentinelPath: filepath.Join(dir, "p"),
	}
	if err := r.Run(context.Background(), Config{}); err != nil {
		t.Fatalf("Run on empty: %v", err)
	}
	if _, err := os.Stat(r.SentinelPath); err != nil {
		t.Error("sentinel should be stamped even when nothing to do (so reboots don't keep checking)")
	}
}

func TestRunner_ScriptFailurePreventsSentinel(t *testing.T) {
	dir := t.TempDir()
	r := &Runner{
		WorkDir:      filepath.Join(dir, "work"),
		SentinelPath: filepath.Join(dir, "p"),
	}
	err := r.Run(context.Background(), Config{Script: "exit 1"})
	if err == nil {
		t.Error("script exit 1 should propagate")
	}
	if _, statErr := os.Stat(r.SentinelPath); statErr == nil {
		t.Error("sentinel must NOT exist after a failed run")
	}
}

func TestRunScript_PreservesEnvVarsAcrossLines(t *testing.T) {
	var out bytes.Buffer
	err := RunScript(context.Background(),
		`FOO=bar; echo "v=$FOO"`,
		t.TempDir(), &out,
	)
	if err != nil {
		t.Fatalf("RunScript: %v", err)
	}
	if !strings.Contains(out.String(), "v=bar") {
		t.Errorf("env propagation lost: %q", out.String())
	}
}

func TestRunner_ClonerErrorPropagates(t *testing.T) {
	dir := t.TempDir()
	want := "no network"
	r := &Runner{
		WorkDir:      filepath.Join(dir, "work"),
		SentinelPath: filepath.Join(dir, "p"),
		Cloner: func(ctx context.Context, _, _, _ string) error {
			return errors.New(want)
		},
	}
	err := r.Run(context.Background(), Config{SourceKind: "git", SourceURL: "x"})
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("cloner error not wrapped : %v", err)
	}
}
