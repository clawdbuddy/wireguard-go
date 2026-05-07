// SPDX-License-Identifier: BSD-3-Clause

// Package regen is a placeholder so the regenerator integration test
// can run from this directory tree. It contains no Go production
// code; the real artifacts here are plan9-xlate.pl, neon_encode.pl,
// regen.sh, and the .cache/ directory regen.sh populates from
// upstream CryptoGAMS at the pinned commit recorded in regen.sh.
package regen

import (
	"bytes"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

var runRegenTests = flag.Bool("run-regen-tests", false,
	"run regenerator integration tests (which fetch upstream Perl from "+
		"the network on first run); always on when CI=true")

// TestRegenReproducible verifies that running tsasm/arm/regen/regen.sh
// produces the .s files already checked in.
//
// The test is skipped by default because it has a network dependency
// on first run (regen.sh fetches the upstream CryptoGAMS .pl files
// from a pinned GitHub URL into a gitignored .cache/ directory).
// Pass --run-regen-tests to opt in, or set CI=true (where we always
// want it to run). It is also skipped on hosts without `perl`, `cpp`,
// `curl`, `sha256sum`, `arm-linux-gnueabihf-as` /
// `arm-linux-gnueabihf-objcopy` (the cross-as is currently needed to
// fill a couple of pure-Perl-encoder gaps), or on non-Unix platforms.
func TestRegenReproducible(t *testing.T) {
	if !*runRegenTests && os.Getenv("CI") != "true" {
		t.Skip("regen integration test is gated: pass --run-regen-tests or set CI=true")
	}
	if runtime.GOOS == "windows" {
		t.Skip("regen pipeline assumes a Unix shell")
	}
	for _, tool := range []string{"perl", "cpp", "curl", "sh", "sha256sum",
		"arm-linux-gnueabihf-as", "arm-linux-gnueabihf-objcopy"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not in PATH: %v", tool, err)
		}
	}

	regenDir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}

	// Snapshot the current committed copies, run regen.sh, diff,
	// then restore. Doing it in-place is the simplest way to avoid
	// having to thread a destination directory through regen.sh.
	committed := []string{
		filepath.Join(regenDir, "..", "poly1305", "poly1305_arm.s"),
		filepath.Join(regenDir, "..", "chacha20", "chacha20_arm.s"),
	}
	saved := make([][]byte, len(committed))
	for i, p := range committed {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		saved[i] = b
	}
	t.Cleanup(func() {
		for i, p := range committed {
			_ = os.WriteFile(p, saved[i], 0o644)
		}
	})

	cmd := exec.Command("sh", filepath.Join(regenDir, "regen.sh"))
	cmd.Dir = regenDir
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("regen.sh failed: %v", err)
	}

	for i, p := range committed {
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read regenerated %s: %v", p, err)
		}
		if !bytes.Equal(got, saved[i]) {
			t.Errorf("%s differs from regen.sh output (the committed copy is stale)", p)
		}
	}
}
