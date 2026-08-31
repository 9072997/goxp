// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"strings"
	"testing"
)

// TestBundledRootsParse checks the compiled-in bundle is a usable pool.
//
// It is nearly all that can be tested on a development machine, and it matters
// more than its size suggests. A bundle that silently failed to parse would
// leave systemVerify's first attempt permanently unable to anchor anything and
// falling through to the platform verifier on every call - which on a machine
// whose own root store works is indistinguishable from success, and on Windows
// XP is the whole bug this file exists to prevent.
func TestBundledRootsParse(t *testing.T) {
	p := NewCertPool()
	if !p.AppendCertsFromPEM([]byte(bundledRootsPEM)) {
		t.Fatal("compiled-in bundle contains no certificates")
	}
	if n := p.len(); n < 100 {
		t.Errorf("compiled-in bundle has %d certificates, want at least 100", n)
	}
	// The root Let's Encrypt chains to, and the single most important one for
	// an XP box: if a refresh ever drops it, this bundle stops being worth its
	// size.
	if !strings.Contains(bundledRootsPEM, "ISRG Root X1") {
		t.Error("compiled-in bundle is missing ISRG Root X1")
	}
}

// TestBundledRootsPoolIsNotSystem guards the one way this could recurse.
//
// verifyWithBundledRoots hands Verify a pool of its own, and Verify routes back
// into systemVerify - which calls verifyWithBundledRoots - whenever opts.Roots
// is nil or is flagged as a system pool. The pool built here is neither, and
// nothing in CertPool's API sets that flag from outside, but the consequence of
// being wrong is unbounded recursion inside every TLS handshake rather than a
// wrong answer, so it is worth a line.
func TestBundledRootsPoolIsNotSystem(t *testing.T) {
	p := bundledRoots()
	if p == nil {
		t.Skip("bundle disabled by GODEBUG")
	}
	if p.systemPool {
		t.Error("bundled root pool is flagged as a system pool; systemVerify would recurse")
	}
}

// TestBundledRootsGODEBUGOff checks the off switch reaches bundledRoots.
//
// It is the negative control for the whole file in miniature: if
// x509bundledroots=0 did not actually stop the bundle being used, a test that
// showed the bundle working would prove nothing, because it could not tell the
// bundle apart from a machine whose own store already worked.
func TestBundledRootsGODEBUGOff(t *testing.T) {
	t.Setenv("GODEBUG", "x509bundledroots=0")
	if p := bundledRoots(); p != nil {
		t.Error("bundledRoots returned a pool with GODEBUG=x509bundledroots=0")
	}
}
