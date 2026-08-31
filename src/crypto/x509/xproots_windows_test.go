// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"strings"
	"syscall"
	"testing"
)

// TestXPNoTrustAnchor pins the one decision this fallback turns on: which
// CertGetCertificateChain trust statuses mean "no anchor" and may be retried
// against the compiled-in roots, and which are real failures that must be left
// alone. It is the only part of the fallback that can be tested on a machine
// whose own root store still works, so it is tested exhaustively.
func TestXPNoTrustAnchor(t *testing.T) {
	const partial = certTrustIsPartialChain

	tests := []struct {
		name   string
		status uint32
		want   bool
	}{
		// No failure at all is not a reason to look for another anchor.
		{"no error", syscall.CERT_TRUST_NO_ERROR, false},

		// The two statuses that mean the chain never reached a trusted root.
		{"untrusted root", syscall.CERT_TRUST_IS_UNTRUSTED_ROOT, true},
		{"partial chain", partial, true},
		{"untrusted root and partial chain", syscall.CERT_TRUST_IS_UNTRUSTED_ROOT | partial, true},

		// Real failures, alone. None of these may fall back: a different root
		// store cannot make an expired, revoked or forged certificate good.
		{"expired", syscall.CERT_TRUST_IS_NOT_TIME_VALID, false},
		{"revoked", syscall.CERT_TRUST_IS_REVOKED, false},
		{"bad signature", syscall.CERT_TRUST_IS_NOT_SIGNATURE_VALID, false},
		{"wrong usage", syscall.CERT_TRUST_IS_NOT_VALID_FOR_USAGE, false},
		{"revocation unknown", syscall.CERT_TRUST_REVOCATION_STATUS_UNKNOWN, false},
		{"cyclic", syscall.CERT_TRUST_IS_CYCLIC, false},
		{"invalid extension", syscall.CERT_TRUST_INVALID_EXTENSION, false},
		{"invalid policy constraints", syscall.CERT_TRUST_INVALID_POLICY_CONSTRAINTS, false},
		{"invalid basic constraints", syscall.CERT_TRUST_INVALID_BASIC_CONSTRAINTS, false},
		{"invalid name constraints", syscall.CERT_TRUST_INVALID_NAME_CONSTRAINTS, false},
		{"excluded name constraint", syscall.CERT_TRUST_HAS_EXCLUDED_NAME_CONSTRAINT, false},
		{"offline revocation", syscall.CERT_TRUST_IS_OFFLINE_REVOCATION, false},
		{"explicit distrust", syscall.CERT_TRUST_IS_EXPLICIT_DISTRUST, false},
		{"unsupported critical extension", syscall.CERT_TRUST_HAS_NOT_SUPPORTED_CRITICAL_EXT, false},

		// A real failure alongside a missing anchor is still a real failure.
		// This is the case that would quietly turn rejections into acceptances
		// if the test were disjunctive instead of conjunctive.
		{"expired and untrusted root", syscall.CERT_TRUST_IS_NOT_TIME_VALID | syscall.CERT_TRUST_IS_UNTRUSTED_ROOT, false},
		{"revoked and untrusted root", syscall.CERT_TRUST_IS_REVOKED | syscall.CERT_TRUST_IS_UNTRUSTED_ROOT, false},
		{"distrusted and partial chain", syscall.CERT_TRUST_IS_EXPLICIT_DISTRUST | partial, false},
		{"bad signature and partial chain", syscall.CERT_TRUST_IS_NOT_SIGNATURE_VALID | partial, false},

		// Anything unrecognised is a real failure too.
		{"unknown bit", 0x40000000, false},
		{"unknown bit with untrusted root", 0x40000000 | syscall.CERT_TRUST_IS_UNTRUSTED_ROOT, false},
	}

	for _, tc := range tests {
		if got := xpNoTrustAnchor(tc.status); got != tc.want {
			t.Errorf("xpNoTrustAnchor(%s, %#08x) = %v, want %v", tc.name, tc.status, got, tc.want)
		}
	}
}

// TestXPFallbackBundleParses checks the compiled-in bundle is a usable pool.
// A bundle that silently fails to parse would leave the fallback inert, and
// nothing on a development machine would notice.
func TestXPFallbackBundleParses(t *testing.T) {
	p := NewCertPool()
	if !p.AppendCertsFromPEM([]byte(xpFallbackRootsPEM)) {
		t.Fatal("compiled-in fallback bundle contains no certificates")
	}
	if n := p.len(); n < 100 {
		t.Errorf("compiled-in fallback bundle has %d certificates, want at least 100", n)
	}
	// The root Let's Encrypt chains to, and the single most important one for
	// an XP box: if a refresh ever drops it, this fallback stops being worth
	// its size.
	if !strings.Contains(xpFallbackRootsPEM, "ISRG Root X1") {
		t.Error("compiled-in fallback bundle is missing ISRG Root X1")
	}
}
