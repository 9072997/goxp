// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"strings"
	"syscall"
	"testing"
)

// TestXPFallbackApplies pins the one decision this fallback turns on: which
// CertGetCertificateChain trust statuses may be retried against the compiled-in
// roots, and which are refusals that have to stand. It is the only part of the
// fallback that can be tested on a machine whose own root store still works, so
// it is tested exhaustively.
//
// The shape to hold on to is two-sided. No anchor bit, no fallback, whatever
// else is set. Anchor bit plus one of the four bits Go's verifier cannot
// re-derive - revocation, in its three forms, and explicit distrust - still no
// fallback. Everything else Go rechecks for itself on the retry, so it is not
// this function's job to pre-judge it.
func TestXPFallbackApplies(t *testing.T) {
	const (
		partial   = certTrustIsPartialChain
		untrusted = syscall.CERT_TRUST_IS_UNTRUSTED_ROOT
	)

	tests := []struct {
		name   string
		status uint32
		want   bool
	}{
		// No failure at all is not a reason to look for another anchor.
		{"no error", syscall.CERT_TRUST_NO_ERROR, false},

		// The two statuses that mean the chain never reached a trusted root.
		{"untrusted root", untrusted, true},
		{"partial chain", partial, true},
		{"untrusted root and partial chain", untrusted | partial, true},

		// The measured case. Windows XP SP3, github.com, 2026-08-31:
		// ErrorStatus 0x28 on the top context, with IS_NOT_SIGNATURE_VALID on
		// all three elements, because github.com's chain is ECDSA end to end
		// and XP's CryptoAPI has no elliptic curve support at all. This is the
		// case the fallback exists for; refusing it - as the first version of
		// this function did - leaves XP exactly as broken as before.
		{"XP ECDSA: bad signature and untrusted root", syscall.CERT_TRUST_IS_NOT_SIGNATURE_VALID | untrusted, true},

		// No anchor bit, no fallback. Each of these is a refusal from a verifier
		// that did reach a root it trusts, so its answer is authoritative and
		// there is nothing for another root store to add.
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
		{"unknown bit", 0x40000000, false},

		// The four Go cannot re-derive, each set alongside a missing anchor.
		// These are the cases that keep this from being a blanket retry: Go
		// does no revocation checking, and cannot see that an administrator put
		// a certificate in this machine's disallowed store.
		{"revoked and untrusted root", syscall.CERT_TRUST_IS_REVOKED | untrusted, false},
		{"revoked and partial chain", syscall.CERT_TRUST_IS_REVOKED | partial, false},
		{"revocation unknown and untrusted root", syscall.CERT_TRUST_REVOCATION_STATUS_UNKNOWN | untrusted, false},
		{"offline revocation and untrusted root", syscall.CERT_TRUST_IS_OFFLINE_REVOCATION | untrusted, false},
		{"distrusted and untrusted root", syscall.CERT_TRUST_IS_EXPLICIT_DISTRUST | untrusted, false},
		{"distrusted and partial chain", syscall.CERT_TRUST_IS_EXPLICIT_DISTRUST | partial, false},
		{"revoked, distrusted and untrusted root", syscall.CERT_TRUST_IS_REVOKED | syscall.CERT_TRUST_IS_EXPLICIT_DISTRUST | untrusted, false},
		{"XP ECDSA case plus revocation", syscall.CERT_TRUST_IS_NOT_SIGNATURE_VALID | untrusted | syscall.CERT_TRUST_IS_REVOKED, false},

		// Everything else alongside a missing anchor is retried, because Go's
		// verifier rechecks all of it - and rejects on its own authority if it
		// agrees. It is not being waved through; it is being asked again, of
		// something that can actually answer.
		{"expired and untrusted root", syscall.CERT_TRUST_IS_NOT_TIME_VALID | untrusted, true},
		{"bad signature and partial chain", syscall.CERT_TRUST_IS_NOT_SIGNATURE_VALID | partial, true},
		{"wrong usage and untrusted root", syscall.CERT_TRUST_IS_NOT_VALID_FOR_USAGE | untrusted, true},
		{"invalid basic constraints and untrusted root", syscall.CERT_TRUST_INVALID_BASIC_CONSTRAINTS | untrusted, true},
		{"invalid name constraints and partial chain", syscall.CERT_TRUST_INVALID_NAME_CONSTRAINTS | partial, true},
		{"unsupported critical extension and untrusted root", syscall.CERT_TRUST_HAS_NOT_SUPPORTED_CRITICAL_EXT | untrusted, true},
		{"unknown bit with untrusted root", 0x40000000 | untrusted, true},
	}

	for _, tc := range tests {
		if got := xpFallbackApplies(tc.status); got != tc.want {
			t.Errorf("xpFallbackApplies(%s, %#08x) = %v, want %v", tc.name, tc.status, got, tc.want)
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
