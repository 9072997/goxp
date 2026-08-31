// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Root-certificate fallback for Windows versions whose trust store has been
// left behind, Windows XP above all.
//
// On Windows, Go does not load a root pool at all: Verify hands the chain to
// CertGetCertificateChain and trusts whatever the machine store says. XP's
// store holds five certificates and its auto-root-update service has been dead
// since 2015, so nothing issued in the last decade has an anchor there -
// github.com chains to USERTrust ECC Certification Authority, which XP has
// never heard of. Go's own TLS handshake succeeds, because Go speaks TLS 1.2
// and 1.3 itself and never touches schannel; it is only the trust decision
// that fails, with "x509: certificate signed by unknown authority".
//
// Every program that wanted to work on XP has so far carried its own copy of
// the Mozilla bundle and set tls.Config.RootCAs by hand. That does not scale,
// and it fails in the worst possible direction: on a development machine the
// platform store is fine, so a program that forgot to install its pool looks
// exactly like one that did.
//
// So this file puts the bundle in the toolchain instead. It is a *fallback*:
// the platform verifier runs first and its answer stands, which is what keeps
// an enterprise CA installed in the Windows store working. Only when the
// platform verifier's sole objection is that it could not reach a root it
// trusts is the chain verified a second time against the compiled-in set.
//
// Do not "clean this up" because it looks like a workaround for a dead
// operating system. It is exactly that, and it is why binaries from this fork
// can reach an HTTPS endpoint from Windows XP at all.

package x509

import (
	"errors"
	"os"
	"sync"
	"syscall"
)

const (
	// envXPBundle names a PEM file to trust instead of the compiled-in set.
	//
	// The bundle goes stale inside every binary ever built with this toolchain
	// and there is no updating it afterwards, so there has to be a way to point
	// a deployed program at a fresher file - or at a private root on a machine
	// whose store cannot be edited. It is also how the wiring is falsified:
	// point it at a PEM that cannot possibly sign the endpoint and every
	// connection that was relying on the fallback must start failing again.
	envXPBundle = "GOXP_CA_BUNDLE"

	// envXPFallback disables the fallback entirely when set to "0", leaving
	// stock Windows behaviour: the platform verifier, and nothing after it.
	envXPFallback = "GOXP_CA_FALLBACK"
)

// certTrustIsPartialChain is CERT_TRUST_IS_PARTIAL_CHAIN from wincrypt.h.
// package syscall's list of CERT_TRUST_ constants stops before it.
const certTrustIsPartialChain = 0x00010000

// xpNoTrustAnchor reports whether a CertGetCertificateChain trust status means
// "could not get to a root I trust", and means nothing else besides.
//
// Two bits carry that meaning. CERT_TRUST_IS_UNTRUSTED_ROOT is set when the
// chain ends in a self-signed certificate that is not in the store;
// CERT_TRUST_IS_PARTIAL_CHAIN is set when it ends somewhere else because the
// issuer could not be found at all. A current chain presented to an XP box
// produces one or both, depending on whether the server sent its root.
//
// Every other bit is a genuine failure and has to stay one: expiry, revocation,
// explicit distrust, a bad signature, a broken name or basic constraint, an
// unsupported critical extension. If any of those is set the answer is no -
// even when a trust-anchor bit is set alongside it - because re-running such a
// chain against a different root store could only turn a correct rejection into
// an acceptance. Keeping the test conjunctive is the entire safety argument for
// this file; a bare "did it fail for any reason" retry would be a security
// regression dressed up as a compatibility fix.
//
// Note that Go asks for no revocation checking (systemVerify passes none of the
// CERT_CHAIN_REVOCATION_CHECK_ flags), so the revocation bits should not appear
// here. If they ever do, the strict test refuses the fallback, which is the
// direction to fail in.
func xpNoTrustAnchor(status uint32) bool {
	const anchorBits = syscall.CERT_TRUST_IS_UNTRUSTED_ROOT | certTrustIsPartialChain
	return status&anchorBits != 0 && status&^anchorBits == 0
}

var (
	xpRootsOnce sync.Once
	xpRoots     *CertPool
)

// xpFallbackRoots returns the pool to verify against when the platform verifier
// has no anchor, or nil if there is to be no second attempt.
func xpFallbackRoots() *CertPool {
	xpRootsOnce.Do(func() {
		if os.Getenv(envXPFallback) == "0" {
			return
		}

		pem := []byte(xpFallbackRootsPEM)
		if path := os.Getenv(envXPBundle); path != "" {
			b, err := os.ReadFile(path)
			if err != nil {
				// Naming a bundle is an instruction to trust that file and
				// nothing else, so an unreadable one means trusting nothing:
				// no second attempt, and the platform verifier's own error is
				// what the caller sees. Silently reverting to the compiled-in
				// set would make a typo look like success.
				return
			}
			pem = b
		}

		p := NewCertPool()
		if !p.AppendCertsFromPEM(pem) {
			return
		}
		xpRoots = p
	})
	return xpRoots
}

// xpVerifyWithFallbackRoots re-runs verification against the fallback pool.
//
// This is a full verification by Go's own verifier, not a patch on the platform
// verifier's answer: expiry, host name, key usage, name and basic constraints
// are all checked again, and the pure-Go path is stricter than CryptoAPI in
// places (it will not build a chain through a SHA-1 signature, for one). The
// only thing that changes is where the trust anchor is allowed to come from.
//
// It cannot recurse back into the platform verifier: Verify only calls
// systemVerify when opts.Roots is nil or is a system pool, and the pool set
// here is neither.
func (c *Certificate) xpVerifyWithFallbackRoots(opts *VerifyOptions) ([][]*Certificate, error) {
	roots := xpFallbackRoots()
	if roots == nil {
		return nil, errXPNoFallbackRoots
	}
	// Copied rather than mutated in place: opts belongs to the caller.
	o := *opts
	o.Roots = roots
	return c.Verify(o)
}

// errXPNoFallbackRoots is internal to this file - systemVerify discards it and
// reports the platform verifier's error instead, so it never reaches a caller.
var errXPNoFallbackRoots = errors.New("x509: no fallback roots available")
