// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Root verification for Windows: a CA bundle compiled into the toolchain,
// tried before the machine's own trust store.
//
// Stock Go on Windows loads no root pool at all. Verify hands the chain to
// CertGetCertificateChain and reports whatever the machine store says. That is
// the right design on a Windows that is still maintained, and it is unusable on
// one that is not. Windows XP's store is not empty - SP3 has 107 roots, most of
// them inside crypt32.dll rather than the registry - but they are the 2001 set,
// and auto-root-update has been dead for years, so nothing issued in the last
// decade has an anchor there. Worse, XP's CryptoAPI predates CNG and has no
// elliptic curve support of any kind, so it cannot evaluate a modern chain even
// when it can anchor one. Go's own TLS handshake succeeds, because Go speaks
// TLS 1.2 and 1.3 itself and never touches schannel; it is only the trust
// decision that fails, with "x509: certificate signed by unknown authority".
//
// Every program that wanted to work on XP has so far carried its own copy of
// the Mozilla bundle and set tls.Config.RootCAs by hand. That does not scale,
// and it fails in the worst possible direction: on a development machine the
// platform store is fine, so a program that forgot to install its pool looks
// exactly like one that did.
//
// So this file puts the bundle in the toolchain, and puts it first.
//
// The order is the whole design. An earlier version ran the platform verifier
// first and consulted the bundle only when the CERT_TRUST_* bits looked like a
// missing anchor. That could not be made to work, because those bits do not
// report what they appear to. XP has no way to say "I cannot evaluate this
// algorithm": it says CERT_TRUST_IS_NOT_SIGNATURE_VALID, the same bit it would
// set for a forgery. It has no way to say "my copy of this root is from 2001":
// it says CERT_TRUST_IS_NOT_TIME_VALID. Measured on XP SP3 on 2026-08-31, one
// minute apart, on two chains that are both perfectly good:
//
//	github.com:443     0x00000028  IS_NOT_SIGNATURE_VALID | IS_UNTRUSTED_ROOT
//	openrouter.ai:443  0x00000009  IS_NOT_TIME_VALID | IS_NOT_SIGNATURE_VALID
//
// Any predicate over those statuses is guessing at an intent the API does not
// express - and the guess accepted the first and refused the second, purely
// because Google's chain cross-certifies up to a root XP holds a stale copy of
// while Sectigo's does not. Ordering the verifiers deletes the question. Go's
// verifier either builds a chain to a current root or it does not, and that
// answer stands on its own terms.
//
// The platform verifier still runs, second, whenever the bundle cannot anchor
// the chain. That is what keeps a privately installed or enterprise CA working:
// such a root is in the machine store and in no public bundle, so the first
// attempt fails and the second succeeds. Read verifyWithBundledRoots for what
// consulting the bundle first costs.
//
// Do not "clean this up" because it looks like a workaround for a dead
// operating system. It began as exactly that, and it is why binaries from this
// fork can reach an HTTPS endpoint from Windows XP at all.

package x509

import (
	"internal/godebug"
	"sync"
)

// x509bundledroots=0 restores stock Windows behaviour: the platform verifier,
// and nothing else. It is the switch for the compatibility change this file
// makes, so it is a GODEBUG rather than an invention of ours - that is what
// GODEBUG is for, and this is a Go toolchain.
//
// Deliberately registered in internal/godebugs with no Changed/Old pair. Those
// fields tie a default to the go directive in the consuming module's go.mod,
// and every module that targets XP declares an older Go than this fork, so a
// version-linked default would silently turn the bundle off in exactly the
// programs that need it.
//
// There is no companion setting for "use this PEM instead of the compiled-in
// one". crypto/x509 already has that, from Go 1.27, on Windows: SSL_CERT_FILE
// and SSL_CERT_DIR are honoured here, loadSystemRoots builds an on-disk pool
// from them, and Verify then uses Go's verifier against it and never reaches
// systemVerify or this file at all. Anything named GOXP_CA_BUNDLE would have
// been a second, private spelling of a documented one.
var x509bundledroots = godebug.New("x509bundledroots")

var (
	bundledRootsOnce sync.Once
	bundledRootsPool *CertPool
)

// bundledRoots returns the pool to verify against, or nil if the bundle is
// switched off.
//
// The setting is read on every call, not once: a GODEBUG can be changed at run
// time, and only the parsing of the PEM is worth caching.
func bundledRoots() *CertPool {
	if x509bundledroots.Value() == "0" {
		x509bundledroots.IncNonDefault()
		return nil
	}
	bundledRootsOnce.Do(func() {
		p := NewCertPool()
		if !p.AppendCertsFromPEM([]byte(bundledRootsPEM)) {
			return
		}
		bundledRootsPool = p
	})
	return bundledRootsPool
}

// verifyWithBundledRoots verifies the chain against roots, using Go's own
// verifier and nothing from Windows.
//
// This is a complete verification, not a patch on someone else's answer:
// signatures, expiry, host name, key usage and every name, policy and basic
// constraint are checked here, by an implementation that supports the
// algorithms in use. In places it is stricter than CryptoAPI - it will not
// build a chain through a SHA-1 signature at all.
//
// systemVerify calls this before the platform verifier, on every Windows
// version. Two facts follow from that, and they are the price of the ordering:
//
//   - Administrator and vendor distrust is not consulted for a chain that
//     verifies here. CryptoAPI checks the disallowed certificate store and
//     Microsoft's untrusted CTL on every call, and on a maintained Windows that
//     is how a distrusted CA is killed. A chain that anchors in this bundle is
//     accepted without reaching any of it, so an explicit-distrust entry - an
//     administrator's or Microsoft's - no longer stops it, and neither does
//     enterprise policy over the machine's root store: what that store holds,
//     or has had removed, does not affect a chain that verifies here.
//
//   - Nothing changes on revocation, which is worth writing down because the
//     opposite is the natural assumption. CryptoAPI can consult CRLs and OCSP,
//     but only on request: it checks revocation only when one of the
//     CERT_CHAIN_REVOCATION_CHECK_ flags is passed to CertGetCertificateChain,
//     and systemVerify passes none of them and never has. Go's verifier does no
//     revocation checking either. So a revoked certificate was accepted before
//     this ordering and is accepted after it, by both paths alike.
//
// The bundle is frozen at link time. It cannot learn that a CA was distrusted
// after the binary was built; SSL_CERT_FILE is the way to move it.
//
// This cannot recurse back into the platform verifier: Verify only calls
// systemVerify when opts.Roots is nil or is a system pool, and the pool passed
// here is neither.
func (c *Certificate) verifyWithBundledRoots(roots *CertPool, opts *VerifyOptions) ([][]*Certificate, error) {
	// Copied rather than mutated in place: opts belongs to the caller.
	o := *opts
	o.Roots = roots
	return c.Verify(o)
}
