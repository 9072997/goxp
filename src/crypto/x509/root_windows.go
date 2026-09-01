// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"bytes"
	"errors"
	"strings"
	"syscall"
	"unsafe"
)

// Windows has no default SSL_CERT_{FILE,DIR} paths.
var certFiles, certDirectories []string

// Creates a new *syscall.CertContext representing the leaf certificate in an in-memory
// certificate store containing itself and all of the intermediate certificates specified
// in the opts.Intermediates CertPool.
//
// A pointer to the in-memory store is available in the returned CertContext's Store field.
// The store is automatically freed when the CertContext is freed using
// syscall.CertFreeCertificateContext.
func createStoreContext(leaf *Certificate, opts *VerifyOptions) (*syscall.CertContext, error) {
	var storeCtx *syscall.CertContext

	leafCtx, err := syscall.CertCreateCertificateContext(syscall.X509_ASN_ENCODING|syscall.PKCS_7_ASN_ENCODING, &leaf.Raw[0], uint32(len(leaf.Raw)))
	if err != nil {
		return nil, err
	}
	defer syscall.CertFreeCertificateContext(leafCtx)

	handle, err := syscall.CertOpenStore(syscall.CERT_STORE_PROV_MEMORY, 0, 0, syscall.CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.CertCloseStore(handle, 0)

	err = syscall.CertAddCertificateContextToStore(handle, leafCtx, syscall.CERT_STORE_ADD_ALWAYS, &storeCtx)
	if err != nil {
		return nil, err
	}

	if opts.Intermediates != nil {
		for i := 0; i < opts.Intermediates.len(); i++ {
			intermediate, _, err := opts.Intermediates.cert(i)
			if err != nil {
				return nil, err
			}
			ctx, err := syscall.CertCreateCertificateContext(syscall.X509_ASN_ENCODING|syscall.PKCS_7_ASN_ENCODING, &intermediate.Raw[0], uint32(len(intermediate.Raw)))
			if err != nil {
				return nil, err
			}

			err = syscall.CertAddCertificateContextToStore(handle, ctx, syscall.CERT_STORE_ADD_ALWAYS, nil)
			syscall.CertFreeCertificateContext(ctx)
			if err != nil {
				return nil, err
			}
		}
	}

	return storeCtx, nil
}

// extractSimpleChain extracts the final certificate chain from a CertSimpleChain.
func extractSimpleChain(simpleChain **syscall.CertSimpleChain, count int) (chain []*Certificate, err error) {
	if simpleChain == nil || count == 0 {
		return nil, errors.New("x509: invalid simple chain")
	}

	simpleChains := unsafe.Slice(simpleChain, count)
	lastChain := simpleChains[count-1]
	elements := unsafe.Slice(lastChain.Elements, lastChain.NumElements)
	for i := 0; i < int(lastChain.NumElements); i++ {
		// Copy the buf, since ParseCertificate does not create its own copy.
		cert := elements[i].CertContext
		encodedCert := unsafe.Slice(cert.EncodedCert, cert.Length)
		buf := bytes.Clone(encodedCert)
		parsedCert, err := ParseCertificate(buf)
		if err != nil {
			return nil, err
		}
		chain = append(chain, parsedCert)
	}

	return chain, nil
}

// checkChainTrustStatus checks the trust status of the certificate chain, translating
// any errors it finds into Go errors in the process.
func checkChainTrustStatus(c *Certificate, chainCtx *syscall.CertChainContext) error {
	if chainCtx.TrustStatus.ErrorStatus != syscall.CERT_TRUST_NO_ERROR {
		status := chainCtx.TrustStatus.ErrorStatus
		switch status {
		case syscall.CERT_TRUST_IS_NOT_TIME_VALID:
			return CertificateInvalidError{c, Expired, ""}
		case syscall.CERT_TRUST_IS_NOT_VALID_FOR_USAGE:
			return CertificateInvalidError{c, IncompatibleUsage, ""}
		// TODO(filippo): surface more error statuses.
		default:
			return UnknownAuthorityError{c, nil, nil}
		}
	}
	return nil
}

// checkChainSSLServerPolicy checks that the certificate chain in chainCtx is valid for
// use as a certificate chain for a SSL/TLS server.
func checkChainSSLServerPolicy(c *Certificate, chainCtx *syscall.CertChainContext, opts *VerifyOptions) error {
	servernamep, err := syscall.UTF16PtrFromString(strings.TrimSuffix(opts.DNSName, "."))
	if err != nil {
		return err
	}
	sslPara := &syscall.SSLExtraCertChainPolicyPara{
		AuthType:   syscall.AUTHTYPE_SERVER,
		ServerName: servernamep,
	}
	sslPara.Size = uint32(unsafe.Sizeof(*sslPara))

	para := &syscall.CertChainPolicyPara{
		ExtraPolicyPara: (syscall.Pointer)(unsafe.Pointer(sslPara)),
	}
	para.Size = uint32(unsafe.Sizeof(*para))

	status := syscall.CertChainPolicyStatus{}
	err = syscall.CertVerifyCertificateChainPolicy(syscall.CERT_CHAIN_POLICY_SSL, chainCtx, para, &status)
	if err != nil {
		return err
	}

	// TODO(mkrautz): use the lChainIndex and lElementIndex fields
	// of the CertChainPolicyStatus to provide proper context, instead
	// using c.
	if status.Error != 0 {
		switch status.Error {
		case syscall.CERT_E_EXPIRED:
			return CertificateInvalidError{c, Expired, ""}
		case syscall.CERT_E_CN_NO_MATCH:
			return HostnameError{c, opts.DNSName}
		case syscall.CERT_E_UNTRUSTEDROOT:
			return UnknownAuthorityError{c, nil, nil}
		default:
			return UnknownAuthorityError{c, nil, nil}
		}
	}

	return nil
}

// windowsExtKeyUsageOIDs are the C NUL-terminated string representations of the
// OIDs for use with the Windows API.
var windowsExtKeyUsageOIDs = make(map[ExtKeyUsage][]byte, len(extKeyUsageOIDs))

func init() {
	for _, eku := range extKeyUsageOIDs {
		windowsExtKeyUsageOIDs[eku.extKeyUsage] = []byte(eku.oid.String() + "\x00")
	}
}

func verifyChain(c *Certificate, chainCtx *syscall.CertChainContext, opts *VerifyOptions) (chain []*Certificate, err error) {
	err = checkChainTrustStatus(c, chainCtx)
	if err != nil {
		return nil, err
	}

	if opts != nil && len(opts.DNSName) > 0 {
		err = checkChainSSLServerPolicy(c, chainCtx, opts)
		if err != nil {
			return nil, err
		}
	}

	chain, err = extractSimpleChain(chainCtx.Chains, int(chainCtx.ChainCount))
	if err != nil {
		return nil, err
	}
	if len(chain) == 0 {
		return nil, errors.New("x509: internal error: system verifier returned an empty chain")
	}

	// Mitigate CVE-2020-0601, where the Windows system verifier might be
	// tricked into using custom curve parameters for a trusted root, by
	// double-checking all ECDSA signatures. If the system was tricked into
	// using spoofed parameters, the signature will be invalid for the correct
	// ones we parsed. (We don't support custom curves ourselves.)
	for i, parent := range chain[1:] {
		if parent.PublicKeyAlgorithm != ECDSA {
			continue
		}
		if err := parent.CheckSignature(chain[i].SignatureAlgorithm,
			chain[i].RawTBSCertificate, chain[i].Signature); err != nil {
			return nil, err
		}
	}
	return chain, nil
}

// systemVerify is like Verify, except that it uses CryptoAPI calls
// to build certificate chains and verify them.
func (c *Certificate) systemVerify(opts *VerifyOptions) (chains [][]*Certificate, err error) {
	// The roots compiled into this toolchain are tried first, by Go's own
	// verifier, on every Windows version. Only if they cannot anchor the chain
	// does the platform verifier below get to decide - which is what keeps a
	// privately installed or enterprise CA working, since such a root is in the
	// machine store and in no public bundle.
	//
	// The order is this way round because CertGetCertificateChain's answer
	// cannot be interpreted. On Windows XP it rejects chains it merely cannot
	// evaluate - its CryptoAPI has no elliptic curve support at all - and it
	// reports that with the same bits it would use for a forgery. Trying to
	// tell the two apart from the CERT_TRUST_* status is guessing at an intent
	// the API does not express, and it guessed wrong on real chains. See
	// rootbundle_windows.go, for that argument and for what the ordering costs.
	//
	// Only an anchor failure falls through. On a machine with a working store
	// the bundle is expected to fail for anything chaining to a private root,
	// and there its "unknown authority" is a worse diagnosis than the
	// platform's - so that one is discarded and the platform decides.
	//
	// Any other failure is kept. verifyWithBundledRoots runs the whole of
	// Verify, so it can also build a chain and then reject it for a specific
	// reason: wrong hostname, expired, incompatible key usage. Discarding that
	// and falling through replaces a precise answer with the platform's
	// generic UnknownAuthorityError - which on XP is what a root store older
	// than the certificate says about almost anything. Callers that switch on
	// the error type, crypto/tls among them, then cannot tell why a connection
	// was refused, and a hostname mismatch becomes indistinguishable from an
	// untrusted issuer.
	//
	// GODEBUG=x509bundledroots=0 makes bundledRoots return nil, leaving stock
	// behaviour: the platform verifier, and nothing else.
	if roots := bundledRoots(); roots != nil {
		chains, err := c.verifyWithBundledRoots(roots, opts)
		if err == nil {
			return chains, nil
		}
		var unknownAuthority UnknownAuthorityError
		if !errors.As(err, &unknownAuthority) {
			return nil, err
		}
	}

	storeCtx, err := createStoreContext(c, opts)
	if err != nil {
		return nil, err
	}
	defer syscall.CertFreeCertificateContext(storeCtx)

	para := new(syscall.CertChainPara)
	para.Size = uint32(unsafe.Sizeof(*para))

	keyUsages := opts.KeyUsages
	if len(keyUsages) == 0 {
		keyUsages = []ExtKeyUsage{ExtKeyUsageServerAuth}
	}
	oids := make([]*byte, 0, len(keyUsages))
	for _, eku := range keyUsages {
		if eku == ExtKeyUsageAny {
			oids = nil
			break
		}
		if oid, ok := windowsExtKeyUsageOIDs[eku]; ok {
			oids = append(oids, &oid[0])
		}
	}
	if oids != nil {
		para.RequestedUsage.Type = syscall.USAGE_MATCH_TYPE_OR
		para.RequestedUsage.Usage.Length = uint32(len(oids))
		para.RequestedUsage.Usage.UsageIdentifiers = &oids[0]
	} else {
		para.RequestedUsage.Type = syscall.USAGE_MATCH_TYPE_AND
		para.RequestedUsage.Usage.Length = 0
		para.RequestedUsage.Usage.UsageIdentifiers = nil
	}

	var verifyTime *syscall.Filetime
	if opts != nil && !opts.CurrentTime.IsZero() {
		ft := syscall.NsecToFiletime(opts.CurrentTime.UnixNano())
		verifyTime = &ft
	}

	// The default is to return only the highest quality chain,
	// setting this flag will add additional lower quality contexts.
	// These are returned in the LowerQualityChains field.
	const CERT_CHAIN_RETURN_LOWER_QUALITY_CONTEXTS = 0x00000080

	// CertGetCertificateChain will traverse Windows's root stores in an attempt to build a verified certificate chain
	var topCtx *syscall.CertChainContext
	err = syscall.CertGetCertificateChain(syscall.Handle(0), storeCtx, verifyTime, storeCtx.Store, para, CERT_CHAIN_RETURN_LOWER_QUALITY_CONTEXTS, 0, &topCtx)
	if err != nil {
		return nil, err
	}
	defer syscall.CertFreeCertificateChain(topCtx)

	chain, topErr := verifyChain(c, topCtx, opts)
	if topErr == nil {
		chains = append(chains, chain)
	}

	if lqCtxCount := topCtx.LowerQualityChainCount; lqCtxCount > 0 {
		lqCtxs := unsafe.Slice(topCtx.LowerQualityChains, lqCtxCount)
		for _, ctx := range lqCtxs {
			chain, err := verifyChain(c, ctx, opts)
			if err == nil {
				chains = append(chains, chain)
			}
		}
	}

	if len(chains) == 0 {
		// Both verifiers have refused: the bundled roots above could not anchor
		// the chain, and neither could the machine store. Report the platform's
		// error, from the highest quality context - the bundle attempt had
		// nothing to add beyond "unknown authority".
		return nil, topErr
	}

	return chains, nil
}
