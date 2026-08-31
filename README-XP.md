# goxp — Go for Windows XP

Go 1.27.0 that produces binaries Windows XP (NT 5.1) will load and run.

    Base:   thongtech/go-legacy-win7 @ 1b73f848   (Go 1.27.0, targets Win7 / PE 6.1)
    Delta:  8 files, +247 / -73                   (takes it back to XP / PE 5.1)
            + a root-certificate fallback         (see "HTTPS on XP" below)

Upstream Go dropped Windows XP after 1.10. `go-legacy-win7` restores Windows 7;
this restores XP on top of it, which is a further set of problems because Go has
kept moving onto Vista-and-later APIs since.

## Building

Needs a Go 1.24.6 or later bootstrap (see `src/cmd/dist/notgo124.go`).

    cd src
    set GOROOT_BOOTSTRAP=C:\Program Files\Go
    make.bat

Leave `GOROOT`, `GOOS`, `GOARCH` and `GOTOOLCHAIN` unset while building.

Then cross-compile as usual. XP is 32-bit here:

    set GOOS=windows
    set GOARCH=386
    set CGO_ENABLED=0
    set GOTOOLCHAIN=local

`GOTOOLCHAIN=local` matters. Without it, a `go` directive above the toolchain's
own version makes the go command silently download an official release and
re-exec, producing a binary XP will not load, with nothing at build time saying
why.

## Verifying the result

Two different questions, and passing the first says nothing about the second.

**Will the loader accept it?** The PE optional header must ask for 5.1 rather
than 6.1. An official toolchain and this one print the same `go version`
string, so check the artifact:

    go run scripts/checkpe.go your.exe        # from the picoclaw tree

**Will it actually start?** The loader resolves every static import before main
runs, so a binary it accepts still dies if the import table names something
kernel32 on XP does not export. That check only helps for C programs, though —
the Go runtime resolves nearly everything through `GetProcAddress`, so a Go
binary's import table is almost empty and proves nothing.

Which is the whole lesson here: **there is no substitute for running it on XP.**
A fork that passes every host-side check can still panic on the hardware at the
first `os.ReadDir`. That is exactly what happened to the fork this one replaced.

## What the 8 files do

| File | Change |
|---|---|
| `src/cmd/link/internal/ld/pe.go` | `PeMinimumTargetMajorVersion` 6 → 5 |
| `src/runtime/os_windows.go` | drop 6 Vista+ symbols from `cgo_import_dynamic`; look them up at runtime |
| `src/runtime/signal_windows.go` | guard `GetErrorMode`, `WerGet/SetFlags`, `RaiseFailFastException` |
| `src/runtime/netpoll_windows.go` | fall back to the singular `GetQueuedCompletionStatus` |
| `src/os/dir_windows.go` | stateful `FindFirstFile` directory reader |
| `src/internal/syscall/windows/zsyscall_windows.go` | `.Find()` guards on 5 Vista+ procs |
| `src/syscall/zsyscall_windows.go` | `.Find()` guards |
| `src/syscall/exec_windows.go` | plain-`STARTUPINFO` process creation |

Three of these were not obvious.

**`os.ReadDir` panicked.** Go 1.22 rewrote the Windows directory reader —
`os/dir_windows.go` went from 80 lines on `FindNextFile` to 230 on
`GetFileInformationByHandleEx` and `GetVolumeInformationByHandle`, both Vista+.
`syscall.LazyProc.mustFind` **panics** rather than returning an error, so guards
alone cannot save it; something has to actually read the directory. The Win7
fork already carried a `readDirFindFirstFile` for SMB 1.0 shares, but it
restarted the search on every call, so `Readdir(n>0)` never terminated. On XP
that stops being a corner case and becomes the only path.

**`os/exec` was a second, unrelated blocker.** Since Go 1.17 `StartProcess`
unconditionally uses `InitializeProcThreadAttributeList` and
`EXTENDED_STARTUPINFO`, also Vista+. When those are absent this falls back to a
plain `STARTUPINFO` with handle inheritance — what Go did before 1.17.

**netpoll called a Vista-only function unguarded.** XP has only the singular
`GetQueuedCompletionStatus`, which returns one completion at a time. The result
loop is written against `overlappedEntry` and does not care how many arrived,
so filling one entry and setting the count to 1 is enough.

## HTTPS on XP

On Windows, Go does not load a root pool at all: `crypto/x509` hands the chain
to `CertGetCertificateChain` and trusts whatever the machine store says. XP's
store holds 107 certificates — measured on SP3, most of them inside
`crypt32.dll` rather than the registry — but they are the 2001 set, GTE
CyberTrust and Valicert and Baltimore, and auto-root-update has been dead for
years. Nothing issued in the last decade has an anchor there: github.com chains
to `USERTrust ECC Certification Authority`, which XP has never heard of. The TLS
handshake itself is fine; Go speaks TLS 1.2 and 1.3 and never touches schannel.
It is only the trust decision that fails, with

    x509: certificate signed by unknown authority

So this toolchain compiles curl's distribution of the Mozilla CA set into every
Windows binary it builds, and verifies against it **before** the machine's own
store:

1. Go's own verifier runs first, against the compiled-in roots. If it builds a
   chain, that is the answer, and `CertGetCertificateChain` is never called.
   This is a complete verification — every signature, expiry, host name, EKU and
   constraint — by an implementation that supports the algorithms in use, and it
   is stricter than CryptoAPI in places (it will not build a chain through a
   SHA-1 signature at all).
2. Only if that fails does the platform verifier run, exactly as in stock Go,
   and its answer — pass or fail — is the one reported. That is what keeps a
   privately installed or enterprise CA working: such a root is in the machine
   store and in no public bundle, so step 1 fails and step 2 succeeds.

The order used to be the other way round, with the bundle consulted only when
the `CERT_TRUST_*` status looked like a missing anchor. That could not be made
to work, and the reason is worth keeping. CryptoAPI has no way to report "I
cannot evaluate this algorithm": XP predates CNG and has no elliptic-curve
support at all, so it marks every signature in an ECDSA chain
`IS_NOT_SIGNATURE_VALID` — the same bit it would set for a forgery. Nor can it
report "my copy of this root is from 2001": it says `IS_NOT_TIME_VALID`.
Measured on XP SP3 hardware on 2026-08-31, one minute apart, on two chains that
are both perfectly good:

    github.com:443     0x00000028   IS_NOT_SIGNATURE_VALID | IS_UNTRUSTED_ROOT
    openrouter.ai:443  0x00000009   IS_NOT_TIME_VALID | IS_NOT_SIGNATURE_VALID

The anchor-bit rule accepted the first and refused the second — leaving
clawxp's own model provider unreachable from XP — and the difference between
them is not a security property. It is that Google's chain cross-certifies up to
a root XP holds a stale copy of, so the walk terminated and no anchor bit was
set, while Sectigo's does not. Any predicate over those bits is guessing at an
intent the API does not express. Ordering the verifiers deletes the question.

**What the ordering costs**, on every Windows version, not only XP:

- A chain that verifies against the bundle is accepted without the platform
  verifier ever running, so Windows' disallowed-certificate store and
  Microsoft's untrusted CTL are not consulted for it. An explicit distrust —
  an administrator's or Microsoft's — no longer stops such a chain, and neither
  does enterprise policy over the machine's root store.
- The bundle is frozen at link time and cannot learn that a CA was distrusted
  after the binary was built. `SSL_CERT_FILE` is the way to move it.
- Revocation is *not* among the costs, though it looks like it should be.
  CryptoAPI checks CRLs and OCSP only when passed one of the
  `CERT_CHAIN_REVOCATION_CHECK_` flags, and `systemVerify` passes none of them
  and never has. Go does no revocation checking either. A revoked certificate
  was accepted before this change and is accepted after it, by both paths.

`scripts/certprobe.go` in the picoclaw tree prints the platform verifier's bits
from a live connection, which is how the measurements above were established.

Programs no longer need their own copy of the bundle, and none of this changes
behaviour on any other GOOS: `linux/386` binaries are byte-identical with and
without the patch.

Switching it off, and pointing it elsewhere, both use interfaces Go already has
rather than any of our own:

| Setting | Effect |
|---|---|
| `GODEBUG=x509bundledroots=0` | Restores stock Windows behaviour: the platform verifier alone, the compiled-in bundle never consulted. This is the negative control for any claim that the bundle is what made a connection work. |
| `SSL_CERT_FILE=<path>` | Verify against that PEM and nothing else. Not ours: crypto/x509 has honoured `SSL_CERT_FILE` and `SSL_CERT_DIR` on Windows since Go 1.27, and when either is set `loadSystemRoots` builds an on-disk pool from it, so `Verify` never reaches `systemVerify` or the bundle. Use it for a fresher bundle than the one frozen into the binary, for a private root, or to falsify the wiring by pointing at a PEM that cannot possibly sign the endpoint. **Needs one of the two below to take effect** — measured on XP, an empty `SSL_CERT_FILE` was silently ignored without them and the bundle still verified the chain. |
| &nbsp;&nbsp;↳ `go 1.27` or later in `go.mod`, or `GODEBUG=x509sslcertoverrideplatform=1` | Upstream registered `x509sslcertoverrideplatform` with `Changed: 27, Old: "0"`, so its default is tied to the consuming module's `go` directive: a module declaring anything older than 1.27 — which every module targeting XP does — gets `=0`, and `SSL_CERT_FILE` is ignored on Windows. This is the exact trap that `x509bundledroots` is registered without `Changed`/`Old` to avoid. |
| `GODEBUG=x509sslcertoverrideplatform=0` | Upstream's switch for the line above: ignore `SSL_CERT_FILE`/`SSL_CERT_DIR` and use the platform store. |

An earlier version of this patch had two private variables, `GOXP_CA_BUNDLE` and
`GOXP_CA_FALLBACK`, for the first two rows. Both are gone: the first was a second
spelling of `SSL_CERT_FILE`, and the second is what GODEBUG exists for.

Note that `x509bundledroots` is registered in `internal/godebugs` with no
`Changed`/`Old` pair, deliberately. Those fields tie a setting's default to the
`go` directive in the consuming module's `go.mod`, and every module that targets
XP declares an older Go than this fork — a version-linked default would switch
the bundle off in precisely the programs that need it.

The bundle costs about **190 KB** per Windows binary that reaches
`crypto/x509` (measured: a hello-world doing one HTTPS GET went from 8,678,912
to 8,872,448 bytes on `windows/386`, +2.2%). Refresh it by regenerating
`src/crypto/x509/rootbundle_data_windows.go` from <https://curl.se/ca/cacert.pem>.

## Known unfixed

- `CancelIoEx` has no XP equivalent. The fallback is `CancelIo`, which only
  cancels I/O issued by the calling thread, so a read blocked past its deadline
  may not be interrupted if the goroutine migrated.
- `os.SameFile` is false for directory entries, because
  `GetFinalPathNameByHandle` is Vista+ and there is no path to open.

Neither is a regression — the Go 1.21 XP backports have the same holes.

Patching the standard library makes *this* toolchain's own programs work. It
does not make every Go program work: anything leaning on `os.Root`, symlink
resolution, or I/O deadlines can still find these holes.

## Verified

Windows XP 5.1.2600 x86, 2026-08-28. An agent binary built with this toolchain
holds a full conversation over TLS, reads directories, and spawns child
processes.

The bundled-roots path above was added later and has since been exercised on
that hardware too: both `github.com:443` and `openrouter.ai:443` verify from XP,
both fail with `GODEBUG=x509bundledroots=0`, and a clawxp agent turn completes
over TLS. On XP this is the path every HTTPS connection takes, so it is measured
there rather than believed.
