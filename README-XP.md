# goxp — Go for Windows XP

Go 1.27.0 that produces binaries Windows XP (NT 5.1) will load and run.

    Base:   thongtech/go-legacy-win7 @ 1b73f848   (Go 1.27.0, targets Win7 / PE 6.1)
    Delta:  59 files, +5628 / -217                (takes it back to XP / PE 5.1)
            + a root-certificate fallback         (see "HTTPS on XP" below)
            + os.Root.RemoveAll restored          (see "os.Root.RemoveAll" below)
            + os.Root made to work at all         (see "os.Root on XP" below)

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

    go run scripts/checkpe.go your.exe        # a companion tool, not included here

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

A companion tool not included here, `certprobe`, prints the platform verifier's
bits from a live connection, which is how the measurements above were
established.

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

## os.Root.RemoveAll

The base fork's commit c0f79a96 "Use removeall_noat variant on Windows" moved
Windows off `removeall_at.go`, which is right — the `_at` walk wants
openat/unlinkat-shaped syscalls — but it deleted `Root.RemoveAll` and *both*
`rootRemoveAll` implementations along with it instead of writing a Windows one.
The result was a toolchain whose `os.Root` was missing a method upstream Go
1.25 shipped and `api/go1.25.txt` still lists: user code calling
`root.RemoveAll` failed to compile, and `go test os` failed to build.

Restored here in four pieces:

| File | Change |
|---|---|
| `src/os/root.go` | the `Root.RemoveAll` method, upstream doc comment and all |
| `src/os/root_removeall_at.go` | `rootRemoveAll` for `unix \|\| wasip1`, upstream's, calling `removeAllFrom` (adapted only to this tree's `doInRoot` signature) |
| `src/os/root_removeall_windows.go` | a new handle-relative walk for Windows |
| `src/os/root_noopenat.go` | `rootRemoveAll` for js/wasm and plan9, plus the `syscall` import c0f79a96 dropped while leaving two uses behind |

Windows cannot use either deleted implementation. The `root_openat.go` one
calls `removeAllFrom`, which lives in the `removeall_at.go` that commit turned
off for Windows; the `root_noopenat.go` one calls `checkPathEscapesLstat`,
which only exists on js and plan9. So Windows gets its own, modelled on
`removeAllFrom` but built from the `*at` primitives `root_windows.go` already
has: `removefileat`, `removedirat`, `rootOpenDir`.

**Why it cannot walk out of the root.** Every syscall in the walk is issued
against an open directory handle with a single path component — never a path,
never `..`. `doInRoot` resolves the caller's path to (parent handle, leaf) and
rejects anything that escapes; from there the recursion only ever descends
through handles it opened itself with `O_NOFOLLOW_ANY`, so a reparse point
cannot be traversed: `rootOpenDir` fails on it rather than following it. (On XP
`O_NOFOLLOW_ANY` is honoured by a different mechanism, described under "os.Root
on XP" below; the guarantee it makes is the same one.) A
symlink met mid-walk is therefore deleted as a link and never followed, whether
it points inside the root or outside it — the same thing upstream's
`removeAllFrom` does. Deletion uses `FILE_OPEN_REPARSE_POINT` for the same
reason. An attacker who swaps a directory for a symlink between two steps
changes nothing: the next `rootOpenDir` on that handle returns `errSymlink`,
the walk stops descending, and `removedirat` removes the link itself.

The one thing resolved by *path* rather than by handle is the name given to the
`*File` wrapping each directory handle, which `File.readdir` needs for its
`FindFirstFile` fallback — the fallback XP takes, since it has no
`GetFileInformationByHandleEx`. That path is used only to *list* names. If it
were ever wrong, the names it produced would still be deleted relative to the
correct parent handle, so the blast radius is a spurious `ENOTEMPTY`, not a
deletion outside the root.

**Edge cases**, matching upstream and pinned by the tests already in
`root_test.go`: trailing separators are stripped, so `RemoveAll("file/")`
succeeds; `RemoveAll(".")` is `EINVAL`; a missing target is success; an
intermediate component that is not a directory is success. That last one is
mapped explicitly on Windows (`ENOTDIR` → `nil`), because here `Root.RemoveAll`
is the `_at` walk while the package-level `RemoveAll` is the `noat` one, and
`TestRootConsistencyRemoveAll` compares the two.

`go test os` passes apart from the pre-existing `TestFileReadDir` failure noted
under "Known unfixed".

**One correctness fix over upstream's shape.** When `Readdirnames` fails during
the walk, upstream's `removeAllFrom` returns success if the error satisfies
`IsNotExist`, on the reasoning that a descriptor reporting its own directory
gone means the directory is gone. This listing is not descriptor-based: on the
Windows versions without `GetFileInformationByHandleEx`, `File.readdir` falls
back to `FindFirstFile`, which resolves the directory *by name*, and a name that
no longer resolves gives `ERROR_PATH_NOT_FOUND` — which `IsNotExist` accepts.
The same error therefore no longer establishes what upstream reads it as, so
here it stops the listing and falls through to `removedirat`, which answers the
question properly: it succeeds if the directory really has gone and returns
`ENOTEMPTY` if it has not. Claiming to have deleted files that are still on disk
is a worse failure than an honest `ENOTEMPTY`.

## os.Root on XP

Before this, essentially none of `os.Root` worked on XP. Measured on SP3, every
handle-relative open failed with `ERROR_INVALID_PARAMETER` and every
handle-relative delete with `ERROR_NOT_SUPPORTED`, so `Open`, `Stat`, `ReadFile`,
`WriteFile`, `Create`, `OpenFile`, `MkdirAll`, `Chtimes`, `Chmod`, `Readlink`,
`Remove`, `RemoveAll`, `OpenRoot` and `FS` were all dead; `Mkdir`, `Rename` and
`Link` happened to work because they do not go through either call. All of them
work now.

Four separate things were wrong.

**`OBJ_DONT_REPARSE` is Windows 10 1607.** `Openat` sets it in
`OBJECT_ATTRIBUTES.Attributes` whenever the caller asks for `O_NOFOLLOW_ANY`,
which `os/root_windows.go` does on every open. Older kernels define
`OBJ_VALID_ATTRIBUTES` as `0x000007F2` and reject any attribute outside it, and
they do so while capturing the object attributes, *before* the name is resolved
— which is why this broke every open and not only the ones that would have met
a link. Measured on XP SP3, opening an existing file relative to a directory
handle:

| attributes | XP SP3 | Windows 11 |
|---|---|---|
| `OBJ_CASE_INSENSITIVE` | `STATUS_SUCCESS` | `STATUS_SUCCESS` |
| `+ OBJ_DONT_REPARSE` | `STATUS_INVALID_PARAMETER` | `STATUS_SUCCESS` |
| `+ OBJ_DONT_REPARSE`, name that does not exist | `STATUS_INVALID_PARAMETER` | `STATUS_OBJECT_NAME_NOT_FOUND` |

That third row is what makes a capability probe cheap and honest: the attribute
is validated before any filesystem is touched, so the probe needs nothing to
exist. `objDontReparseSupported` in `at_windows.go` opens `\??\NUL` twice, once
with the attribute and once without, and concludes the attribute is unsupported
only when the flagged open is refused as invalid and the unflagged one is not.
Every ambiguous answer resolves towards "supported", which is the stricter path.
No version number is consulted, so Wine, ReactOS and Server 2003 each get the
answer that is true of them.

**Containment is kept, not traded away.** Dropping `OBJ_DONT_REPARSE` and
opening normally would have made `os.Root` work while letting a junction lead
straight out of the root, so it was worth checking whether the older primitive
is enough. It is. `FILE_OPEN_REPARSE_POINT` is an NT 4-era create option that
tells the filesystem to open a reparse point rather than follow it, and
`GetFileInformationByHandle` — Windows 2000 — then reports whether that is what
we got. So where `OBJ_DONT_REPARSE` is unavailable, `Openat` asks for the link
itself and refuses the handle afterwards, returning the same `ELOOP` the object
manager would have produced. Measured, XP SP3 and Windows 11 agreeing exactly:

| open of a junction, relative to a directory handle | resulting attributes |
|---|---|
| without `FILE_OPEN_REPARSE_POINT` | `0x010` — the link was followed |
| with `FILE_OPEN_REPARSE_POINT` | `0x410` — `FILE_ATTRIBUTE_REPARSE_POINT` set |

Three properties make this a real substitute rather than a near-enough one.
The check is on a handle already held, so nothing can be swapped between the
test and the use — it is not a path-based race. Every name reaching `Openat`
from `os.Root` is a single component resolved against a directory handle,
because `doInRoot` walks a path one element at a time, so "the last component"
is the only component and `FILE_OPEN_REPARSE_POINT` covers all of it. And the
check runs before `O_TRUNC` does, so a link is never truncated on its way to
being refused. Callers that legitimately want the link — `Lstat`, `Readlink`,
`Chmod` — pass `O_FILE_FLAG_OPEN_REPARSE_POINT` themselves and are exempted,
which is also what happens where `OBJ_DONT_REPARSE` exists: the two flags
together open the reparse point rather than failing.

From there the existing machinery is untouched. `ELOOP` sends
`os/root_windows.go` to `readReparseLinkAt`, the link target comes back as
`errSymlink`, and `doInRoot` re-resolves it inside the root — so a junction
pointing *within* the root still resolves, and one pointing outside becomes
`ErrPathEscapes`.

**`Deleteat` had no XP path at all.** Its primary route is
`NtSetInformationFile` with `FileDispositionInformationEx` (class 64, Windows 10
1607); on XP that returns `STATUS_INVALID_INFO_CLASS`, and the fallback it drops
to ended at `SetFileInformationByHandle`, which is Vista and guarded here as
`ERROR_NOT_SUPPORTED`. But the Win32 call is a thin wrapper over
`NtSetInformationFile` with `FileDispositionInformation` (class 13) and
`FileBasicInformation` (class 4), both of which NT has had since 3.1 and both of
which were measured working on XP SP3. `SetFileBasicInfoByHandle` and
`setFileDispositionByHandle` use the Win32 call where it exists and the native
one it wraps where it does not, chosen by `procSetFileInformationByHandle.Find()`.
`FILE_BASIC_INFO` and `FILE_BASIC_INFORMATION` have the same 40-byte layout, so
the same struct serves both. This also fixes `Root.Chmod`, which went through
`SetFileInformationByHandle` too and silently did nothing whenever an attribute
actually needed changing.

**`ReOpenFile` is not on XP**, despite being documented as XP and later — it
arrived with Server 2003. `deleteatFallback` calls it to get write-attributes
access before clearing a read-only bit, and because `LazyProc.Addr` *panics*
rather than returning an error, `Root.Remove` of a read-only file took the whole
process down. It is now guarded like the other five, and `reopenFileHandle`
falls back to what `ReOpenFile` is itself implemented as: an `NtOpenFile` of the
empty name relative to the handle, the NT idiom for "this same file again".
That reaches the file by handle rather than by name, so nothing can be
substituted underneath it.

**The reparse tag had no pre-Vista source.** `newFileStatFromGetFileInformationByHandle`
reads it with `GetFileInformationByHandleEx(FileAttributeTagInfo)`, so on XP
`Lstat` of any reparse point failed outright — and without a tag, `Mode` would
have reported a junction as an ordinary directory, which is how a walk ends up
following one. `readReparseTagHandle` reads it from the reparse point with
`FSCTL_GET_REPARSE_POINT`, which is how this was done before that call existed.
`FSCTL_GET_REPARSE_POINT` is defined `FILE_ANY_ACCESS`, so it works on the
zero-access handles `os.Lstat` opens. This fixes path-based `os.Lstat` on XP as
well, not only `Root.Lstat`.

| File | Change |
|---|---|
| `src/internal/syscall/windows/at_windows.go` | the `OBJ_DONT_REPARSE` probe and its `FILE_OPEN_REPARSE_POINT` substitute; native `FileBasicInformation`/`FileDispositionInformation`; `reopenFileHandle` |
| `src/internal/syscall/windows/zsyscall_windows.go` | a sixth `.Find()` guard, on `ReOpenFile` |
| `src/os/types_windows.go` | reparse tag via `FSCTL_GET_REPARSE_POINT` when `GetFileInformationByHandleEx` is absent |
| `src/os/file_windows.go` | `readReparseTagHandle` |
| `src/os/root_windows.go` | `chmodat` through `SetFileBasicInfoByHandle` |
| `src/os/root_removeall_windows.go` | stop reporting success on an unlistable directory |
| `src/testing/testing_windows.go` | tolerate a `QueryPerformanceCounter` that runs backwards |

That last one is not about `os.Root`, but it is what stood between the change
and being able to test it on the hardware. `QueryPerformanceCounter` is read
from each core's TSC on XP and is not synchronised between them, so a goroutine
that migrates sees time run backwards; `testing`'s `highPrecisionTime.sub` turned
the negative delta into a near-2^64 unsigned one and `bits.Div64` panicked
partway through the run. A negative delta now reports no elapsed time, which on
a machine whose counter really is monotonic never happens.

### What XP still cannot do

- **`os.Symlink` does not work.** `CreateSymbolicLinkW` is Vista, and XP's I/O
  manager cannot resolve a symbolic-link reparse point even if one exists.
  `Root.Symlink` is stranger: it builds the reparse point itself with
  `FSCTL_SET_REPARSE_POINT`, and XP's NTFS accepts the tag, so the call
  *succeeds* and `Root.Readlink` reads it back — but the OS will not follow the
  result (`os.Open` on it fails with `ERROR_CANT_ACCESS_FILE`), while `os.Root`
  will, because `doInRoot` resolves links itself. Do not create symlinks on XP
  expecting anything else to see them.
- **Deleting or renaming over a file that is still open behaves differently.**
  XP has no POSIX-semantics delete or rename; `FILE_DISPOSITION_INFORMATION_EX`
  and `FILE_RENAME_INFORMATION_EX` are both Windows 10 1607. Measured, with
  another handle open on the victim:

  | | XP SP3 | Windows 11 |
  |---|---|---|
  | `Root.Remove` | returns nil, name stays in the directory and opens with `ERROR_ACCESS_DENIED` until the last handle closes | name gone at once |
  | `Root.Rename` onto it | `ERROR_ACCESS_DENIED` | succeeds |
  | `os.Remove` / `os.Rename` (path-based) | fails | fails |

  So on XP `Root.Remove` is `DeleteFileW`'s deferred deletion rather than an
  unlink. This is a difference in *when*, not in *what*: nothing outside the root
  is reachable either way.

### Verified on hardware

Windows XP 5.1.2600 SP3, 2026-08-31, cross-compiled `windows/386`. Before this
change the same probe reported `OpenRoot` and `Mkdir` working, everything else
failing with "The parameter is incorrect" or "The request is not supported", and
then panicked in `ReOpenFile` on the first read-only delete. After:

    read paths:   Open, Stat, Lstat, ReadFile, Open dir, Readdirnames,
                  OpenRoot, FS ReadFile, FS ReadDir            all OK
    write paths:  WriteFile, Create, OpenFile O_CREATE, Mkdir, MkdirAll,
                  Chmod both ways, Chtimes, Rename, Link       all OK
    delete paths: Remove, Remove read-only, RemoveAll file,
                  RemoveAll tree, Remove dir                   all OK

with a junction planted inside the root pointing out of it — created with
`FSCTL_SET_REPARSE_POINT`, since `mklink` is Vista — and confirmed to resolve by
path first:

    Root.Open   through junction   refused: path escapes from parent
    Root.Stat   through junction   refused: path escapes from parent
    Root.ReadFile through junction refused: path escapes from parent
    Root.OpenRoot on junction      refused: path escapes from parent
    Root.Stat   on junction        refused: path escapes from parent
    Root.Remove through junction   refused: path escapes from parent
    Root.RemoveAll through junction refused: path escapes from parent
    Root.WriteFile through junction refused: path escapes from parent
    Root.Lstat  on junction        OK, mode ?rw-rw-rw-, IsDir false
    Root.Readlink on junction      OK, "...\OUTSIDE"
    Root.RemoveAll over the directory containing it   OK
      the junction's target and its contents          survive
      the directory containing the junction           gone

The same binary built for `windows/amd64` prints an identical report on Windows
11, line for line, which is the point: the XP path is not a weaker one.

`TestRootJunctionContainment` in `os/root_windows_test.go` is that experiment as
a test, and runs on every Windows version.

The `os` test binary run on the hardware with `-test.run '^TestRoot'` passes
everything outside the `TestRootMulti` family. Within it, 1638 subtests fail
because `os.Symlink` cannot build their fixture, and 258 fail in `t.TempDir()`
cleanup because `dirTreeContents` in `root_test.go` never closes the files it
opens and XP cannot delete a file that is still open. Eight of those 258 also
report a real inconsistency, and all eight are the deferred-delete difference
described above. Nothing else in the suite disagrees between XP and Windows 11.

## Known unfixed

- `CancelIoEx` has no XP equivalent, and this is the root of most of what
  follows. The fallback is `CancelIo`, which only cancels I/O issued by the
  calling thread — no use when that thread is itself parked inside `ReadFile`.
  `execIO` now pins a goroutine to its thread so `CancelIo` can at least reach
  the operations it is able to, and `Close` gives up after five seconds rather
  than waiting forever on a completion that cannot arrive, leaking the handle
  and thread instead of hanging. Set `GOXP_ABANDONED_CLOSE=warn` (or `panic`)
  to find out when that happens.
- `Cmd.WaitDelay` does not bound `Wait` when a grandchild inherits the child's
  output pipe. WaitDelay works by abandoning the pending read, which is the one
  thing XP cannot do, so `Wait` blocks until the grandchild exits on its own.
- `CreateProcess` does not reject a file that is not a valid PE image. 32-bit
  Windows hands it to NTVDM, the DOS subsystem, which starts successfully and
  then waits at an error dialog. So starting a corrupt `.exe` returns no error
  and the resulting process never exits, where 64-bit Windows fails cleanly
  with `ERROR_BAD_EXE_FORMAT`.
- Symbolic links cannot be created with `os.Symlink` or followed by anything but
  `os.Root`, and deleting or renaming over a file that is still open is deferred
  rather than immediate. Both are detailed under "os.Root on XP".

None of these is a regression against the Go 1.21 XP backports, which have the
same holes or worse. `os.SameFile` was in this list and is not any more: it now
takes the volume serial from `GetFileInformationByHandle` and the path from the
`NtQueryObject` shim, and answers correctly for directory entries.

Patching the standard library makes *this* toolchain's own programs work. It
does not make every Go program work: anything leaning on symlink resolution or
I/O deadlines can still find these holes.

## Verified

Windows XP 5.1.2600 x86, 2026-08-28. An agent binary built with this toolchain
holds a full conversation over TLS, reads directories, and spawns child
processes.

The bundled-roots path above was added later and has since been exercised on
that hardware too: both `github.com:443` and `openrouter.ai:443` verify from XP,
both fail with `GODEBUG=x509bundledroots=0`, and a clawxp agent turn completes
over TLS. On XP this is the path every HTTPS connection takes, so it is measured
there rather than believed.

`os.Root` was brought up on that hardware on 2026-08-31, junction and all; see
"os.Root on XP" for what was measured and what still differs.
