# goxp — Go for Windows XP

Go 1.27.1 that produces binaries Windows XP (NT 5.1) will load and run.

    Base:   thongtech/go-legacy-win7 v1.27.1-1 @ 2f6cdc24   (Go 1.27.1, targets Win7 / PE 6.1)
    Delta:  58 files, +6373 / -212                (takes it back to XP / PE 5.1)
            + a root-certificate fallback         (see "HTTPS on XP" below)
            + os.Root made to work at all         (see "os.Root on XP" below)
            + directories listed by handle        (see "Directory listing on XP" below)

The base is merged, not rebased: `go1.27.1-xp` is the XP line with
`v1.27.1-1` merged into it, and "Merging the base" below says what that merge
had to reconcile. The hardware measurements recorded in this file were taken
on XP builds from before that merge.

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
| `src/os/dir_windows.go` | a directory reader that works without `GetFileInformationByHandleEx` |
| `src/internal/syscall/windows/zsyscall_windows.go` | `.Find()` guards on 5 Vista+ procs |
| `src/syscall/zsyscall_windows.go` | `.Find()` guards |
| `src/syscall/exec_windows.go` | plain-`STARTUPINFO` process creation |

Three of these were not obvious.

**`os.ReadDir` panicked.** Go 1.22 rewrote the Windows directory reader —
`os/dir_windows.go` went from 80 lines on `FindNextFile` to 230 on
`GetFileInformationByHandleEx` and `GetVolumeInformationByHandle`, both Vista+.
`syscall.LazyProc.mustFind` **panics** rather than returning an error, so guards
alone cannot save it; something has to actually read the directory. On XP
that is `NtQueryDirectoryFile` on the directory's own handle, described under
"Directory listing on XP".

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

`Root.RemoveAll` and the package-level `RemoveAll` are one handle-relative walk
on Windows, the `removeAllFrom` in `removeall_at.go`, as in upstream Go. Every
syscall in it is issued against an open directory handle with a single path
component, and it descends only through handles opened with `O_NOFOLLOW_ANY`,
so a link met mid-walk is deleted as a link and never followed. On XP
`O_NOFOLLOW_ANY` is honoured by a different mechanism, described under
"os.Root on XP"; the guarantee it makes is the same one.

Two things make that walk correct on XP.

**It lists by handle.** The walk wraps each directory handle in a `*File` named
only by the entry's base name, so a listing that resolved the directory by name
would list a directory of that name relative to the current directory instead.
`File.readdir` lists by handle, XP included (see "Directory listing on XP").
Only its last resort, for a file system that refuses to list a directory by
handle at all, uses that name, and even then every name it produced is deleted
relative to the correct parent handle, so the blast radius is a spurious
`ENOTEMPTY`, not a deletion outside the root.

**An unlistable directory is not reported as deleted.** When `Readdirnames`
fails during the walk, upstream's `removeAllFrom` returns success if the error
satisfies `IsNotExist`, on the reasoning that a descriptor reporting its own
directory gone means the directory is gone. On Windows the last-resort listing
resolves a name, and a name that does not resolve gives `ERROR_PATH_NOT_FOUND`,
which `IsNotExist` accepts. So on Windows that error stops the listing and falls
through to `removedirat`, which succeeds if the directory really has gone and
returns `ENOTEMPTY` if it has not.

| File | Change |
|---|---|
| `src/os/removeall_at.go` | on Windows, an `IsNotExist` listing error ends the listing rather than the walk |

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
answer that is true of them. The probe decides once, before the first open, so
no open has to fail first to teach it; `TestOpenatNoObjDontReparse` forces the
substitute below on any Windows, and `ObjDontReparseUnsupportedForTest` reports
the probe's answer.

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
the same struct serves both. `Root.Chmod`, `File.Chmod`, and every step of the
delete fallback that sets information on a handle go through them: clearing a
read-only bit, marking the file for deletion, and marking for deletion the copy
that `Renameat`'s fallback moves aside when it replaces a rename target. Called
directly, `SetFileInformationByHandle` reports `ERROR_NOT_SUPPORTED` on XP, and
that last one would leave the moved copy in the temporary directory for good.

**`ReOpenFile` is not on XP**, despite being documented as XP and later: it
arrived with Server 2003, and `LazyProc.Addr` *panics* on a missing entry point
rather than returning an error. It is guarded like the other five and reports
`ERROR_NOT_SUPPORTED`. Nothing in `os.Root` calls it: the delete fallback gets
write-attributes access by opening the name again relative to the parent
handle, and clears the read-only bit only if the file it opened is the one it
is deleting, by volume serial and file index.

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
| `src/internal/syscall/windows/at_windows.go` | the `OBJ_DONT_REPARSE` probe and its `FILE_OPEN_REPARSE_POINT` substitute; native `FileBasicInformation`/`FileDispositionInformation`, used by the delete and rename fallbacks |
| `src/internal/syscall/windows/zsyscall_windows.go` | a sixth `.Find()` guard, on `ReOpenFile` |
| `src/os/types_windows.go` | reparse tag via `FSCTL_GET_REPARSE_POINT` when `GetFileInformationByHandleEx` is absent |
| `src/os/file_windows.go` | `readReparseTagHandle` |
| `src/os/root_windows.go` | `chmodat` through `SetFileBasicInfoByHandle` |
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

## Directory listing on XP

`File.readdir` reads a directory from its handle on every Windows version. It
is what `os.ReadDir`, `File.ReadDir`, `Readdir`, `Readdirnames`, `fs.ReadDir` on
`os.DirFS` and `Root.FS`, and the `RemoveAll` walk all list with. Go's own
reader uses `GetFileInformationByHandleEx`, which is Vista, with
`FileFullDirectoryRestartInfo`, and falls back to `FileIdBothDirectoryRestartInfo`
where the kernel predates the first. Where the call is missing, or refuses both
classes, this fork calls `NtQueryDirectoryFile` on the same handle. It is an NT 3.1
system call, and XP's ntdll exports it.

Listing by handle is what keeps an `os.Root` listing inside the root. Take a
directory opened through a `Root`, rename it away, and put a junction to a
directory outside the root under its old name. The handle still refers to the
original, and a listing through it lists the original. A reader that looks the
directory up again by name lists the outside directory instead, which leaks the
names, sizes, times and attributes of its entries.

The information class is `FileBothDirectoryInformation`, the one kernel32's
`FindFirstFileW` and `FindNextFileW` are built on. Any file system those can
list answers it, and each entry carries exactly what `WIN32_FIND_DATAW`
carries: attributes, the three times, the size, and for a reparse point the
reparse tag in `EaSize`. The tag is what makes a junction report as a link
rather than as a directory.

- The first query restarts the handle's scan and later ones continue it. A
  bounded `Readdir(n)` keeps its place across calls and ends with `io.EOF`, and
  a `Seek` back to the start lists again from the beginning.
- `STATUS_NO_SUCH_FILE` on the first query is an empty directory.
- If not even one entry fits the 64 kB buffer, the buffer doubles, up to 1 MB,
  and the scan restarts, skipping the entries already returned. Whether a file
  system moves past an entry that did not fit is up to the file system, so
  carrying on without the restart could skip or repeat one.
- `.` and `..` are skipped, and are not counted when skipping after a restart:
  NTFS, with a buffer too small for both, returns `.` and never `..`.
- A directory opened with `FILE_FLAG_OVERLAPPED` would answer the query with
  `STATUS_PENDING`, so it is listed through a second, synchronous handle, opened
  by `NtOpenFile` of the empty name relative to the first. That reaches the same
  directory by handle, not by name. `ReOpenFile` cannot do this: on Windows 11
  it fails with `ERROR_ACCESS_DENIED` on directories for every access mask and
  share mode tried. Go's own reader, on Vista and later, blocks forever on such
  a handle; this fork does not change that.
- `FindFirstFile`, which resolves the directory by name, is the last resort. It
  is used only when the file system refuses the first query outright
  (`STATUS_INVALID_INFO_CLASS`, `STATUS_INVALID_PARAMETER`,
  `STATUS_NOT_SUPPORTED` or `STATUS_NOT_IMPLEMENTED`) on a handle that is a
  directory. Local NTFS and FAT do not refuse it.

The directory handles `os` opens already allow the query. `os.Open` goes through
`CreateFileW` with `GENERIC_READ` and without `FILE_FLAG_OVERLAPPED`, and
`os.Root` through `NtCreateFile` with `FILE_GENERIC_READ` and
`FILE_SYNCHRONOUS_IO_NONALERT`. Both grant `FILE_LIST_DIRECTORY` and synchronous
I/O.

`os.SameFile` compares identities it reads by opening each `FileInfo`'s path
again. For a listing entry that path is the directory's joined with the name;
for a `Stat` or `Lstat` result it is the path `stat` opened. Both reopens go
through `fixLongPath`, as the original opens did, so a long path gets its
`\\?\` prefix. A process that is not long-path aware, which on XP is every
process, cannot open a path of 248 characters or more without it. Upstream's
`fileStat.loadFileId` reopens a `Stat` or `Lstat` path without the prefix,
and there `os.SameFile` reports false for such a path.

| File | Change |
|---|---|
| `src/os/dir_windows.go` | `readDirNtQuery`; the `FindFirstFile` reader as the last resort |
| `src/os/types_windows.go` | `newFileStatFromFileBothDirInformation`; `loadFileId` reopens a `Stat` or `Lstat` path through `fixLongPath` |
| `src/internal/syscall/windows/syscall_windows.go` | `NtQueryDirectoryFile`, `FILE_BOTH_DIR_INFORMATION`, six status codes |
| `src/internal/syscall/windows/zsyscall_windows.go` | the `NtQueryDirectoryFile` binding, with a `.Find()` guard |
| `src/internal/syscall/windows/at_windows.go` | `ReopenDirectoryForListing` |
| `src/os/dir_windows_test.go` | the tests below |

`FILE_BOTH_DIR_INFORMATION`'s `ShortNameLength` is one byte, so `FileName` is at
offset 94; `TestFileBothDirInformationLayout` pins that. The tests in
`os/dir_windows_test.go` run each case twice on any Windows: once as the
machine is, and once with `readDirPreVista` forcing the XP reader, so the build
host tests the XP path too.

- `TestRootReadDirAfterJunctionSwap`: the swap above, through `Open` listed four
  ways and through a sub-root's `Open(".")` and `FS`.
- `TestReadDirByHandleFields`: every field of every entry, and `os.SameFile`,
  against `Lstat`, including a junction, a read-only file, a non-ASCII name and
  a 200-character name.
- `TestReadDirByHandlePaging`: pages of 1, 3, 5 and 100, past the end, after a
  `Seek`, and with a 128-byte buffer so that entries overflow it mid-listing.
- `TestReadDirByHandleOverlapped` and `TestReadDirByHandleOddCases`: an
  overlapped handle, an empty directory, a regular file (`ENOTDIR`), and the
  named-pipe file system.
- `TestSameFileLongPath`: `os.SameFile` between `Lstat`, `Stat` and a listing
  entry of a file whose path is 248 characters or more, in a process that is
  not long-path aware. On a Windows that makes the process long-path aware, the
  test clears the PEB bit that does so for its duration, and first checks that
  the path without the prefix really fails to open.

### Verified on hardware

Windows XP 5.1.2600 SP3, 2026-09-15, cross-compiled `windows/386`.

`osroot-probe` reports 91 passed, 0 failed. Both swap cases list the original
directory: `R01` lists `inside-only.txt`, and `R04`, through a sub-root, lists
`planted.txt,secret.txt`, the original's entries rather than the outside
directory's `secret.txt,sub`. `R02` and `R03`, which read and write through the
swapped sub-root, pass. A directory reached by a 365-character path, past
`MAX_PATH`, lists correctly.

The `os` test binary, run from a copy of `src/os` with

    os.test.exe -test.v -test.run "^(TestRootReadDirAfterJunctionSwap|TestReadDirByHandle.*|TestRootJunctionContainment|TestReadDir.*|TestReaddir.*|TestFileReadDir|TestFileReaddir.*|TestDirFS.*|TestRootDirFS|TestRootRemoveAll.*|TestRemoveAll.*|TestRootOpen_Directory|TestSameFile.*)$"

passes every test it runs. The 42 skips are symlink fixtures XP cannot build and
tests that do not apply to Windows. That includes `TestFileReadDir` and
`TestReadDirByHandleFields`, which compare each entry of a listing with `Lstat`
by `os.SameFile`, the latter's 200-character name included, and
`TestSameFileLongPath`.

## Merging the base

`v1.27.1-1` brings Go 1.27.1 and a set of Windows 7 fixes, several of which
reach the same code as the XP patches: a Windows 7 kernel lacks many of the
same things an XP one does. Where the two answer the same question, this tree
keeps one answer, and says which.

| Area | `v1.27.1-1` | This tree |
|---|---|---|
| PE stamp, `cmd/link/internal/ld/pe.go` | 6.1, with a test that checks it | 5.1; `TestPEMinimumTargetVersion` checks 5.1 |
| Kernels without `OBJ_DONT_REPARSE`, `Openat` | learns it from the first open refused with `STATUS_INVALID_PARAMETER`, retried | the `\??\NUL` probe decides before the first open; the base's test hooks report and force it |
| Delete fallback, `deleteatFallback` | reopens the name to clear a read-only bit, and moves a file aside so its name goes at once | the same, with every set-information call through the XP wrappers |
| Rename over a held or linked target, `Renameat` | moves the target aside, renames, deletes the moved copy | the same, with the delete through the XP wrapper; a directory link as target is left alone on XP, where its tag cannot be read that way |
| Directory listing, `File.readdir` | `FileFullDirectoryRestartInfo`, then `FileIdBothDirectoryRestartInfo`; the `FindFirstFile` reader removed | both classes first, then `NtQueryDirectoryFile` by handle, then `FindFirstFile` |
| `RemoveAll` | the handle-relative `removeAllFrom` for both `os.RemoveAll` and `Root.RemoveAll` | the same walk, with the change under "os.Root.RemoveAll" |
| Console names in `os.Stat` | retry `GetFileAttributesEx` misses and `CreateFile` refusals by name, and open `\\.\CONIN$` as `CONIN$` | the base's, which covers XP's refusals as well; `SupportDeviceNamesInFileAPIs` only gates a test |
| Runtime DLL loading | `LoadLibraryExW` with `LOAD_LIBRARY_SEARCH_SYSTEM32`, then by absolute path in the system directory; `ProcessPrng`, then `RtlGenRandom` | the same; the Vista kernel32 entry points are looked up in the kernel32 that path loads |
| File I/O, `internal/poll` | handles other than sockets stay off the completion port where it cannot release them, each operation waiting on an event | the same, and `Close` wakes those waits where `CancelIoEx` is missing, since `CancelIo` from `Close`'s thread cannot reach them |
| `os.Remove` | deletes through `Deleteat` on the parent first | the base's |

The rest of `v1.27.1-1` merges without touching an XP patch.

## Known unfixed

- `CancelIoEx` has no XP equivalent, and this is the root of most of what
  follows. The fallback is `CancelIo`, which only cancels I/O issued by the
  calling thread — no use when that thread is itself parked inside `ReadFile`.
  `execIO` now pins a goroutine to its thread so `CancelIo` can at least reach
  the operations it is able to, and `Close` gives up after five seconds rather
  than waiting forever on a completion that cannot arrive, leaking the handle
  and thread instead of hanging. Set `GOXP_ABANDONED_CLOSE=warn` (or `panic`)
  to find out when that happens. Handles other than sockets stay off the
  completion port on XP, because it cannot take a handle back off one, and an
  operation on them waits on its own event; `Close` signals those waits so that
  each cancels its own operation from the thread it is pinned to.
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
"os.Root on XP" for what was measured and what still differs. Directory listing
by handle was verified there on 2026-09-15; see "Directory listing on XP".
