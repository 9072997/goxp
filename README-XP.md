# goxp — Go for Windows XP

Go 1.27.0 that produces binaries Windows XP (NT 5.1) will load and run.

    Base:   thongtech/go-legacy-win7 @ 1b73f848   (Go 1.27.0, targets Win7 / PE 6.1)
    Delta:  8 files, +247 / -73                   (takes it back to XP / PE 5.1)

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
