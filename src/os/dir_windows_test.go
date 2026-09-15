// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package os_test

import (
	"errors"
	"fmt"
	"internal/syscall/windows"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// forEachReadDirReader runs f once with File.readdir as it is on this machine,
// and once as it is on Windows XP, where GetFileInformationByHandleEx does not
// exist and directories are listed with NtQueryDirectoryFile instead. On XP
// itself the two runs take the same path.
func forEachReadDirReader(t *testing.T, f func(t *testing.T)) {
	t.Run("default", f)
	t.Run("prevista", func(t *testing.T) {
		*os.ReadDirPreVista = true
		defer func() { *os.ReadDirPreVista = false }()
		f(t)
	})
}

func mustMkJunction(t *testing.T, link, target string) {
	t.Helper()
	var rd reparseData
	rd.addSubstituteName(`\??\` + target)
	rd.addPrintName(target)
	if err := createMountPoint(link, &rd); err != nil {
		t.Skipf("cannot create a junction here: %v", err)
	}
}

// TestRootReadDirAfterJunctionSwap holds a directory handle obtained through a
// Root, renames the directory away and puts a junction to a directory outside
// the root under its old name, then lists the handle. The listing must be the
// original directory's: the handle still refers to it. A reader that resolves
// the directory by name lists the outside directory instead, which is what the
// FindFirstFile reader did on Windows XP.
func TestRootReadDirAfterJunctionSwap(t *testing.T) {
	forEachReadDirReader(t, testRootReadDirAfterJunctionSwap)
}

func testRootReadDirAfterJunctionSwap(t *testing.T) {
	tmp := t.TempDir()
	outside := filepath.Join(tmp, "outside")
	if err := os.Mkdir(outside, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("outside"), 0o666); err != nil {
		t.Fatal(err)
	}
	rootDir := filepath.Join(tmp, "ROOT")
	for _, d := range []string{"a", "b"} {
		if err := os.MkdirAll(filepath.Join(rootDir, d), 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(rootDir, d, "inside"), []byte("inside"), 0o666); err != nil {
			t.Fatal(err)
		}
	}

	r, err := os.OpenRoot(rootDir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	// Handles taken before the swap: one per way of listing, since a listing
	// consumes the handle's scan.
	var held []*os.File
	for range 4 {
		f, err := r.Open("a")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		held = append(held, f)
	}
	sub, err := r.OpenRoot("b")
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()

	swap := func(name string) {
		t.Helper()
		if err := os.Rename(filepath.Join(rootDir, name), filepath.Join(rootDir, name+"-moved")); err != nil {
			t.Fatalf("renaming a directory held open through a Root: %v", err)
		}
		mustMkJunction(t, filepath.Join(rootDir, name), outside)
		// The junction really does lead outside when resolved by name, or
		// nothing below proves anything.
		if got, err := os.ReadFile(filepath.Join(rootDir, name, "secret")); err != nil || string(got) != "outside" {
			t.Fatalf("junction does not resolve (%q, %v), so this test proves nothing", got, err)
		}
	}
	swap("a")
	swap("b")

	want := []string{"inside"}
	check := func(what string, got []string, err error) {
		t.Helper()
		slices.Sort(got)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("%s after the swap = %q, %v; want %q", what, got, err, want)
		}
	}

	names, err := held[0].Readdirnames(-1)
	check(`Open("a").Readdirnames(-1)`, names, err)

	entries, err := held[1].ReadDir(-1)
	names = nil
	for _, e := range entries {
		names = append(names, e.Name())
	}
	check(`Open("a").ReadDir(-1)`, names, err)

	infos, err := held[2].Readdir(-1)
	names = nil
	for _, fi := range infos {
		names = append(names, fi.Name())
	}
	check(`Open("a").Readdir(-1)`, names, err)

	names = nil
	for {
		chunk, err := held[3].Readdirnames(1)
		names = append(names, chunk...)
		if err == io.EOF {
			break
		}
		if err != nil || len(names) > 10 {
			t.Errorf(`Open("a").Readdirnames(1) = %q, %v`, names, err)
			break
		}
	}
	check(`Open("a").Readdirnames(1) paged`, names, nil)

	d, err := sub.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	names, err = d.Readdirnames(-1)
	check(`sub-root Open(".").Readdirnames(-1)`, names, err)

	entries, err = fs.ReadDir(sub.FS(), ".")
	names = nil
	for _, e := range entries {
		names = append(names, e.Name())
	}
	check(`fs.ReadDir(sub.FS(), ".")`, names, err)
}

// TestReadDirByHandleFields lists a directory holding one of everything a
// listing distinguishes, and checks that every field of every entry agrees
// with Lstat of the same name.
func TestReadDirByHandleFields(t *testing.T) {
	forEachReadDirReader(t, testReadDirByHandleFields)
}

func testReadDirByHandleFields(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "file"), []byte("twelve bytes"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "readonly"), []byte("ro"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "café-日本"), nil, 0o666); err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("L", 200)
	if err := os.WriteFile(filepath.Join(dir, long), []byte("long"), 0o666); err != nil {
		t.Fatal(err)
	}
	mustMkJunction(t, filepath.Join(dir, "junction"), filepath.Join(dir, "subdir"))
	wantNames := []string{"café-日本", "file", "junction", long, "readonly", "subdir"}
	slices.Sort(wantNames)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	again, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for i, e := range entries {
		names = append(names, e.Name())
		path := filepath.Join(dir, e.Name())
		lst, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		fi, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		if e.IsDir() != lst.IsDir() || e.Type() != lst.Mode().Type() {
			t.Errorf("%s: DirEntry IsDir %v, Type %v; Lstat IsDir %v, Type %v",
				e.Name(), e.IsDir(), e.Type(), lst.IsDir(), lst.Mode().Type())
		}
		if fi.Mode() != lst.Mode() || fi.Size() != lst.Size() || !fi.ModTime().Equal(lst.ModTime()) {
			t.Errorf("%s: Info mode %v size %d mtime %v; Lstat mode %v size %d mtime %v",
				e.Name(), fi.Mode(), fi.Size(), fi.ModTime(), lst.Mode(), lst.Size(), lst.ModTime())
		}
		got := fi.Sys().(*syscall.Win32FileAttributeData)
		want := lst.Sys().(*syscall.Win32FileAttributeData)
		if got.FileAttributes != want.FileAttributes || got.CreationTime != want.CreationTime ||
			got.LastWriteTime != want.LastWriteTime || got.FileSizeHigh != want.FileSizeHigh || got.FileSizeLow != want.FileSizeLow {
			t.Errorf("%s: Info().Sys() = %+v; Lstat = %+v", e.Name(), *got, *want)
		}
		// An entry's identity is looked up lazily, by opening the directory's
		// path joined with the entry's name, and that join goes through
		// fixLongPath. Compare it with the same entry from a second listing,
		// which exercises that lookup for every name, the long one included.
		if fi2, err := again[i].Info(); err != nil || again[i].Name() != e.Name() || !os.SameFile(fi, fi2) {
			t.Errorf("%s: os.SameFile of the entry from two listings = false (second: %q, %v)", e.Name(), again[i].Name(), err)
		}
		// Comparing with Lstat also needs Lstat's result to be looked up, and
		// os.SameFile cannot do that for a path fixLongPath would have to
		// extend, where the process is not long-path aware (Windows XP, or a
		// later Windows without long paths enabled): stat saves the path as
		// given, and fileStat.loadFileId passes it to CreateFile without
		// fixLongPath, so the open fails and os.SameFile reports false. That
		// is independent of how the directory was listed, so it is not
		// asserted there.
		if windows.CanUseLongPaths || len(path) < 248 {
			if !os.SameFile(fi, lst) {
				t.Errorf("%s: os.SameFile(DirEntry.Info(), Lstat) = false", e.Name())
			}
		}
	}
	if !slices.Equal(names, wantNames) {
		t.Errorf("ReadDir names = %q; want %q", names, wantNames)
	}
	// The junction must be reported as a link, not as the directory it leads
	// to: that is what stops a walk from following it. It is only true if the
	// reparse tag came through.
	for _, e := range entries {
		if e.Name() == "junction" && (e.IsDir() || e.Type()&fs.ModeIrregular == 0) {
			t.Errorf("junction: IsDir %v, Type %v; want not a directory, ModeIrregular", e.IsDir(), e.Type())
		}
	}
}

// TestReadDirByHandlePaging checks that bounded reads keep their position and
// terminate, including when entries do not fit the buffer and the reader has
// to grow it and restart its scan.
func TestReadDirByHandlePaging(t *testing.T) {
	dir := t.TempDir()
	var want []string
	for i := range 12 {
		name := fmt.Sprintf("f%02d", i)
		if i == 5 || i == 9 {
			// Long enough that the entry cannot fit a small buffer that
			// holds the short ones, so the overflow happens mid-listing.
			name += strings.Repeat("x", 150)
		}
		want = append(want, name)
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o666); err != nil {
			t.Fatal(err)
		}
	}
	slices.Sort(want)

	for _, bufSize := range []int{0, 128} {
		for _, page := range []int{1, 3, 5, 100} {
			forEachReadDirReader(t, func(t *testing.T) {
				if bufSize != 0 {
					if !*os.ReadDirPreVista {
						return
					}
					old := *os.ReadDirNtQueryBufSize
					*os.ReadDirNtQueryBufSize = bufSize
					defer func() { *os.ReadDirNtQueryBufSize = old }()
				}
				f, err := os.Open(dir)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				var got []string
				for {
					chunk, err := f.Readdirnames(page)
					if len(chunk) > page {
						t.Fatalf("Readdirnames(%d) returned %d names", page, len(chunk))
					}
					got = append(got, chunk...)
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Fatalf("Readdirnames(%d): %v", page, err)
					}
					if len(got) > 2*len(want) {
						t.Fatalf("Readdirnames(%d) did not terminate: %q", page, got)
					}
				}
				slices.Sort(got)
				if !slices.Equal(got, want) {
					t.Errorf("buffer %d, Readdirnames(%d) pages = %q; want %q", bufSize, page, got, want)
				}
				// A listing that has ended stays ended.
				if chunk, err := f.Readdirnames(page); len(chunk) != 0 || err != io.EOF {
					t.Errorf("Readdirnames(%d) after the end = %q, %v; want io.EOF", page, chunk, err)
				}
				// Seeking to the start makes the listing start again.
				if _, err := f.Seek(0, io.SeekStart); err != nil {
					t.Fatal(err)
				}
				again, err := f.Readdirnames(-1)
				slices.Sort(again)
				if err != nil || !slices.Equal(again, want) {
					t.Errorf("Readdirnames(-1) after Seek = %q, %v; want %q", again, err, want)
				}
			})
		}
	}
}

// TestReadDirByHandleOverlapped lists a directory opened for asynchronous I/O,
// on which NtQueryDirectoryFile would return STATUS_PENDING.
//
// Only the pre-Vista reader is tested. Measured on Windows 11, the
// GetFileInformationByHandleEx reader, which is upstream's, blocks forever on
// such a handle.
func TestReadDirByHandleOverlapped(t *testing.T) {
	*os.ReadDirPreVista = true
	defer func() { *os.ReadDirPreVista = false }()

	dir := t.TempDir()
	for _, name := range []string{"a", "b"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o666); err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.OpenFile(dir, os.O_RDONLY|windows.O_FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, err := f.Readdirnames(-1)
	slices.Sort(got)
	if err != nil || !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("Readdirnames(-1) = %q, %v; want [a b]", got, err)
	}
}

// TestReadDirByHandleOddCases covers listings that are not of an ordinary
// directory on a local disk.
func TestReadDirByHandleOddCases(t *testing.T) {
	forEachReadDirReader(t, func(t *testing.T) {
		// An empty directory.
		dir := t.TempDir()
		if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
			t.Errorf("ReadDir(empty) = %v, %v; want no entries", entries, err)
		}

		// A regular file.
		file := filepath.Join(dir, "file")
		if err := os.WriteFile(file, nil, 0o666); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(file)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.Readdirnames(-1)
		f.Close()
		if !errors.Is(err, syscall.ENOTDIR) {
			t.Errorf("Readdirnames on a regular file = %v; want ENOTDIR", err)
		}

		// The named-pipe file system, which is not NTFS.
		pipes := `\\.\pipe\`
		if fi, err := os.Stat(pipes); err == nil && fi.IsDir() {
			if _, err := os.ReadDir(pipes); err != nil {
				t.Errorf("ReadDir(%q) = %v", pipes, err)
			}
		}
	})
}
