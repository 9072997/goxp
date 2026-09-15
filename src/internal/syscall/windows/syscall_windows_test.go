// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package windows_test

import (
	"bytes"
	"internal/syscall/windows"
	"strings"
	"testing"
	"unicode/utf16"
	"unsafe"
)

// TestRtlGenRandom checks the generator crypto/internal/sysrand falls back
// to when ProcessPrng is unavailable. It is called directly, so the fallback
// is covered on a host that has ProcessPrng as well.
func TestRtlGenRandom(t *testing.T) {
	b := make([]byte, 32)
	if err := windows.RtlGenRandom(b); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(b, make([]byte, len(b))) {
		t.Error("RtlGenRandom left the buffer zeroed")
	}
}

func TestUTF16PtrToStringAllocs(t *testing.T) {
	msg := "Hello, world 🐻"
	testUTF16PtrToStringAllocs(t, msg)
	testUTF16PtrToStringAllocs(t, strings.Repeat(msg, 10))
}

func testUTF16PtrToStringAllocs(t *testing.T, msg string) {
	in := utf16.Encode([]rune(msg + "\x00"))
	var out string
	alloccnt := testing.AllocsPerRun(1000, func() {
		out = windows.UTF16PtrToString(&in[0])
	})
	if out != msg {
		t.Errorf("windows.UTF16PtrToString(%v) returned %q; want %q", in, out, msg)
	}
	if alloccnt > 1.01 {
		t.Errorf("windows.UTF16PtrToString(%v) made %v allocs per call; want 1", in, alloccnt)
	}
}

// FILE_BOTH_DIR_INFORMATION is read straight out of a buffer the kernel fills,
// so its layout has to be the C one: ShortNameLength is a single byte, which
// puts ShortName at 70 and FileName at 94.
func TestFileBothDirInformationLayout(t *testing.T) {
	var info windows.FILE_BOTH_DIR_INFORMATION
	for _, c := range []struct {
		field     string
		got, want uintptr
	}{
		{"EndOfFile", unsafe.Offsetof(info.EndOfFile), 40},
		{"FileAttributes", unsafe.Offsetof(info.FileAttributes), 56},
		{"FileNameLength", unsafe.Offsetof(info.FileNameLength), 60},
		{"EaSize", unsafe.Offsetof(info.EaSize), 64},
		{"ShortNameLength", unsafe.Offsetof(info.ShortNameLength), 68},
		{"ShortName", unsafe.Offsetof(info.ShortName), 70},
		{"FileName", unsafe.Offsetof(info.FileName), 94},
	} {
		if c.got != c.want {
			t.Errorf("offset of %s = %d, want %d", c.field, c.got, c.want)
		}
	}
}
