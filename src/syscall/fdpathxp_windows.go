// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package syscall

import (
	"internal/syscall/windows/sysdll"
	"unsafe"
)

// GetFinalPathNameByHandleW arrived with Windows Vista, so on XP a handle
// cannot be turned into a DOS path by asking for one. Two calls that have
// been present since NT 4 reconstruct the same answer: NtQueryObject reports
// the object's NT path, and QueryDosDevice maps a device prefix back to the
// drive letter that stands for it.
//
// Without this, anything reaching syscall.Fchdir fails on XP -- os.File.Chdir
// and testing.Chdir among them -- because fdpath is the first thing Fchdir
// does.

var (
	modntdllxp        = NewLazyDLL(sysdll.Add("ntdll.dll"))
	procNtQueryObject = modntdllxp.NewProc("NtQueryObject")
	procQueryDosDevic = modkernel32.NewProc("QueryDosDeviceW")
)

const _ObjectNameInformation = 1

// The NT path separator, spelled without an escape so that it survives
// being moved between shells.
const pathSep = 0x5c

const (
	_STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
	_STATUS_BUFFER_OVERFLOW      = 0x80000005
	_STATUS_BUFFER_TOO_SMALL     = 0xC0000023
)

// ntObjectName returns the NT path of the object a handle refers to, e.g.
// \Device\HarddiskVolume1\WINDOWS\system32.
func ntObjectName(fd Handle) (string, error) {
	// OBJECT_NAME_INFORMATION is a UNICODE_STRING whose Buffer points just
	// past itself, so the whole thing has to live in one allocation.
	b := make([]byte, 512)
	for {
		var n uint32
		st, _, _ := SyscallN(procNtQueryObject.Addr(), uintptr(fd),
			uintptr(_ObjectNameInformation), uintptr(unsafe.Pointer(&b[0])),
			uintptr(len(b)), uintptr(unsafe.Pointer(&n)))
		if st == 0 {
			break
		}
		if st != _STATUS_INFO_LENGTH_MISMATCH && st != _STATUS_BUFFER_OVERFLOW &&
			st != _STATUS_BUFFER_TOO_SMALL {
			return "", _ERROR_NOT_SUPPORTED
		}
		// A grown buffer that is not bigger is a loop, not a retry.
		if int(n) <= len(b) {
			return "", _ERROR_NOT_SUPPORTED
		}
		b = make([]byte, n)
	}
	type unicodeString struct {
		Length        uint16
		MaximumLength uint16
		Buffer        *uint16
	}
	u := (*unicodeString)(unsafe.Pointer(&b[0]))
	if u.Buffer == nil || u.Length == 0 {
		return "", _ERROR_NOT_SUPPORTED
	}
	return UTF16ToString(unsafe.Slice(u.Buffer, u.Length/2)), nil
}

// dosPathFromNt rewrites an NT device path as a drive-letter path, or reports
// that no drive maps to it.
func dosPathFromNt(nt string) (string, bool) {
	var target [MAX_PATH + 1]uint16
	for c := byte('A'); c <= 'Z'; c++ {
		drive := []uint16{uint16(c), ':', 0}
		r, _, _ := SyscallN(procQueryDosDevic.Addr(),
			uintptr(unsafe.Pointer(&drive[0])),
			uintptr(unsafe.Pointer(&target[0])), uintptr(len(target)))
		if r == 0 {
			continue
		}
		dev := UTF16ToString(target[:])
		// Match on the separator too, so \Device\HarddiskVolume1 does not
		// claim a path belonging to \Device\HarddiskVolume10.
		if len(nt) > len(dev) && nt[:len(dev)] == dev && nt[len(dev)] == pathSep {
			return string([]byte{c}) + ":" + nt[len(dev):], true
		}
	}
	return "", false
}

// fdpathXP is the pre-Vista stand-in for GetFinalPathNameByHandleW.
func fdpathXP(fd Handle) ([]uint16, error) {
	nt, err := ntObjectName(fd)
	if err != nil {
		return nil, err
	}
	dos, ok := dosPathFromNt(nt)
	if !ok {
		return nil, _ERROR_NOT_SUPPORTED
	}
	return UTF16FromString(dos)
}
