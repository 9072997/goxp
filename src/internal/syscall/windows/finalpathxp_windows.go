// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package windows

import (
	"internal/syscall/windows/sysdll"
	"syscall"
	"unsafe"
)

// GetFinalPathNameByHandleW is Windows Vista and later, so FinalPath has no
// answer on XP and the shim reports ERROR_NOT_SUPPORTED. Two calls that have
// been present since NT 4 reconstruct the same result: NtQueryObject reports
// the object's NT path, and QueryDosDevice maps a device prefix back to the
// drive letter standing for it.
//
// src/syscall/fdpathxp_windows.go does the same thing for syscall.Fchdir. The
// duplication is deliberate: syscall cannot import this package - the
// dependency runs the other way - and exporting the helper would add to the
// syscall package's public surface for one internal caller.

var (
	modntdllxp           = syscall.NewLazyDLL(sysdll.Add("ntdll.dll"))
	procNtQueryObject    = modntdllxp.NewProc("NtQueryObject")
	procQueryDosDeviceXP = modkernel32.NewProc("QueryDosDeviceW")
)

const objectNameInformation = 1

const (
	statusInfoLengthMismatch = 0xC0000004
	statusBufferOverflow     = 0x80000005
	statusBufferTooSmall     = 0xC0000023
)

// pathSepXP is the NT path separator, spelled without an escape so it survives
// being moved between shells.
const pathSepXP = 0x5c

// ntObjectName returns the NT path of the object a handle refers to, for
// example \Device\HarddiskVolume1\WINDOWS\system32.
func ntObjectName(h syscall.Handle) (string, error) {
	// OBJECT_NAME_INFORMATION is a UNICODE_STRING whose Buffer points just past
	// itself, so it has to be read out of one allocation rather than copied.
	b := make([]byte, 512)
	for {
		var n uint32
		st, _, _ := syscall.SyscallN(procNtQueryObject.Addr(), uintptr(h),
			uintptr(objectNameInformation), uintptr(unsafe.Pointer(&b[0])),
			uintptr(len(b)), uintptr(unsafe.Pointer(&n)))
		if st == 0 {
			break
		}
		if st != statusInfoLengthMismatch && st != statusBufferOverflow &&
			st != statusBufferTooSmall {
			return "", ERROR_NOT_SUPPORTED
		}
		// A grown buffer that is not bigger is a loop, not a retry.
		if int(n) <= len(b) {
			return "", ERROR_NOT_SUPPORTED
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
		return "", ERROR_NOT_SUPPORTED
	}
	return syscall.UTF16ToString(unsafe.Slice(u.Buffer, u.Length/2)), nil
}

// dosPathFromNt rewrites an NT device path as a drive-letter path, or reports
// that no drive maps to it.
func dosPathFromNt(nt string) (string, bool) {
	var target [syscall.MAX_PATH + 1]uint16
	for c := byte('A'); c <= 'Z'; c++ {
		drive := []uint16{uint16(c), ':', 0}
		r, _, _ := syscall.SyscallN(procQueryDosDeviceXP.Addr(),
			uintptr(unsafe.Pointer(&drive[0])),
			uintptr(unsafe.Pointer(&target[0])), uintptr(len(target)))
		if r == 0 {
			continue
		}
		dev := syscall.UTF16ToString(target[:])
		// Match the separator too, or \Device\HarddiskVolume1 claims a path
		// belonging to \Device\HarddiskVolume10.
		if len(nt) > len(dev) && nt[:len(dev)] == dev && nt[len(dev)] == pathSepXP {
			return string([]byte{c}) + ":" + nt[len(dev):], true
		}
	}
	return "", false
}

// finalPathXP is the pre-Vista stand-in for GetFinalPathNameByHandleW.
func finalPathXP(h syscall.Handle) (string, error) {
	nt, err := ntObjectName(h)
	if err != nil {
		return "", err
	}
	dos, ok := dosPathFromNt(nt)
	if !ok {
		return "", ERROR_NOT_SUPPORTED
	}
	return dos, nil
}
